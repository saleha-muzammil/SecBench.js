#!/usr/bin/env python3
"""
Generate FIXED-version Dockerfiles for SecBench.js benchmark entries.

This is the sibling of generate_dockerfile.py. Instead of the vulnerable version,
it builds each entry against the patched ``fixedVersion`` from the folder's
package.json, while running the SAME exploit test. The expected result inverts:

    vulnerable image  -> exploit test PASSES (vulnerability reproduces)
    fixed image       -> exploit test FAILS  (patch closed the hole)

To avoid clobbering the vulnerable Dockerfile, output goes to ``Dockerfile.fixed``
next to it, and the image tag is ``secbench-fixed/<folder>``. Build with:

    docker build -t secbench-fixed/djv_2.0.0 -f Dockerfile.fixed code-injection/djv_2.0.0

All the heavy lifting (templates, repo resolution, npm fallback, entry walking)
is reused from generate_dockerfile.py — only the version is swapped.

Usage:
    python3 generate_dockerfile_fixed.py <owner/repo | package>   # one entry
    python3 generate_dockerfile_fixed.py --category code-injection # a whole class
    python3 generate_dockerfile_fixed.py --all                     # everything
    # options: [--csv repositories.csv] [--force] [--node 16] [--print]

Entries whose package.json has no usable fixedVersion (n/a / empty) are skipped.
"""

import argparse
import sys
from pathlib import Path

from generate_dockerfile import (
    ROOT, CATEGORIES, FLAG_HTML, version_gt, shared_utils_step, scanners_step,
    DOCKERFILE_HEAD, CLONE_STEP, CLONE_STEP_STRICT, NPM_STEP, DOCKERFILE_TAIL,
    NPM_INSTALL, NPM_INSTALL_LEGACY,
    csv_repo_index, build_entry, collect_entries, find_matches_disk,
)

OUTPUT_NAME = "Dockerfile.fixed"


def render_fixed(entry, node, allow_npm_fallback=False, scanners=True):
    """Render a Dockerfile for the patched version; returns (build_path, text)."""
    fixed = entry["fixed_version"]
    flag = (FLAG_HTML.replace("\\", "\\\\")
            .replace("'", "'\\''")
            .replace("\n", "\\n"))
    folder = entry["folder"]
    build_path = f"{entry['category']}/{folder}"
    sha = entry.get("fix_commit_sha", "")
    if entry["repository_url"]:
        # Strict by default. A fixed image that silently falls back to the
        # default branch (or to npm) is worse than no image: the whole pipeline
        # takes it as the patched baseline, so "exploit fails here" gets read as
        # "the patch works" when it may just be different code entirely.
        step = CLONE_STEP if allow_npm_fallback else CLONE_STEP_STRICT
        source_mode = f"git clone {entry['repository_url']} @ {fixed} (fixed)"
    else:
        step = NPM_STEP
        source_mode = f"npm install {entry['package']}@{fixed} (fixed, no repo resolved)"

    # Fixed image: prefer the exact fix-commit SHA (always present in a full clone,
    # and many packages publish to npm without tagging releases), falling back to
    # the version tag. Checking out the fix commit also makes the patch reverse-apply
    # cleanly (the tree is exactly that commit), instead of falling back to an npm
    # tarball that has no git history to revert.
    # A plain `git checkout <sha>` only reaches commits reachable from a branch.
    # Packages published from a since-rebased or since-deleted branch (dotty) keep
    # the object on the server but not in any ref, so a full clone misses it; an
    # explicit `git fetch origin <sha>` still retrieves it. Try that before giving
    # up on the ref -- the alternative is the npm fallback, which has no git tree.
    def _resolve(ref):
        return (f'git checkout -q "{ref}" '
                f'|| {{ git fetch -q --depth 1 origin "{ref}" && git checkout -q FETCH_HEAD; }}')

    tag_clause = f'git checkout -q "v{fixed}" || git checkout -q "{fixed}"'
    if sha:
        checkout_clause = f'{_resolve(sha)} || {tag_clause}'
        checkout_desc = f"commit {sha[:10]} / tag v{fixed}"
    else:
        checkout_clause = tag_clause
        checkout_desc = f"version tag v{fixed}/{fixed}"

    body = DOCKERFILE_HEAD + step + DOCKERFILE_TAIL
    return build_path, body.format(
        package=entry["package"],
        version=fixed,                       # <-- the only real change: fixed version
        category=entry["category"],
        cve=entry["cve"],
        repository=entry["repository"] or "(none)",
        repository_url=entry["repository_url"],
        source_mode=source_mode,
        checkout_clause=checkout_clause,
        checkout_desc=checkout_desc,
        tag=f"secbench-fixed/{folder}".lower(),
        build_path=build_path,
        folder=folder,
        node=node,
        flag=flag,
        shared_utils=shared_utils_step(entry["category"]),
        scanners=scanners_step(scanners),
        npm_install=NPM_INSTALL,
        npm_install_legacy=NPM_INSTALL_LEGACY,
    )


def main():
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("name", nargs="?",
                    help="repository (owner/repo) or npm package name "
                         "(omit when using --category or --all)")
    ap.add_argument("--category", "-c",
                    help="generate for EVERY entry in this category")
    ap.add_argument("--all", action="store_true",
                    help="generate for every entry in every category")
    ap.add_argument("--csv", default="repositories.csv",
                    help="CSV used to enrich repositories (default: repositories.csv)")
    ap.add_argument("--node", default="16", help="Node major version (default: 16)")
    ap.add_argument("--force", action="store_true",
                    help=f"overwrite an existing {OUTPUT_NAME}")
    ap.add_argument("--allow-npm-fallback", action="store_true",
                    help="when the fix commit / version tag is missing, install from "
                         "npm instead of failing the build (default: fail loudly, so "
                         "the fixed baseline is never silently the wrong tree)")
    ap.add_argument("--no-scanners", dest="scanners", action="store_false",
                    help="omit semgrep and the CodeQL CLI. They are ON by default "
                         "here because this is the image the evasion pipeline runs "
                         "its scanner gates inside (--docker-image); without them "
                         "the gates silently pass everything. The layers are shared "
                         "across every entry, so the cost on disk is paid once.")
    ap.add_argument("--print", dest="print_only", action="store_true",
                    help="print the Dockerfile(s) instead of writing")
    args = ap.parse_args()

    if sum(bool(x) for x in (args.name, args.category, args.all)) != 1:
        ap.error("provide exactly one of: a name, --category CAT, or --all")

    csv_path = Path(args.csv)
    if not csv_path.is_absolute():
        csv_path = ROOT / csv_path
    repo_index = csv_repo_index(csv_path)

    if args.category:
        cat = args.category.strip().strip("/").lower()
        if cat not in CATEGORIES and not (ROOT / cat).is_dir():
            sys.exit(f"error: unknown category '{args.category}'. "
                     f"Known categories: {', '.join(CATEGORIES)}")
        matches = collect_entries([cat], repo_index)
        print(f"Generating FIXED Dockerfiles for {len(matches)} entries in '{cat}'.")
    elif args.all:
        matches = collect_entries(CATEGORIES, repo_index)
        print(f"Generating FIXED Dockerfiles for all {len(matches)} entries.")
    else:
        matches = find_matches_disk(args.name, repo_index)
        if not matches:
            sys.exit(f"error: no benchmark entry matches '{args.name}'.")
        print(f"Matched {len(matches)} entr{'y' if len(matches) == 1 else 'ies'} "
              f"for '{args.name}'.")

    written = skipped_exists = skipped_nofix = skipped_badfix = 0
    for entry in matches:
        build_path = f"{entry['category']}/{entry['folder']}"
        if not entry["fixed_version"]:
            print(f"  ~ skip {build_path}: no fixedVersion in package.json")
            skipped_nofix += 1
            continue

        # A fixedVersion at or below the vulnerable version cannot be a fix.
        # lodash@4.17.15 records fixedVersion 4.17.5 and simple-markdown@0.7.2
        # records 0.6.1, so both "fixed" images were built from code OLDER than
        # the vulnerable one -- and duly reported the exploit as still firing.
        if not version_gt(entry["fixed_version"], entry["version"]):
            print(f"  ! skip {build_path}: fixedVersion "
                  f"{entry['fixed_version']} is not newer than the vulnerable "
                  f"{entry['version']} -- the metadata is wrong, fix it in "
                  f"repositories.csv/package.json before building a baseline")
            skipped_badfix += 1
            continue

        _, dockerfile = render_fixed(entry, args.node, args.allow_npm_fallback,
                                     scanners=args.scanners)

        if args.print_only:
            print(f"\n# ===== {build_path}/{OUTPUT_NAME} =====")
            print(dockerfile)
            continue

        target = entry["path"] / OUTPUT_NAME
        if target.exists() and not args.force:
            print(f"  - exists, skipping (use --force): {build_path}/{OUTPUT_NAME}")
            skipped_exists += 1
            continue

        target.write_text(dockerfile, encoding="utf-8")
        written += 1
        mode = "clone" if entry["repository_url"] else "npm"
        print(f"  + wrote {build_path}/{OUTPUT_NAME}  "
              f"({entry['package']}@{entry['fixed_version']}, {mode}, build with: "
              f"docker build -f {OUTPUT_NAME} {build_path})")

    if not args.print_only:
        print(f"\nDone. {written} written, {skipped_exists} already existed, "
              f"{skipped_nofix} had no fixedVersion.")


if __name__ == "__main__":
    main()
