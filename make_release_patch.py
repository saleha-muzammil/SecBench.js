#!/usr/bin/env python3
"""
Rebuild patch.txt as the VULNERABLE -> FIXED release diff.

fetch_patch.py writes patch.txt from the advisory's mined fix commit. That is
the right thing when the mined commit really is the fix, and the wrong thing
often enough to matter: across the campaign CSVs, 46 entries reverse-applied
their patch cleanly and then failed to reproduce the exploit, because the mined
commit was a release bump (set-value: the commit titled "4.0.1", touching only
package.json), one commit of a multi-commit fix (merge-deep: "[PATCH 1/3]"), a
test refactor (html-dom-parser), or the fix for a different CVE in the same
package (lodash@4.17.4: the PoC calls _.lowerCase, the patch fixes trim).

The two images bracket the bug by construction -- the vulnerable one is built
at the vulnerable release, the fixed one at the fixed release -- so the diff
between those two refs is, by definition, everything that closed it. Reverting
it on the fixed tree reproduces the vulnerable tree exactly, and the pipeline's
own ddmin pass then cuts that back down to the units the exploit actually needs.
So the mined commit is not needed to define the patch; it was only ever a guess
at where inside this range the fix lives.

Two things keep the diff usable as a benchmark input:

  * non-production paths are dropped (tests, docs, lockfiles, CI config), since
    reverting a test file cannot reopen a vulnerability but can break the run;
  * if the range still spans more files than --max-files, it is narrowed to the
    sink file recorded in the entry's package.json, and then to that file's
    directory. Release ranges across a major version (three@0.122 -> 0.125)
    otherwise produce thousands of files and nothing can minimize that.

Non-destructive: the previous patch.txt is kept as patch.txt.mined-fix-commit.

Usage:
    python3 make_release_patch.py redos/browserslist_4.16.4
    python3 make_release_patch.py --category path-traversal --dry-run
    python3 make_release_patch.py redos/cejs_2.0.20170212 --max-files 40
"""
import argparse
import json
import re
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
from minimize_and_evade import is_production_path          # noqa: E402

CACHE = ROOT / ".release-patch-cache"
SHA_RE = re.compile(r"\b([0-9a-f]{7,40})\b", re.I)


def sh(args, cwd=None, timeout=1800, check=False):
    r = subprocess.run(args, cwd=cwd, capture_output=True, text=True, timeout=timeout)
    if check and r.returncode != 0:
        raise RuntimeError(f"{' '.join(args[:4])}... failed: {r.stderr.strip()[-300:]}")
    return r


def clone(url, dest):
    """Partial clone: history and trees, blobs fetched on demand."""
    if dest.exists():
        return dest
    dest.parent.mkdir(parents=True, exist_ok=True)
    sh(["git", "clone", "--filter=blob:none", "--no-checkout", url + ".git", str(dest)],
       check=True)
    return dest


def version_at(repo, ref, manifest="package.json"):
    r = sh(["git", "show", f"{ref}:{manifest}"], cwd=repo)
    if r.returncode != 0:
        return None
    try:
        return json.loads(r.stdout).get("version")
    except json.JSONDecodeError:
        return None


def resolve(repo, version, extra_shas=(), package="", manifest="package.json"):
    """Find a ref for `version`: its tag, an explicit sha, or the bump commit.

    `manifest` is the package.json that carries the version. For a monorepo
    entry that is the leaf (packages/<name>/package.json), not the root -- the
    root's version has nothing to do with the released package.
    """
    # `<package>@<version>` is how lerna/nx monorepos (conventional-changelog,
    # fast-csv, ethers) tag a release; plain `v<version>` never exists there.
    candidates = [f"v{version}", version]
    if package:
        candidates.append(f"{package}@{version}")
    for ref in candidates:
        if sh(["git", "rev-parse", "--verify", "-q", f"{ref}^{{commit}}"],
              cwd=repo).returncode == 0:
            return ref, f"tag {ref}"
    for sha in extra_shas:
        if not sha:
            continue
        if sh(["git", "cat-file", "-e", f"{sha}^{{commit}}"], cwd=repo).returncode != 0:
            sh(["git", "fetch", "-q", "--depth", "1", "origin", sha], cwd=repo)
        if sh(["git", "cat-file", "-e", f"{sha}^{{commit}}"], cwd=repo).returncode == 0:
            if version_at(repo, sha, manifest) == version:
                return sha, f"commit {sha[:10]} ({manifest} says {version})"
    # Last resort: walk the manifest's history for the commit that bumped to it.
    hit = None
    for sha in sh(["git", "log", "--format=%H", "--", manifest],
                  cwd=repo).stdout.split():
        if version_at(repo, sha, manifest) == version:
            hit = sha                      # newest->oldest, so this ends on the bump
    if hit:
        return hit, f"version-bump commit {hit[:10]} in {manifest}"
    return None, f"no tag, sha or bump commit for {version}"


def entry_meta(folder):
    path = ROOT / folder
    meta = json.loads((path / "package.json").read_text(encoding="utf-8"))
    deps = meta.get("dependencies") or {}
    package = next(iter(deps), "") or path.name.rpartition("_")[0]
    url = ""
    for key in ("fixedReleaseCommit", "fixCommit"):
        m = re.match(r"(https://github\.com/[^/]+/[^/]+)", meta.get(key) or "")
        if m:
            url = m.group(1)
            break
    return {
        "path": path, "package": package,
        "version": path.name.rpartition("_")[2],
        "fixed": (meta.get("fixedVersion") or "").strip(),
        "fix_sha": (SHA_RE.search(meta.get("fixCommit") or "") or [None, ""])[1],
        "release_sha": (SHA_RE.search(meta.get("fixedReleaseCommit") or "") or [None, ""])[1],
        "sink": (meta.get("sink") or "").split(":")[0],
        "patch_files": list(meta.get("patchFiles") or []),
        "url": url,
    }


def narrow(repo, a, b, files, sink, max_files):
    """Shrink an over-wide release range to something minimizable."""
    if len(files) <= max_files:
        return files, f"{len(files)} production file(s)"
    if sink:
        base = sink.split("/")[-1]
        hit = [f for f in files if f.endswith("/" + base) or f == base or f == sink]
        if hit:
            return hit, (f"narrowed from {len(files)} to the sink file {hit[0]} "
                         f"(range too wide to minimize)")
        d = sink.rpartition("/")[0]
        if d:
            hit = [f for f in files if f.startswith(d + "/")]
            if hit and len(hit) <= max_files:
                return hit, (f"narrowed from {len(files)} to the sink directory "
                             f"{d}/ ({len(hit)} files)")
    return None, (f"{len(files)} production files exceeds --max-files {max_files} "
                  f"and the sink ({sink or 'unrecorded'}) does not narrow it")


def build(folder, args):
    e = entry_meta(folder)
    tag = f"{folder}"
    if not e["url"] or not e["fixed"]:
        return tag, None, "no repository url or no fixedVersion"
    repo = clone(e["url"], CACHE / e["package"].replace("/", "-"))

    manifest = "package.json"
    if e["sink"].startswith("packages/"):
        manifest = "/".join(e["sink"].split("/")[:2]) + "/package.json"
    ref_v, how_v = resolve(repo, e["version"], package=e["package"],
                           manifest=manifest)
    ref_f, how_f = resolve(repo, e["fixed"], (e["release_sha"], e["fix_sha"]),
                           package=e["package"], manifest=manifest)
    if not ref_v:
        return tag, None, f"vulnerable ref: {how_v}"
    if not ref_f:
        return tag, None, f"fixed ref: {how_f}"

    names = sh(["git", "diff", "--name-only", f"{ref_v}..{ref_f}"], cwd=repo)
    if names.returncode != 0:
        return tag, None, f"git diff failed: {names.stderr.strip()[-200:]}"
    all_files = [f for f in names.stdout.split("\n") if f.strip()]
    prod = [f for f in all_files if is_production_path(f)]
    if not prod:
        return tag, None, (f"{ref_v}..{ref_f} changes no production code "
                           f"({len(all_files)} file(s) total)")
    if e["patch_files"]:
        # An explicit list, for ranges where some production file is coupled to a
        # dependency's layout rather than to the bug: markdown-it's
        # lib/common/entities.js switches between entities@1 (maps/) and
        # entities@2 (lib/maps/), so reverting it makes the module unloadable on
        # either pin and the exploit can never run.
        missing = [f for f in e["patch_files"] if f not in prod]
        if missing:
            return tag, None, (f"patchFiles not in the {ref_v}..{ref_f} production "
                               f"diff: {', '.join(missing)}")
        keep = e["patch_files"]
        why = f"{len(keep)} file(s) pinned by patchFiles (of {len(prod)} in range)"
    else:
        keep, why = narrow(repo, ref_v, ref_f, prod, e["sink"], args.max_files)
        if keep is None:
            return tag, None, why

    diff = sh(["git", "diff", "--binary", f"{ref_v}..{ref_f}", "--"] + keep,
              cwd=repo, check=True).stdout
    if not diff.strip():
        return tag, None, f"{ref_v}..{ref_f} produced an empty diff over {keep[:3]}"

    header = (
        f"From {ref_f if len(ref_f) == 40 else '0' * 40} Mon Sep 17 00:00:00 2001\n"
        f"From: make_release_patch.py <secbench>\n"
        f"Subject: [PATCH] {e['package']} {e['version']} -> {e['fixed']} "
        f"(release range, production files only)\n"
        f"\n"
        f"Generated from {how_v} .. {how_f}; {why}.\n"
        f"Reverting this on the fixed tree reproduces the {e['version']} tree.\n"
        f"---\n"
    )
    return tag, header + diff, f"{how_v} .. {how_f}; {why}"


def main():
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("folders", nargs="*", help="category/folder paths")
    ap.add_argument("--category", "-c", help="every entry in this category")
    ap.add_argument("--max-files", type=int, default=25,
                    help="widest production diff to accept before narrowing to "
                         "the sink (default: 25)")
    ap.add_argument("--dry-run", action="store_true",
                    help="report what each entry would get; write nothing")
    args = ap.parse_args()

    folders = list(args.folders)
    if args.category:
        folders += [f"{args.category}/{p.name}"
                    for p in sorted((ROOT / args.category).iterdir())
                    if p.is_dir() and (p / "package.json").exists()]
    if not folders:
        ap.error("give at least one folder or --category")

    ok = bad = 0
    for folder in folders:
        try:
            tag, patch, why = build(folder, args)
        except Exception as exc:                                  # noqa: BLE001
            print(f"  ! {folder}: {exc!r}", flush=True)
            bad += 1
            continue
        if patch is None:
            print(f"  ~ skip {folder}: {why}", flush=True)
            bad += 1
            continue
        n = len(re.findall(r"^diff --git ", patch, re.M))
        print(f"  + {folder}: {n} file(s) -- {why}", flush=True)
        ok += 1
        if args.dry_run:
            continue
        dst = ROOT / folder / "patch.txt"
        keep = dst.with_suffix(".txt.mined-fix-commit")
        if dst.exists() and not keep.exists():
            shutil.copy2(dst, keep)
        dst.write_text(patch, encoding="utf-8")

    print(f"\n{ok} rebuilt, {bad} skipped."
          + ("  (dry run -- nothing written)" if args.dry_run else ""))


if __name__ == "__main__":
    main()
