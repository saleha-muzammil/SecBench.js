#!/usr/bin/env python3
"""
Inventory the tests and CI of each benchmark repository.

For every entry in a category (default: code-injection) this script resolves the
upstream repository (the same way generate_dockerfile.py does), shallow-clones it
at the vulnerable version, scans it for:

  * package.json test scripts and test-framework dependencies;
  * test directories and test files;
  * test runner config (jest/mocha/ava/karma/...);
  * CI / workflow files (.github/workflows, Travis, CircleCI, GitLab, ...);

and writes a human-readable summary to <category>/<folder>/tests_and_ci.txt.

Entries with no resolvable upstream repository (installed from npm) get a short
note instead.

Usage:
    python3 inspect_tests_ci.py                       # all code-injection entries
    python3 inspect_tests_ci.py --category redos
    python3 inspect_tests_ci.py --all
    python3 inspect_tests_ci.py code-injection/djv_2.0.0   # a single entry
    # options: [--csv repositories.csv] [--force] [--keep-clones]
"""

import argparse
import json
import shutil
import subprocess
import sys
import tempfile
from datetime import date
from pathlib import Path

# Reuse the repository-resolution logic from the Dockerfile generator.
from generate_dockerfile import (
    ROOT, CATEGORIES, csv_repo_index, build_entry, collect_entries,
)

OUTPUT_NAME = "tests_and_ci.txt"

# Directories that commonly hold tests.
TEST_DIR_NAMES = {"test", "tests", "__tests__", "spec", "specs", "test-suite"}

# Test-file name patterns (glob, relative to repo root, node_modules/.git excluded).
TEST_FILE_GLOBS = ["**/*.test.js", "**/*.spec.js", "**/*.test.ts", "**/*.spec.ts",
                   "**/*-test.js", "**/test.js"]

# Test runner config files to look for at the repo root.
TEST_CONFIG_NAMES = [
    "jest.config.js", "jest.config.ts", "jest.config.json", "jest.config.cjs",
    ".mocharc", ".mocharc.json", ".mocharc.yml", ".mocharc.yaml", ".mocharc.js",
    "mocha.opts", "karma.conf.js", "ava.config.js", "vitest.config.js",
    "vitest.config.ts", "jasmine.json", "protractor.conf.js", "wallaby.js",
]

# Known test-framework package names (checked against dependencies/devDependencies).
TEST_FRAMEWORKS = ["jest", "mocha", "ava", "tape", "tap", "jasmine", "karma",
                   "vitest", "qunit", "should", "chai", "expect.js", "nyc",
                   "istanbul", "cypress", "playwright"]

# CI / workflow locations. (dir, glob) entries are expanded; plain strings are files.
CI_DIRS = [(".github/workflows", "*.yml"), (".github/workflows", "*.yaml"),
           (".circleci", "*.yml"), (".circleci", "*.yaml")]
CI_FILES = [".travis.yml", ".gitlab-ci.yml", "appveyor.yml", ".appveyor.yml",
            "azure-pipelines.yml", "Jenkinsfile", "wercker.yml",
            "bitbucket-pipelines.yml", ".drone.yml", "cloudbuild.yaml"]

CI_CONTENT_CAP = 4000   # max chars of each CI file to embed


def run(cmd, cwd=None):
    return subprocess.run(cmd, cwd=cwd, stdout=subprocess.PIPE,
                          stderr=subprocess.STDOUT, text=True)


def clone_at_version(url, version, dest):
    """Shallow-clone url at the vulnerable version. Returns the ref used, or None."""
    base = url[:-4] if url.endswith(".git") else url
    git_url = base + ".git"
    for ref in (f"v{version}", version):
        shutil.rmtree(dest, ignore_errors=True)
        r = run(["git", "clone", "--depth", "1", "--branch", ref, git_url, str(dest)])
        if r.returncode == 0:
            return ref
    # Fall back to a shallow clone of the default branch.
    shutil.rmtree(dest, ignore_errors=True)
    r = run(["git", "clone", "--depth", "1", git_url, str(dest)])
    return None if r.returncode == 0 else False  # False => clone failed entirely


def iter_files(repo, globs):
    """Yield repo-relative paths matching any glob, skipping node_modules/.git."""
    seen = set()
    for pattern in globs:
        for p in repo.glob(pattern):
            if not p.is_file():
                continue
            rel = p.relative_to(repo)
            parts = set(rel.parts)
            if "node_modules" in parts or ".git" in parts:
                continue
            if rel not in seen:
                seen.add(rel)
                yield rel


def load_pkg(repo):
    pj = repo / "package.json"
    if not pj.exists():
        return {}
    try:
        return json.loads(pj.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return {}


def infer_run_steps(pkg, frameworks):
    """Best-effort 'how to run the tests' commands."""
    scripts = pkg.get("scripts") or {}
    steps = []
    install = "yarn install" if (
        scripts.get("test", "").startswith("yarn") or "workspaces" in pkg) else "npm install"
    steps.append(install)
    if "test" in scripts:
        steps.append("npm test")
    elif "jest" in frameworks:
        steps.append("npx jest")
    elif "mocha" in frameworks:
        steps.append("npx mocha")
    elif "ava" in frameworks:
        steps.append("npx ava")
    elif "tape" in frameworks or "tap" in frameworks:
        steps.append("npx tape test/*.js")
    else:
        steps.append("# no test script or known runner detected")
    return steps


def inspect(repo):
    """Gather a report dict from a cloned repo working tree."""
    pkg = load_pkg(repo)
    scripts = pkg.get("scripts") or {}
    deps = {**(pkg.get("dependencies") or {}), **(pkg.get("devDependencies") or {})}
    frameworks = [f for f in TEST_FRAMEWORKS if f in deps]

    # test scripts: the canonical "test" plus anything that looks test-related.
    test_scripts = {k: v for k, v in scripts.items()
                    if k == "test" or k.startswith("test")
                    or any(fw in str(v) for fw in TEST_FRAMEWORKS)
                    or "coverage" in k.lower()}

    test_dirs = []
    for child in sorted(repo.iterdir()) if repo.is_dir() else []:
        if child.is_dir() and child.name.lower() in TEST_DIR_NAMES:
            n = sum(1 for _ in iter_files(child, ["**/*"]))
            test_dirs.append((child.name, n))

    test_files = sorted(str(p) for p in iter_files(repo, TEST_FILE_GLOBS))

    test_configs = [n for n in TEST_CONFIG_NAMES if (repo / n).exists()]
    if "ava" in (pkg or {}):
        test_configs.append("package.json#ava")
    if "jest" in (pkg or {}):
        test_configs.append("package.json#jest")
    if "mocha" in (pkg or {}):
        test_configs.append("package.json#mocha")

    ci = []
    for d, glob in CI_DIRS:
        ci_dir = repo / d
        if ci_dir.is_dir():
            ci += [str((Path(d) / f.name)) for f in sorted(ci_dir.glob(glob)) if f.is_file()]
    for f in CI_FILES:
        if (repo / f).exists():
            ci.append(f)

    return {
        "pkg_name": pkg.get("name", ""),
        "test_scripts": test_scripts,
        "frameworks": frameworks,
        "run_steps": infer_run_steps(pkg, frameworks),
        "test_dirs": test_dirs,
        "test_files": test_files,
        "test_configs": test_configs,
        "ci": ci,
    }


def format_report(entry, ref, report, repo):
    lines = []
    add = lines.append
    add("SecBench.js — test & CI inventory")
    add("=" * 60)
    add(f"Entry      : {entry['category']}/{entry['folder']}")
    add(f"Package    : {entry['package']}@{entry['version']}")
    add(f"Repository : {entry['repository_url'] or '(none)'}")
    checkout = ("(default branch — version tag not found)" if ref is None
                else f"checked out: {ref}")
    add(f"Source     : {checkout}")
    add(f"Generated  : {date.today().isoformat()}")
    add("")

    add("== package.json test scripts ==")
    if report["test_scripts"]:
        for k, v in report["test_scripts"].items():
            add(f"  {k}: {v}")
    else:
        add("  (none found)")
    add("")

    add("== test framework dependencies ==")
    add("  " + (", ".join(report["frameworks"]) if report["frameworks"] else "(none detected)"))
    add("")

    add("== how to run the tests ==")
    for step in report["run_steps"]:
        add(f"  {step}")
    add("")

    add("== test directories ==")
    if report["test_dirs"]:
        for name, n in report["test_dirs"]:
            add(f"  {name}/   ({n} files)")
    else:
        add("  (none found)")
    add("")

    add(f"== test files ({len(report['test_files'])} found) ==")
    if report["test_files"]:
        for f in report["test_files"][:60]:
            add(f"  {f}")
        if len(report["test_files"]) > 60:
            add(f"  ... and {len(report['test_files']) - 60} more")
    else:
        add("  (none found)")
    add("")

    add("== test runner config ==")
    add("  " + (", ".join(report["test_configs"]) if report["test_configs"] else "(none found)"))
    add("")

    add("== CI / workflows ==")
    if report["ci"]:
        for f in report["ci"]:
            add(f"  {f}")
        add("")
        for f in report["ci"]:
            p = repo / f
            try:
                content = p.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            add(f"  --- {f} ---")
            snippet = content[:CI_CONTENT_CAP]
            for cl in snippet.splitlines():
                add(f"  | {cl}")
            if len(content) > CI_CONTENT_CAP:
                add(f"  | ... (truncated, {len(content) - CI_CONTENT_CAP} more chars)")
            add("")
    else:
        add("  (no CI / workflow files found)")
        add("")

    return "\n".join(lines) + "\n"


def npm_only_report(entry):
    return (
        "SecBench.js — test & CI inventory\n" + "=" * 60 + "\n"
        f"Entry      : {entry['category']}/{entry['folder']}\n"
        f"Package    : {entry['package']}@{entry['version']}\n"
        "Repository : (none resolved)\n\n"
        "No upstream source repository could be resolved for this package, so it is\n"
        "installed from the npm registry. There is no repo to inspect for tests/CI.\n"
        "To examine the published tarball instead:\n"
        f"  npm pack {entry['package']}@{entry['version']} && tar -xf *.tgz\n"
    )


def clonefail_report(entry):
    return (
        "SecBench.js — test & CI inventory\n" + "=" * 60 + "\n"
        f"Entry      : {entry['category']}/{entry['folder']}\n"
        f"Package    : {entry['package']}@{entry['version']}\n"
        f"Repository : {entry['repository_url']}\n\n"
        "The resolved upstream repository could not be cloned (it is private, was\n"
        "renamed/removed, or the metadata points at a dead fork). Tests/CI could not\n"
        "be inspected. Options:\n"
        "  * find the current repo and clone it manually, or\n"
        f"  * inspect the published npm tarball instead:\n"
        f"      npm pack {entry['package']}@{entry['version']} && tar -xf *.tgz\n"
    )


def process(entry, keep_clones, force):
    out_path = entry["path"] / OUTPUT_NAME
    rel = f"{entry['category']}/{entry['folder']}"
    if out_path.exists() and not force:
        print(f"  - exists, skipping (use --force): {rel}/{OUTPUT_NAME}")
        return "skip"

    if not entry["repository_url"]:
        out_path.write_text(npm_only_report(entry), encoding="utf-8")
        print(f"  ~ {rel}: no repo (npm-only note written)")
        return "norepo"

    tmp = Path(tempfile.mkdtemp(prefix="secbench-clone-"))
    repo = tmp / "repo"
    try:
        ref = clone_at_version(entry["repository_url"], entry["version"], repo)
        if ref is False:
            out_path.write_text(clonefail_report(entry), encoding="utf-8")
            print(f"  ! {rel}: clone FAILED ({entry['repository_url']})")
            return "clonefail"
        report = inspect(repo)
        out_path.write_text(format_report(entry, ref, report, repo), encoding="utf-8")
        tag = ref if ref else "default-branch"
        print(f"  + {rel}: {len(report['test_files'])} test files, "
              f"{len(report['ci'])} CI files  [{tag}]")
        return "ok"
    finally:
        if keep_clones:
            dest = entry["path"] / "_repo_clone"
            shutil.rmtree(dest, ignore_errors=True)
            if repo.exists():
                shutil.move(str(repo), str(dest))
        shutil.rmtree(tmp, ignore_errors=True)


def main():
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("target", nargs="?",
                    help="a single <category>/<folder> to inspect")
    ap.add_argument("--category", "-c", default=None,
                    help="inspect a whole category (default: code-injection)")
    ap.add_argument("--all", action="store_true", help="inspect every category")
    ap.add_argument("--csv", default="repositories.csv",
                    help="CSV used to enrich repositories (default: repositories.csv)")
    ap.add_argument("--force", action="store_true",
                    help=f"overwrite an existing {OUTPUT_NAME}")
    ap.add_argument("--keep-clones", action="store_true",
                    help="leave the cloned repo in <folder>/_repo_clone for inspection")
    args = ap.parse_args()

    csv_path = Path(args.csv)
    if not csv_path.is_absolute():
        csv_path = ROOT / csv_path
    repo_index = csv_repo_index(csv_path)

    if args.target:
        target = args.target.rstrip("/")
        path = Path(target)
        if not path.is_absolute():
            path = ROOT / target
        if not path.is_dir():
            sys.exit(f"error: no such folder: {target}")
        entry = build_entry(path.parent.name, path, repo_index)
        if not entry:
            sys.exit(f"error: {target} has no readable package.json")
        entries = [entry]
    elif args.all:
        entries = collect_entries(CATEGORIES, repo_index)
    else:
        cat = (args.category or "code-injection").strip().strip("/").lower()
        if not (ROOT / cat).is_dir():
            sys.exit(f"error: unknown category '{cat}'. Known: {', '.join(CATEGORIES)}")
        entries = collect_entries([cat], repo_index)

    print(f"Inspecting {len(entries)} entr{'y' if len(entries) == 1 else 'ies'} ...")
    counts = {}
    for entry in entries:
        result = process(entry, args.keep_clones, args.force)
        counts[result] = counts.get(result, 0) + 1

    print("\nDone. " + ", ".join(f"{v} {k}" for k, v in sorted(counts.items())))


if __name__ == "__main__":
    main()
