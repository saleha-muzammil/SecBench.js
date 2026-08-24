#!/usr/bin/env python3
"""Build every `Dockerfile.fixed` target, then measure what reverting `patch.txt` costs in semgrep findings.

For each `<category>/<target>/` that has a `Dockerfile.fixed`:

  1. `docker build -f Dockerfile.fixed` -> the target is BUILD_FAIL or built.
  2. Copy the fixed package tree out of the image (the `node_modules/<pkg>` the Dockerfile clones).
  3. Scan that tree with semgrep -> the FIXED baseline.
  4. If `patch.txt` exists: copy the tree, reverse-apply the patch (re-introducing the vulnerability),
     scan again -> the REVERTED count, and report the delta.

The semgrep configuration is mini-swe-agent's: the same registry packs plus
`src/minisweagent/config/extra/semgrep_rules.yaml`, plus any rules the repo itself ships.

Usage:
    python3 fixed_revert_semgrep.py                       # everything under code-injection/
    python3 fixed_revert_semgrep.py --only js-yaml_3.13.0 --only underscore_1.13.0-0
    python3 fixed_revert_semgrep.py --skip-build          # reuse images from a previous run
    python3 fixed_revert_semgrep.py --no-packs            # mini rules only (offline / fast)
"""

from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess
import sys
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field, asdict
from pathlib import Path

# --------------------------------------------------------------------------------------
# Configuration
# --------------------------------------------------------------------------------------

BENCH_ROOT = Path("/Users/saleha/Desktop/cispa/SecBench.js")
MINI_ROOT = Path("/Users/saleha/Desktop/cispa/mini-swe-agent")
MINI_RULES = MINI_ROOT / "src/minisweagent/config/extra/semgrep_rules.yaml"

# Same packs curl_issue.py::_SEMGREP_PACKS enables.
SEMGREP_PACKS = ("p/default", "p/javascript", "p/typescript", "p/nodejs", "p/golang",
                 "p/security-audit", "p/owasp-top-ten", "p/xss", "p/command-injection", "p/secrets")
SEMGREP_REPO_RULES = (".semgrep.yml", ".semgrep.yaml", ".semgrep")

IMAGE_PREFIX = "secbench-fixed"


# --------------------------------------------------------------------------------------
# Small helpers
# --------------------------------------------------------------------------------------

def run(cmd: list[str], cwd: Path | None = None, timeout: int = 3600) -> tuple[int, str]:
    """Exit code + combined output. A timeout is a failure, not an exception."""
    try:
        p = subprocess.run(cmd, cwd=cwd, timeout=timeout, text=True,
                           stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        return p.returncode, p.stdout or ""
    except subprocess.TimeoutExpired as e:
        return 124, f"TIMEOUT after {timeout}s\n{(e.stdout or b'') if isinstance(e.stdout, bytes) else (e.stdout or '')}"
    except FileNotFoundError as e:
        return 127, str(e)


def tail(text: str, n: int = 2000) -> str:
    return text if len(text) <= n else "…\n" + text[-n:]


# --------------------------------------------------------------------------------------
# Dockerfile parsing: where the package actually lives inside the image
# --------------------------------------------------------------------------------------

def parse_dockerfile(dockerfile: Path, target_name: str) -> tuple[str, str]:
    """(workdir, package_dir_name) — the image path of the cloned package tree.

    The Dockerfiles are generated, so `WORKDIR /exploit/<target>` and
    `git clone <url> node_modules/<pkg>` are both reliably present; both have a fallback anyway
    because the npm-install branch of the Dockerfile does not repeat the clone line.
    """
    text = dockerfile.read_text(errors="replace")
    workdir = m.group(1).strip() if (m := re.search(r"^\s*WORKDIR\s+(\S+)", text, re.M)) else f"/exploit/{target_name}"
    if m := re.search(r"git\s+clone\s+\S+\s+node_modules/([\w.@\-]+)", text):
        pkg = m.group(1)
    else:  # `mathjs_3.9.0` -> `mathjs`; version suffix is always the last underscore group
        pkg = target_name.rsplit("_", 1)[0]
    return workdir, pkg


# --------------------------------------------------------------------------------------
# Reverse-applying patch.txt
# --------------------------------------------------------------------------------------

def split_patch_by_file(patch_text: str) -> list[tuple[str, str]]:
    """[(path, single-file patch text)] — used when a whole-patch revert fails.

    The npm-install fallback branch of the Dockerfile produces a tree with no test files, so a patch
    that also touches `test/` cannot revert as a unit; reverting the lib files alone still restores
    the vulnerability, which is what the scan is measuring.
    """
    chunks, current, path = [], [], None
    for line in patch_text.splitlines(keepends=True):
        if line.startswith("diff --git "):
            if current and path:
                chunks.append((path, "".join(current)))
            current, path = [line], None
            if m := re.match(r"diff --git a/(.+?) b/(.+)$", line.strip()):
                path = m.group(2)
        elif current:
            current.append(line)
    if current and path:
        chunks.append((path, "".join(current)))
    return chunks


def revert_patch(tree: Path, patch: Path, scratch: Path) -> tuple[str, list[str], str]:
    """(status, reverted_files, log). status: ok | partial | failed."""
    is_git = (tree / ".git").exists()
    log = []

    for label, extra in (("plain", []), ("3way", ["--3way"] if is_git else None)):
        if extra is None:
            continue
        rc, out = run(["git", "apply", "-R", "-p1", *extra, str(patch)], cwd=tree)
        log.append(f"--- git apply -R {label}: rc={rc}\n{tail(out, 800)}")
        if rc == 0:
            files = [p for p, _ in split_patch_by_file(patch.read_text(errors="replace"))]
            return "ok", files, "\n".join(log)

    # Per-file fallback: revert every file that exists and reverts cleanly.
    reverted, skipped = [], []
    for path, chunk in split_patch_by_file(patch.read_text(errors="replace")):
        if not (tree / path).exists():
            skipped.append(f"{path} (absent)")
            continue
        piece = scratch / "piece.patch"
        piece.write_text(chunk)
        rc, out = run(["git", "apply", "-R", "-p1", str(piece)], cwd=tree)
        if rc != 0 and is_git:
            rc, out = run(["git", "apply", "-R", "-p1", "--3way", str(piece)], cwd=tree)
        (reverted if rc == 0 else skipped).append(path if rc == 0 else f"{path} ({tail(out, 200).strip()})")
    log.append(f"--- per-file revert: {len(reverted)} reverted, {len(skipped)} skipped\n"
               + "\n".join(f"  skip {s}" for s in skipped))
    return ("ok" if reverted and not skipped else "partial" if reverted else "failed"), reverted, "\n".join(log)


# --------------------------------------------------------------------------------------
# Semgrep
# --------------------------------------------------------------------------------------

def semgrep_configs(tree: Path, use_packs: bool) -> list[str]:
    configs = ([*SEMGREP_PACKS] if use_packs else []) + [str(MINI_RULES)]
    configs += [n for n in SEMGREP_REPO_RULES if (tree / n).exists()]
    return [arg for c in configs for arg in ("--config", c)]


def semgrep_scan(tree: Path, out_json: Path, use_packs: bool, timeout: int) -> list[dict] | None:
    """Every finding in `tree`, or None if semgrep did not produce results (broken != clean)."""
    cmd = ["semgrep", "scan", *semgrep_configs(tree, use_packs),
           "--max-target-bytes", "0",     # don't silently skip large/bundled files
           "--timeout", "60",             # per-rule-per-file budget, like the pipeline uses
           "--exclude", "node_modules", "--exclude", ".git",
           "--metrics", "off", "--json", "--output", str(out_json), "--quiet"]
    rc, out = run(cmd, cwd=tree, timeout=timeout)
    if not out_json.exists():
        print(f"    ⚠️  semgrep produced no results (exit {rc}): {tail(out, 400)}", flush=True)
        return None
    try:
        return json.loads(out_json.read_text()).get("results", [])
    except json.JSONDecodeError:
        return None


def severity_of(f: dict) -> str:
    return (f.get("extra", {}).get("severity") or "UNKNOWN").upper()


def key_of(f: dict) -> tuple[str, str, str]:
    """Identity that survives the line shifts a revert introduces."""
    return (f.get("check_id", "?"), f.get("path", "?"),
            (f.get("extra", {}).get("lines") or "").strip()[:200])


# --------------------------------------------------------------------------------------
# Per-target pipeline
# --------------------------------------------------------------------------------------

@dataclass
class Result:
    target: str
    build: str = "skipped"            # ok | FAILED | skipped
    extract: str = "n/a"              # ok | FAILED
    revert: str = "n/a"               # ok | partial | failed | no-patch
    fixed_total: int | None = None
    reverted_total: int | None = None
    new_findings: int | None = None
    new_in_patched_files: int | None = None
    new_by_rule: dict[str, int] = field(default_factory=dict)
    new_by_severity: dict[str, int] = field(default_factory=dict)
    note: str = ""


def process(target: Path, args, out_root: Path) -> Result:
    name = target.name
    res = Result(target=name)
    work = out_root / name
    work.mkdir(parents=True, exist_ok=True)
    image = f"{IMAGE_PREFIX}/{name.lower()}"

    # 1. Build --------------------------------------------------------------------------
    if args.skip_build:
        rc, _ = run(["docker", "image", "inspect", image])
        if rc != 0:
            res.build, res.note = "FAILED", "no pre-existing image and --skip-build was set"
            return res
        res.build = "ok (reused)"
    else:
        print(f"[{name}] building…", flush=True)
        rc, out = run(["docker", "build", "-f", str(target / "Dockerfile.fixed"),
                       "-t", image, str(target)], timeout=args.build_timeout)
        (work / "build.log").write_text(out)
        if rc != 0:
            res.build, res.note = "FAILED", f"see {work / 'build.log'}"
            print(f"[{name}] BUILD FAILED", flush=True)
            return res
        res.build = "ok"

    # 2. Extract the package tree from the image ----------------------------------------
    workdir, pkg = parse_dockerfile(target / "Dockerfile.fixed", name)
    fixed_tree = work / "fixed"
    shutil.rmtree(fixed_tree, ignore_errors=True)
    rc, out = run(["docker", "create", "--name", f"tmp-{name.lower()}-extract", image])
    cid = out.strip().splitlines()[-1] if rc == 0 else ""
    if rc != 0:
        run(["docker", "rm", "-f", f"tmp-{name.lower()}-extract"])
        rc, out = run(["docker", "create", "--name", f"tmp-{name.lower()}-extract", image])
        cid = out.strip().splitlines()[-1] if rc == 0 else ""
    if rc != 0:
        res.extract, res.note = "FAILED", f"docker create: {tail(out, 300)}"
        return res
    try:
        src = f"{cid}:{workdir.rstrip('/')}/node_modules/{pkg}"
        rc, out = run(["docker", "cp", src, str(fixed_tree)])
        if rc != 0:
            res.extract, res.note = "FAILED", f"docker cp {src}: {tail(out, 300)}"
            return res
    finally:
        run(["docker", "rm", "-f", cid])
    res.extract = "ok"

    # 3. Baseline scan of the fixed tree --------------------------------------------------
    print(f"[{name}] semgrep (fixed)…", flush=True)
    fixed = semgrep_scan(fixed_tree, work / "semgrep_fixed.json", args.packs, args.semgrep_timeout)
    if fixed is None:
        res.note = "semgrep failed on the fixed tree"
        return res
    res.fixed_total = len(fixed)

    # 4. Revert the patch and rescan -----------------------------------------------------
    patch = target / "patch.txt"
    if not patch.exists():
        res.revert = "no-patch"
        return res

    rev_tree = work / "reverted"
    shutil.rmtree(rev_tree, ignore_errors=True)
    shutil.copytree(fixed_tree, rev_tree, symlinks=True, ignore_dangling_symlinks=True)
    status, reverted_files, log = revert_patch(rev_tree, patch, work)
    (work / "revert.log").write_text(log)
    res.revert = status
    if status == "failed":
        res.note = f"patch would not reverse-apply; see {work / 'revert.log'}"
        return res

    print(f"[{name}] semgrep (reverted)…", flush=True)
    reverted = semgrep_scan(rev_tree, work / "semgrep_reverted.json", args.packs, args.semgrep_timeout)
    if reverted is None:
        res.note = "semgrep failed on the reverted tree"
        return res
    res.reverted_total = len(reverted)

    # New findings = present after the revert, absent before it.
    before = Counter(key_of(f) for f in fixed)
    new = []
    for f in reverted:
        k = key_of(f)
        if before[k]:
            before[k] -= 1
        else:
            new.append(f)
    res.new_findings = len(new)
    touched = {p for p in reverted_files}
    res.new_in_patched_files = sum(1 for f in new if f.get("path", "") in touched)
    res.new_by_rule = dict(Counter(f.get("check_id", "?").split(".")[-1] for f in new).most_common())
    res.new_by_severity = dict(Counter(severity_of(f) for f in new).most_common())
    (work / "new_findings.json").write_text(json.dumps(new, indent=2))
    return res


# --------------------------------------------------------------------------------------
# Main
# --------------------------------------------------------------------------------------

def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--category", default="code-injection", help="subdirectory of the benchmark to sweep")
    ap.add_argument("--root", type=Path, default=BENCH_ROOT)
    ap.add_argument("--out", type=Path, default=None, help="where logs/trees/JSON go (default: <root>/.semgrep-revert)")
    ap.add_argument("--only", action="append", default=[], help="restrict to these target dirs (repeatable)")
    ap.add_argument("--skip-build", action="store_true", help="reuse images already built")
    ap.add_argument("--jobs", type=int, default=3, help="targets in parallel")
    ap.add_argument("--build-timeout", type=int, default=2400)
    ap.add_argument("--semgrep-timeout", type=int, default=1800)
    ap.add_argument("--no-packs", dest="packs", action="store_false",
                    help="skip the semgrep registry packs; use the mini-swe-agent rules only")
    args = ap.parse_args()

    if not shutil.which("semgrep"):
        print("semgrep not found on PATH", file=sys.stderr)
        return 2
    if not MINI_RULES.exists():
        print(f"mini-swe-agent rules missing: {MINI_RULES}", file=sys.stderr)
        return 2
    if not args.skip_build:
        rc, out = run(["docker", "info"], timeout=60)
        if rc != 0:
            print(f"docker is not available — start Docker Desktop first:\n{tail(out, 300)}", file=sys.stderr)
            return 2

    category = args.root / args.category
    targets = sorted(p.parent for p in category.glob("*/Dockerfile.fixed"))
    if args.only:
        targets = [t for t in targets if t.name in set(args.only)]
    if not targets:
        print(f"no Dockerfile.fixed targets under {category}", file=sys.stderr)
        return 1

    out_root = args.out or (args.root / ".semgrep-revert")
    out_root.mkdir(parents=True, exist_ok=True)
    print(f"{len(targets)} target(s) with Dockerfile.fixed; artifacts -> {out_root}\n", flush=True)

    with ThreadPoolExecutor(max_workers=max(1, args.jobs)) as pool:
        results = list(pool.map(lambda t: process(t, args, out_root), targets))

    (out_root / "summary.json").write_text(json.dumps([asdict(r) for r in results], indent=2))

    # ---- report -----------------------------------------------------------------------
    build_failed = [r for r in results if r.build == "FAILED"]
    extract_failed = [r for r in results if r.build != "FAILED" and r.extract == "FAILED"]

    print("\n" + "=" * 96)
    print(f"{'target':<34}{'build':<12}{'revert':<10}{'fixed':>7}{'revert’d':>10}{'new':>7}{'new(patched)':>14}")
    print("-" * 96)
    for r in results:
        n = lambda v: "-" if v is None else str(v)
        print(f"{r.target:<34}{r.build:<12}{r.revert:<10}{n(r.fixed_total):>7}"
              f"{n(r.reverted_total):>10}{n(r.new_findings):>7}{n(r.new_in_patched_files):>14}")
    print("=" * 96)

    if build_failed:
        print(f"\nBUILD FAILURES ({len(build_failed)}):")
        for r in build_failed:
            print(f"  {r.target:<34} {r.note}")
    if extract_failed:
        print(f"\nEXTRACTION FAILURES ({len(extract_failed)}):")
        for r in extract_failed:
            print(f"  {r.target:<34} {r.note}")

    scanned = [r for r in results if r.new_findings is not None]
    if scanned:
        print(f"\nNEW SEMGREP FINDINGS AFTER REVERTING patch.txt ({len(scanned)} target(s)):")
        for r in sorted(scanned, key=lambda r: -r.new_findings):
            sev = ", ".join(f"{k}:{v}" for k, v in r.new_by_severity.items()) or "none"
            rules = ", ".join(f"{k}×{v}" for k, v in list(r.new_by_rule.items())[:4]) or "none"
            flag = "  ⚠️ partial revert" if r.revert == "partial" else ""
            print(f"  {r.target:<34} {r.new_findings:>3} new  [{sev}]  {rules}{flag}")
        silent = [r.target for r in scanned if r.new_findings == 0]
        if silent:
            print(f"\n  semgrep stays SILENT on the reverted (vulnerable) code for: {', '.join(silent)}")

    no_patch = [r.target for r in results if r.revert == "no-patch"]
    if no_patch:
        print(f"\nBuilt but no patch.txt to revert ({len(no_patch)}): {', '.join(no_patch)}")

    print(f"\nsummary.json + per-target logs, trees and findings: {out_root}")
    return 1 if build_failed or extract_failed else 0


if __name__ == "__main__":
    sys.exit(main())
