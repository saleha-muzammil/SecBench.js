#!/usr/bin/env python3
"""How much does semgrep notice when a security patch is reverted?

Scope: every `code-injection/<target>/` that ships a **patch.txt**. For each one:

  1. Build its `Dockerfile.fixed` (the patched/fixed source tree).
  2. Copy the package tree out of the image.
  3. semgrep -> FIXED count (the patched baseline).
  4. Reverse-apply patch.txt, re-introducing the vulnerability.
  5. semgrep -> REVERTED count.

Result per repository goes to **code-injection-semgrep-analysis.csv**. The number to read is
`new_findings`: warnings present only after the revert, i.e. what semgrep actually catches about
the reintroduced vulnerability. A 0 there means the detector is blind to it.

semgrep runs mini-swe-agent's configuration: the registry packs from curl_issue.py::_SEMGREP_PACKS
plus `src/minisweagent/config/extra/semgrep_rules.yaml`, plus any rules the repo itself ships.

Usage:
    python3 code-injection-semgrep-analysis.py                  # all patch.txt targets
    python3 code-injection-semgrep-analysis.py --only js-yaml_3.13.0
    python3 code-injection-semgrep-analysis.py --skip-build     # reuse images
    python3 code-injection-semgrep-analysis.py --no-packs       # mini rules only (offline/fast)
"""

from __future__ import annotations

import argparse
import csv
import json
import re
import shutil
import subprocess
import sys
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field, asdict
from pathlib import Path

BENCH_ROOT = Path(__file__).resolve().parent
MINI_ROOT = Path("/Users/saleha/Desktop/cispa/mini-swe-agent")
MINI_RULES = MINI_ROOT / "src/minisweagent/config/extra/semgrep_rules.yaml"

# Same packs curl_issue.py::_SEMGREP_PACKS enables.
SEMGREP_PACKS = ("p/default", "p/javascript", "p/typescript", "p/nodejs", "p/golang",
                 "p/security-audit", "p/owasp-top-ten", "p/xss", "p/command-injection", "p/secrets")
SEMGREP_REPO_RULES = (".semgrep.yml", ".semgrep.yaml", ".semgrep")

CSV_NAME = "code-injection-semgrep-analysis.csv"
IMAGE_PREFIX = "secbench-fixed"

CSV_COLUMNS = [
    "repository", "package", "status",
    "fixed_findings", "reverted_findings", "new_findings", "new_in_patched_files",
    "new_errors", "new_warnings", "new_info",
    "detected", "top_rules",
    "codeql_status", "codeql_fixed", "codeql_reverted", "codeql_new", "codeql_detected",
    "codeql_top_rules", "detected_by",
    "semgrep_messages", "codeql_messages",
    "revert_status", "files_reverted", "note",
]

# How many findings get spelled out in the CSV, and how much of each message. The complete,
# untruncated findings always remain in <out>/<target>/new_findings.json and codeql_new.json --
# these columns exist to make the CSV readable on its own, not to replace those.
MAX_MESSAGES = 6
MAX_MESSAGE_CHARS = 220


def _one_line(text: str, limit: int = MAX_MESSAGE_CHARS) -> str:
    """Collapse a finding message to a single line short enough to sit in a CSV cell."""
    flat = " ".join((text or "").split())
    return flat if len(flat) <= limit else flat[:limit - 1] + "…"


def format_semgrep_messages(findings: list[dict]) -> str:
    out = [f"{f.get('check_id', '?').split('.')[-1]} @ {f.get('path', '?')}"
           f":{(f.get('start') or {}).get('line', '?')} — "
           f"{_one_line((f.get('extra') or {}).get('message', ''))}"
           for f in findings[:MAX_MESSAGES]]
    if len(findings) > MAX_MESSAGES:
        out.append(f"(+{len(findings) - MAX_MESSAGES} more)")
    return " || ".join(out)


def format_codeql_messages(alerts: list) -> str:
    # csv row layout: name, description, severity, message, path
    out = [f"{a[0]} @ {a[4] if len(a) > 4 else '?'} — {_one_line(a[3] if len(a) > 3 else '')}"
           for a in alerts[:MAX_MESSAGES]]
    if len(alerts) > MAX_MESSAGES:
        out.append(f"(+{len(alerts) - MAX_MESSAGES} more)")
    return " || ".join(out)


# --------------------------------------------------------------------------------------
# shell helpers
# --------------------------------------------------------------------------------------

def run(cmd: list[str], cwd: Path | None = None, timeout: int = 3600) -> tuple[int, str]:
    """Exit code + combined output. A timeout is a failure, not an exception."""
    try:
        p = subprocess.run(cmd, cwd=cwd, timeout=timeout, text=True,
                           stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        return p.returncode, p.stdout or ""
    except subprocess.TimeoutExpired as e:
        out = e.stdout.decode(errors="replace") if isinstance(e.stdout, bytes) else (e.stdout or "")
        return 124, f"TIMEOUT after {timeout}s\n{out}"
    except FileNotFoundError as e:
        return 127, str(e)


def tail(text: str, n: int = 2000) -> str:
    return text if len(text) <= n else "…\n" + text[-n:]


# --------------------------------------------------------------------------------------
# where the package lives inside the image
# --------------------------------------------------------------------------------------

def parse_dockerfile(dockerfile: Path, target_name: str) -> tuple[str, str]:
    """(workdir, package dir under node_modules) as declared by the Dockerfile itself."""
    text = dockerfile.read_text(errors="replace")
    workdir = m.group(1).strip() if (m := re.search(r"^\s*WORKDIR\s+(\S+)", text, re.M)) else f"/exploit/{target_name}"
    # `(?:@scope/)?` is required, not cosmetic: a scoped package lives at node_modules/@scope/name,
    # and a pattern that stops at the slash yields `@vivaxy` -- a path that does not exist in the
    # image, so the extraction fails instead of the scan running.
    scoped = r"(?:@[\w.\-]+/)?[\w.\-]+"
    if m := re.search(rf"git\s+clone\s+\S+\s+node_modules/({scoped})", text):
        pkg = m.group(1)
    elif m := re.search(rf"npm install[^\n]*?\s({scoped})@[\d][^\s\\;]*", text):
        pkg = m.group(1)           # npm-sourced entries have no clone line
    else:
        pkg = target_name.rsplit("_", 1)[0]   # `mathjs_3.9.0` -> `mathjs`
    return workdir, pkg


# --------------------------------------------------------------------------------------
# reverse-applying patch.txt
# --------------------------------------------------------------------------------------

def split_patch_by_file(patch_text: str) -> list[tuple[str, str]]:
    """[(path, that file's slice of the patch)] — used when a whole-patch revert fails."""
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
    """(status, files actually reverted, log). status: ok | partial | failed.

    Whole-patch first. The per-file fallback exists because a patch that also touches lockfiles or
    tests cannot always reverse-apply as a unit -- reverting the source files alone still restores
    the vulnerability, which is what the scan measures.
    """
    is_git = (tree / ".git").exists()
    log = []
    for label, extra in (("plain", []), ("3way", ["--3way"] if is_git else None)):
        if extra is None:
            continue
        rc, out = run(["git", "apply", "-R", "-p1", *extra, str(patch)], cwd=tree)
        log.append(f"--- git apply -R {label}: rc={rc}\n{tail(out, 800)}")
        if rc == 0:
            return "ok", [p for p, _ in split_patch_by_file(patch.read_text(errors="replace"))], "\n".join(log)

    reverted, skipped = [], []
    for path, chunk in split_patch_by_file(patch.read_text(errors="replace")):
        if not (tree / path).exists():
            skipped.append(f"{path} (absent)")
            continue
        (piece := scratch / "piece.patch").write_text(chunk)
        rc, out = run(["git", "apply", "-R", "-p1", str(piece)], cwd=tree)
        if rc != 0 and is_git:
            rc, out = run(["git", "apply", "-R", "-p1", "--3way", str(piece)], cwd=tree)
        (reverted if rc == 0 else skipped).append(path if rc == 0 else f"{path} ({tail(out, 200).strip()})")
    log.append(f"--- per-file revert: {len(reverted)} reverted, {len(skipped)} skipped\n"
               + "\n".join(f"  skip {s}" for s in skipped))
    return ("ok" if reverted and not skipped else "partial" if reverted else "failed"), reverted, "\n".join(log)


# --------------------------------------------------------------------------------------
# semgrep
# --------------------------------------------------------------------------------------

# Minified duplicates of the same source. Excluded for two independent reasons:
#   memory -- a minified file is one enormous line, and combined with --max-target-bytes 0 it is
#     the classic semgrep OOM trigger (it took a laptop down on the 56-target redos sweep);
#   measurement -- underscore ships underscore.js, underscore-esm.js AND underscore-esm-min.js, so
#     one finding is counted three times, inflating a baseline that then buries real deltas.
# Deliberately NOT excluding dist/ or bundle files: for a TypeScript package the only JavaScript
# that exists is in dist/, so dropping it would silently under-scan the very code under test.
MINIFIED_GLOBS = ("*.min.js", "*-min.js", "*.min.mjs", "*.min.cjs")


def semgrep_scan(tree: Path, out_json: Path, args, timeout: int) -> list[dict] | None:
    """Every finding in `tree`, or None if semgrep produced no results (broken != clean)."""
    configs = ([*SEMGREP_PACKS] if args.packs else []) + [str(MINI_RULES)]
    configs += [n for n in SEMGREP_REPO_RULES if (tree / n).exists()]
    excludes = ["node_modules", ".git"] + ([] if args.include_minified else list(MINIFIED_GLOBS))
    cmd = ["semgrep", "scan", *[a for c in configs for a in ("--config", c)],
           # mini-swe-agent's pipeline sets this to 0 ("never skip a file"). That is not survivable
           # on a small machine: an unbounded single file is semgrep's dominant memory cost, and the
           # redos corpus ships multi-MB bundled artifacts. Files above the cap are generated or
           # vendored bundles, never the patched source a patch.txt touches.
           "--max-target-bytes", str(args.max_target_bytes),
           "--timeout", "60",           # per-rule-per-file budget, as the pipeline uses
           # Without a cap semgrep grows until the machine dies; with one it skips the offending
           # rule/file and says so, which is a bad result instead of no result.
           "--max-memory", str(args.max_memory),
           *[a for e in excludes for a in ("--exclude", e)],
           "--metrics", "off", "--json", "--output", str(out_json), "--quiet"]
    rc, out = run(cmd, cwd=tree, timeout=timeout)
    if not out_json.exists():
        print(f"    ⚠️  semgrep produced no results (exit {rc}): {tail(out, 400)}", flush=True)
        return None
    try:
        return json.loads(out_json.read_text()).get("results", [])
    except json.JSONDecodeError:
        return None


# --------------------------------------------------------------------------------------
# CodeQL -- default configuration, matching curl_issue.py::_run_codeql
# --------------------------------------------------------------------------------------

def codeql_scan(tree: Path, out_csv: Path, args, timeout: int) -> list[tuple] | None:
    """Alerts from the default query pack, or None if CodeQL could not produce results.

    Default configuration means exactly that: the stock `codeql/<lang>-queries` suite, no custom
    config file and no extra packs -- the same thing mini-swe-agent runs. --threads=1 is not a
    tuning choice but a correctness one: --threads=0 splits the heap across cores and OOMs every
    query on a small machine.
    """
    if not shutil.which("codeql"):
        return None
    db = out_csv.with_name(out_csv.stem + "-db")
    shutil.rmtree(db, ignore_errors=True)
    try:
        rc, out = run(["codeql", "database", "create", str(db), f"--language={args.codeql_language}",
                       "--source-root", str(tree), "--overwrite",
                       f"--ram={args.codeql_ram}", f"--threads={args.codeql_threads}"],
                      cwd=tree, timeout=timeout)
        if rc != 0:
            print(f"    ⚠️  codeql database create failed (exit {rc}): {tail(out, 300)}", flush=True)
            return None
        rc, out = run(["codeql", "database", "analyze", str(db),
                       f"codeql/{args.codeql_language}-queries", "--download",
                       "--format=csv", f"--output={out_csv}",
                       f"--ram={args.codeql_ram}", f"--threads={args.codeql_threads}"],
                      cwd=tree, timeout=timeout)
        if rc != 0 or not out_csv.exists():
            print(f"    ⚠️  codeql analyze failed (exit {rc}): {tail(out, 300)}", flush=True)
            return None
        with out_csv.open(newline="") as fh:
            # csv columns: name, description, severity, message, path, start_line, ...
            return [tuple(r[:5]) for r in csv.reader(fh) if len(r) >= 5]
    finally:
        # A JS database runs to hundreds of MB; keeping 2 per target would refill the disk.
        shutil.rmtree(db, ignore_errors=True)


def codeql_key(a: tuple) -> tuple:
    """Alert identity that survives line shifts: (rule, path, message)."""
    return (a[0], a[4], a[3][:200])


def key_of(f: dict) -> tuple[str, str, str]:
    """Finding identity that survives the line shifts a revert introduces."""
    return (f.get("check_id", "?"), f.get("path", "?"),
            (f.get("extra", {}).get("lines") or "").strip()[:200])


# --------------------------------------------------------------------------------------
# per-repository pipeline
# --------------------------------------------------------------------------------------

@dataclass
class Row:
    repository: str
    package: str = ""
    status: str = "ok"                 # ok | build_failed | extract_failed | revert_failed | semgrep_failed
    fixed_findings: int | None = None
    reverted_findings: int | None = None
    new_findings: int | None = None
    new_in_patched_files: int | None = None
    new_errors: int = 0
    new_warnings: int = 0
    new_info: int = 0
    detected: str = ""                 # yes | no  -- did semgrep react to the revert at all
    top_rules: str = ""
    revert_status: str = ""
    files_reverted: int = 0
    note: str = ""
    codeql_status: str = "not run"      # ok | failed | not run
    codeql_fixed: int | None = None
    codeql_reverted: int | None = None
    codeql_new: int | None = None
    codeql_detected: str = ""
    codeql_top_rules: str = ""
    detected_by: str = ""               # semgrep | codeql | both | neither
    semgrep_messages: str = ""          # what semgrep actually said about the new findings
    codeql_messages: str = ""           # what CodeQL actually said about the new alerts
    _by_rule: dict = field(default_factory=dict, repr=False)


def docker_tag(name: str) -> str:
    """A target name reduced to a legal docker repository component.

    Docker only accepts lowercase alphanumerics separated by `.`, `_` or `-`, and the name must
    start and end with an alphanumeric. A scoped npm package (`@vivaxy-here_3.1.0`) therefore
    cannot be used verbatim -- `docker build` rejects the whole tag with "invalid reference
    format" and the target reads as a build failure.
    """
    return re.sub(r"[^a-z0-9._-]", "-", name.lower()).strip("._-") or "target"


def process(target: Path, args, out_root: Path) -> Row:
    name = target.name
    row = Row(repository=name)
    work = out_root / name
    work.mkdir(parents=True, exist_ok=True)
    image = f"{IMAGE_PREFIX}/{docker_tag(name)}"

    dockerfile = target / "Dockerfile.fixed"
    if not dockerfile.exists():
        row.status, row.note = "build_failed", "no Dockerfile.fixed"
        return row

    # 1. build ---------------------------------------------------------------------------
    if args.skip_build and run(["docker", "image", "inspect", image])[0] == 0:
        pass
    else:
        print(f"[{name}] building…", flush=True)
        rc, out = run(["docker", "build", "-f", str(dockerfile), "-t", image, str(target)],
                      timeout=args.build_timeout)
        (work / "build.log").write_text(out)
        if rc != 0:
            row.status, row.note = "build_failed", f"docker build failed; see {work / 'build.log'}"
            print(f"[{name}] BUILD FAILED", flush=True)
            return row

    # 2. extract the package tree --------------------------------------------------------
    workdir, pkg = parse_dockerfile(dockerfile, name)
    row.package = pkg
    fixed_tree = work / "fixed"
    shutil.rmtree(fixed_tree, ignore_errors=True)
    cname = f"tmp-{docker_tag(name)}-extract"
    run(["docker", "rm", "-f", cname])
    rc, out = run(["docker", "create", "--name", cname, image])
    if rc != 0:
        row.status, row.note = "extract_failed", f"docker create: {tail(out, 200)}"
        return row
    try:
        src = f"{cname}:{workdir.rstrip('/')}/node_modules/{pkg}"
        rc, out = run(["docker", "cp", src, str(fixed_tree)])
        if rc != 0:
            row.status, row.note = "extract_failed", f"docker cp {src}: {tail(out, 200)}"
            return row
    finally:
        run(["docker", "rm", "-f", cname])
        # The image has served its only purpose. Keeping it is not free: these images are ~1.6 GB
        # each (a full node base + npm tree), so a sweep of any size fills the Docker disk and
        # every later build dies with ENOSPC -- which looks like dozens of unrelated build
        # failures. Dropping it here makes disk use O(1) in the number of targets instead of O(n).
        if not args.keep_images:
            run(["docker", "rmi", "-f", image])

    # 3. baseline scan -------------------------------------------------------------------
    print(f"[{name}] semgrep (fixed)…", flush=True)
    fixed = semgrep_scan(fixed_tree, work / "semgrep_fixed.json", args, args.semgrep_timeout)
    if fixed is None:
        row.status, row.note = "semgrep_failed", "semgrep failed on the fixed tree"
        return row
    row.fixed_findings = len(fixed)

    # 4. revert + rescan -----------------------------------------------------------------
    rev_tree = work / "reverted"
    shutil.rmtree(rev_tree, ignore_errors=True)
    shutil.copytree(fixed_tree, rev_tree, symlinks=True, ignore_dangling_symlinks=True)
    status, reverted_files, log = revert_patch(rev_tree, target / "patch.txt", work)
    (work / "revert.log").write_text(log)
    row.revert_status, row.files_reverted = status, len(reverted_files)
    if status == "failed":
        row.status, row.note = "revert_failed", f"patch would not reverse-apply; see {work / 'revert.log'}"
        return row

    print(f"[{name}] semgrep (reverted)…", flush=True)
    reverted = semgrep_scan(rev_tree, work / "semgrep_reverted.json", args, args.semgrep_timeout)
    if reverted is None:
        row.status, row.note = "semgrep_failed", "semgrep failed on the reverted tree"
        return row
    row.reverted_findings = len(reverted)

    # New = present after the revert, absent before it.
    before = Counter(key_of(f) for f in fixed)
    new = []
    for f in reverted:
        if before[k := key_of(f)]:
            before[k] -= 1
        else:
            new.append(f)

    sev = Counter((f.get("extra", {}).get("severity") or "UNKNOWN").upper() for f in new)
    by_rule = Counter(f.get("check_id", "?").split(".")[-1] for f in new)
    touched = set(reverted_files)

    row.new_findings = len(new)
    row.new_in_patched_files = sum(1 for f in new if f.get("path", "") in touched)
    row.new_errors, row.new_warnings, row.new_info = sev["ERROR"], sev["WARNING"], sev["INFO"]
    row.detected = "yes" if new else "no"
    row.top_rules = "; ".join(f"{r}×{c}" for r, c in by_rule.most_common(5))
    row._by_rule = dict(by_rule)
    if status == "partial":
        row.note = "partial revert: some patched files could not be reverted (see revert.log)"
    row.semgrep_messages = format_semgrep_messages(new)
    (work / "new_findings.json").write_text(json.dumps(new, indent=2))

    # 5. CodeQL on both trees ------------------------------------------------------------
    # Runs after semgrep and after the revert, so both analysers see byte-identical trees and the
    # two "new" columns are directly comparable.
    if args.codeql:
        print(f"[{name}] codeql (fixed)…", flush=True)
        ql_fixed = codeql_scan(fixed_tree, work / "codeql_fixed.csv", args, args.codeql_timeout)
        ql_rev = None
        if ql_fixed is not None:
            print(f"[{name}] codeql (reverted)…", flush=True)
            ql_rev = codeql_scan(rev_tree, work / "codeql_reverted.csv", args, args.codeql_timeout)
        if ql_fixed is None or ql_rev is None:
            row.codeql_status = "failed"
        else:
            row.codeql_status = "ok"
            row.codeql_fixed, row.codeql_reverted = len(ql_fixed), len(ql_rev)
            ql_before = Counter(codeql_key(a) for a in ql_fixed)
            ql_new = []
            for a in ql_rev:
                if ql_before[k := codeql_key(a)]:
                    ql_before[k] -= 1
                else:
                    ql_new.append(a)
            row.codeql_new = len(ql_new)
            row.codeql_detected = "yes" if ql_new else "no"
            row.codeql_top_rules = "; ".join(
                f"{r}×{c}" for r, c in Counter(a[0] for a in ql_new).most_common(5))
            row.codeql_messages = format_codeql_messages(ql_new)
            (work / "codeql_new.json").write_text(json.dumps(ql_new, indent=2))

    row.detected_by = {(True, True): "both", (True, False): "semgrep",
                       (False, True): "codeql", (False, False): "neither"}[
        (bool(row.new_findings), bool(row.codeql_new))]
    return row


# --------------------------------------------------------------------------------------
# main
# --------------------------------------------------------------------------------------

def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--category", default="code-injection")
    ap.add_argument("--root", type=Path, default=BENCH_ROOT)
    ap.add_argument("--csv", type=Path, default=None, help=f"output CSV (default: <root>/{CSV_NAME})")
    ap.add_argument("--out", type=Path, default=None, help="logs/trees/JSON (default: <root>/.semgrep-analysis)")
    ap.add_argument("--only", action="append", default=[], help="restrict to these targets (repeatable)")
    ap.add_argument("--skip-build", action="store_true", help="reuse images already built")
    # Each parallel worker holds a semgrep process with a multi-GB working set on top of
    # Docker's VM, so the ceiling here is RAM, not CPU.
    ap.add_argument("--jobs", type=int, default=1)
    ap.add_argument("--build-timeout", type=int, default=2400)
    ap.add_argument("--semgrep-timeout", type=int, default=1800)
    ap.add_argument("--no-packs", dest="packs", action="store_false",
                    help="skip the registry packs; use the mini-swe-agent rules only")
    # NB: semgrep's --max-memory bounds ONE RULE ON ONE FILE, not the process total, so it must be
    # set well below available RAM -- with N rule packs the process high-water mark is a multiple.
    ap.add_argument("--max-memory", type=int, default=1500,
                    help="MB ceiling for a single rule on a single file (NOT a process total)")
    ap.add_argument("--max-target-bytes", type=int, default=5_000_000,
                    help="skip files larger than this (0 = no limit, matches mini-swe-agent but "
                         "risks OOM on bundled artifacts)")
    ap.add_argument("--include-minified", action="store_true",
                    help=f"also scan {', '.join(MINIFIED_GLOBS)} (duplicated source; memory-hungry)")
    ap.add_argument("--codeql", action="store_true",
                    help="also run CodeQL (default query pack) on both trees and report its delta")
    ap.add_argument("--codeql-language", default="javascript")
    # Deviates from mini-swe-agent's 4096 because this runs on an 8 GB machine where CodeQL and
    # Docker must coexist; raise it on a bigger host.
    ap.add_argument("--codeql-ram", type=int, default=3000, help="MB of RAM for CodeQL")
    ap.add_argument("--codeql-threads", type=int, default=1,
                    help="0 = all cores, which splits the heap per core and OOMs on small machines")
    ap.add_argument("--codeql-timeout", type=int, default=3600)
    ap.add_argument("--keep-images", action="store_true",
                    help="keep each image after its tree is extracted (needs ~1.6 GB per target; "
                         "implied by --skip-build, which exists to reuse them)")
    args = ap.parse_args()
    args.keep_images = args.keep_images or args.skip_build

    if not shutil.which("semgrep"):
        print("semgrep not found on PATH", file=sys.stderr)
        return 2
    if not MINI_RULES.exists():
        print(f"mini-swe-agent rules missing: {MINI_RULES}", file=sys.stderr)
        return 2
    if not args.skip_build and (rc := run(["docker", "info"], timeout=60))[0] != 0:
        print(f"docker is not available — start Docker Desktop first:\n{tail(rc[1], 300)}", file=sys.stderr)
        return 2

    # The population is defined by patch.txt: no patch, nothing to revert, nothing to measure.
    category = args.root / args.category
    targets = sorted(p.parent for p in category.glob("*/patch.txt"))
    if args.only:
        targets = [t for t in targets if t.name in set(args.only)]
    if not targets:
        print(f"no targets with patch.txt under {category}", file=sys.stderr)
        return 1

    # Resolved to absolute: semgrep and codeql run with cwd set to the extracted tree, so a
    # relative --out/--csv would write results inside that tree (and then get deleted with it).
    args.out = args.out.resolve() if args.out else None
    args.csv = args.csv.resolve() if args.csv else None
    out_root = args.out or (args.root / ".semgrep-analysis")
    out_root.mkdir(parents=True, exist_ok=True)
    csv_path = args.csv or (args.root / CSV_NAME)
    print(f"{len(targets)} repositor{'y' if len(targets) == 1 else 'ies'} with patch.txt; "
          f"artifacts -> {out_root}\n", flush=True)

    with ThreadPoolExecutor(max_workers=max(1, args.jobs)) as pool:
        rows = list(pool.map(lambda t: process(t, args, out_root), targets))

    # ---- CSV ---------------------------------------------------------------------------
    # Merge instead of overwrite, keyed by repository. Targets are commonly run a few at a time
    # (memory limits make one-target-per-process the safe way to sweep a large category), and a
    # plain "w" would leave the CSV holding only whatever the last invocation happened to cover.
    merged: dict[str, dict] = {}
    if csv_path.exists():
        with csv_path.open(newline="") as fh:
            for old in csv.DictReader(fh):
                if old.get("repository"):
                    merged[old["repository"]] = old
    for r in rows:
        merged[r.repository] = {k: ("" if v is None else v)
                                for k, v in asdict(r).items() if k in CSV_COLUMNS}
    with csv_path.open("w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=CSV_COLUMNS, extrasaction="ignore")
        w.writeheader()
        for name in sorted(merged):
            w.writerow(merged[name])

    (out_root / "summary.json").write_text(
        json.dumps([{k: v for k, v in asdict(r).items() if not k.startswith("_")} | {"by_rule": r._by_rule}
                    for r in rows], indent=2))

    # ---- console report ----------------------------------------------------------------
    print("\n" + "=" * 92)
    print(f"{'repository':<30}{'status':<14}"
          f"{'sg fixed':>9}{'sg rev':>8}{'sg new':>8}"
          f"{'ql fixed':>10}{'ql rev':>8}{'ql new':>8}{'detected by':>13}")
    print("-" * 92)
    for r in rows:
        n = lambda v: "-" if v is None else str(v)
        print(f"{r.repository:<30}{r.status:<14}"
              f"{n(r.fixed_findings):>9}{n(r.reverted_findings):>8}{n(r.new_findings):>8}"
              f"{n(r.codeql_fixed):>10}{n(r.codeql_reverted):>8}{n(r.codeql_new):>8}"
              f"{r.detected_by or '-':>13}")
    print("=" * 92)

    ok = [r for r in rows if r.new_findings is not None]
    failed = [r for r in rows if r.status != "ok"]
    caught = [r for r in ok if r.new_findings > 0]
    missed = [r for r in ok if r.new_findings == 0]

    if caught:
        print(f"\nsemgrep REACTS to the reverted patch ({len(caught)}/{len(ok)}):")
        for r in sorted(caught, key=lambda r: -r.new_findings):
            flag = "  ⚠️ partial revert" if r.revert_status == "partial" else ""
            print(f"  {r.repository:<32} {r.new_findings:>3} new  {r.top_rules}{flag}")
    if missed:
        print(f"\nsemgrep is SILENT on the reintroduced vulnerability ({len(missed)}/{len(ok)}):")
        for r in missed:
            print(f"  {r.repository:<32} {r.fixed_findings} findings before and after the revert")
    if failed:
        print(f"\nCOULD NOT MEASURE ({len(failed)}):")
        for r in failed:
            print(f"  {r.repository:<32} {r.status}: {r.note}")

    print(f"\nCSV  -> {csv_path}")
    print(f"logs -> {out_root}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
