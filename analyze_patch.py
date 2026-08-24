#!/usr/bin/env python3
"""
Revert a fix-commit patch inside its fixed Docker image and analyze ONLY the
reverted change with semgrep + npm audit, writing analyzer-report.txt to the
benchmark folder on the host.

For each benchmark folder ``<category>/<package>_<version>/`` that has BOTH a
``Dockerfile.fixed`` and a ``patch.txt`` (produced by fetch_patch.py), this:

  1. builds the fixed image (``secbench-fixed/<folder>``) if it is not present;
  2. starts a throwaway container from it;
  3. inside the cloned, patched source tree (node_modules/<package>), records an
     npm-audit baseline, then reverse-applies patch.txt (``git apply -R``) to
     reintroduce the vulnerable code;
  4. runs the OFFICIAL semgrep container over ONLY the files the patch touched
     (the change), not the whole codebase;
  5. runs npm audit again and reports the DELTA -- the advisories that the
     revert newly introduces;
  6. writes a human-readable analyzer-report.txt into the host benchmark folder
     (never inside the container).

The fixed image checks the source out at the fixed tag, which contains the fix
commit, so reverse-applying that exact commit's diff lands on the pre-fix
(vulnerable) tree. Entries whose fixed image fell back to an npm install (no git
clone) cannot be reverted and are skipped with a note.

Requires a running Docker daemon and network access (semgrep pulls its public
rule packs; npm audit queries the advisory DB).

Usage:
    python3 analyze_patch.py <owner/repo | package>   # one entry
    python3 analyze_patch.py --category code-injection # a whole class
    python3 analyze_patch.py --all                     # everything
    # options: [--force] [--build] [--no-build] [--keep]
    #          [--semgrep-config p/xyz ...] [--csv repositories.csv]
"""

import argparse
import json
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

from generate_dockerfile import (
    ROOT, CATEGORIES,
    csv_repo_index, collect_entries, find_matches_disk,
)

OUTPUT_NAME = "analyzer-report.txt"
SEMGREP_IMAGE = "semgrep/semgrep"
# The generic packs are kept as the "all default rules" baseline; the local
# ruleset adds the eval/Function/vm/deserialize sinks the packs miss.
DEFAULT_SEMGREP_CONFIGS = ["p/javascript", "p/nodejs", "p/security-audit"]
RULES_DIR = ROOT / "semgrep-rules"
LOCAL_RULESET = "secbench-code-injection.yml"
JS_EXT = (".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx")


# --------------------------------------------------------------------------- #
# small subprocess helpers
# --------------------------------------------------------------------------- #
def run(cmd, **kw):
    """Run a command, capturing text output; never raises on non-zero exit."""
    return subprocess.run(cmd, capture_output=True, text=True, **kw)


def dexec(cid, script):
    """Run a /bin/sh script inside the container `cid`."""
    return run(["docker", "exec", cid, "sh", "-c", script])


# --------------------------------------------------------------------------- #
# image / container lifecycle
# --------------------------------------------------------------------------- #
def image_tag(folder):
    # Docker reference components allow only [a-z0-9._-]; a scoped package folder
    # (@vivaxy/here -> "@vivaxy-here_3.1.0") carries an '@', which makes
    # "secbench-fixed/@vivaxy-here_3.1.0" an invalid tag and fails the build with
    # "invalid reference format". Map every disallowed character to '-' and trim
    # the separators Docker rejects at the edges. Unscoped names (djv_2.0.0) are
    # unchanged, so existing tags keep their identity.
    safe = re.sub(r"[^a-z0-9._-]", "-", folder.lower()).strip("-._") or "img"
    return f"secbench-fixed/{safe}"


def ensure_image(entry, tag, build_mode):
    """Make sure the fixed image exists. build_mode: 'auto' | 'force' | 'never'."""
    exists = run(["docker", "image", "inspect", tag]).returncode == 0
    if exists and build_mode != "force":
        return True, "using existing image"
    if build_mode == "never":
        return False, "image missing and --no-build given"
    path = entry["path"]
    bp = run(["docker", "build", "-t", tag,
              "-f", str(path / "Dockerfile.fixed"), str(path)])
    if bp.returncode != 0:
        # The last 2000 characters of a buildkit failure are its trailer: the
        # echoed Dockerfile source and "ERROR: failed to solve". The output of
        # the command that ACTUALLY failed sits further up and used to be cut
        # off entirely, which made every image-failed row undiagnosable without
        # a manual rebuild. Keep the whole log on disk and excerpt the lines
        # that carry a real error message.
        full = ((bp.stdout or "") + "\n" + (bp.stderr or "")).strip()
        log_path = path / "docker-build.log"
        try:
            log_path.write_text(full, encoding="utf-8")
        except OSError:
            log_path = None
        hits = [ln for ln in full.splitlines()
                if re.search(r"npm ERR!|fatal:|error TS\d|^ERROR|"
                             r"\berror\b|not found|cannot|denied|E404|ENOENT",
                             ln, re.I)]
        excerpt = "\n".join(hits[-25:]) or full[-2000:]
        where = f"\nfull log: {log_path}" if log_path else ""
        return False, f"docker build failed:\n{excerpt}{where}"
    return True, ("rebuilt image" if exists else "built image")


# --------------------------------------------------------------------------- #
# npm audit delta
# --------------------------------------------------------------------------- #
def parse_audit(raw):
    """Return (counts_dict, advisory_set) from `npm audit --json` text.

    advisory_set holds 'package :: title' strings so we can diff two runs. npm
    output is tolerant-parsed; junk before the JSON (warnings) is stripped.
    """
    counts, advisories = {}, set()
    start = raw.find("{")
    if start < 0:
        return counts, advisories
    try:
        data = json.loads(raw[start:])
    except json.JSONDecodeError:
        return counts, advisories
    counts = (data.get("metadata") or {}).get("vulnerabilities") or {}
    for pkg, info in (data.get("vulnerabilities") or {}).items():
        for via in info.get("via") or []:
            if isinstance(via, dict):
                title = via.get("title") or via.get("url") or "advisory"
            else:
                title = f"(via {via})"
            advisories.add(f"{pkg} :: {title}")
        if not info.get("via"):
            advisories.add(f"{pkg} :: {info.get('severity', 'unknown')}")
    return counts, advisories


def fmt_counts(counts):
    if not counts:
        return "(no data)"
    keys = ["critical", "high", "moderate", "low", "info", "total"]
    return ", ".join(f"{k}={counts[k]}" for k in keys if k in counts)


# --------------------------------------------------------------------------- #
# per-entry analysis
# --------------------------------------------------------------------------- #
def analyze(entry, args):
    """Run the full pipeline for one entry; return the report text (str)."""
    folder = entry["folder"]
    package = entry["package"]
    tag = image_tag(folder)
    workdir = f"/exploit/{folder}"
    repodir = f"{workdir}/node_modules/{package}"
    patch_host = entry["path"] / "patch.txt"

    # The declared sink (e.g. "lib/foo.js:258:31") points at where the vuln
    # actually lives -- often an unchanged line the diff never touches.
    try:
        meta = json.loads((entry["path"] / "package.json").read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        meta = {}
    sink_field = (meta.get("sink") or "").strip()
    sink_path = sink_field.split(":", 1)[0].strip() if sink_field else ""

    lines = []
    def section(title):
        lines.append("")
        lines.append("=" * 72)
        lines.append(title)
        lines.append("=" * 72)

    lines.append(f"Analyzer report for {entry['category']}/{folder}")
    lines.append(f"Package : {package}@{entry['version']}  (fixed: {entry['fixed_version'] or 'n/a'})")
    lines.append(f"CVE     : {entry['cve']}")
    lines.append(f"Repo    : {entry['repository'] or '(none)'}")
    lines.append(f"Image   : {tag}")

    ok, msg = ensure_image(entry, tag, args.build_mode)
    lines.append(f"Image   : {msg}")
    if not ok:
        section("ABORTED")
        lines.append(msg)
        return "\n".join(lines) + "\n", False

    # Start a long-lived container (override the jest CMD).
    cid = run(["docker", "run", "-d", "--rm", tag,
               "tail", "-f", "/dev/null"]).stdout.strip()
    if not cid:
        section("ABORTED")
        lines.append("could not start container")
        return "\n".join(lines) + "\n", False

    tmp = Path(tempfile.mkdtemp(prefix="analyze_patch_"))
    try:
        # 0. is this a real git clone (revertable) or an npm-install fallback?
        if dexec(cid, f"test -d {repodir}/.git").returncode != 0:
            section("SKIPPED")
            lines.append("source is an npm-install fallback (no git clone); "
                         "the patch cannot be reverted in place.")
            return "\n".join(lines) + "\n", False

        # 1. npm-audit baseline on the FIXED tree.
        audit_fixed = dexec(cid, f"cd {repodir} && npm audit --json 2>/dev/null").stdout

        # 2. clean tracked files to the fixed commit, then reverse-apply the fix.
        run(["docker", "cp", str(patch_host), f"{cid}:/tmp/fix.patch"])
        dexec(cid, f"cd {repodir} && git checkout -- . 2>/dev/null; "
                   f"git reset -q --hard HEAD 2>/dev/null || true")
        rev = dexec(cid, f"cd {repodir} && git apply -R --recount /tmp/fix.patch")
        applied = "git apply -R"
        if rev.returncode != 0:
            rev = dexec(cid, f"cd {repodir} && git apply -R --recount --3way /tmp/fix.patch")
            applied = "git apply -R --3way"
        if rev.returncode != 0:
            section("ABORTED")
            lines.append("could not reverse-apply patch.txt onto the fixed tree:")
            lines.append(rev.stderr.strip()[-1500:])
            return "\n".join(lines) + "\n", False

        # 3. files the patch touched (excluding ones the revert deleted).
        all_changed = dexec(cid, f"cd {repodir} && git diff --name-only").stdout.split()
        scan_files = dexec(
            cid, f"cd {repodir} && git diff --name-only --diff-filter=d").stdout.split()

        section("PATCH REVERT")
        lines.append(f"Reverted patch.txt via: {applied}")
        lines.append(f"Files changed by the patch ({len(all_changed)}):")
        lines += [f"  {f}" for f in all_changed] or ["  (none)"]

        # 4. semgrep over the change PLUS the declared sink file, via the
        #    official container, with the default packs + the local sink rules.
        section("SEMGREP (sink file + changed files)")
        targets = [f for f in scan_files if f.endswith(JS_EXT)]
        sink_note = "no sink declared in package.json"
        if sink_path:
            if dexec(cid, f"cd {repodir} && test -f '{sink_path}'").returncode == 0:
                if sink_path not in targets:
                    targets.append(sink_path)
                sink_note = f"sink file scanned: {sink_path}"
            else:
                sink_note = (f"sink file '{sink_path}' not present in the tree "
                             f"(built/transpiled elsewhere?) -- not scanned")
        # de-dup, keep order
        targets = list(dict.fromkeys(targets))
        lines.append(sink_note)

        if not targets:
            lines.append("no scannable JS files among the change or sink.")
        else:
            # tar just the target files out of the container, preserving paths.
            filelist = " ".join(f"'{f}'" for f in targets)
            dexec(cid, f"cd {repodir} && tar -cf /tmp/changed.tar {filelist}")
            run(["docker", "cp", f"{cid}:/tmp/changed.tar", str(tmp / "changed.tar")])
            srcdir = tmp / "src"
            srcdir.mkdir()
            run(["tar", "-xf", str(tmp / "changed.tar"), "-C", str(srcdir)])

            configs = list(args.semgrep_config or DEFAULT_SEMGREP_CONFIGS)
            cfg = ["--config", f"/rules/{LOCAL_RULESET}"]
            for c in configs:
                cfg += ["--config", c]
            sg = run(["docker", "run", "--rm",
                      "-v", f"{srcdir}:/src",
                      "-v", f"{RULES_DIR}:/rules:ro",
                      SEMGREP_IMAGE, "semgrep", *cfg,
                      "--metrics", "off", "--disable-version-check", "/src"])
            out = (sg.stdout or "").strip()
            err = (sg.stderr or "")
            summary = next((m.group(0) for m in
                            re.finditer(r"Ran [\d,]+ rules on [\d,]+ files?: "
                                        r"[\d,]+ findings?\.", err)), None)
            lines.append(f"Scanned files: {', '.join(targets)}")
            lines.append(f"semgrep configs: {LOCAL_RULESET} (local), "
                         f"{', '.join(configs)}")
            lines.append(f"Summary: {summary or '(semgrep printed no run summary)'}")
            lines.append("")
            lines.append(out if out else "No findings.")
            if sg.returncode not in (0, 1):
                lines.append("\n[semgrep error -- stderr tail]")
                lines.append(err.strip()[-1500:])

        # 5. npm-audit delta after the revert.
        section("NPM AUDIT DELTA (introduced by reverting the fix)")
        audit_reverted = dexec(cid, f"cd {repodir} && npm audit --json 2>/dev/null").stdout
        c_fixed, a_fixed = parse_audit(audit_fixed)
        c_rev, a_rev = parse_audit(audit_reverted)
        lines.append(f"fixed tree   : {fmt_counts(c_fixed)}")
        lines.append(f"reverted tree: {fmt_counts(c_rev)}")
        new = sorted(a_rev - a_fixed)
        lines.append("")
        if new:
            lines.append(f"Advisories introduced by the revert ({len(new)}):")
            lines += [f"  + {a}" for a in new]
        else:
            lines.append("No new advisories introduced by the revert "
                         "(deps unchanged or already-known to the audit DB).")

        return "\n".join(lines) + "\n", True
    finally:
        if args.keep:
            lines_note = f"\n[kept container {cid} and {tmp} for debugging]\n"
            print(lines_note)
        else:
            run(["docker", "rm", "-f", cid])
            shutil.rmtree(tmp, ignore_errors=True)


# --------------------------------------------------------------------------- #
# cli
# --------------------------------------------------------------------------- #
def main():
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("name", nargs="?",
                    help="repository (owner/repo) or npm package name "
                         "(omit when using --category or --all)")
    ap.add_argument("--category", "-c", help="analyze EVERY entry in this category")
    ap.add_argument("--all", action="store_true", help="analyze every entry")
    ap.add_argument("--csv", default="repositories.csv",
                    help="CSV used to enrich repositories (default: repositories.csv)")
    ap.add_argument("--force", action="store_true",
                    help=f"overwrite an existing {OUTPUT_NAME}")
    ap.add_argument("--build", action="store_true",
                    help="rebuild the fixed image even if it already exists")
    ap.add_argument("--no-build", action="store_true",
                    help="never build; fail if the fixed image is missing")
    ap.add_argument("--keep", action="store_true",
                    help="keep the container and temp dir for debugging")
    ap.add_argument("--semgrep-config", action="append", metavar="CONF",
                    help=f"semgrep --config value (repeatable; default: "
                         f"{' '.join(DEFAULT_SEMGREP_CONFIGS)})")
    args = ap.parse_args()

    if sum(bool(x) for x in (args.name, args.category, args.all)) != 1:
        ap.error("provide exactly one of: a name, --category CAT, or --all")
    if args.build and args.no_build:
        ap.error("--build and --no-build are mutually exclusive")
    args.build_mode = "force" if args.build else ("never" if args.no_build else "auto")

    if run(["docker", "info"]).returncode != 0:
        sys.exit("error: Docker daemon is not reachable. Start Docker and retry.")

    csv_path = Path(args.csv)
    if not csv_path.is_absolute():
        csv_path = ROOT / csv_path
    repo_index = csv_repo_index(csv_path)

    if args.category:
        cat = args.category.strip().strip("/").lower()
        if cat not in CATEGORIES and not (ROOT / cat).is_dir():
            sys.exit(f"error: unknown category '{args.category}'. "
                     f"Known: {', '.join(CATEGORIES)}")
        matches = collect_entries([cat], repo_index)
    elif args.all:
        matches = collect_entries(CATEGORIES, repo_index)
    else:
        matches = find_matches_disk(args.name, repo_index)
        if not matches:
            sys.exit(f"error: no benchmark entry matches '{args.name}'.")

    # only entries that have both a fixed image recipe and a patch to revert
    eligible = [e for e in matches
                if (e["path"] / "Dockerfile.fixed").exists()
                and (e["path"] / "patch.txt").exists()]
    skipped = [e for e in matches if e not in eligible]
    for e in skipped:
        print(f"  ~ skip {e['category']}/{e['folder']}: "
              f"missing Dockerfile.fixed or patch.txt")
    print(f"Analyzing {len(eligible)} entr"
          f"{'y' if len(eligible) == 1 else 'ies'}.\n")

    done = wrote = failed = 0
    for entry in eligible:
        bp = f"{entry['category']}/{entry['folder']}"
        target = entry["path"] / OUTPUT_NAME
        if target.exists() and not args.force:
            print(f"  - exists, skipping (use --force): {bp}/{OUTPUT_NAME}")
            continue
        print(f"  > analyzing {bp} ...")
        report, ok = analyze(entry, args)
        target.write_text(report, encoding="utf-8")
        wrote += 1
        done += ok
        failed += (not ok)
        status = "ok" if ok else "incomplete (see report)"
        print(f"    {'+' if ok else '!'} wrote {bp}/{OUTPUT_NAME}  [{status}]")

    print(f"\nDone. {wrote} report(s) written ({done} complete, {failed} incomplete).")


if __name__ == "__main__":
    main()
