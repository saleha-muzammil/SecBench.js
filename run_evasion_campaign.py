#!/usr/bin/env python3
"""
End-to-end evasion campaign for one SecBench.js category (default: code-injection).

Answers one question, for every entry in the category:

    can the fix be reverted MINIMALLY -- only the added/removed/modified lines,
    never the surrounding context -- and rewritten so that the exploit test still
    PASSES while neither semgrep nor CodeQL reports anything the fixed tree did
    not already report?  And in how many cases?

Pipeline, strictly one entry at a time:

  setup     1. generate Dockerfile.fixed for entries that lack one
                 (generate_dockerfile_fixed.py -- needs a usable fixedVersion)
            2. fetch patch.txt for entries that lack one
                 (fetch_patch.py -- needs a resolvable fix commit)
            3. build the fixed image, one build at a time, with a disk/memory
               preflight before each one
  analyse   4. minimize_and_evade.process() per entry: minimal line-level revert
               -> exploit oracle -> hard-coded evasive rewrites -> semgrep +
               CodeQL scored against the CLEAN FIXED baseline
  report    5. evasion-campaign-<category>.csv  (one row per entry)
            6. evasion-campaign-<category>.md   (the counts, in prose)

Resource policy -- this runs on a laptop, so nothing here is concurrent:
  * one docker build at a time, one container alive at a time, one scanner at a
    time (semgrep is memory-capped, CodeQL is --threads=1 with a RAM cap; both
    live in minimize_and_evade.py);
  * a preflight refuses to start an entry when free disk is below --min-disk-gb,
    because a full disk mid-run corrupts an image and reads as a benchmark
    failure rather than a host failure;
  * `docker image prune -f` between entries with --prune, since each fixed image
    is a full node tree and the category adds up to tens of GB.

Usage:
    python3 run_evasion_campaign.py                       # code-injection
    python3 run_evasion_campaign.py -c command-injection
    python3 run_evasion_campaign.py --setup-only          # dockerfiles+patches
    python3 run_evasion_campaign.py --only djv_2.0.0 --force
    # options: [--no-codeql] [--prune] [--min-disk-gb 15] [--limit N]
    #          [--skip-repo-tests] [--resume]
"""

import argparse
import csv
import json
import re
import shutil
import subprocess
import sys
import time
from collections import Counter
from pathlib import Path

from generate_dockerfile import ROOT, CATEGORIES, csv_repo_index, collect_entries
import minimize_and_evade as ME

CAMPAIGN_CSV = "evasion-campaign-{cat}.csv"
CAMPAIGN_MD = "evasion-campaign-{cat}.md"
CAMPAIGN_LOG = ".evasion-campaign/{cat}"

# Columns: the per-entry verdict first (what the campaign is for), then the
# evidence behind it. Deliberately a superset of nothing -- every column here is
# read straight off minimize_and_evade's metrics dict.
COLUMNS = [
    "category", "repository", "package", "version",
    "outcome", "evaded_both", "status",
    "baseline_test", "exploit_reproduces",
    "granularity", "units_total", "units_kept",
    "winning_transform", "transform_layers",
    "semgrep_fixed", "semgrep_new_full", "semgrep_new_minimal", "semgrep_new_final",
    "codeql_fixed", "codeql_new_full", "codeql_new_minimal", "codeql_new_final",
    "detected_by", "semgrep_top_rules", "codeql_top_rules",
    "ci_strategy", "ci_verdict", "audit_new",
    # non-empty when the cloned repository looks unrelated to the package, i.e.
    # the image may be built from a different project and the row is not a result
    "repo_suspect",
    "semgrep_messages", "codeql_messages",
]


def sh(cmd, **kw):
    return subprocess.run(cmd, capture_output=True, text=True, **kw)


def free_gb(path):
    return shutil.disk_usage(path).free / (1 << 30)


def free_ram_gb():
    """Free + inactive physical memory, in GB (macOS). 0.0 if unknown.

    `inactive` counts because macOS reclaims those pages on demand -- excluding
    them would report a machine with a warm file cache as out of memory.
    """
    r = sh(["vm_stat"])
    if r.returncode != 0:
        return 0.0
    page, free, inactive = 4096, 0, 0
    for line in (r.stdout or "").splitlines():
        m = re.match(r"Mach Virtual Memory Statistics: \(page size of (\d+)", line)
        if m:
            page = int(m.group(1))
        m = re.match(r"Pages free:\s+(\d+)", line)
        if m:
            free = int(m.group(1))
        m = re.match(r"Pages inactive:\s+(\d+)", line)
        if m:
            inactive = int(m.group(1))
    return (free + inactive) * page / (1 << 30)


def preflight(min_disk_gb, min_ram_gb=1.0):
    """Refuse to start work the host cannot finish. Returns (ok, message).

    Checked before EVERY entry, not just at startup: semgrep and CodeQL are the
    memory-hungry steps and they run once per entry, so the moment to notice a
    starved host is between entries, while stopping cleanly is still possible.
    """
    if sh(["docker", "info"]).returncode != 0:
        return False, "Docker daemon is not reachable"
    gb = free_gb(ROOT)
    if gb < min_disk_gb:
        return False, (f"only {gb:.1f} GB free on the volume holding {ROOT} "
                       f"(need {min_disk_gb} GB). Run with --prune, or free space "
                       f"with `docker system prune -a`.")
    ram = free_ram_gb()
    if ram and ram < min_ram_gb:
        return False, (f"only {ram:.1f} GB of memory available (need "
                       f"{min_ram_gb} GB). Close other applications, or lower "
                       f"the scanner caps in minimize_and_evade.py.")
    return True, f"{gb:.1f} GB disk, {ram:.1f} GB RAM free"


# --------------------------------------------------------------------------- #
# setup
# --------------------------------------------------------------------------- #
def run_setup(cat, force):
    """Generate the missing Dockerfile.fixed / patch.txt for the category.

    Both generators are idempotent and skip entries they cannot resolve (no
    fixedVersion, no fix commit), so this is safe to re-run; their stdout is
    echoed because their skip reasons are the explanation for every entry that
    later shows up as `missing-patch-or-test`.
    """
    for script, what in (("generate_dockerfile_fixed.py", "Dockerfile.fixed"),
                         ("fetch_patch.py", "patch.txt")):
        print(f"\n--- setup: {what} ({script}) ---", flush=True)
        cmd = [sys.executable, str(ROOT / script), "--category", cat]
        if force:
            cmd.append("--force")
        r = sh(cmd, cwd=ROOT)
        out = (r.stdout or "") + (r.stderr or "")
        print("\n".join("    " + ln for ln in out.strip().splitlines()[-40:]))
        if r.returncode != 0:
            print(f"    ! {script} exited {r.returncode} -- continuing with "
                  f"whatever it did produce", flush=True)


_GH_REPO = re.compile(r"github\.com/([^/]+)/([^/]+)", re.I)


def suspect_repo(entry):
    """The repo this entry builds from, when it looks unrelated to the package.

    repositories.csv maps some packages to the WRONG project -- samsung-remote
    to ronomon/opened, scp to kellyselden/git-diff-apply, strider-git to
    Turistforeningen/node-im-metadata. Because the fixCommit is derived from the
    same row, the two agree with each other and both are wrong, so they cannot
    be cross-checked. What can be checked is the package name against the repo
    name: Dockerfile.fixed CLONES that repo, so a wrong mapping means the image
    is built from a different project entirely and every downstream verdict for
    the row is meaningless.

    This is a heuristic, not a proof -- a renamed repo or a monorepo package
    (@thi.ng/egf really does live in thi-ng/umbrella) trips it too. Hence
    "suspect": a prompt to verify the row, not a claim that it is broken.
    """
    repo = (entry.get("repository") or "").strip().lower()
    if not repo or "/" not in repo:
        return ""
    name = re.sub(r"[^a-z0-9]", "", repo.split("/")[-1])
    # strip the conventional node-/js- decorations before comparing
    name = re.sub(r"^(node|js)|(node|js)$", "", name)
    pkg = re.sub(r"[^a-z0-9]", "", (entry.get("package") or "").lower().lstrip("@"))
    if not pkg or not name:
        return ""
    return "" if (pkg in name or name in pkg) else repo


def eligibility(entry):
    """Why an entry can or cannot be analysed, as a short reason string."""
    missing = []
    if not (entry["path"] / "Dockerfile.fixed").exists():
        missing.append("Dockerfile.fixed")
    if not (entry["path"] / "patch.txt").exists():
        missing.append("patch.txt")
    if not list(entry["path"].glob("*.test.js")):
        missing.append("*.test.js")
    return ", ".join(missing)


# --------------------------------------------------------------------------- #
# the campaign
# --------------------------------------------------------------------------- #
def main():
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--category", "-c", default="code-injection",
                    choices=CATEGORIES)
    ap.add_argument("--csv", default="repositories.csv")
    ap.add_argument("--out-csv", default="",
                    help="write results here instead of evasion-campaign-"
                         "<category>.csv (the .md report follows the same "
                         "stem). Seeded from the canonical campaign CSV on "
                         "first write, so the new file is a complete table; "
                         "the canonical file is left untouched.")
    ap.add_argument("--only", action="append", default=[],
                    help="restrict to these folder names (repeatable)")
    ap.add_argument("--limit", type=int, help="stop after N analysed entries")
    ap.add_argument("--setup-only", action="store_true",
                    help="generate Dockerfile.fixed/patch.txt and exit")
    ap.add_argument("--no-setup", action="store_true",
                    help="assume Dockerfile.fixed/patch.txt already exist")
    ap.add_argument("--resume", action="store_true",
                    help="skip entries that already have an evasion-report.txt")
    ap.add_argument("--force", action="store_true",
                    help="re-analyse entries that already have a report")
    ap.add_argument("--prune", action="store_true",
                    help="docker image prune -f between entries (reclaims tens "
                         "of GB across a category)")
    ap.add_argument("--min-disk-gb", type=float, default=15.0)
    ap.add_argument("--min-ram-gb", type=float, default=1.0,
                    help="refuse to start an entry below this much free memory")
    ap.add_argument("--cooldown-sec", type=int, default=0,
                    help="idle-sleep this many seconds between entries so the "
                         "laptop can shed heat (0 = no pause)")
    # forwarded to minimize_and_evade.process()
    ap.add_argument("--no-codeql", action="store_true")
    ap.add_argument("--no-evade", action="store_true")
    ap.add_argument("--skip-repo-tests", action="store_true")
    ap.add_argument("--keep", action="store_true")
    ap.add_argument("--codeql-suite", default=ME.CODEQL_SUITE)
    ap.add_argument("--codeql-scope", choices=("package", "files"),
                    default="package",
                    help="CodeQL database scope; 'package' matches the scope "
                         "semgrep-codeql-analysis.py used for the *-analysis.csv "
                         "files, 'files' misses cross-file taint paths")
    ap.add_argument("--codeql-loop-budget", type=int, default=4)
    ap.add_argument("--max-compose", type=int, default=3)
    ap.add_argument("--max-units", type=int, default=60)
    ap.add_argument("--report-only", action="store_true",
                    help="rebuild the markdown report from the existing "
                         "evasion-campaign-<category>.csv; runs nothing")
    args = ap.parse_args()
    cat = args.category

    if args.report_only:
        src = ROOT / (args.out_csv or CAMPAIGN_CSV.format(cat=cat))
        if not src.exists():
            sys.exit(f"error: {src.name} does not exist yet")
        with src.open(encoding="utf-8") as fh:
            rows = [_untype(r) for r in csv.DictReader(fh)]
        write_outputs(cat, rows, [], Counter(r["status"] for r in rows), args)
        return

    ok, msg = preflight(args.min_disk_gb, args.min_ram_gb)
    print(f"preflight: {msg}")
    if not ok:
        sys.exit(f"error: {msg}")

    if not args.no_setup:
        run_setup(cat, args.force)
    if args.setup_only:
        return

    csv_path = Path(args.csv)
    if not csv_path.is_absolute():
        csv_path = ROOT / csv_path
    entries = collect_entries([cat], csv_repo_index(csv_path))
    if args.only:
        want = set(args.only)
        entries = [e for e in entries if e["folder"] in want]

    logdir = ROOT / CAMPAIGN_LOG.format(cat=cat)
    logdir.mkdir(parents=True, exist_ok=True)

    # minimize_and_evade.process() reads these off the args object.
    args.build_mode = "auto"
    args.keep = args.keep

    rows, skipped, tally = [], [], Counter()
    analysed = 0
    for entry in entries:
        folder = entry["folder"]
        why = eligibility(entry)
        if why:
            skipped.append((folder, f"missing {why}"))
            print(f"  - skip {folder}: missing {why}", flush=True)
            continue
        report_path = entry["path"] / ME.REPORT_OUT
        if report_path.exists() and args.resume and not args.force:
            print(f"  - skip {folder}: already analysed (--resume)", flush=True)
            continue
        if args.limit and analysed >= args.limit:
            skipped.append((folder, "--limit reached"))
            continue

        ok, msg = preflight(args.min_disk_gb, args.min_ram_gb)
        if not ok:
            print(f"  ! stopping before {folder}: {msg}", flush=True)
            skipped.append((folder, f"host: {msg}"))
            break

        print(f"\n[{analysed + 1}] {cat}/{folder}  (free disk {msg})", flush=True)
        t0 = time.time()
        try:
            report, status, _patch, m = ME.process(entry, args)
        except Exception as exc:                      # noqa: BLE001
            # One broken entry must not take the campaign down with it: record
            # it as a harness error and keep going.
            report, status = f"harness error: {exc!r}\n", "harness-error"
            m = {"repository": entry.get("repository") or "", "package": entry["package"],
                 "category": cat, "version": entry.get("version") or "",
                 "status": status}
            print(f"    ! harness error: {exc!r}", flush=True)
        dt = time.time() - t0
        report_path.write_text(report, encoding="utf-8")
        (logdir / f"{folder}.log").write_text(report, encoding="utf-8")

        m.setdefault("outcome", ME.outcome_of(m.get("status")))
        m["repo_suspect"] = suspect_repo(entry)
        m["exploit_reproduces"] = "no" if "EXPLOIT-BROKEN" in (status or "") else (
            "yes" if str(m.get("outcome")) == "ok" else "")
        rows.append(m)
        tally[status] = tally[status] + 1
        analysed += 1
        print(f"  => {folder}: {status}   [{dt / 60:.1f} min, "
              f"evaded_both={m.get('evaded_both') or 'n/a'}]", flush=True)

        # Reclaim THIS entry's image now that the entry is done. Targeted, so it
        # can never take out an image another entry is about to run -- unlike a
        # blanket `docker image prune -a`, which protects only images backing a
        # running container and so races the build->run window (see
        # .disk-keeper.sh). Each fixed image is 1.5-2 GB, so this is where the
        # campaign's disk headroom actually comes from.
        sh(["docker", "rmi", "-f", ME.image_tag(folder)])
        if args.prune:
            sh(["docker", "image", "prune", "-f"])

        # Give the machine time to shed heat before the next entry's CodeQL
        # database build pegs every core again. A pure sleep, so the CPU is idle
        # (not just lightly loaded) for the whole interval. `entries` includes the
        # skipped ones, so compare against the analysable count -- otherwise the
        # loop cools down once more after the final real entry for nothing.
        remaining_analysable = sum(
            1 for e in entries[entries.index(entry) + 1:] if not eligibility(e))
        if args.cooldown_sec and remaining_analysable:
            print(f"    cooldown {args.cooldown_sec}s (letting the CPU cool) ...",
                  flush=True)
            time.sleep(args.cooldown_sec)

    write_outputs(cat, rows, skipped, tally, args)


# --------------------------------------------------------------------------- #
# reporting
# --------------------------------------------------------------------------- #
# Numeric columns the report does arithmetic on. A CSV round-trip turns them
# into strings, and "0" is truthy, so a report rebuilt from disk would count
# every entry as detected without this.
_NUMERIC = {"units_total", "units_kept", "audit_new",
            "semgrep_fixed", "semgrep_new_full", "semgrep_new_minimal",
            "semgrep_new_final", "codeql_fixed", "codeql_new_full",
            "codeql_new_minimal", "codeql_new_final"}


def _untype(row):
    """Restore the numeric columns of a CSV row; "" and "n/a" stay None."""
    out = dict(row)
    for k in _NUMERIC:
        v = (out.get(k) or "").strip()
        out[k] = int(v) if v.lstrip("-").isdigit() else None
    return out


def _cell(v):
    if v is None:
        return ""
    if isinstance(v, bool):
        return "yes" if v else "no"
    if isinstance(v, int) and v < 0:
        return "n/a"
    return str(v)


def write_outputs(cat, rows, skipped, tally, args):
    default_csv = ROOT / CAMPAIGN_CSV.format(cat=cat)
    out_csv = default_csv
    out_md = ROOT / CAMPAIGN_MD.format(cat=cat)
    if getattr(args, "out_csv", ""):
        out_csv = Path(args.out_csv)
        if not out_csv.is_absolute():
            out_csv = ROOT / out_csv
        out_md = out_csv.with_suffix(".md")
    # A partial run (--only, --limit, an interrupted campaign) must not erase the
    # entries it did not touch: merge onto whatever is already on disk, keyed by
    # package, with this run's rows winning. Without this, re-running one entry
    # silently reduces the campaign CSV to that single row.
    #
    # For a run writing somewhere else (--out-csv), seed the merge from the
    # CANONICAL campaign CSV the first time, so the new file is a complete,
    # directly comparable table rather than just the handful of re-run rows --
    # while leaving the canonical file untouched.
    seed = out_csv if out_csv.exists() else default_csv
    merged = {}
    if seed.exists():
        with seed.open(encoding="utf-8") as fh:
            for old in csv.DictReader(fh):
                merged[old.get("package") or old.get("repository")] = _untype(old)
    for r in rows:
        merged[r.get("package") or r.get("repository")] = r
    rows = [merged[k] for k in sorted(merged)]
    with out_csv.open("w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=COLUMNS)
        w.writeheader()
        for r in rows:
            w.writerow({k: _cell(r.get(k)) for k in COLUMNS})

    # --- the counts -------------------------------------------------------- #
    reached = [r for r in rows if str(r.get("outcome")) == "ok"]
    judged = [r for r in reached if r.get("evaded_both") in ("yes", "no")]
    won = [r for r in judged if r["evaded_both"] == "yes"]
    sg_only = [r for r in reached if r.get("semgrep_new_final") == 0]
    cq_only = [r for r in reached if r.get("codeql_new_final") == 0]

    def stage(key):
        seen = [r for r in reached if r.get(key) is not None]
        return sum(1 for r in seen if r.get(key) == 0), len(seen)

    # Two very different reasons an entry ends up undetected, and merging them
    # would overstate the result: either a rewrite defeated a detector that DID
    # flag the plain revert, or the detector never distinguished the fixed tree
    # from the reverted one at all (0 new findings before any rewrite). Only the
    # first is evasion; the second is a pre-existing blind spot.
    blind = [r for r in won if not (r.get("winning_transform") or "").strip()]
    earned = [r for r in won if (r.get("winning_transform") or "").strip()]

    lines = [
        f"# Evasion campaign — {cat}",
        "",
        f"Detectors: semgrep ({len(ME.EVADE_SEMGREP_PACKS)} registry packs + "
        f"{', '.join(ME.LOCAL_RULESETS)}"
        + (" + mini-swe-agent semgrep_rules.yaml" if ME.MINI_RULES.exists() else "")
        + f"); CodeQL suite `{args.codeql_suite}`.",
        "",
        "A finding counts only when it is NEW relative to a scan of the CLEAN "
        "FIXED tree over the same files — pre-existing alerts in a patched file "
        "are not something the patch introduced.",
        "",
        "## Headline",
        "",
        f"- entries analysed: **{len(rows)}**",
        f"- reached the evasion stage (minimal revert reproduces the exploit): "
        f"**{len(reached)}**",
        f"- judged by BOTH detectors: **{len(judged)}**",
        f"- **exploit passes AND both detectors evaded: {len(won)}/{len(judged)}**",
        f"  - of which a rewrite was what defeated the detector: **{len(earned)}**",
        f"  - of which no rewrite was needed — neither detector flagged the plain "
        f"revert either, i.e. a pre-existing blind spot rather than an evasion: "
        f"**{len(blind)}**",
        "",]
    if blind:
        lines += ["  Blind-spot entries (0 new findings before any rewrite): "
                  + ", ".join(f"`{r.get('repository') or r.get('package')}`"
                              for r in blind), ""]
    lines += [
        "## Per-detector, per-stage (0 new findings)",
        "",
        "| stage | semgrep | codeql |",
        "| --- | --- | --- |",
    ]
    for label, sk, ck in (("no changes (full revert)", "semgrep_new_full", "codeql_new_full"),
                          ("minimal revert (changed lines only)", "semgrep_new_minimal", "codeql_new_minimal"),
                          ("minimal + evasive rewrites", "semgrep_new_final", "codeql_new_final")):
        a, b = stage(sk)
        c, d = stage(ck)
        lines.append(f"| {label} | {a}/{b} | {c}/{d} |")

    lines += ["", "## What the evasion was", ""]
    xf = Counter((r.get("winning_transform") or "(none needed)") for r in won)
    if xf:
        for name, n in xf.most_common():
            lines.append(f"- `{name}` — {n}")
    else:
        lines.append("- (no entry evaded both detectors)")

    lines += ["", "## Minimality", ""]
    gran = Counter(r.get("granularity") or "?" for r in reached)
    lines.append("- revert expressed at: "
                 + ", ".join(f"{k}={v}" for k, v in gran.items()))
    kept = [(r.get("units_kept"), r.get("units_total")) for r in reached
            if r.get("units_kept") is not None]
    if kept:
        lines.append(f"- change units kept / total (median): "
                     f"{sorted(k for k, _ in kept)[len(kept) // 2]} / "
                     f"{sorted(t for _, t in kept)[len(kept) // 2]}")

    lines += ["", "## Still detected", ""]
    for r in reached:
        if r.get("evaded_both") == "no":
            lines.append(f"- `{r.get('repository') or r.get('package')}` — "
                         f"detected_by={r.get('detected_by')}; "
                         f"semgrep={r.get('semgrep_top_rules') or '-'}; "
                         f"codeql={r.get('codeql_top_rules') or '-'}")

    bad_repo = [r for r in rows if (r.get("repo_suspect") or "").strip()]
    if bad_repo:
        lines += ["", "## Benchmark data bugs (not evasion results)", "",
                  "The package name and the cloned repository share no name token, so the image "
                  "may be built from a DIFFERENT project. Verify before trusting these rows "
                  "(heuristic -- monorepos and renamed repos trip it too):", ""]
        for r in bad_repo:
            lines.append(f"- `{r.get('package')}` — builds from "
                         f"`{r['repo_suspect']}` ({r.get('status')})")

    lines += ["", "## Entries that never reached the evasion stage", ""]
    for r in rows:
        if str(r.get("outcome")) != "ok":
            lines.append(f"- `{r.get('repository') or r.get('package')}` — "
                         f"{r.get('status')} "
                         f"({ME.FAULT_CLASS.get(re.sub(r' \(ci:[^)]*\)$', '', str(r.get('status'))), '?')})")
    for folder, why in skipped:
        lines.append(f"- `{folder}` — not attempted: {why}")

    out_md.write_text("\n".join(lines) + "\n", encoding="utf-8")

    print("\n" + "\n".join(lines[:24]))
    print(f"\nwrote {out_csv.name} and {out_md.name}")
    if tally:
        print("\nstatus tally:")
        for k, v in sorted(tally.items()):
            print(f"  {v:>2}  {k}")


if __name__ == "__main__":
    main()
