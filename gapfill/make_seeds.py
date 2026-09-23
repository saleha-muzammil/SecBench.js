#!/usr/bin/env python3
"""
Seed the 82 never-run campaign benchmarks with a PLAIN (non-evasive) loop seed.

run_stratified_full_loop.py hardcodes its seed to <category>/<folder>/exploit-evasive.patch
and applies it FORWARD (`git apply --3way --recount`) onto the fixed checkout, so the seed
must be a fixed -> vulnerable diff. The evasive seed is the minimized+transformed form of
exactly that; the unminimized form is the reverse of the fix commit in patch.txt.

This writes that reverse diff, restricted to production paths using minimize_and_evade's own
`is_production_path` (so lockfiles/tests/docs hunks -- the usual cause of `revert-apply-failed`
-- are dropped), but ONLY where exploit-evasive.patch is absent or empty. A real evasive seed
is never overwritten.

    python3 gapfill/make_seeds.py --dry-run     # report only
    python3 gapfill/make_seeds.py               # write the seeds + gapfill/<category>.csv
    python3 gapfill/make_seeds.py --undo        # delete only the seeds this script wrote
"""
import argparse, csv, glob, json, re, sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from minimize_and_evade import is_production_path, split_hunks   # same filter the campaign used
from run_stratified_full_loop import folder_name                  # @eivifj/dot -> eivifj-dot

CATS = ["code-injection", "command-injection", "path-traversal", "prototype-pollution", "redos"]
GAP = ROOT / "gapfill"
LEDGER = GAP / "written-seeds.json"
HUNK_RE = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@(.*)$")


def reverse_hunk(hunk: str) -> str:
    """Flip one @@ block from fix-direction to revert-direction."""
    lines = hunk.splitlines(keepends=True)
    m = HUNK_RE.match(lines[0].rstrip("\n"))
    ol, os_, nl, ns, tail = m.group(1), m.group(2) or "1", m.group(3), m.group(4) or "1", m.group(5)
    out = [f"@@ -{nl},{ns} +{ol},{os_} @@{tail}\n"]
    for ln in lines[1:]:
        if ln.startswith("+"):
            out.append("-" + ln[1:])
        elif ln.startswith("-"):
            out.append("+" + ln[1:])
        else:
            # context, and "\ No newline at end of file" -- the latter annotates the line
            # before it, which keeps its position, so order is preserved on the flip.
            out.append(ln)
    return "".join(out)


def reverse_header(header: str) -> str:
    """Flip a per-file preamble. Pure modifications only: a/X and b/X are the same path,
    so only the index blob hashes swap."""
    out = []
    for ln in header.splitlines(keepends=True):
        m = re.match(r"^index ([0-9a-f]+)\.\.([0-9a-f]+)(.*)$", ln.rstrip("\n"))
        out.append(f"index {m.group(2)}..{m.group(1)}{m.group(3)}\n" if m else ln)
    return "".join(out)


def build_seed(patch_text: str):
    """(seed_text, kept_files, skipped) -- reverse of the production-code part of patch.txt."""
    units, skipped = split_hunks(patch_text), []
    by_file, order = {}, []
    for fpath, header, hunk in units:
        if not is_production_path(fpath):
            skipped.append((fpath, "non-production path"))
            continue
        if re.search(r"^(new file mode|deleted file mode|rename from|similarity index)",
                     header, re.M) or "Binary files" in header:
            skipped.append((fpath, "add/delete/rename/binary -- not a plain modification"))
            continue
        if fpath not in by_file:
            by_file[fpath] = [reverse_header(header), []]
            order.append(fpath)
        by_file[fpath][1].append(reverse_hunk(hunk))
    # Reversed hunks are emitted bottom-up so their line numbers stay self-consistent;
    # `git apply --recount` does not care, but a human reading the patch does.
    parts = []
    for f in order:
        header, hunks = by_file[f]
        parts.append(header)
        parts.extend(hunks)
    return "".join(parts), order, skipped


def load_campaign_rows():
    """(category, folder) -> best campaign row, across every evasion-campaign-*.csv."""
    camp = {}
    for f in sorted(ROOT.glob("evasion-campaign-*.csv")):
        if "ALL" in f.name:
            continue
        with open(f, newline="", encoding="utf-8") as fh:
            for r in csv.DictReader(fh):
                cat = (r.get("category") or "").strip()
                if cat not in CATS:
                    continue
                k = (cat, folder_name(r.get("package", "").strip(),
                                      r.get("version", "").strip()))
                sc = ((r.get("evaded_both") or "").strip() == "yes",
                      (r.get("exploit_reproduces") or "").strip() == "yes")
                if k not in camp or sc > camp[k][0]:
                    camp[k] = (sc, r)
    return {k: v[1] for k, v in camp.items()}


def run_set():
    """Every (category, folder) already touched by a full-loop run."""
    known = {c: {d.name for d in (ROOT / c).iterdir() if d.is_dir()} for c in CATS}
    names = {}
    for c in CATS:
        for n in known[c]:
            names.setdefault(n, c)

    def resolve(cat, name):
        n = name
        for _ in range(4):
            if cat and n in known[cat]:
                return cat, n
            if not cat and n in names:
                return names[n], n
            m = re.match(r"^(.*?)(?:-{1,3}\d+|_\d+|-solved-safe|-solved)$", n)
            if not m:
                break
            n = m.group(1)
        return (cat or names.get(n, "")), n

    run = set()
    pats = [("stratified-samples-full-loop/*/*/", 1, 2),
            ("stratified-samples-full-loop-judge*/*/*/", 1, 2),
            ("stratified-rerun/*/*/*/", 2, 3),
            ("rejected-by-judge/stratified-samples-full-loop/*/*/", 2, 3)]
    for pat, ci, fi in pats:
        for p in glob.glob(str(ROOT / pat)):
            parts = Path(p).relative_to(ROOT).parts
            cat = parts[ci]
            run.add(resolve(None if cat == "rejections" else cat, parts[fi]))
    return run


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--undo", action="store_true")
    args = ap.parse_args()

    if args.undo:
        if not LEDGER.exists():
            sys.exit("nothing to undo: no gapfill/written-seeds.json")
        wrote = json.loads(LEDGER.read_text())
        for rel in wrote:
            (ROOT / rel).unlink(missing_ok=True)
        LEDGER.unlink()
        print(f"removed {len(wrote)} synthesized seed(s)")
        return

    GAP.mkdir(exist_ok=True)
    camp, run = load_campaign_rows(), run_set()
    todo = sorted(k for k in camp if k not in run)

    wrote, reused, failed, by_cat = [], [], [], {}
    for cat, folder in todo:
        d = ROOT / cat / folder
        if not d.is_dir() and (ROOT / cat / f"@{folder}").is_dir():
            d = ROOT / cat / f"@{folder}"   # a few scoped dirs kept their leading '@' on disk
        by_cat.setdefault(cat, []).append(camp[(cat, folder)])
        seed = d / "exploit-evasive.patch"
        missing = [n for n in ("Dockerfile.fixed",) if not (d / n).exists()]
        if not list(d.glob("*.test.js")):
            missing.append("*.test.js")
        if not d.is_dir():
            failed.append((cat, folder, "no benchmark dir on disk"))
            continue
        if missing:
            failed.append((cat, folder, "missing " + ", ".join(missing)))
            continue
        if seed.exists() and seed.stat().st_size:
            reused.append((cat, folder))
            continue
        pt = d / "patch.txt"
        if not pt.exists() or not pt.stat().st_size:
            failed.append((cat, folder, "no patch.txt to reverse"))
            continue
        text, files, skipped = build_seed(pt.read_text(errors="replace"))
        if not text.strip():
            failed.append((cat, folder,
                           "patch.txt has no production-code hunks (" +
                           "; ".join(f"{f}: {w}" for f, w in skipped[:3]) + ")"))
            continue
        if not args.dry_run:
            seed.write_text(text)
            wrote.append(str(seed.relative_to(ROOT)))
        else:
            wrote.append(str(seed.relative_to(ROOT)))
        print(f"  seed  {cat}/{folder}  <- reverse of patch.txt  ({len(files)} file(s), "
              f"{len(skipped)} hunk(s) dropped)")

    if not args.dry_run:
        LEDGER.write_text(json.dumps(wrote, indent=1) + "\n")
        cols = ["category", "repository", "package", "version", "outcome", "evaded_both",
                "status", "exploit_reproduces"]
        for cat, rows in by_cat.items():
            with open(GAP / f"{cat}.csv", "w", newline="", encoding="utf-8") as fh:
                w = csv.DictWriter(fh, fieldnames=cols)
                w.writeheader()
                for r in rows:
                    w.writerow({c: r.get(c, "") for c in cols})
        runnable = [f"{c}\t{f}" for c, f in todo
                    if not any(f == bf and c == bc for bc, bf, _ in failed)]
        (GAP / "targets.tsv").write_text("\n".join(runnable) + "\n")

    print(f"\n  {len(todo)} never-run benchmark(s)")
    print(f"  {len(wrote)} synthesized plain seed(s) from patch.txt")
    print(f"  {len(reused)} already had a real evasive seed: "
          + ", ".join(f"{c}/{f}" for c, f in reused))
    print(f"  {len(failed)} cannot be seeded at all:")
    for c, f, why in failed:
        print(f"      {c}/{f}: {why}")
    if not args.dry_run:
        print(f"\n  -> gapfill/targets.tsv ({len(todo) - len(failed)} runnable), "
              f"gapfill/<category>.csv, gapfill/written-seeds.json")


if __name__ == "__main__":
    main()
