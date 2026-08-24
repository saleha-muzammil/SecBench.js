#!/usr/bin/env python3
"""
Collect per-repo stats from every run under stratified-samples-full-loop/ into one CSV.

The full-loop runner rewrites summary.csv from only the repos of its *current* invocation, so
single-repo runs overwrite earlier results. This script is independent of that: it walks every
<category>/<folder>/run_meta.json that exists on disk and emits a consolidated table. Each folder's
run_meta.json reflects that folder's most recent run, which is the state you want.

Usage:
    python3 collect_full_loop_stats.py                       # -> stratified-samples-full-loop/collected_stats.csv
    python3 collect_full_loop_stats.py --root <dir> --out <file.csv>
"""

import argparse
import csv
import json
from pathlib import Path

COLUMNS = [
    "category", "folder", "package", "version", "status", "verdict",
    "seed_patch_applies", "seed_exploit_fires", "evades_both", "evasive_patch_regenerated",
    "base_commit",
    "instance_cost", "api_calls", "prompt_tokens", "completion_tokens", "total_tokens", "trajectories",
    "wall_seconds_setup", "wall_seconds_pipeline", "wall_seconds_total",
    "started_at", "finished_at", "error",
]


def row_from_meta(meta: dict) -> dict:
    totals = (meta.get("metrics") or {}).get("totals", {}) or {}
    return {
        "category": meta.get("category", ""),
        "folder": meta.get("folder", ""),
        "package": meta.get("package", ""),
        "version": meta.get("version", ""),
        "status": meta.get("status", ""),
        "verdict": meta.get("verdict", ""),
        "seed_patch_applies": meta.get("seed_patch_applies"),
        "seed_exploit_fires": meta.get("seed_exploit_fires"),
        "evades_both": meta.get("evades_both"),
        "evasive_patch_regenerated": meta.get("evasive_patch_regenerated"),
        "base_commit": (meta.get("base_commit") or "")[:12],
        "instance_cost": totals.get("instance_cost", ""),
        "api_calls": totals.get("api_calls", ""),
        "prompt_tokens": totals.get("prompt_tokens", ""),
        "completion_tokens": totals.get("completion_tokens", ""),
        "total_tokens": totals.get("total_tokens", ""),
        "trajectories": totals.get("trajectories", ""),
        "wall_seconds_setup": meta.get("wall_seconds_setup", ""),
        "wall_seconds_pipeline": meta.get("wall_seconds_pipeline", ""),
        "wall_seconds_total": meta.get("wall_seconds_total", ""),
        "started_at": meta.get("started_at", ""),
        "finished_at": meta.get("finished_at", ""),
        "error": meta.get("error", ""),
    }


def recompute_metrics_from_trajectories(repo_dir: Path) -> dict | None:
    """Fallback: if run_meta has no metrics (e.g. an old/partial run), sum the trajectories directly."""
    out_dirs = list(repo_dir.glob("pipeline_*"))
    if not out_dirs:
        return None
    t = {"instance_cost": 0.0, "api_calls": 0, "prompt_tokens": 0,
         "completion_tokens": 0, "total_tokens": 0, "trajectories": 0}
    for traj in repo_dir.rglob("*.traj.json"):
        try:
            data = json.loads(traj.read_text())
        except Exception:
            continue
        stats = data.get("info", {}).get("model_stats", {})
        cost = float(stats.get("instance_cost", 0.0) or 0.0)
        msg_cost = 0.0
        for m in data.get("messages", []):
            extra = m.get("extra", {}) or {}
            msg_cost += float(extra.get("cost", 0.0) or 0.0)
            usage = (extra.get("response", {}) or {}).get("usage") or {}
            t["prompt_tokens"] += int(usage.get("prompt_tokens", 0) or 0)
            t["completion_tokens"] += int(usage.get("completion_tokens", 0) or 0)
            t["total_tokens"] += int(usage.get("total_tokens", 0) or 0)
        t["instance_cost"] += cost or msg_cost
        t["api_calls"] += int(stats.get("api_calls", 0) or 0)
        t["trajectories"] += 1
    t["instance_cost"] = round(t["instance_cost"], 6)
    return {"totals": t}


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--root", default="stratified-samples-full-loop", help="results root to scan")
    ap.add_argument("--out", default="", help="output CSV (default: <root>/collected_stats.csv)")
    args = ap.parse_args()

    root = Path(args.root)
    out = Path(args.out) if args.out else root / "collected_stats.csv"

    rows = []
    for meta_path in sorted(root.glob("*/*/run_meta.json")):
        try:
            meta = json.loads(meta_path.read_text())
        except Exception as e:
            print(f"  skip {meta_path}: {e}")
            continue
        # Backfill metrics from trajectories if the meta didn't carry any.
        if not (meta.get("metrics") or {}).get("totals"):
            recomputed = recompute_metrics_from_trajectories(meta_path.parent)
            if recomputed:
                meta["metrics"] = recomputed
        rows.append(row_from_meta(meta))

    rows.sort(key=lambda r: (r["category"], r["folder"]))
    with open(out, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=COLUMNS)
        w.writeheader()
        w.writerows(rows)

    # console summary
    done = [r for r in rows if str(r["status"]).startswith("ok")]
    ran = [r for r in rows if r["seed_exploit_fires"] is True]
    tot_cost = sum(float(r["instance_cost"]) for r in rows if str(r["instance_cost"]).strip() not in ("", "None"))
    tot_tok = sum(int(r["total_tokens"]) for r in rows if str(r["total_tokens"]).strip() not in ("", "None"))
    print(f"Collected {len(rows)} repo(s) from {root}/")
    print(f"  ran the loop (exploit fired): {len(ran)}   status=ok: {len(done)}")
    print(f"  total cost ${tot_cost:.4f}   total tokens {tot_tok:,}")
    print(f"  -> {out}")


if __name__ == "__main__":
    main()
