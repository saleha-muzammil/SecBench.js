#!/usr/bin/env python3
"""
Stratified full-loop runner for the SecBench.js evasion benchmark.

For each of the four categories:

    code-injection, command-injection, path-traversal, prototype-pollution

this script:

  1. randomly (seeded, so reproducible) picks up to N=3 repositories whose
     evasive patch already EVADED BOTH semgrep and CodeQL -- i.e. rows with
     evaded_both == "yes" in evasion-campaign-<category>.csv;

  2. sets up the SecBench "fixed" Docker image for each one, one at a time
     (builds Dockerfile.fixed, then `docker cp`s the checked-out package
     source -- a git checkout at the fixed ref with its deps installed -- out
     of the image to a local checkout the pipeline can solve in);

  3. makes sure the minimal evasive seed patch (exploit-evasive.patch, the diff
     that re-opens the vuln while evading both scanners) is present -- reusing
     it if it already evades both, otherwise regenerating it with
     run_evasion_campaign.py --only <folder> --force;

  4. runs the adversarial cve-pipeline loop on the FIXED version:

        mini-extra cve-pipeline \
          --patch  exploit-evasive.patch    # the minimal evasive seed diff
          --ex_file <package>.test.js        # exploit proving the sink still fires
          --repo-path <checkout>             # fixed checkout with deps + git
          --base    <fixed-commit>           # clean starting ref

  5. collects the metrics the pipeline already records (dollar cost, API calls,
     prompt/completion/total tokens) from every trajectory it writes, plus the
     wall-clock time this runner measures, and saves everything under

        stratified-samples-full-loop/<category>/<folder>/

     with a top-level summary.csv aggregating all runs.

Everything is one-at-a-time (one docker build, one container, one pipeline run)
to keep laptop disk/memory sane, matching run_evasion_campaign.py's policy.

Usage:
    python3 run_stratified_full_loop.py                      # all 4 categories, 3 each
    python3 run_stratified_full_loop.py --seed 42
    python3 run_stratified_full_loop.py -c prototype-pollution -c code-injection
    python3 run_stratified_full_loop.py --only eivifj-dot_1.0.2 --only clamscan_1.2.0
    python3 run_stratified_full_loop.py --dry-run            # just show the selection
    python3 run_stratified_full_loop.py --resume             # skip repos already done

Pipeline knobs (pass-through; defaults match the cve-pipeline defaults):
    --max-iterations N   --cost-limit F   --model M   --extra "--confirm-runs 2 ..."
"""

import argparse
import csv
import json
import os
import random
import re
import shlex
import shutil
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent
CATEGORIES = ["code-injection", "command-injection", "path-traversal", "prototype-pollution"]
DEFAULT_OUT = "stratified-samples-full-loop"
DEFAULT_SEED = 20260817
DEFAULT_N = 3
IMAGE_PREFIX = "secbench-fullloop"


# --------------------------------------------------------------------------- #
# small helpers
# --------------------------------------------------------------------------- #
def log(msg: str) -> None:
    print(f"[{datetime.now().strftime('%H:%M:%S')}] {msg}", flush=True)


def run(cmd, cwd=None, timeout=None, log_path: Path | None = None, env=None):
    """Run a command, optionally teeing combined output to log_path. Returns
    (returncode, combined_output)."""
    proc = subprocess.Popen(
        cmd, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        text=True, bufsize=1, env=env,
    )
    chunks: list[str] = []
    fh = open(log_path, "a", encoding="utf-8") if log_path else None
    try:
        assert proc.stdout is not None
        for line in proc.stdout:
            chunks.append(line)
            if fh:
                fh.write(line)
                fh.flush()
        proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        proc.kill()
        chunks.append(f"\n[runner] TIMEOUT after {timeout}s\n")
    finally:
        if fh:
            fh.close()
    return proc.returncode, "".join(chunks)


def folder_name(package: str, version: str) -> str:
    """@eivifj/dot , 1.0.2  ->  eivifj-dot_1.0.2  (matches the on-disk dirs)."""
    base = re.sub(r"^@", "", package).replace("/", "-")
    return f"{base}_{version}"


# category -> campaign CSV override, set from --csv (see main())
CSV_OVERRIDES: dict[str, Path] = {}


def campaign_csv(category: str) -> Path:
    """Campaign CSV to draw candidates from: an explicit --csv override if given,
    else evasion-campaign-<category>.csv next to this script."""
    return CSV_OVERRIDES.get(category, ROOT / f"evasion-campaign-{category}.csv")


def eligible_rows(category: str) -> list[dict]:
    """Rows whose evasive patch is a valid loop seed: the exploit reproduced AND
    it evaded BOTH scanners (exploit + semgrep + codeql all pass)."""
    csv_path = campaign_csv(category)
    if not csv_path.exists():
        return []
    out = []
    with open(csv_path, newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            if ((row.get("evaded_both") or "").strip() == "yes"
                    and (row.get("exploit_reproduces") or "").strip() == "yes"):
                out.append(row)
    return out


def patch_evades_both(repo_dir: Path) -> bool:
    """True when exploit-evasive.patch is present/non-empty AND the recorded
    findings say neither scanner flagged it."""
    patch = repo_dir / "exploit-evasive.patch"
    findings = repo_dir / "evasion-findings.json"
    if not patch.exists() or patch.stat().st_size == 0:
        return False
    if not findings.exists():
        return False
    try:
        data = json.loads(findings.read_text())
    except Exception:
        return False
    return (data.get("detected_by") == "neither"
            and not data.get("semgrep", {}).get("new_final")
            and not data.get("codeql", {}).get("new_final"))


def find_test_file(repo_dir: Path) -> Path | None:
    tests = sorted(repo_dir.glob("*.test.js"))
    return tests[0] if tests else None


# --------------------------------------------------------------------------- #
# docker setup: build the fixed image, extract the checkout the pipeline solves
# --------------------------------------------------------------------------- #
def docker_setup(category: str, folder: str, package: str, src_dir: Path,
                 setup_log: Path, keep_images: bool) -> tuple[Path, str]:
    """Build Dockerfile.fixed and copy /exploit/<folder>/node_modules/<package>
    (a git checkout at the fixed ref, with deps installed) to a host checkout.
    The built image is left in place (docker-loop mode runs the pipeline inside
    it); the caller removes it. Returns (checkout_path, base_commit_sha, image_tag)."""
    repo_dir = ROOT / category / folder
    if not (repo_dir / "Dockerfile.fixed").exists():
        raise RuntimeError(f"{repo_dir}/Dockerfile.fixed missing")

    tag = f"{IMAGE_PREFIX}/{folder}".lower()
    log(f"    docker build {tag}")
    rc, _ = run(
        ["docker", "build", "-f", str(repo_dir / "Dockerfile.fixed"),
         "-t", tag, str(repo_dir)],
        log_path=setup_log, timeout=3600,
    )
    if rc != 0:
        raise RuntimeError(f"docker build failed (rc={rc}) -- see {setup_log.name}")

    checkout = src_dir / f"{folder}-src"
    if checkout.exists():
        shutil.rmtree(checkout, ignore_errors=True)

    container_src = f"/exploit/{folder}/node_modules/{package}"
    rc, out = run(["docker", "create", tag], log_path=setup_log)
    cid = out.strip().splitlines()[-1].strip() if rc == 0 else ""
    if not cid:
        raise RuntimeError("docker create failed")
    try:
        rc, _ = run(["docker", "cp", f"{cid}:{container_src}", str(checkout)],
                    log_path=setup_log, timeout=1200)
        if rc != 0 or not checkout.exists():
            raise RuntimeError(f"docker cp of {container_src} failed")
    finally:
        run(["docker", "rm", "-f", cid], log_path=setup_log)
        # NB: the IMAGE is kept -- docker-loop mode runs the pipeline inside it
        # (--docker-image tag). process_repo removes it afterwards unless
        # --keep-images. keep_images is accepted for signature compatibility.

    if not (checkout / ".git").exists():
        raise RuntimeError(f"extracted checkout {checkout} has no .git")
    rc, sha = run(["git", "-C", str(checkout), "rev-parse", "HEAD"])
    sha = sha.strip()
    if rc != 0 or not sha:
        raise RuntimeError("could not read base commit from checkout")
    run(["git", "-C", str(checkout), "reset", "--hard", "-q", sha])
    return checkout, sha, tag


# --------------------------------------------------------------------------- #
# evasive patch: reuse if it evades both, else regenerate
# --------------------------------------------------------------------------- #
def ensure_evasive_patch(category: str, folder: str, regen_log: Path,
                         regenerate: bool) -> tuple[Path, bool, bool]:
    """Returns (patch_path, evades_both, regenerated)."""
    repo_dir = ROOT / category / folder
    if patch_evades_both(repo_dir):
        return repo_dir / "exploit-evasive.patch", True, False
    if not regenerate:
        patch = repo_dir / "exploit-evasive.patch"
        return patch, patch_evades_both(repo_dir), False

    log(f"    regenerating evasive patch (run_evasion_campaign.py --only {folder})")
    rc, _ = run(
        [sys.executable, "-u", "run_evasion_campaign.py", "-c", category,
         "--only", folder, "--force", "--prune"],
        cwd=str(ROOT), log_path=regen_log, timeout=7200,
    )
    return repo_dir / "exploit-evasive.patch", patch_evades_both(repo_dir), True


# --------------------------------------------------------------------------- #
# seed-exploit preflight: the loop is only worth running when the SEED patch's
# exploit actually fires on this host checkout. It uses the same oracle the
# pipeline does (mini-extra run-test -> curl_issue._run_ex_test), no LLM cost.
# --------------------------------------------------------------------------- #
def seed_exploit_fires(checkout: Path, patch: Path, ex_file: Path, base_sha: str,
                       log_path: Path) -> tuple[bool, bool]:
    """Apply the evasive seed patch, run the exploit, reset. Returns (applied, fired)."""
    patch_abs = str(patch.resolve())  # git -C cds into the checkout, so the path must be absolute
    run(["git", "-C", str(checkout), "reset", "--hard", "-q", base_sha], log_path=log_path)
    rc, _ = run(["git", "-C", str(checkout), "apply", "--3way", "--whitespace=nowarn", patch_abs],
                log_path=log_path)
    if rc != 0:
        rc, _ = run(["git", "-C", str(checkout), "apply", "--recount", patch_abs], log_path=log_path)
    applied = rc == 0
    fired = False
    if applied:
        rc, _ = run(["mini-extra", "run-test", "--ex_file", str(ex_file),
                     "--repo-path", str(checkout)], log_path=log_path, timeout=1200)
        fired = rc == 0
    run(["git", "-C", str(checkout), "reset", "--hard", "-q", base_sha], log_path=log_path)
    return applied, fired


# --------------------------------------------------------------------------- #
# metrics: aggregate cost / api_calls / tokens from every trajectory the
# pipeline wrote, plus the verdict it printed to run.log
# --------------------------------------------------------------------------- #
def collect_metrics(out_dir: Path) -> dict:
    total = {
        "instance_cost": 0.0, "api_calls": 0,
        "prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0,
        "trajectories": 0,
    }
    per_traj = []
    for traj in sorted(out_dir.rglob("*.traj.json")):
        try:
            data = json.loads(traj.read_text())
        except Exception:
            continue
        stats = data.get("info", {}).get("model_stats", {})
        cost = float(stats.get("instance_cost", 0.0) or 0.0)
        calls = int(stats.get("api_calls", 0) or 0)
        pt = ct = tt = 0
        msg_cost = 0.0
        for m in data.get("messages", []):
            extra = m.get("extra", {}) or {}
            msg_cost += float(extra.get("cost", 0.0) or 0.0)
            usage = (extra.get("response", {}) or {}).get("usage") or {}
            pt += int(usage.get("prompt_tokens", 0) or 0)
            ct += int(usage.get("completion_tokens", 0) or 0)
            tt += int(usage.get("total_tokens", 0) or 0)
        # instance_cost is 0 for models litellm can't price (e.g. deepseek-v4-flash);
        # fall back to summed per-message cost when the rollup came back empty.
        if cost == 0.0 and msg_cost > 0.0:
            cost = msg_cost
        total["instance_cost"] += cost
        total["api_calls"] += calls
        total["prompt_tokens"] += pt
        total["completion_tokens"] += ct
        total["total_tokens"] += tt
        total["trajectories"] += 1
        per_traj.append({
            "file": str(traj.relative_to(out_dir)),
            "instance_cost": round(cost, 6), "api_calls": calls,
            "prompt_tokens": pt, "completion_tokens": ct, "total_tokens": tt,
        })
    total["instance_cost"] = round(total["instance_cost"], 6)
    return {"totals": total, "per_trajectory": per_traj}


def parse_verdict(run_log: Path) -> str:
    if not run_log.exists():
        return ""
    for line in reversed(run_log.read_text(errors="ignore").splitlines()):
        if "Pipeline done." in line:
            return line.strip().strip("= ").strip()
    return ""


# --------------------------------------------------------------------------- #
# one repo, end to end
# --------------------------------------------------------------------------- #
def process_repo(category: str, row: dict, args) -> dict:
    package = row["package"]
    version = row["version"]
    folder = folder_name(package, version)
    repo_dir = ROOT / category / folder
    result_dir = Path(args.out) / category / folder
    result_dir.mkdir(parents=True, exist_ok=True)

    meta = {
        "category": category, "repository": row.get("repository", ""),
        "package": package, "version": version, "folder": folder,
        "started_at": datetime.now(timezone.utc).isoformat(),
        "status": "started", "error": "",
        "base_commit": "", "checkout": "", "image_tag": "", "docker_loop": None,
        "evasive_patch_reused": None, "evasive_patch_regenerated": False,
        "evades_both": None, "seed_patch_applies": None, "seed_exploit_fires": None,
        "verdict": "",
        "wall_seconds_setup": 0.0, "wall_seconds_pipeline": 0.0,
        "wall_seconds_total": 0.0,
        "metrics": {}, "pipeline_cmd": "",
    }
    t_repo = time.time()

    if args.resume and (result_dir / "metrics.json").exists() and (result_dir / "run_meta.json").exists():
        try:
            prev = json.loads((result_dir / "run_meta.json").read_text())
            if prev.get("status") == "ok":
                log(f"  == {folder}: already done (resume), skipping")
                prev["status"] = "ok (resumed)"
                return prev
        except Exception:
            pass

    log(f"  == {category}/{folder}  ({package}@{version})")
    setup_log = result_dir / "setup.log"
    regen_log = result_dir / "regen.log"
    pipeline_log = result_dir / "pipeline.log"
    for p in (setup_log, regen_log, pipeline_log, result_dir / "preflight.log"):
        p.unlink(missing_ok=True)

    try:
        # 1. docker setup + extract checkout
        t0 = time.time()
        checkout, base_sha, image_tag = docker_setup(
            category, folder, package, Path(args.src_dir), setup_log, args.keep_images)
        meta["wall_seconds_setup"] = round(time.time() - t0, 1)
        meta["checkout"] = str(checkout)
        meta["base_commit"] = base_sha
        meta["image_tag"] = image_tag
        meta["docker_loop"] = args.docker_loop
        log(f"    checkout={checkout}  base={base_sha[:12]}")

        # 2. evasive patch
        patch_src, evades, regenerated = ensure_evasive_patch(
            category, folder, regen_log, not args.no_regen)
        meta["evasive_patch_regenerated"] = regenerated
        meta["evasive_patch_reused"] = not regenerated
        meta["evades_both"] = evades
        if not patch_src.exists() or patch_src.stat().st_size == 0:
            raise RuntimeError("no evasive patch available (regeneration failed)")
        if not evades:
            log("    ⚠️  evasive patch does not (re)confirm evading both scanners; running anyway")
        staged_patch = result_dir / "exploit-evasive.patch"
        shutil.copy2(patch_src, staged_patch)

        # 3. exploit/test file
        test_file = find_test_file(repo_dir)
        if not test_file:
            raise RuntimeError(f"no *.test.js in {repo_dir}")
        shutil.copy2(test_file, result_dir / test_file.name)

        # 3b. seed-exploit preflight: abort unless the exploit fires on the seed.
        # Redundant in docker-loop mode -- the loop then runs the exploit in the
        # SAME image minimize_and_evade proved it in, and the pipeline applies the
        # seed itself, so the host-checkout preflight only reintroduces the env gap
        # (missing system binaries, macOS shell) it was meant to catch.
        if not args.no_preflight and not args.docker_loop:
            applied, fired = seed_exploit_fires(
                Path(meta["checkout"]), staged_patch, test_file, base_sha,
                result_dir / "preflight.log")
            meta["seed_patch_applies"] = applied
            meta["seed_exploit_fires"] = fired
            if not (applied and fired):
                reason = ("seed patch did not apply" if not applied
                          else "seed exploit did not reproduce on host checkout")
                meta["status"] = "aborted"
                meta["error"] = f"preflight: {reason}"
                log(f"    ABORT: {reason} -- skipping the loop")
                return meta
            log("    preflight: seed exploit fires ✅")

        # 4. run the pipeline on the fixed version
        cmd = [
            "mini-extra", "cve-pipeline",
            "--patch", str(staged_patch),
            "--ex_file", str(test_file),
            "--repo-path", str(checkout),
            "--base", base_sha,
            "--repo", f"{category}/{folder}",
        ]
        if args.docker_loop:
            # Everything -- both agents and every evaluation command (git, jest,
            # semgrep, codeql) -- runs inside the fixed image, with the checkout
            # bind-mounted at the same path. This is the environment the evasive
            # patch was minimized+verified in, so env-dependent exploits (system
            # binaries, Linux shell semantics) reproduce here as they did there.
            cmd += ["--docker-image", image_tag]
        if args.max_iterations is not None:
            cmd += ["--max-iterations", str(args.max_iterations)]
        if args.cost_limit is not None:
            cmd += ["--cost-limit", str(args.cost_limit)]
        if args.model:
            cmd += ["-m", args.model, "--draft-model", args.model,
                    "--judge-model", args.model, "--transform-model", args.model]
        if args.extra:
            cmd += shlex.split(args.extra)
        meta["pipeline_cmd"] = " ".join(shlex.quote(c) for c in cmd)
        log(f"    pipeline: {meta['pipeline_cmd']}")

        t0 = time.time()
        rc, _ = run(cmd, cwd=str(ROOT), log_path=pipeline_log, timeout=args.pipeline_timeout)
        meta["wall_seconds_pipeline"] = round(time.time() - t0, 1)
        meta["pipeline_returncode"] = rc

        # 5. metrics + verdict.  Pipeline writes to <patch parent>/pipeline_<stem>
        out_dir = staged_patch.parent / f"pipeline_{staged_patch.stem}"
        meta["pipeline_out_dir"] = str(out_dir)
        meta["verdict"] = parse_verdict(out_dir / "run.log")
        meta["metrics"] = collect_metrics(out_dir) if out_dir.exists() else {}
        (result_dir / "metrics.json").write_text(json.dumps(meta["metrics"], indent=2) + "\n")

        meta["status"] = "ok" if rc == 0 else f"pipeline-rc-{rc}"
    except Exception as e:
        meta["status"] = "error"
        meta["error"] = str(e)
        log(f"    ERROR: {e}")
    finally:
        if meta["checkout"] and not args.keep_src:
            shutil.rmtree(meta["checkout"], ignore_errors=True)
        if meta.get("image_tag") and not args.keep_images:
            run(["docker", "image", "rm", "-f", meta["image_tag"]],
                log_path=result_dir / "setup.log")
        meta["wall_seconds_total"] = round(time.time() - t_repo, 1)
        meta["finished_at"] = datetime.now(timezone.utc).isoformat()
        (result_dir / "run_meta.json").write_text(json.dumps(meta, indent=2) + "\n")
    return meta


# --------------------------------------------------------------------------- #
# summary.csv
# --------------------------------------------------------------------------- #
SUMMARY_COLUMNS = [
    "category", "folder", "package", "version", "status", "verdict",
    "seed_exploit_fires", "evades_both", "evasive_patch_regenerated", "base_commit",
    "instance_cost", "api_calls", "prompt_tokens", "completion_tokens",
    "total_tokens", "trajectories",
    "wall_seconds_setup", "wall_seconds_pipeline", "wall_seconds_total", "error",
]


def write_summary(out: Path, metas: list[dict]) -> None:
    rows = []
    for m in metas:
        t = (m.get("metrics") or {}).get("totals", {})
        rows.append({
            "category": m.get("category", ""), "folder": m.get("folder", ""),
            "package": m.get("package", ""), "version": m.get("version", ""),
            "status": m.get("status", ""), "verdict": m.get("verdict", ""),
            "seed_exploit_fires": m.get("seed_exploit_fires"),
            "evades_both": m.get("evades_both"),
            "evasive_patch_regenerated": m.get("evasive_patch_regenerated"),
            "base_commit": (m.get("base_commit") or "")[:12],
            "instance_cost": t.get("instance_cost", ""),
            "api_calls": t.get("api_calls", ""),
            "prompt_tokens": t.get("prompt_tokens", ""),
            "completion_tokens": t.get("completion_tokens", ""),
            "total_tokens": t.get("total_tokens", ""),
            "trajectories": t.get("trajectories", ""),
            "wall_seconds_setup": m.get("wall_seconds_setup", ""),
            "wall_seconds_pipeline": m.get("wall_seconds_pipeline", ""),
            "wall_seconds_total": m.get("wall_seconds_total", ""),
            "error": m.get("error", ""),
        })
    with open(out / "summary.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=SUMMARY_COLUMNS)
        w.writeheader()
        w.writerows(rows)


# --------------------------------------------------------------------------- #
# selection + main
# --------------------------------------------------------------------------- #
def select(categories: list[str], n: int, seed: int, only: set[str],
           full: bool = False) -> dict[str, list[dict]]:
    """Shuffled eligible rows per category. `full` keeps the whole ordered list
    (for --until-success, which walks it until it gets n loops that run);
    otherwise it is truncated to n (fixed sample)."""
    chosen: dict[str, list[dict]] = {}
    for cat in categories:
        rows = eligible_rows(cat)
        if only:
            chosen[cat] = [r for r in rows if folder_name(r["package"], r["version"]) in only]
            continue
        rng = random.Random(f"{seed}:{cat}")   # per-category stream -> stable per category
        rng.shuffle(rows)
        chosen[cat] = rows if full else rows[:min(n, len(rows))]
    return chosen


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("-c", "--category", action="append", dest="categories",
                    choices=CATEGORIES, help="restrict to category (repeatable)")
    ap.add_argument("-n", "--num", type=int, default=DEFAULT_N,
                    help="repos per category (default 3; fewer if not that many evaded both)")
    ap.add_argument("--until-success", action="store_true",
                    help="walk shuffled candidates per category until -n of them pass the "
                         "preflight (exploit fires + evades both) and run the loop, skipping aborts")
    ap.add_argument("--seed", type=int, default=DEFAULT_SEED, help="random seed (reproducible)")
    ap.add_argument("--only", action="append", default=[],
                    help="restrict to specific folder(s), e.g. eivifj-dot_1.0.2 (repeatable, bypasses sampling)")
    ap.add_argument("--csv", action="append", default=[], metavar="[CATEGORY=]PATH",
                    help="campaign CSV to draw candidates from instead of "
                         "evasion-campaign-<category>.csv, e.g. "
                         "--csv evasion-campaign-command-injection-rerun.csv (repeatable; "
                         "prefix with CATEGORY= when running more than one category)")
    ap.add_argument("--out", default=DEFAULT_OUT, help="results folder")
    ap.add_argument("--src-dir", default="/tmp", help="where to place extracted checkouts")
    ap.add_argument("--dry-run", action="store_true", help="print the selection and exit")
    ap.add_argument("--resume", action="store_true", help="skip repos already finished ok")
    ap.add_argument("--keep-src", action="store_true", help="keep extracted checkouts (large)")
    ap.add_argument("--keep-images", action="store_true", help="keep built docker images (large)")
    ap.add_argument("--no-regen", action="store_true",
                    help="never regenerate a missing/weak evasive patch")
    ap.add_argument("--no-preflight", action="store_true",
                    help="skip the seed-exploit check that aborts repos whose exploit does not fire")
    ap.add_argument("--docker-loop", dest="docker_loop", action="store_true", default=True,
                    help="run the whole pipeline (agents + git + tests + scanners) INSIDE the fixed "
                         "image, matching the environment the evasive patch was verified in "
                         "(default). Env-dependent exploits reproduce; the host preflight is skipped.")
    ap.add_argument("--no-docker-loop", dest="docker_loop", action="store_false",
                    help="run the pipeline on the host checkout instead (legacy). Exploits needing "
                         "Linux system binaries or shell semantics will fail the host preflight.")
    # pipeline pass-through (defaults = cve-pipeline defaults when omitted)
    ap.add_argument("--max-iterations", type=int, default=None)
    ap.add_argument("--cost-limit", type=float, default=0.3,
                    help="per-agent dollar cap passed to cve-pipeline (codegen is bounded by this "
                         "alone -- its step limit is disabled in the pipeline)")
    ap.add_argument("--model", default=None, help="set -m/--draft/--judge/--transform model together")
    ap.add_argument("--extra", default="", help="extra args appended verbatim to cve-pipeline")
    ap.add_argument("--pipeline-timeout", type=int, default=14400, help="per-repo pipeline timeout (s)")
    args = ap.parse_args()

    categories = args.categories or CATEGORIES
    for spec in args.csv:
        cat, sep, path = spec.partition("=")
        if not sep:
            if len(categories) != 1:
                ap.error("--csv without a CATEGORY= prefix needs exactly one -c/--category")
            cat, path = categories[0], spec
        if cat not in CATEGORIES:
            ap.error(f"--csv: unknown category {cat!r}")
        csv_path = Path(path) if Path(path).is_absolute() else ROOT / path
        if not csv_path.exists():
            ap.error(f"--csv: {csv_path} does not exist")
        CSV_OVERRIDES[cat] = csv_path
    for cat in categories:
        log(f"candidates for {cat}: {campaign_csv(cat).name}")
    only = set(args.only)
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)

    selection = select(categories, args.num, args.seed, only, full=args.until_success)

    mode = f"until-success, target {args.num}/category" if args.until_success else f"fixed n={args.num}"
    print(f"\n=== Selection (seed={args.seed}, {mode}) ===")
    plan = {"seed": args.seed, "n": args.num, "until_success": args.until_success,
            "generated_at": datetime.now(timezone.utc).isoformat(), "categories": {}}
    for cat in categories:
        rows = selection[cat]
        plan["categories"][cat] = [
            {"folder": folder_name(r["package"], r["version"]),
             "package": r["package"], "version": r["version"],
             "repository": r.get("repository", "")}
            for r in rows
        ]
        label = "candidate(s) in try-order" if args.until_success else "repo(s)"
        print(f"  {cat}: {len(rows)} {label}")
        for r in rows:
            print(f"      - {folder_name(r['package'], r['version'])}")
    (out / "selection.json").write_text(json.dumps(plan, indent=2) + "\n")

    if args.dry_run:
        print("\n(dry run -- nothing built or executed)")
        return

    metas: list[dict] = []
    for cat in categories:
        successes = 0
        for row in selection[cat]:
            meta = process_repo(cat, row, args)
            metas.append(meta)
            write_summary(out, metas)   # rewrite after each repo so partial runs are usable
            if meta.get("seed_exploit_fires") is True:  # preflight passed -> the loop actually ran
                successes += 1
            if args.until_success and successes >= args.num:
                break
        if args.until_success and successes < args.num:
            log(f"  {cat}: only {successes}/{args.num} candidate(s) passed preflight "
                f"(exhausted {len(selection[cat])} eligible)")

    print("\n=== Done ===")
    ok = sum(1 for m in metas if m.get("status", "").startswith("ok"))
    tot_cost = sum((m.get("metrics") or {}).get("totals", {}).get("instance_cost", 0) or 0 for m in metas)
    print(f"  {ok}/{len(metas)} repos completed; total cost ${tot_cost:.4f}")
    print(f"  results -> {out}/  (summary.csv, selection.json, <category>/<folder>/)")


if __name__ == "__main__":
    main()
