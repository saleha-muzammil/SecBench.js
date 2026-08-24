#!/usr/bin/env python3
"""
Re-test every redos benchmark with a CORRECTED exploit oracle and rewrite the
per-entry label, independently of minimize_and_evade.py.

Two things the original pipeline got wrong for redos are fixed here:

  1. SETUP: the exploit tests do `require("../utils")`, which resolves to
     /exploit/utils.js in the container -- a file the Dockerfile never copies
     in (build context is the entry folder; utils.js lives one level up). If it
     is missing, the test throws MODULE_NOT_FOUND before any regex runs, so the
     revert step is recorded as "does NOT reproduce" for EVERY entry. We stage
     an instrumented utils.js into the container before measuring.

  2. ORACLE: the test asserts wall-clock `time > 1s` with no timeout anywhere.
     That misjudges (a) borderline reverts that measure just under 1s on a fast
     host, and (b) severe reverts that hang (a hang IS a successful DoS, but the
     bare `jest` call would stall the pipeline).

Which oracle a given entry uses depends on whether its test has been migrated:

  * expectRedos/expectRedosPair (see redos/utils.js) compute a benign baseline
    in the SAME process, after warmup, timing only the vulnerable call. Their
    numbers are self-contained, so the label follows directly from them and no
    cross-run comparison happens at all.

  * Tests still on `measureTime` only yield a wall clock, so the fixed image's
    run remains the baseline and the old relative threshold
    (reverted >= max(FLOOR, RATIO*fixed)) applies. That rule is weak by nature:
    when the fixed baseline is itself seconds -- chrono-node measures 2669 ms
    before it parses anything -- it demands a 53-second attack before conceding
    a ReDoS exists. Entries labelled through this path are marked
    `legacy-wall-clock` and should be migrated before their labels are trusted.

Either way a timeout counts as REPRODUCES.

Non-destructive: writes redos-retest-summary.tsv at the repo root and a
retest-report.txt into each entry folder; leaves evasion-report.txt alone.

Usage:
    python3 retest_redos.py                 # all redos entries
    python3 retest_redos.py ansi-regex_4.1.0 date-and-time_0.14.1   # a subset
    python3 retest_redos.py --no-build      # only use images that already exist
    python3 retest_redos.py --timeout 30 --ratio 20 --min-attack-ms 50
"""
import argparse
import json
import re
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent
REDOS = ROOT / "redos"
UTILS_SRC = REDOS / "utils.js"

BUILTINS = {
    "assert", "buffer", "child_process", "cluster", "crypto", "dgram", "dns",
    "events", "fs", "http", "https", "net", "os", "path", "process",
    "querystring", "readline", "stream", "string_decoder", "tls", "tty", "url",
    "util", "v8", "vm", "zlib", "timers", "console",
}


def run(cmd, **kw):
    return subprocess.run(cmd, capture_output=True, text=True, **kw)


def dexec(cid, script):
    return run(["docker", "exec", cid, "sh", "-c", script])


def image_tag(folder):
    return f"secbench-fixed/{folder}".lower()


def instrumented_utils():
    """utils.js that records what the measured region actually cost.

    Two oracles coexist while the tests are migrated:

      * measureTime  -- the old absolute-threshold form. Only a wall-clock
        figure is available, written to /tmp/secbench_ms, and the verdict has
        to be reconstructed by comparing two container runs.
      * measureRedos / measureRedosPair -- the ratio oracle, which already
        computed a same-process benign baseline and a scaling factor. Those go
        to /tmp/secbench_metrics as JSON, and the verdict needs no cross-run
        comparison at all: the numbers are self-contained.
    """
    src = UTILS_SRC.read_text(encoding="utf-8")
    wrapper = (
        "\n// --- retest instrumentation: record what the measured region cost ---\n"
        "var __fs = require('fs');\n"
        "var __om = measureTime;\n"
        "measureTime = function (f, p) {\n"
        "  var r = __om(f, p);\n"
        "  try { __fs.writeFileSync('/tmp/secbench_ms', String(r[0] * 1000 + r[1] / 1e6)); } catch (e) {}\n"
        "  return r;\n"
        "};\n"
        "function __record(m) {\n"
        "  try {\n"
        "    __fs.writeFileSync('/tmp/secbench_metrics', JSON.stringify(m));\n"
        "    __fs.writeFileSync('/tmp/secbench_ms', String(m.attackMs));\n"
        "  } catch (e) {}\n"
        "  return m;\n"
        "}\n"
        "var __omr = measureRedos, __omrp = measureRedosPair;\n"
        "measureRedos = function (s) { return __record(__omr(s)); };\n"
        "measureRedosPair = function (s) { return __record(__omrp(s)); };\n"
    )
    anchor = "module.exports.genstr = genstr;"
    if anchor in src:
        return src.replace(anchor, wrapper + anchor, 1)
    return src + wrapper + "\nmodule.exports.measureTime = measureTime;\n"


def test_requires(text):
    mods = set(re.findall(r"""require\(\s*['"]([^'"]+)['"]\s*\)""", text))
    return {m for m in mods if not m.startswith(".") and m not in BUILTINS}


def package_name(folder):
    """Target dependency name from the entry's package.json (fallback: folder stem)."""
    try:
        meta = json.loads((REDOS / folder / "package.json").read_text(encoding="utf-8"))
        deps = list((meta.get("dependencies") or {}).keys())
        if deps:
            return deps[0]
    except Exception:
        pass
    return folder.rsplit("_", 1)[0]


def ensure_image(folder, build):
    tag = image_tag(folder)
    if run(["docker", "image", "inspect", tag]).returncode == 0:
        return True, "using existing image"
    if not build:
        return False, "image missing and --no-build given"
    bp = run(["docker", "build", "-t", tag,
              "-f", str(REDOS / folder / "Dockerfile.fixed"), str(REDOS / folder)])
    if bp.returncode != 0:
        return False, "docker build failed:\n" + bp.stderr.strip()[-800:]
    return True, "built image"


def measure_ms(cid, workdir, timeout_s):
    """Run the jest exploit test bounded by `timeout`; return (elapsed_ms, metrics).

    elapsed_ms is inf when the run timed out (a hang IS a successful DoS) and
    None when the test errored before reaching the measured region.

    metrics is the ratio oracle's own numbers when the test uses expectRedos,
    else None. It is read even on a FAILING jest run: assertRedos throws to fail
    the test, but measureRedos has already recorded why, and that reason is the
    interesting part.
    """
    dexec(cid, "rm -f /tmp/secbench_ms /tmp/secbench_metrics")
    r = dexec(cid, f"cd {workdir} && timeout {timeout_s} jest --runInBand "
                   f">/tmp/jest.log 2>&1; echo EXIT=$?")
    m = re.search(r"EXIT=(\d+)", r.stdout)
    code = m.group(1) if m else "1"
    if code == "124":
        return float("inf"), None

    metrics = None
    blob = dexec(cid, "cat /tmp/secbench_metrics 2>/dev/null").stdout.strip()
    if blob:
        try:
            metrics = json.loads(blob)
        except json.JSONDecodeError:
            metrics = None

    got = dexec(cid, "cat /tmp/secbench_ms 2>/dev/null")
    try:
        return float(got.stdout.strip()), metrics
    except ValueError:
        return None, metrics


def classify(fixed_ms, rev_ms, floor_ms, ratio, metrics=None,
             min_attack_ms=50.0, min_scaling=3.0):
    """Label the revert as reproduces / no-repro / test-error.

    When the test used the ratio oracle, `metrics` carries a same-process benign
    baseline and a scaling factor, and the verdict comes from those directly.
    That is strictly better than comparing two container runs: the old rule
    thresholded at 20x the FIXED image's wall clock, which for a package whose
    fixed baseline is already seconds (chrono-node 2669 ms) demanded a 53-second
    attack before it would admit a ReDoS existed.
    """
    if rev_ms is None and not metrics:
        return "test-error", "exploit test errored before measuring (setup/dep issue)"
    if rev_ms == float("inf"):
        return "reproduces", "revert HANGS past timeout -- catastrophic ReDoS"

    if metrics:
        att = metrics.get("attackMs") or 0.0
        base_ms = metrics.get("baselineMs") or 0.0
        rat = metrics.get("ratio") or 0.0
        scal = metrics.get("scaling")
        detail = (f"attack {att:.1f}ms vs same-process benign baseline "
                  f"{base_ms:.3f}ms -> {rat:.1f}x"
                  + (f", scaling {scal:.1f}x" if scal is not None else ""))
        if att < min_attack_ms:
            return "no-repro", f"{detail} -- too fast to be backtracking"
        if rat < ratio:
            return "no-repro", f"{detail} -- uniformly slow, not input-triggered"
        if scal is not None and scal < min_scaling:
            return "no-repro", f"{detail} -- linear in input size, not catastrophic"
        return "reproduces", detail

    # Legacy path: tests still on measureTime have only a wall-clock number, so
    # the fixed image's run is the only baseline available.
    base = (fixed_ms if isinstance(fixed_ms, (int, float))
            and fixed_ms not in (None, float("inf")) else 0.0)
    threshold = max(floor_ms, ratio * max(base, 1.0))
    if rev_ms >= threshold:
        return "reproduces", (f"reverted {rev_ms:.0f}ms >= threshold {threshold:.0f}ms "
                              f"(fixed {base:.1f}ms) [legacy wall-clock oracle]")
    return "no-repro", (f"reverted {rev_ms:.0f}ms < threshold {threshold:.0f}ms "
                        f"(fixed {base:.1f}ms) [legacy wall-clock oracle] -- "
                        f"may be an oracle artefact; migrate this test to "
                        f"expectRedos before trusting it")


def retest(folder, args):
    path = REDOS / folder
    tag = image_tag(folder)
    package = package_name(folder)
    workdir = f"/exploit/{folder}"
    repodir = f"{workdir}/node_modules/{package}"
    tests = list(path.glob("*.test.js"))
    patch = path / "patch.txt"
    result = {"folder": folder, "package": package, "label": "?", "oracle": "",
              "fixed_ms": None, "rev_ms": None, "detail": ""}

    if not tests or not patch.exists():
        result.update(label="missing-patch-or-test", detail="no *.test.js or patch.txt")
        return result
    ok, msg = ensure_image(folder, args.build)
    if not ok:
        result.update(label="image-failed", detail=msg)
        return result

    cid = run(["docker", "run", "-d", "--rm", tag, "tail", "-f", "/dev/null"]).stdout.strip()
    if not cid:
        result.update(label="infra-error", detail="could not start container")
        return result
    tmp = Path(tempfile.mkdtemp(prefix="retest_"))
    try:
        if dexec(cid, f"test -d {repodir}/.git").returncode != 0:
            result.update(label="npm-fallback", detail="no git tree to revert")
            return result

        # stage the instrumented helper the tests require as ../utils
        inst = tmp / "utils.js"
        inst.write_text(instrumented_utils(), encoding="utf-8")
        run(["docker", "cp", str(inst), f"{cid}:/exploit/utils.js"])

        # install any other undeclared deps the test needs
        deps = sorted(test_requires(tests[0].read_text(encoding="utf-8")) - {package})
        if deps:
            dexec(cid, f"cd {workdir} && npm install --no-audit --no-fund "
                       f"{' '.join(deps)} >/tmp/npm.log 2>&1 || true")

        # 1. baseline on the clean FIXED tree
        dexec(cid, f"cd {repodir} && git checkout -q -- . 2>/dev/null; "
                   f"git reset -q --hard HEAD 2>/dev/null; git clean -fdq 2>/dev/null || true")
        result["fixed_ms"], _ = measure_ms(cid, workdir, args.timeout)

        # 2. revert the fix -> vulnerable tree
        run(["docker", "cp", str(patch), f"{cid}:/tmp/fix.patch"])
        rev = dexec(cid, f"cd {repodir} && git apply -R --recount /tmp/fix.patch")
        if rev.returncode != 0:
            rev = dexec(cid, f"cd {repodir} && git apply -R --recount --3way /tmp/fix.patch")
        if rev.returncode != 0:
            result.update(label="revert-apply-failed",
                          detail="git apply -R rejected (drifted/lockfile hunks)")
            return result

        # 3. measure the reverted tree and classify
        result["rev_ms"], metrics = measure_ms(cid, workdir, args.timeout)
        result["oracle"] = "ratio" if metrics else "legacy-wall-clock"
        label, detail = classify(result["fixed_ms"], result["rev_ms"],
                                 args.floor_ms, args.ratio, metrics,
                                 args.min_attack_ms, args.min_scaling)
        result.update(label=label, detail=detail)
        return result
    finally:
        run(["docker", "kill", cid])
        for f in tmp.glob("*"):
            f.unlink()
        tmp.rmdir()


def fmt_ms(v):
    if v is None:
        return "n/a"
    if v == float("inf"):
        return "HANG"
    return f"{v:.0f}"


def main():
    ap = argparse.ArgumentParser(description="Re-test redos benchmarks with a corrected oracle.")
    ap.add_argument("folders", nargs="*", help="entry folder names (default: all redos)")
    ap.add_argument("--no-build", dest="build", action="store_false",
                    help="only use images that already exist")
    ap.add_argument("--timeout", type=int, default=25, help="per-run wall cap, seconds")
    ap.add_argument("--floor-ms", type=float, default=250.0,
                    help="min reverted ms to count as a DoS")
    ap.add_argument("--ratio", type=float, default=20.0,
                    help="attack must be >= ratio x the benign baseline (ratio "
                         "oracle), or >= ratio*fixed (legacy wall-clock oracle)")
    ap.add_argument("--min-attack-ms", type=float, default=50.0,
                    help="ratio oracle: absolute floor below which timing noise "
                         "dominates and no ratio is believable")
    ap.add_argument("--min-scaling", type=float, default=3.0,
                    help="ratio oracle: growth from the half-size input to the "
                         "full one; linear work is ~2x, backtracking explodes")
    args = ap.parse_args()

    if run(["docker", "info"]).returncode != 0:
        sys.exit("error: docker daemon not reachable.")
    if not UTILS_SRC.exists():
        sys.exit(f"error: {UTILS_SRC} not found.")

    folders = args.folders or sorted(
        p.name for p in REDOS.iterdir()
        if p.is_dir() and (p / "patch.txt").exists() and list(p.glob("*.test.js")))

    rows, flips = [], 0
    print(f"Re-testing {len(folders)} redos entr{'y' if len(folders)==1 else 'ies'} "
          f"(timeout={args.timeout}s, floor={args.floor_ms:.0f}ms, ratio={args.ratio:.0f}x)\n")
    print(f"{'entry':38} {'fixed':>7} {'revert':>7}  label")
    print("-" * 78)
    for folder in folders:
        r = retest(folder, args)
        rows.append(r)
        old_no_repro = "does NOT reproduce" in \
            ((REDOS / folder / "evasion-report.txt").read_text(encoding="utf-8")
             if (REDOS / folder / "evasion-report.txt").exists() else "")
        flipped = old_no_repro and r["label"] == "reproduces"
        flips += 1 if flipped else 0
        mark = "  <== FLIPPED (was no-repro)" if flipped else ""
        print(f"{folder:38} {fmt_ms(r['fixed_ms']):>7} {fmt_ms(r['rev_ms']):>7}  "
              f"{r['label']}{mark}")
        (REDOS / folder / "retest-report.txt").write_text(
            f"=== redos/{folder} (corrected retest) ===\n"
            f"package        : {r['package']}\n"
            f"fixed-tree ms  : {fmt_ms(r['fixed_ms'])}\n"
            f"reverted ms    : {fmt_ms(r['rev_ms'])}\n"
            f"corrected label: {r['label']}\n"
            f"detail         : {r['detail']}\n"
            f"oracle         : {r.get('oracle') or 'n/a'}\n"
            + (f"                 in-process ratio: attack>={args.min_attack_ms:.0f}ms "
               f"AND >={args.ratio:.0f}x benign baseline AND "
               f">={args.min_scaling:.0f}x half-size input\n"
               if r.get("oracle") == "ratio" else
               f"                 legacy wall-clock: HANG or "
               f"reverted>=max({args.floor_ms:.0f}ms, {args.ratio:.0f}x fixed); "
               f"migrate this test to expectRedos to remove the cross-run "
               f"comparison\n"),
            encoding="utf-8")

    summary = ROOT / "redos-retest-summary.tsv"
    with summary.open("w", encoding="utf-8") as fh:
        fh.write("folder\tpackage\tfixed_ms\treverted_ms\tcorrected_label\tdetail\n")
        for r in rows:
            fh.write(f"{r['folder']}\t{r['package']}\t{fmt_ms(r['fixed_ms'])}\t"
                     f"{fmt_ms(r['rev_ms'])}\t{r['label']}\t{r['detail']}\n")

    counts = {}
    for r in rows:
        counts[r["label"]] = counts.get(r["label"], 0) + 1
    print("-" * 78)
    print("labels:", ", ".join(f"{k}={v}" for k, v in sorted(counts.items())))
    print(f"flipped no-repro -> reproduces: {flips}")
    print(f"summary: {summary}")


if __name__ == "__main__":
    main()
