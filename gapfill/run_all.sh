#!/bin/bash
# Run every benchmark in gapfill/targets.tsv through the full loop, JOBS at a time.
#
# Parallelizing at the --only level is safe: the runner keys its docker image (secbench/<folder>),
# its checkout (<src-dir>/<folder>-src) and its results (<out>/<category>/<folder>) on the folder,
# so workers never touch each other's state -- including the per-folder `docker image rm` in its
# cleanup. Only <out>/summary.csv and <out>/selection.json race (last writer wins); read the real
# table with collect_full_loop_stats.py, which exists for exactly that reason.
#
#   JOBS=3 bash gapfill/run_all.sh            # fresh run
#   JOBS=3 RESUME=1 bash gapfill/run_all.sh   # skip benchmarks that already finished ok
set -uo pipefail
cd "$(dirname "$0")/.."

export JOBS="${JOBS:-3}"
export OUT="${OUT:-stratified-samples-gapfill}"
export SRC="${SRC:-/tmp/gapfill-src}"
export COST="${COST:-0.3}"
export TIMEOUT="${TIMEOUT:-14400}"
export RESUME="${RESUME:-0}"
TARGETS="${TARGETS:-gapfill/targets.tsv}"

mkdir -p "$OUT/_logs" "$SRC"

# One benchmark dir kept a leading '@' that the runner's folder_name() strips, so without this
# link run_stratified_full_loop.py reports "Dockerfile.fixed missing" for it.
if [ -d "path-traversal/@vivaxy-here_3.1.0" ] && [ ! -e "path-traversal/vivaxy-here_3.1.0" ]; then
  ln -s "@vivaxy-here_3.1.0" "path-traversal/vivaxy-here_3.1.0"
fi

n=$(grep -c . "$TARGETS")
echo "=== $n targets, $JOBS at a time -> $OUT ===" | tee "$OUT/_logs/_progress.log"
date | tee -a "$OUT/_logs/_progress.log"

# -n2: category and folder per invocation. No field contains whitespace.
tr '\t' '\n' < "$TARGETS" | xargs -P "$JOBS" -n 2 bash gapfill/run_one.sh

echo "=== all targets finished $(date) ===" | tee -a "$OUT/_logs/_progress.log"
python3 collect_full_loop_stats.py --root "$OUT" --out "$OUT/collected_stats.csv"
