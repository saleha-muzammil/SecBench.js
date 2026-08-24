#!/bin/bash
# Serial semgrep + CodeQL patch-revert analysis across SecBench.js categories.
#
# For every <category>/<target>/ that ships a patch.txt AND a Dockerfile.fixed:
#   build the fixed image -> extract the package tree -> scan with semgrep AND CodeQL ->
#   reverse-apply patch.txt -> scan both again -> record what each analyser newly reports.
#
# Output: one CSV per category, <category>-semgrep-codeql-analysis.csv. The columns that answer
# "which analyser noticed the vulnerability coming back" are new_findings (semgrep),
# codeql_new (CodeQL) and detected_by (semgrep | codeql | both | neither).
#
# Design constraints this script exists to satisfy:
#   * ONE TARGET PER PROCESS, strictly serial. semgrep and CodeQL only release their peak memory
#     when the process exits, so a fresh process per target caps memory at one target's worth
#     rather than the whole sweep's. Running these in parallel has crashed an 8 GB machine twice.
#   * RESUMABLE. Targets already in the category CSV are skipped and the CSV merges rather than
#     overwrites, so a crash or Ctrl-C costs at most the target in flight -- just run it again.
#   * DOCKER AND DISK CLEANED CONTINUOUSLY. Images are ~1.6 GB each and extracted trees up to 1 GB
#     twice over; left to accumulate they fill the disk and every later build dies with ENOSPC.
#
# Usage:
#   ./semgrep-codeql-analysis.sh                                   # all four categories, in order
#   ./semgrep-codeql-analysis.sh prototype-pollution               # one category
#   ./semgrep-codeql-analysis.sh code-injection 5                  # first 5 unmeasured targets
#   NO_CODEQL=1 ./semgrep-codeql-analysis.sh path-traversal        # semgrep only (much faster)

set -uo pipefail
cd "$(dirname "$0")"

DEFAULT_CATEGORIES=(code-injection command-injection prototype-pollution path-traversal)
IMPL=semgrep-codeql-analysis.py

# A category name as $1 selects it; a bare number as $1 is a per-category limit.
if [[ $# -gt 0 && ! "$1" =~ ^[0-9]+$ ]]; then
    CATEGORIES=("$1"); LIMIT="${2:-9999}"
else
    CATEGORIES=("${DEFAULT_CATEGORIES[@]}"); LIMIT="${1:-9999}"
fi

CODEQL_FLAG="--codeql"
[ "${NO_CODEQL:-0}" = "1" ] && CODEQL_FLAG=""

command -v semgrep >/dev/null || { echo "semgrep not on PATH"; exit 2; }
docker info >/dev/null 2>&1 || { echo "docker is not running -- start Docker Desktop first"; exit 2; }
[ -n "$CODEQL_FLAG" ] && ! command -v codeql >/dev/null && {
    echo "codeql not on PATH (use NO_CODEQL=1 to run semgrep only)"; exit 2; }

for category in "${CATEGORIES[@]}"; do
    [ -d "$category" ] || { echo "no such category: $category"; continue; }

    CSV="${category}-semgrep-codeql-analysis.csv"
    OUT=".${category}-analysis"
    LOG=".${category}-analysis.log"

    # Only fully measured targets are skipped, so a transient failure (semgrep OOM, docker
    # hiccup) is retried on the next pass instead of being frozen into the CSV.
    done_list=$([ -f "$CSV" ] && awk -F, 'NR>1 && $3=="ok" {print $1}' "$CSV" || true)
    total=$(ls -d "$category"/*/ 2>/dev/null | while read -r d; do
                [ -f "$d/patch.txt" ] && [ -f "$d/Dockerfile.fixed" ] && echo x; done | wc -l | tr -d ' ')
    echo "===== $category: $total target(s) with patch.txt + Dockerfile.fixed -> $CSV" | tee -a "$LOG"
    n=0

    for d in "$category"/*/; do
        t=$(basename "$d")
        # Both files are required: patch.txt defines what to revert, Dockerfile.fixed provides the
        # patched baseline to revert it from. Targets missing either are reported at the end.
        [ -f "$d/patch.txt" ] && [ -f "$d/Dockerfile.fixed" ] || continue
        grep -qx "$t" <<<"$done_list" && continue
        [ "$((n + 1))" -gt "$LIMIT" ] && break
        n=$((n + 1))

        echo "[$(date +%H:%M:%S)] ($n/$total) $category/$t" | tee -a "$LOG"
        timeout 3600 python3 "$IMPL" --category "$category" --only "$t" \
            --csv "$CSV" --out "$OUT" --jobs 1 $CODEQL_FLAG >>"$LOG" 2>&1
        rc=$?
        [ $rc -ne 0 ] && echo "    -> exit $rc (see $LOG)" | tee -a "$LOG"
        # repository, semgrep fixed/reverted/new, codeql fixed/reverted/new, detected_by
        grep "^$t," "$CSV" 2>/dev/null | cut -d, -f1,4,5,6,14,15,16,19 | tee -a "$LOG"

        # Reclaim between targets, not at the end: the trees are reproducible from the image and
        # the results (semgrep_*.json / codeql_*.csv / *_new.json) are what actually matter.
        rm -rf "$OUT"/*/fixed "$OUT"/*/reverted
        # The Python script removes each image after extraction; this catches the build cache and
        # any stopped containers, which otherwise grow unbounded across dozens of builds.
        docker builder prune -af >/dev/null 2>&1
        docker container prune -f >/dev/null 2>&1
    done

    echo "[$(date +%H:%M:%S)] $category done: $n this pass, $(($(wc -l <"$CSV" 2>/dev/null || echo 1) - 1)) rows" | tee -a "$LOG"

    missing=$(for d in "$category"/*/; do
                  [ -f "$d/patch.txt" ] && [ ! -f "$d/Dockerfile.fixed" ] && basename "$d"; done)
    [ -n "$missing" ] && {
        echo "  NOT MEASURABLE (patch.txt but no Dockerfile.fixed):" | tee -a "$LOG"
        sed 's/^/    /' <<<"$missing" | tee -a "$LOG"; }
done

echo "all requested categories finished"
