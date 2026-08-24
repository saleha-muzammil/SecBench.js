#!/bin/bash
# Serial, resumable driver for redos-semgrep-analysis.py.
#
# One target per PROCESS, strictly one at a time. That matters on a small machine: semgrep's
# high-water mark is released only when the process exits, so a fresh process per target keeps the
# ceiling at one target's worth of memory instead of the whole sweep's.
#
# Resumable: targets already present in the CSV are skipped, and the CSV merges rather than
# overwrites, so a crash (or Ctrl-C) costs at most the target in flight. Just run it again.
#
#   ./run-redos-serial.sh                 # all remaining targets
#   ./run-redos-serial.sh 5               # only the next 5

set -uo pipefail
cd "$(dirname "$0")"

CSV=redos-semgrep-analysis.csv
LOG=.redos-serial.log
LIMIT="${1:-9999}"

done_list=$([ -f "$CSV" ] && tail -n +2 "$CSV" | cut -d, -f1 || true)
n=0

for d in redos/*/; do
    t=$(basename "$d")
    [ -f "$d/patch.txt" ] && [ -f "$d/Dockerfile.fixed" ] || continue
    grep -qx "$t" <<<"$done_list" && continue
    n=$((n + 1)); [ "$n" -gt "$LIMIT" ] && break

    echo "[$(date +%H:%M:%S)] ($n) $t" | tee -a "$LOG"
    timeout 2400 python3 redos-semgrep-analysis.py --only "$t" --jobs 1 --codeql >>"$LOG" 2>&1
    rc=$?
    [ $rc -ne 0 ] && echo "    -> exit $rc" | tee -a "$LOG"
    grep "^$t," "$CSV" 2>/dev/null | cut -d, -f1,4,5,6,14,15,16,19 | tee -a "$LOG"

    # Extracted trees are the bulk of the disk cost (up to 1 GB per target, twice over) and are
    # reproducible from the image; the scan JSONs that hold the actual results are kept.
    rm -rf .redos-semgrep-analysis/*/fixed .redos-semgrep-analysis/*/reverted
    # Images are removed by the Python script after extraction; this catches the build cache, which
    # otherwise grows unbounded across dozens of builds.
    docker builder prune -af >/dev/null 2>&1
done

echo "[$(date +%H:%M:%S)] done: $n target(s) this pass, $(($(wc -l <"$CSV") - 1)) rows in $CSV" | tee -a "$LOG"
