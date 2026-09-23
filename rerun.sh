#!/usr/bin/env bash
cd /Users/saleha/Desktop/cispa/SecBench.js
LIST="${1:-rerun-crashed.txt}"
export QLRAM="${QLRAM:-768}"
mkdir -p rerun-logs stratified-rerun
# docker cp needs the destination's PARENT to exist; the runner never creates it
awk '{print $1}' "$LIST" | sort -u | while read -r c; do mkdir -p "/tmp/rerun-$c"; done
echo "=== start $(date) : $(wc -l < "$LIST" | tr -d ' ') repos, P=${P:-9}, codeql-ram=$QLRAM ==="
xargs -P "${P:-9}" -L 1 bash -c '
  cat="$0"; f="$1"
  echo "[$(date +%H:%M:%S)] START $cat/$f"
  python3 -u run_stratified_full_loop.py \
    -c "$cat" --only "$f" \
    --csv "evasion-campaign-$cat-fixed.csv" \
    --out "stratified-rerun/$cat--$f" \
    --src-dir "/tmp/rerun-$cat" \
    --no-regen --allow-detected-seed \
    --max-iterations 5 --cost-limit 0.3 \
    --extra "--no-run-codegen --gate-in-loop --gate-runs 1 --revise-iterations 2 --codeql-ram $QLRAM" \
    > "rerun-logs/$cat--$f.log" 2>&1
  rc=$?
  echo "[$(date +%H:%M:%S)] DONE  $cat/$f rc=$rc"
' < "$LIST"
echo "=== all done $(date) ==="
