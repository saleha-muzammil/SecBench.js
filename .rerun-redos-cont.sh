#!/bin/sh
# Continue the full redos rerun that was paused (and then reaped) at entry 36.
# The 35 entries already finished are on disk in evasion-campaign-redos-rerun.csv;
# this covers only the 24 that never ran.
#
# --only rather than --resume on purpose: --resume skips any entry that HAS an
# evasion-report.txt, and these 24 still carry stale reports from the previous
# (pre-fix, codeql-broken) campaign -- so --resume would skip exactly the entries
# that need running. --force + an explicit list is unambiguous.
cd /Users/saleha/Desktop/cispa/SecBench.js || exit 1

ONLY=""
for f in $(cat /private/tmp/claude-501/-Users-saleha-Desktop-cispa-SecBench-js/b052d541-f0cb-434e-8554-bdeaa42d9f2b/scratchpad/todo.txt); do
    ONLY="$ONLY --only $f"
done

LOW="--no-setup --skip-repo-tests --force --prune --cooldown-sec 30 --max-compose 2 --min-ram-gb 1"

sh .disk-keeper.sh &
KEEPER=$!
echo "=== REDOS CONTINUE START $(date) ==="
nice -n 5 python3 -u run_evasion_campaign.py -c redos $ONLY $LOW \
    --out-csv evasion-campaign-redos-rerun.csv
echo "=== REDOS CONTINUE DONE $(date) ==="
kill $KEEPER 2>/dev/null
