#!/bin/sh
cd /Users/saleha/Desktop/cispa/SecBench.js
LOW="--skip-repo-tests --force --prune --codeql-loop-budget 0 --cooldown-sec 30 --max-compose 2 --min-ram-gb 1"
echo "=== PATH-TRAVERSAL START $(date) ==="
nice -n 5 python3 -u run_evasion_campaign.py -c path-traversal $LOW > .evasion-pathtrav.log 2>&1
echo "=== PATH-TRAVERSAL DONE $(date) ==="
docker system prune -f >/dev/null 2>&1
echo "=== PROTOTYPE-POLLUTION START $(date) ==="
nice -n 5 python3 -u run_evasion_campaign.py -c prototype-pollution $LOW > .evasion-protopoll.log 2>&1
echo "=== PROTOTYPE-POLLUTION DONE $(date) ==="
