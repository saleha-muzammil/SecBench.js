#!/bin/sh
# Rerun redos + prototype-pollution after the harness fixes:
#   * _ASSERTIONS knows expectRedos/assertRedos  -> 22 redos PoCs stop being
#     rejected as poc-no-assertions before a container is ever started
#   * test_requires() drops deep self-imports, and Phase-0 installs test deps
#     into /sb-testdeps instead of the benchmark folder -> npm can no longer
#     reinstall the vulnerable version over the fixed git checkout
#   * .disk-keeper.sh no longer prunes images younger than 90m, and the campaign
#     removes each entry's image itself -> no more phantom infra-error
#   * corrected repo/fix-commit/patch for ms, object-path, lodash and
#     @aws-sdk/shared-ini-file-loader
#
# --no-setup on purpose: Dockerfile.fixed / patch.txt for the corrected entries
# were repaired by hand and must not be regenerated out from under this run.
cd /Users/saleha/Desktop/cispa/SecBench.js || exit 1
LOW="--no-setup --skip-repo-tests --force --prune --codeql-loop-budget 0 --cooldown-sec 30 --max-compose 2 --min-ram-gb 1"

sh .disk-keeper.sh &
KEEPER=$!

echo "=== REDOS START $(date) ==="
nice -n 5 python3 -u run_evasion_campaign.py -c redos $LOW > .evasion-redos-rerun.log 2>&1
echo "=== REDOS DONE $(date) ==="

echo "=== PROTOTYPE-POLLUTION START $(date) ==="
nice -n 5 python3 -u run_evasion_campaign.py -c prototype-pollution $LOW > .evasion-protopoll-rerun.log 2>&1
echo "=== PROTOTYPE-POLLUTION DONE $(date) ==="

kill $KEEPER 2>/dev/null
