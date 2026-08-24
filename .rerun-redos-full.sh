#!/bin/sh
# FULL redos campaign rerun -- all 59 eligible entries, with CodeQL actually
# working this time.
#
# What changed since .evasion-redos-rerun.log (2026-08-20 13:50-16:50):
#   * ~/.codeql/packages/codeql/javascript-queries/2.4.3/ was an EMPTY directory
#     left by a failed `codeql pack download` (CLI 2.25.6 cannot parse the OCI
#     manifest that pack version publishes). CodeQL resolves to the highest
#     installed version, found it empty, and every scan in the previous run died
#     with "Query pack ... cannot be found" -> codeql_* = n/a on all 59 rows.
#     The empty dir is gone; 2.4.2 resolves and returns real findings.
#   * Dockerfile templates retry `npm install --legacy-peer-deps` on ERESOLVE
#     (locutus, postcss, react-native, validator).
#   * exploit_self_fires() stubs every .js/.cjs in the package rather than only
#     package.json's `main`, so deep-import PoCs (axios/lib/utils,
#     colors-cli/safe, natural/lib/.../dice_coefficient.js) are judged against a
#     stub that is actually on their resolution path.
#   * postcss / simple-markdown fixedVersion corrected against repositories.csv.
#
# --no-setup on purpose: Dockerfile.fixed / patch.txt for the hand-corrected
# entries (ms, object-path, lodash, @aws-sdk/shared-ini-file-loader) must not be
# regenerated out from under this run.
#
# --out-csv is seeded from the previous rerun table, so the 36 entries that are
# skipped for missing patch.txt/Dockerfile.fixed keep their rows instead of
# vanishing; every entry that actually runs overwrites its own row.
cd /Users/saleha/Desktop/cispa/SecBench.js || exit 1

# 8 GB machine, native CodeQL heap competes with the Docker VM -> keep the
# concurrency and RAM floor conservative and let entries cool between runs.
LOW="--no-setup --skip-repo-tests --force --prune --cooldown-sec 30 --max-compose 2 --min-ram-gb 1"

sh .disk-keeper.sh &
KEEPER=$!

echo "=== REDOS FULL RERUN START $(date) ==="
nice -n 5 python3 -u run_evasion_campaign.py -c redos $LOW \
    --out-csv evasion-campaign-redos-rerun.csv
echo "=== REDOS FULL RERUN DONE $(date) ==="

kill $KEEPER 2>/dev/null
