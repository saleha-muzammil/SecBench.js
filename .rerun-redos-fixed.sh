#!/bin/sh
# Rerun ONLY the redos entries whose verdict can actually change after the
# 2026-08-20 fixes:
#   * Dockerfile templates retry `npm install --legacy-peer-deps` on ERESOLVE
#     -> locutus, postcss, react-native, validator stop failing to build
#   * exploit_self_fires() stubs every .js in the package, not just `main`
#     -> axios, colors-cli, natural stop being mislabelled self-firing
#   * postcss/simple-markdown fixedVersion corrected against repositories.csv
#   * the empty ~/.codeql/packages/codeql/javascript-queries/2.4.3 directory
#     (a failed `codeql pack download`) was shadowing the working 2.4.2 pack,
#     so EVERY codeql scan in the previous run died with "pack cannot be
#     found" -> removed; codeql now produces real numbers.
# --out-csv seeds from the existing rerun CSV and merges by package, so only
# these rows are overwritten.
cd /Users/saleha/Desktop/cispa/SecBench.js || exit 1

ONLY="--only locutus_2.0.10 --only postcss_8.0.0 --only react-native_0.63.0-rc.0 \
--only validator_13.5.2 --only axios_0.21.0 --only colors-cli_1.0.25 \
--only natural_5.1.0 --only simple-markdown_0.7.2"

LOW="--no-setup --skip-repo-tests --force --prune --cooldown-sec 30 --max-compose 2 --min-ram-gb 1"

sh .disk-keeper.sh &
KEEPER=$!
echo "=== REDOS FIXED-SUBSET START $(date) ==="
nice -n 5 python3 -u run_evasion_campaign.py -c redos $ONLY $LOW \
    --out-csv evasion-campaign-redos-rerun.csv
echo "=== REDOS FIXED-SUBSET DONE $(date) ==="
kill $KEEPER 2>/dev/null
