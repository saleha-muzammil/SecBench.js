# Coverage gap analysis

Computed against the 603 benchmark dirs at the repo root, using
`run_stratified_full_loop.py`'s own predicates (`patch_evades_both`, `find_test_file`,
`Dockerfile.fixed`). "Run" = touched by any of the 8 full-loop runs, `stratified-rerun/`,
or `rejected-by-judge/`. 126 distinct benchmarks were run.

## Loop-level gap: 6 benchmarks have an evasive-patch seed but were never run

| category | benchmark | seed state | verdict |
| --- | --- | --- | --- |
| command-injection | bestzip_2.1.6 | evades both, test + Dockerfile.fixed present | **ready to run** |
| command-injection | diskusage-ng_0.2.6 | evades both, test + Dockerfile.fixed present | **ready to run** |
| redos | minimatch_3.0.0 | evades both, test + Dockerfile.fixed present | **ready to run** (stage `redos/utils.js`) |
| code-injection | serialize-to-js_0.5.0 | patch present, `evasion-findings.json` MISSING | re-run scanners first |
| prototype-pollution | algoliasearch-helper_3.6.0 | patch present, `evasion-findings.json` MISSING | re-run scanners first |
| redos | ducktype_1.2.0 | CodeQL still flags `js/redos` in ducktype.js:161 | needs `--allow-detected-seed` or a better patch |

Command for the three ready ones:

    python3 run_stratified_full_loop.py \
      --only bestzip_2.1.6 --only diskusage-ng_0.2.6 --only minimatch_3.0.0 \
      -c command-injection -c redos \
      -o stratified-samples-gap-fill

## Campaign-level gap: 407 of 603 benchmarks never entered the evasion campaign

| category | dirs | in a campaign CSV | exploit reproduces | evaded both | has patch | never in CSV |
| --- | --- | --- | --- | --- | --- | --- |
| code-injection | 40 | 13 | 9 | 5 | 10 | 27 |
| command-injection | 101 | 28 | 20 | 13 | 21 | 73 |
| path-traversal | 171 | 10 | 6 | 2 | 6 | **161** |
| prototype-pollution | 193 | 86 | 45 | 27 | 50 | 107 |
| redos | 98 | 59 | 33 | 9 | 34 | 39 |
| **TOTAL** | **603** | **196** | **113** | **56** | **121** | **407** |

The loop is not the bottleneck — 115 of the 121 benchmarks that have a seed were run.
The bottleneck is upstream: path-traversal in particular is almost entirely unexplored
(10 of 171 attempted, 2 evaded).

## Caveat on scanner verdicts

33 benchmarks that WERE run now read as "flagged by scanner" on disk. Their
`evasion-findings.json` files show as modified in git, so the current verdicts are
post-run state, not the eligibility state at run time. The patch-presence column above
is the reliable universe; do not re-derive eligibility from the working-tree findings.
