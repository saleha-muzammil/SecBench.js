# stratified-samples-merged

Single merged view of the 8 `stratified-samples-full-loop*` run folders, re-organized
by vulnerability category. Nothing was deleted or altered — every project directory is a
verified byte-identical copy of its source (APFS clone, so little extra disk is used).

**Deduplicated**: exactly one directory per (category, benchmark) — 115 unique. Where a
benchmark was run more than once, the best outcome is kept (SOLVED > SOLVED_SAFE >
not-solved > failed; ties broken by longer pipeline time, then later finish). The 25
superseded runs are kept under `_duplicates/`.

## Layout

    <category>/<benchmark>/                        # the kept run, named for the benchmark
    _duplicates/<category>/<benchmark>/<run-dir>__<srccat>-<tag>/   # superseded runs
    _sources/<tag>/                                # per-run selection.json / summary.csv
    MANIFEST.csv                                   # every dir -> unique|duplicate, origin, outcome
    OUTCOMES.csv                                   # one row per unique benchmark + its verdict
    COVERAGE-GAP.md                                # what could have been run but was not

The former `rejections/` bucket is gone: those runs were judge-rejected attempts at
benchmarks that belong to a real category, so they were folded into their category and
ranked with everything else.

Four package names exist at root under two different categories and are NOT the same
benchmark — `hot-formula-parser_3.0.0` and `open_0.0.5` and `local-devices_2.0.0`
(code-injection + command-injection), `total.js_3.4.6` (command-injection +
prototype-pollution). Dedup keys on the run's own recorded category, so these stay
separate.

## Source tags

| tag | source folder |
| --- | --- |
| base | stratified-samples-full-loop |
| judge6 | stratified-samples-full-loop-judge6 |
| judge7 | stratified-samples-full-loop-judge7 |
| judge8 | stratified-samples-full-loop-judge8 |
| judge9 | stratified-samples-full-loop-judge9 |
| judge10 | stratified-samples-full-loop-judge10 |
| judge13 | stratified-samples-full-loop-judge13 |
| judge14 | stratified-samples-full-loop-judge14 |

## Duplicates

21 benchmarks were run more than once (25 superseded runs total). The kept run sits at
`<category>/<benchmark>/`; the others are under `_duplicates/<category>/<benchmark>/`,
each named `<original-run-dir>__<source-category>-<tag>` so its provenance is readable.
Nothing was deleted. `MANIFEST.csv` maps every directory, kept or superseded, back to its
original path in the source run folder.

16 of the 21 groups were genuine upgrades — a better outcome replaced a worse one,
including 8 where a `failed` run was replaced by one that completed.

## Not included

`stratified-rerun/` (different layout: `<category>--<project>/<category>/<project>/`) and
`rejected-by-judge/stratified-samples-full-loop/` were left untouched — they are separate
trees, not part of the 8 full-loop run folders.
