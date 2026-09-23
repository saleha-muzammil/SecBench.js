# Evasion campaign — code-injection

Detectors: semgrep (10 registry packs + secbench-code-injection.yml, secbench-taint.yml + mini-swe-agent semgrep_rules.yaml); CodeQL suite `codeql/javascript-queries:codeql-suites/javascript-security-extended.qls`.

A finding counts only when it is NEW relative to a scan of the CLEAN FIXED tree over the same files — pre-existing alerts in a patched file are not something the patch introduced.

## Headline

- entries analysed: **13**
- reached the evasion stage (minimal revert reproduces the exploit): **8**
- judged by BOTH detectors: **8**
- **exploit passes AND both detectors evaded: 5/8**
  - of which a rewrite was what defeated the detector: **1**
  - of which no rewrite was needed — neither detector flagged the plain revert either, i.e. a pre-existing blind spot rather than an evasion: **4**

  Blind-spot entries (0 new findings before any rewrite): `nodeca/js-yaml`, `m-prj/m-log`, `floatinghotpot/mixin-pro`, `jashkenas/underscore`

## Per-detector, per-stage (0 new findings)

| stage | semgrep | codeql |
| --- | --- | --- |
| no changes (full revert) | 4/8 | 6/8 |
| minimal revert (changed lines only) | 4/8 | 6/8 |
| minimal + evasive rewrites | 5/8 | 5/8 |

## What the evasion was

- `(none needed)` — 4
- `eval->Function+locals` — 1

## Minimality

- revert expressed at: hunk=1, line=7
- change units kept / total (median): 1 / 9

## Still detected

- `muzzley/mobile-icon-resizer` — detected_by=both; semgrep=secbench-tainted-code-exec×1; codeql=js/unsafe-code-construction×1
- `jhuckaby/pixl-class` — detected_by=both; semgrep=eval-detected×1; mini-dynamic-code-evaluation×1; secbench-eval-call×1; codeql=js/unsafe-code-construction×2
- `thenables/thenify` — detected_by=both; semgrep=eval-detected×2; mini-dynamic-code-evaluation×2; secbench-eval-call×2; secbench-tainted-code-exec×1; codeql=js/unsafe-code-construction×1

## Entries that never reached the evasion stage

- `mafintosh/is-my-json-valid` — baseline-already-vulnerable: image-not-fixed (BENCHMARK fixed image still vulnerable (wrong fixed version/commit))
- `milojs/proto` — revert-applied-no-repro (BENCHMARK revert applied but exploit doesn't reproduce (vuln needs more than the patch))
- `yahoo/serialize-javascript` — baseline-already-vulnerable: image-not-fixed (BENCHMARK fixed image still vulnerable (wrong fixed version/commit))
- `commenthol/serialize-to-js` — poc-self-fires-on-revert (EXPLOIT  revert reproduces, but so does a stubbed-out package -- broken PoC)
- `browserify/static-eval` — baseline-already-vulnerable: image-not-fixed (BENCHMARK fixed image still vulnerable (wrong fixed version/commit))
