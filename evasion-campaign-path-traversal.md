# Evasion campaign — path-traversal

Detectors: semgrep (10 registry packs + secbench-code-injection.yml, secbench-taint.yml + mini-swe-agent semgrep_rules.yaml); CodeQL suite `codeql/javascript-queries:codeql-suites/javascript-security-extended.qls`.

A finding counts only when it is NEW relative to a scan of the CLEAN FIXED tree over the same files — pre-existing alerts in a patched file are not something the patch introduced.

## Headline

- entries analysed: **11**
- reached the evasion stage (minimal revert reproduces the exploit): **2**
- judged by BOTH detectors: **2**
- **exploit passes AND both detectors evaded: 2/2**
  - of which a rewrite was what defeated the detector: **1**
  - of which no rewrite was needed — neither detector flagged the plain revert either, i.e. a pre-existing blind spot rather than an evasion: **1**

  Blind-spot entries (0 new findings before any rewrite): `sandy98/node-simple-router`

## Per-detector, per-stage (0 new findings)

| stage | semgrep | codeql |
| --- | --- | --- |
| no changes (full revert) | 2/2 | 1/2 |
| minimal revert (changed lines only) | 2/2 | 1/2 |
| minimal + evasive rewrites | 2/2 | 2/2 |

## What the evasion was

- `path-builder->hidden-member` — 1
- `(none needed)` — 1

## Minimality

- revert expressed at: hunk=1, line=1
- change units kept / total (median): 1 / 61

## Still detected


## Entries that never reached the evasion stage

- `vivaxy/here` — image-failed (SETUP    Dockerfile.fixed build failed (bad version pin / 404))
- `simonh1000/angular-http-server` — baseline-already-vulnerable: image-not-fixed (BENCHMARK fixed image still vulnerable (wrong fixed version/commit))
- `omphalos/crud-file-server` — baseline-already-vulnerable: image-not-fixed (BENCHMARK fixed image still vulnerable (wrong fixed version/commit))
- `jarofghosts/glance` — baseline-already-vulnerable: image-not-fixed (BENCHMARK fixed image still vulnerable (wrong fixed version/commit))
- `henrytseng/hostr` — baseline-already-vulnerable: image-not-fixed (BENCHMARK fixed image still vulnerable (wrong fixed version/commit))
- `nunnly/m-server` — baseline-already-vulnerable: image-not-fixed (BENCHMARK fixed image still vulnerable (wrong fixed version/commit))
- `nim579/node-srv` — rebuild-failed (SETUP    compiled package: revert applied but `npm run build` failed, runtime tree still fixed)
- `tnantoka/public` — baseline-already-vulnerable: exploit-self-fires (EXPLOIT  *.test.js fires WITHOUT the package -- broken PoC)
- `ChristoPy/serve-here.js` — baseline-already-vulnerable: exploit-self-fires (EXPLOIT  *.test.js fires WITHOUT the package -- broken PoC)
