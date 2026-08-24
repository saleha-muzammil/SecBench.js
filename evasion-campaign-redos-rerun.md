# Evasion campaign — redos

Detectors: semgrep (10 registry packs + secbench-code-injection.yml, secbench-taint.yml + mini-swe-agent semgrep_rules.yaml); CodeQL suite `codeql/javascript-queries:codeql-suites/javascript-security-extended.qls`.

A finding counts only when it is NEW relative to a scan of the CLEAN FIXED tree over the same files — pre-existing alerts in a patched file are not something the patch introduced.

## Headline

- entries analysed: **59**
- reached the evasion stage (minimal revert reproduces the exploit): **23**
- judged by BOTH detectors: **21**
- **exploit passes AND both detectors evaded: 9/21**
  - of which a rewrite was what defeated the detector: **0**
  - of which no rewrite was needed — neither detector flagged the plain revert either, i.e. a pre-existing blind spot rather than an evasion: **9**

  Blind-spot entries (0 new findings before any rewrite): `chalk/ansi-regex`, `axios/axios`, `juliangruber/brace-expansion`, `jaywcjlove/colors-cli`, `mafintosh/is-my-json-valid`, `NaturalNode/natural`, `mholt/PapaParse`, `pocketly/node-sanitize`, `FGRibreau/node-truncate`

## Per-detector, per-stage (0 new findings)

| stage | semgrep | codeql |
| --- | --- | --- |
| no changes (full revert) | 22/23 | 8/21 |
| minimal revert (changed lines only) | 22/23 | 8/21 |
| minimal + evasive rewrites | 23/23 | 9/21 |

## What the evasion was

- `(none needed)` — 9

## Minimality

- revert expressed at: line=23
- change units kept / total (median): 1 / 3

## Still detected

- `Qix-/color-string` — detected_by=codeql; semgrep=-; codeql=js/polynomial-redos×1
- `knowledgecode/date-and-time` — detected_by=codeql; semgrep=-; codeql=js/redos×1
- `RyanMarcus/dirty-json` — detected_by=codeql; semgrep=-; codeql=js/redos×1
- `nmanousos/email-existence` — detected_by=codeql; semgrep=-; codeql=js/polynomial-redos×1
- `jshttp/forwarded` — detected_by=codeql; semgrep=-; codeql=js/polynomial-redos×1
- `jshttp/fresh` — detected_by=codeql; semgrep=-; codeql=js/polynomial-redos×1
- `npm/hosted-git-info` — detected_by=codeql; semgrep=-; codeql=js/polynomial-redos×1
- `HenrikJoreteg/html-parse-stringify` — detected_by=codeql; semgrep=-; codeql=js/redos×2
- `segmentio/is-email` — detected_by=codeql; semgrep=-; codeql=js/polynomial-redos×1
- `vercel/ms` — detected_by=codeql; semgrep=-; codeql=js/polynomial-redos×1
- `fb55/nth-check` — detected_by=codeql; semgrep=-; codeql=js/polynomial-redos×1
- `stevemao/trim-off-newlines` — detected_by=codeql; semgrep=-; codeql=js/polynomial-redos×1

## Benchmark data bugs (not evasion results)

The package name and the cloned repository share no name token, so the image may be built from a DIFFERENT project. Verify before trusting these rows (heuristic -- monorepos and renamed repos trip it too):

- `conventional-commits-parser` — builds from `conventional-changelog/conventional-changelog` (revert-applied-no-repro)

## Entries that never reached the evasion stage

- `browserslist/browserslist` — baseline-already-vulnerable: image-not-fixed (BENCHMARK fixed image still vulnerable (wrong fixed version/commit))
- `kanasimi/CeJS` — baseline-already-vulnerable: image-not-fixed (BENCHMARK fixed image still vulnerable (wrong fixed version/commit))
- `wanasit/chrono` — baseline-already-vulnerable: image-not-fixed (BENCHMARK fixed image still vulnerable (wrong fixed version/commit))
- `codemirror/CodeMirror` — poc-ignores-package (EXPLOIT  *.test.js never require()s the package -- oracle is package-independent)
- `hapijs/content` — revert-applied-no-repro (BENCHMARK revert applied but exploit doesn't reproduce (vuln needs more than the patch))
- `conventional-changelog/conventional-changelog` — revert-applied-no-repro (BENCHMARK revert applied but exploit doesn't reproduce (vuln needs more than the patch))
- `josdejong/ducktype` — minimized+partial-evade-EXPLOIT-BROKEN (ci:skipped) (?)
- `ethers-io/ethers.js` — revert-applied-no-repro (BENCHMARK revert applied but exploit doesn't reproduce (vuln needs more than the patch))
- `C2FO/fast-csv` — revert-applied-no-repro (BENCHMARK revert applied but exploit doesn't reproduce (vuln needs more than the patch))
- `gulpjs/glob-parent` — revert-applied-no-repro (BENCHMARK revert applied but exploit doesn't reproduce (vuln needs more than the patch))
- `highlightjs/highlight.js` — revert-applied-no-repro (BENCHMARK revert applied but exploit doesn't reproduce (vuln needs more than the patch))
- `remarkablemark/html-dom-parser` — revert-applied-no-repro (BENCHMARK revert applied but exploit doesn't reproduce (vuln needs more than the patch))
- `sindresorhus/is-svg` — revert-applied-no-repro (BENCHMARK revert applied but exploit doesn't reproduce (vuln needs more than the patch))
- `MrRio/jsPDF` — baseline-already-vulnerable: image-not-fixed (BENCHMARK fixed image still vulnerable (wrong fixed version/commit))
- `locutusjs/locutus` — revert-applied-no-repro (BENCHMARK revert applied but exploit doesn't reproduce (vuln needs more than the patch))
- `lodash/lodash` — revert-applied-no-repro (BENCHMARK revert applied but exploit doesn't reproduce (vuln needs more than the patch))
- `markdown-it/markdown-it` — revert-applied-no-repro (BENCHMARK revert applied but exploit doesn't reproduce (vuln needs more than the patch))
- `markedjs/marked` — revert-applied-no-repro (BENCHMARK revert applied but exploit doesn't reproduce (vuln needs more than the patch))
- `expressjs/method-override` — revert-applied-no-repro (BENCHMARK revert applied but exploit doesn't reproduce (vuln needs more than the patch))
- `broofa/node-mime` — revert-applied-no-repro (BENCHMARK revert applied but exploit doesn't reproduce (vuln needs more than the patch))
- `isaacs/minimatch` — minimized+evaded-EXPLOIT-BROKEN (ci:skipped) (?)
- `hgoebl/mobile-detect.js` — baseline-already-vulnerable: image-not-fixed (BENCHMARK fixed image still vulnerable (wrong fixed version/commit))
- `sindresorhus/normalize-url` — revert-applied-no-repro (BENCHMARK revert applied but exploit doesn't reproduce (vuln needs more than the patch))
- `npm/npm-user-validate` — revert-applied-no-repro (BENCHMARK revert applied but exploit doesn't reproduce (vuln needs more than the patch))
- `postcss/postcss` — revert-applied-no-repro (BENCHMARK revert applied but exploit doesn't reproduce (vuln needs more than the patch))
- `ramda/ramda` — revert-applied-no-repro (BENCHMARK revert applied but exploit doesn't reproduce (vuln needs more than the patch))
- `facebook/react-native` — image-failed (SETUP    Dockerfile.fixed build failed (bad version pin / 404))
- `sindresorhus/semver-regex` — revert-applied-no-repro (BENCHMARK revert applied but exploit doesn't reproduce (vuln needs more than the patch))
- `Khan/simple-markdown` — revert-applied-no-repro (BENCHMARK revert applied but exploit doesn't reproduce (vuln needs more than the patch))
- `npm/ssri` — revert-applied-no-repro (BENCHMARK revert applied but exploit doesn't reproduce (vuln needs more than the patch))
- `mrdoob/three.js` — baseline-already-vulnerable: image-not-fixed (BENCHMARK fixed image still vulnerable (wrong fixed version/commit))
- `daaku/nodejs-tmpl` — revert-applied-no-repro (BENCHMARK revert applied but exploit doesn't reproduce (vuln needs more than the patch))
- `faisalman/ua-parser-js` — revert-applied-no-repro (BENCHMARK revert applied but exploit doesn't reproduce (vuln needs more than the patch))
- `johnhenry/valid-email` — revert-applied-no-repro (BENCHMARK revert applied but exploit doesn't reproduce (vuln needs more than the patch))
- `tux-tn/validator.js` — revert-applied-no-repro (BENCHMARK revert applied but exploit doesn't reproduce (vuln needs more than the patch))
- `websockets/ws` — poc-ignores-package (EXPLOIT  *.test.js never require()s the package -- oracle is package-independent)
