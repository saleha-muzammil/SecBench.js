# Evasion campaign — redos

Detectors: semgrep (10 registry packs + secbench-code-injection.yml, secbench-taint.yml + mini-swe-agent semgrep_rules.yaml); CodeQL suite `codeql/javascript-queries:codeql-suites/javascript-security-extended.qls`.

A finding counts only when it is NEW relative to a scan of the CLEAN FIXED tree over the same files — pre-existing alerts in a patched file are not something the patch introduced.

## Headline

- entries analysed: **59**
- reached the evasion stage (minimal revert reproduces the exploit): **1**
- judged by BOTH detectors: **1**
- **exploit passes AND both detectors evaded: 0/1**
  - of which a rewrite was what defeated the detector: **0**
  - of which no rewrite was needed — neither detector flagged the plain revert either, i.e. a pre-existing blind spot rather than an evasion: **0**

## Per-detector, per-stage (0 new findings)

| stage | semgrep | codeql |
| --- | --- | --- |
| no changes (full revert) | 1/1 | 0/1 |
| minimal revert (changed lines only) | 1/1 | 0/1 |
| minimal + evasive rewrites | 1/1 | 0/1 |

## What the evasion was

- (no entry evaded both detectors)

## Minimality

- revert expressed at: line=1
- change units kept / total (median): 2 / 3

## Still detected

- `HenrikJoreteg/html-parse-stringify` — detected_by=codeql; semgrep=-; codeql=js/redos×2

## Benchmark data bugs (not evasion results)

The package name and the cloned repository share no name token, so the image may be built from a DIFFERENT project. Verify before trusting these rows (heuristic -- monorepos and renamed repos trip it too):

- `conventional-commits-parser` — builds from `conventional-changelog/conventional-changelog` (poc-no-assertions)

## Entries that never reached the evasion stage

- `chalk/ansi-regex` — poc-no-assertions (EXPLOIT  *.test.js has no assertions -- jest passes it unconditionally)
- `axios/axios` — revert-applied-no-repro (BENCHMARK revert applied but exploit doesn't reproduce (vuln needs more than the patch))
- `juliangruber/brace-expansion` — revert-applied-no-repro (BENCHMARK revert applied but exploit doesn't reproduce (vuln needs more than the patch))
- `browserslist/browserslist` — revert-applied-no-repro (BENCHMARK revert applied but exploit doesn't reproduce (vuln needs more than the patch))
- `kanasimi/CeJS` — revert-apply-failed (SETUP    patch.txt won't reverse-apply (lockfile/built/drifted hunks))
- `wanasit/chrono` — rebuild-failed (SETUP    compiled package: revert applied but `npm run build` failed, runtime tree still fixed)
- `jakubpawlowicz/clean-css` — revert-applied-no-repro (BENCHMARK revert applied but exploit doesn't reproduce (vuln needs more than the patch))
- `codemirror/CodeMirror` — poc-no-assertions (EXPLOIT  *.test.js has no assertions -- jest passes it unconditionally)
- `Qix-/color-string` — poc-no-assertions (EXPLOIT  *.test.js has no assertions -- jest passes it unconditionally)
- `jaywcjlove/colors-cli` — poc-no-assertions (EXPLOIT  *.test.js has no assertions -- jest passes it unconditionally)
- `hapijs/content` — revert-applied-no-repro (BENCHMARK revert applied but exploit doesn't reproduce (vuln needs more than the patch))
- `conventional-changelog/conventional-changelog` — poc-no-assertions (EXPLOIT  *.test.js has no assertions -- jest passes it unconditionally)
- `knowledgecode/date-and-time` — revert-applied-no-repro (BENCHMARK revert applied but exploit doesn't reproduce (vuln needs more than the patch))
- `RyanMarcus/dirty-json` — revert-applied-no-repro (BENCHMARK revert applied but exploit doesn't reproduce (vuln needs more than the patch))
- `josdejong/ducktype` — poc-no-assertions (EXPLOIT  *.test.js has no assertions -- jest passes it unconditionally)
- `nmanousos/email-existence` — revert-applied-no-repro (BENCHMARK revert applied but exploit doesn't reproduce (vuln needs more than the patch))
- `ethers-io/ethers.js` — revert-applied-no-repro (BENCHMARK revert applied but exploit doesn't reproduce (vuln needs more than the patch))
- `C2FO/fast-csv` — revert-applied-no-repro (BENCHMARK revert applied but exploit doesn't reproduce (vuln needs more than the patch))
- `jshttp/forwarded` — poc-no-assertions (EXPLOIT  *.test.js has no assertions -- jest passes it unconditionally)
- `jshttp/fresh` — poc-no-assertions (EXPLOIT  *.test.js has no assertions -- jest passes it unconditionally)
- `gulpjs/glob-parent` — poc-no-assertions (EXPLOIT  *.test.js has no assertions -- jest passes it unconditionally)
- `highlightjs/highlight.js` — rebuild-failed (SETUP    compiled package: revert applied but `npm run build` failed, runtime tree still fixed)
- `npm/hosted-git-info` — revert-applied-no-repro (BENCHMARK revert applied but exploit doesn't reproduce (vuln needs more than the patch))
- `remarkablemark/html-dom-parser` — poc-no-assertions (EXPLOIT  *.test.js has no assertions -- jest passes it unconditionally)
- `segmentio/is-email` — poc-no-assertions (EXPLOIT  *.test.js has no assertions -- jest passes it unconditionally)
- `mafintosh/is-my-json-valid` — revert-applied-no-repro (BENCHMARK revert applied but exploit doesn't reproduce (vuln needs more than the patch))
- `sindresorhus/is-svg` — poc-no-assertions (EXPLOIT  *.test.js has no assertions -- jest passes it unconditionally)
- `MrRio/jsPDF` — rebuild-failed (SETUP    compiled package: revert applied but `npm run build` failed, runtime tree still fixed)
- `locutusjs/locutus` — image-failed (SETUP    Dockerfile.fixed build failed (bad version pin / 404))
- `lodash/lodash` — revert-applied-no-repro (BENCHMARK revert applied but exploit doesn't reproduce (vuln needs more than the patch))
- `markdown-it/markdown-it` — revert-applied-no-repro (BENCHMARK revert applied but exploit doesn't reproduce (vuln needs more than the patch))
- `markedjs/marked` — rebuild-failed (SETUP    compiled package: revert applied but `npm run build` failed, runtime tree still fixed)
- `expressjs/method-override` — revert-applied-no-repro (BENCHMARK revert applied but exploit doesn't reproduce (vuln needs more than the patch))
- `broofa/node-mime` — poc-no-assertions (EXPLOIT  *.test.js has no assertions -- jest passes it unconditionally)
- `isaacs/minimatch` — poc-no-assertions (EXPLOIT  *.test.js has no assertions -- jest passes it unconditionally)
- `hgoebl/mobile-detect.js` — revert-applied-no-repro (BENCHMARK revert applied but exploit doesn't reproduce (vuln needs more than the patch))
- `caolan/forms` — poc-no-assertions (EXPLOIT  *.test.js has no assertions -- jest passes it unconditionally)
- `NaturalNode/natural` — poc-no-assertions (EXPLOIT  *.test.js has no assertions -- jest passes it unconditionally)
- `sindresorhus/normalize-url` — revert-applied-no-repro (BENCHMARK revert applied but exploit doesn't reproduce (vuln needs more than the patch))
- `npm/npm-user-validate` — poc-no-assertions (EXPLOIT  *.test.js has no assertions -- jest passes it unconditionally)
- `fb55/nth-check` — poc-no-assertions (EXPLOIT  *.test.js has no assertions -- jest passes it unconditionally)
- `mholt/PapaParse` — revert-applied-no-repro (BENCHMARK revert applied but exploit doesn't reproduce (vuln needs more than the patch))
- `postcss/postcss` — image-failed (SETUP    Dockerfile.fixed build failed (bad version pin / 404))
- `ramda/ramda` — rebuild-failed (SETUP    compiled package: revert applied but `npm run build` failed, runtime tree still fixed)
- `facebook/react-native` — image-failed (SETUP    Dockerfile.fixed build failed (bad version pin / 404))
- `pocketly/node-sanitize` — revert-applied-no-repro (BENCHMARK revert applied but exploit doesn't reproduce (vuln needs more than the patch))
- `sindresorhus/semver-regex` — revert-applied-no-repro (BENCHMARK revert applied but exploit doesn't reproduce (vuln needs more than the patch))
- `Khan/simple-markdown` — revert-applied-no-repro (BENCHMARK revert applied but exploit doesn't reproduce (vuln needs more than the patch))
- `npm/ssri` — revert-applied-no-repro (BENCHMARK revert applied but exploit doesn't reproduce (vuln needs more than the patch))
- `cronvel/terminal-kit` — poc-no-assertions (EXPLOIT  *.test.js has no assertions -- jest passes it unconditionally)
- `mrdoob/three.js` — infra-error (SETUP    host/Docker failure (disk, daemon, OOM) -- rerun after fixing)
- `daaku/nodejs-tmpl` — poc-no-assertions (EXPLOIT  *.test.js has no assertions -- jest passes it unconditionally)
- `stevemao/trim-off-newlines` — poc-no-assertions (EXPLOIT  *.test.js has no assertions -- jest passes it unconditionally)
- `FGRibreau/node-truncate` — revert-applied-no-repro (BENCHMARK revert applied but exploit doesn't reproduce (vuln needs more than the patch))
- `faisalman/ua-parser-js` — rebuild-failed (SETUP    compiled package: revert applied but `npm run build` failed, runtime tree still fixed)
- `johnhenry/valid-email` — revert-applied-no-repro (BENCHMARK revert applied but exploit doesn't reproduce (vuln needs more than the patch))
- `tux-tn/validator.js` — image-failed (SETUP    Dockerfile.fixed build failed (bad version pin / 404))
- `websockets/ws` — poc-no-assertions (EXPLOIT  *.test.js has no assertions -- jest passes it unconditionally)
