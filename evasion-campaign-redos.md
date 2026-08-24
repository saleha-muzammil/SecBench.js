# Evasion campaign — redos

Detectors: semgrep (10 registry packs + secbench-code-injection.yml, secbench-taint.yml + mini-swe-agent semgrep_rules.yaml); CodeQL suite `codeql/javascript-queries:codeql-suites/javascript-security-extended.qls`.

A finding counts only when it is NEW relative to a scan of the CLEAN FIXED tree over the same files — pre-existing alerts in a patched file are not something the patch introduced.

## Headline

- entries analysed: **59**
- reached the evasion stage (minimal revert reproduces the exploit): **0**
- judged by BOTH detectors: **0**
- **exploit passes AND both detectors evaded: 0/0**
  - of which a rewrite was what defeated the detector: **0**
  - of which no rewrite was needed — neither detector flagged the plain revert either, i.e. a pre-existing blind spot rather than an evasion: **0**

## Per-detector, per-stage (0 new findings)

| stage | semgrep | codeql |
| --- | --- | --- |
| no changes (full revert) | 0/0 | 0/0 |
| minimal revert (changed lines only) | 0/0 | 0/0 |
| minimal + evasive rewrites | 0/0 | 0/0 |

## What the evasion was

- (no entry evaded both detectors)

## Minimality

- revert expressed at: 

## Still detected


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
- `HenrikJoreteg/html-parse-stringify` — rebuild-failed (SETUP    compiled package: revert applied but `npm run build` failed, runtime tree still fixed)
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
- `ajv_5.2.2` — not attempted: missing patch.txt
- `amqp-match_0.0.0` — not attempted: missing Dockerfile.fixed, patch.txt
- `ansi-html_0.0.7` — not attempted: missing Dockerfile.fixed, patch.txt
- `charset_1.0.0` — not attempted: missing patch.txt
- `checkit_0.7.0` — not attempted: missing Dockerfile.fixed, patch.txt
- `content-type-parser_1.0.1` — not attempted: missing Dockerfile.fixed
- `d3-color_2.0.0` — not attempted: missing Dockerfile.fixed
- `express-validators_1.0.3` — not attempted: missing Dockerfile.fixed, patch.txt
- `github-url-to-object_4.0.2` — not attempted: missing patch.txt
- `html-parse-stringify2_2.0.1` — not attempted: missing Dockerfile.fixed
- `htmlparser_1.7.7` — not attempted: missing Dockerfile.fixed, patch.txt
- `is-url_1.2.2` — not attempted: missing patch.txt
- `markdown-to-jsx_5.4.2` — not attempted: missing Dockerfile.fixed, patch.txt
- `markdown_0.3.0` — not attempted: missing Dockerfile.fixed, patch.txt
- `millisecond_0.1.1` — not attempted: missing patch.txt
- `moment_2.18.1` — not attempted: missing patch.txt
- `no-case_2.3.1` — not attempted: missing patch.txt
- `parsejson_0.0.3` — not attempted: missing Dockerfile.fixed, patch.txt
- `path-parse_1.0.6` — not attempted: missing patch.txt
- `platform_1.3.4` — not attempted: missing Dockerfile.fixed, patch.txt
- `printf_0.6.0` — not attempted: missing patch.txt
- `prompts_2.4.0` — not attempted: missing patch.txt
- `prototype_0.0.5` — not attempted: missing Dockerfile.fixed, patch.txt
- `remarkable_1.7.2` — not attempted: missing patch.txt
- `remove-markdown_0.3.0` — not attempted: missing Dockerfile.fixed, patch.txt
- `revalidator_0.3.1` — not attempted: missing Dockerfile.fixed, patch.txt
- `rgb2hex_0.1.0` — not attempted: missing patch.txt
- `slug_0.9.1` — not attempted: missing patch.txt
- `sshpk_1.13.1` — not attempted: missing patch.txt
- `string_3.3.3` — not attempted: missing Dockerfile.fixed, patch.txt
- `timespan_2.3.0` — not attempted: missing Dockerfile.fixed, patch.txt
- `tough-cookie_2.3.2` — not attempted: missing patch.txt
- `trim_0.0.1` — not attempted: missing patch.txt
- `underscore.string_3.3.4` — not attempted: missing patch.txt
- `uri-js_2.1.1` — not attempted: missing patch.txt
- `url-regex_5.0.0` — not attempted: missing Dockerfile.fixed, patch.txt
- `urlregex_0.5.0` — not attempted: missing Dockerfile.fixed, patch.txt
- `vant_2.12.11` — not attempted: missing patch.txt
