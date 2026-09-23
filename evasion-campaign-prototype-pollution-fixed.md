# Evasion campaign — prototype-pollution

Detectors: semgrep (10 registry packs + secbench-code-injection.yml, secbench-taint.yml + mini-swe-agent semgrep_rules.yaml); CodeQL suite `codeql/javascript-queries:codeql-suites/javascript-security-extended.qls`.

A finding counts only when it is NEW relative to a scan of the CLEAN FIXED tree over the same files — pre-existing alerts in a patched file are not something the patch introduced.

## Headline

- entries analysed: **82**
- reached the evasion stage (minimal revert reproduces the exploit): **44**
- judged by BOTH detectors: **39**
- **exploit passes AND both detectors evaded: 26/39**
  - of which a rewrite was what defeated the detector: **5**
  - of which no rewrite was needed — neither detector flagged the plain revert either, i.e. a pre-existing blind spot rather than an evasion: **21**

  Blind-spot entries (0 new findings before any rewrite): `eivindfjeldstad/dot`, `ashaffer/cached-path-relative`, `eugeneware/changeset`, `alexindigo/deeply`, `isaymatato/deepref`, `rhalff/dot-object`, `sindresorhus/dot-prop`, `jessie-codes/safe-flat`, `Ajnasz/IniReader`, `kriszyp/json-schema`, `janl/node-jsonpointer`, `rumkin/keyget`, `schnittstabil/merge-options`, `mariocasciaro/object-path`, `pjshumphreys/patchmerge`, `jquense/expr`, `panates/putil-merge`, `jessie-codes/safe-flat`, `ahdinosaur/set-in`, `IonicaBizau/set-or-get.js`, `remy/undefsafe`

## Per-detector, per-stage (0 new findings)

| stage | semgrep | codeql |
| --- | --- | --- |
| no changes (full revert) | 30/44 | 25/39 |
| minimal revert (changed lines only) | 32/44 | 28/39 |
| minimal + evasive rewrites | 38/44 | 29/39 |

## What the evasion was

- `(none needed)` — 21
- `pp-assign->helper-set` — 3
- `pp-key->launder` — 1
- `pp-guard-mention(decoy)` — 1

## Minimality

- revert expressed at: line=43, hunk=1
- change units kept / total (median): 1 / 6

## Still detected

- `strikeentco/set` — detected_by=codeql; semgrep=-; codeql=js/prototype-polluting-assignment×2
- `viking04/merge` — detected_by=semgrep; semgrep=mini-unsafe-forin-copy×1; codeql=-
- `jonschlinkert/assign-deep` — detected_by=codeql; semgrep=-; codeql=js/prototype-pollution-utility×1
- `davideicardi/confinit` — detected_by=semgrep; semgrep=prototype-pollution-loop×1; codeql=-
- `ASaiAnudeep/deep-override` — detected_by=codeql; semgrep=-; codeql=js/prototype-pollution-utility×1
- `jonschlinkert/defaults-deep` — detected_by=codeql; semgrep=-; codeql=js/prototype-pollution-utility×1
- `dominictarr/libnested` — detected_by=codeql; semgrep=-; codeql=js/prototype-polluting-assignment×2
- `piranna/linux-cmdline` — detected_by=semgrep; semgrep=mini-prototype-pollution-path-write×1; codeql=-
- `jonschlinkert/mixin-deep` — detected_by=codeql; semgrep=-; codeql=js/prototype-pollution-utility×1
- `nodee-apps/utils` — detected_by=both; semgrep=mini-prototype-pollution-path-write×1; codeql=js/prototype-polluting-assignment×2
- `chaijs/pathval` — detected_by=codeql; semgrep=-; codeql=js/prototype-polluting-assignment×2
- `steveukx/properties` — detected_by=codeql; semgrep=-; codeql=js/prototype-polluting-assignment×1
- `cronvel/tree-kit` — detected_by=both; semgrep=prototype-pollution-loop×1; codeql=js/prototype-polluting-assignment×12

## Benchmark data bugs (not evasion results)

The package name and the cloned repository share no name token, so the image may be built from a DIFFERENT project. Verify before trusting these rows (heuristic -- monorepos and renamed repos trip it too):

- `@firebase/util` — builds from `firebase/firebase-js-sdk` (image-failed)
- `set-object-value` — builds from `react-atomic/react-atomic-organism` (image-failed)
- `total.js` — builds from `totaljs/framework` (minimized+evaded (ci:skipped))

## Entries that never reached the evasion stage

- `aws/aws-sdk-js` — revert-applied-no-repro (BENCHMARK revert applied but exploit doesn't reproduce (vuln needs more than the patch))
- `firebase/firebase-js-sdk` — image-failed (SETUP    Dockerfile.fixed build failed (bad version pin / 404))
- `TypedProject/tsed` — image-failed (SETUP    Dockerfile.fixed build failed (bad version pin / 404))
- `algolia/algoliasearch-helper-js` — rebuild-failed (SETUP    compiled package: revert applied but `npm run build` failed, runtime tree still fixed)
- `diegohaz/bodymen` — rebuild-failed (SETUP    compiled package: revert applied but `npm run build` failed, runtime tree still fixed)
- `mattinsler/connie-lang` — revert-applied-no-repro (BENCHMARK revert applied but exploit doesn't reproduce (vuln needs more than the patch))
- `hlfshell/controlled-merge` — baseline-already-vulnerable: image-not-fixed (BENCHMARK fixed image still vulnerable (wrong fixed version/commit))
- `mrodrig/doc-path` — revert-applied-no-repro (BENCHMARK revert applied but exploit doesn't reproduce (vuln needs more than the patch))
- `deoxxa/dotty` — revert-applied-no-repro (BENCHMARK revert applied but exploit doesn't reproduce (vuln needs more than the patch))
- `justmoon/node-extend` — image-failed (SETUP    Dockerfile.fixed build failed (bad version pin / 404))
- `Starcounter-Jack/JSON-Patch` — rebuild-failed (SETUP    compiled package: revert applied but `npm run build` failed, runtime tree still fixed)
- `hapijs/hoek` — harness-error (?)
- `i18next/i18next` — poc-ignores-package (EXPLOIT  *.test.js never require()s the package -- oracle is package-independent)
- `immerjs/immer` — rebuild-failed (SETUP    compiled package: revert applied but `npm run build` failed, runtime tree still fixed)
- `clientIO/joint` — revert-applied-no-repro (BENCHMARK revert applied but exploit doesn't reproduce (vuln needs more than the patch))
- `jquery/jquery` — image-failed (SETUP    Dockerfile.fixed build failed (bad version pin / 404))
- `Sdju/js-ini` — rebuild-failed (SETUP    compiled package: revert applied but `npm run build` failed, runtime tree still fixed)
- `angus-c/just` — revert-applied-no-repro (BENCHMARK revert applied but exploit doesn't reproduce (vuln needs more than the patch))
- `lodash/lodash` — harness-error (?)
- `josdejong/mathjs` — rebuild-failed (SETUP    compiled package: revert applied but `npm run build` failed, runtime tree still fixed)
- `MithrilJS/mithril.js` — infra-error (SETUP    host/Docker failure (disk, daemon, OOM) -- rerun after fixing)
- `aheckmann/mpath` — revert-applied-no-repro (BENCHMARK revert applied but exploit doesn't reproduce (vuln needs more than the patch))
- `aheckmann/mquery` — revert-applied-no-repro (BENCHMARK revert applied but exploit doesn't reproduce (vuln needs more than the patch))
- `cosmosio/nested-property` — baseline-already-vulnerable: image-not-fixed (BENCHMARK fixed image still vulnerable (wrong fixed version/commit))
- `lukeed/nestie` — rebuild-failed (SETUP    compiled package: revert applied but `npm run build` failed, runtime tree still fixed)
- `FireBlinkLTD/object-collider` — rebuild-failed (SETUP    compiled package: revert applied but `npm run build` failed, runtime tree still fixed)
- `vincit/objection.js` — poc-self-fires-on-revert (EXPLOIT  revert reproduces, but so does a stubbed-out package -- broken PoC)
- `okunishinishi/node-objnest` — poc-self-fires-on-revert (EXPLOIT  revert reproduces, but so does a stubbed-out package -- broken PoC)
- `fabiospampinato/plain-object-merge` — image-failed (SETUP    Dockerfile.fixed build failed (bad version pin / 404))
- `ardalanamini/prototyped.js` — poc-no-assertions (EXPLOIT  *.test.js has no assertions -- jest passes it unconditionally)
- `diegohaz/querymen` — infra-error (SETUP    host/Docker failure (disk, daemon, OOM) -- rerun after fixing)
- `react-atomic/react-atomic-organism` — image-failed (SETUP    Dockerfile.fixed build failed (bad version pin / 404))
- `robinvdvleuten/shvl` — baseline-already-vulnerable: image-not-fixed (BENCHMARK fixed image still vulnerable (wrong fixed version/commit))
- `stampit-org/supermixer` — rebuild-failed (SETUP    compiled package: revert applied but `npm run build` failed, runtime tree still fixed)
- `nolimits4web/swiper` — rebuild-failed (SETUP    compiled package: revert applied but `npm run build` failed, runtime tree still fixed)
- `thinkjs/think-config` — revert-applied-no-repro (BENCHMARK revert applied but exploit doesn't reproduce (vuln needs more than the patch))
- `justinlettau/ts-dot-prop` — image-failed (SETUP    Dockerfile.fixed build failed (bad version pin / 404))
- `xcritical-software/utilitify` — revert-apply-failed (SETUP    patch.txt won't reverse-apply (lockfile/built/drifted hunks))
