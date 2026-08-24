# Evasion campaign — prototype-pollution

Detectors: semgrep (10 registry packs + secbench-code-injection.yml, secbench-taint.yml + mini-swe-agent semgrep_rules.yaml); CodeQL suite `codeql/javascript-queries:codeql-suites/javascript-security-extended.qls`.

A finding counts only when it is NEW relative to a scan of the CLEAN FIXED tree over the same files — pre-existing alerts in a patched file are not something the patch introduced.

## Headline

- entries analysed: **82**
- reached the evasion stage (minimal revert reproduces the exploit): **41**
- judged by BOTH detectors: **40**
- **exploit passes AND both detectors evaded: 27/40**
  - of which a rewrite was what defeated the detector: **6**
  - of which no rewrite was needed — neither detector flagged the plain revert either, i.e. a pre-existing blind spot rather than an evasion: **21**

  Blind-spot entries (0 new findings before any rewrite): `eivindfjeldstad/dot`, `ashaffer/cached-path-relative`, `eugeneware/changeset`, `alexindigo/deeply`, `isaymatato/deepref`, `rhalff/dot-object`, `sindresorhus/dot-prop`, `jessie-codes/safe-flat`, `Ajnasz/IniReader`, `kriszyp/json-schema`, `janl/node-jsonpointer`, `rumkin/keyget`, `schnittstabil/merge-options`, `mariocasciaro/object-path`, `pjshumphreys/patchmerge`, `jquense/expr`, `panates/putil-merge`, `jessie-codes/safe-flat`, `ahdinosaur/set-in`, `IonicaBizau/set-or-get.js`, `remy/undefsafe`

## Per-detector, per-stage (0 new findings)

| stage | semgrep | codeql |
| --- | --- | --- |
| no changes (full revert) | 29/41 | 25/40 |
| minimal revert (changed lines only) | 31/41 | 28/40 |
| minimal + evasive rewrites | 36/41 | 30/40 |

## What the evasion was

- `(none needed)` — 21
- `pp-assign->helper-set` — 4
- `pp-key->launder` — 1
- `pp-guard-mention(decoy)` — 1

## Minimality

- revert expressed at: line=40, hunk=1
- change units kept / total (median): 1 / 5

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
- `unclechu/node-deep-extend` — revert-applied-no-repro (BENCHMARK revert applied but exploit doesn't reproduce (vuln needs more than the patch))
- `mrodrig/doc-path` — revert-applied-no-repro (BENCHMARK revert applied but exploit doesn't reproduce (vuln needs more than the patch))
- `deoxxa/dotty` — revert-applied-no-repro (BENCHMARK revert applied but exploit doesn't reproduce (vuln needs more than the patch))
- `justmoon/node-extend` — image-failed (SETUP    Dockerfile.fixed build failed (bad version pin / 404))
- `Starcounter-Jack/JSON-Patch` — rebuild-failed (SETUP    compiled package: revert applied but `npm run build` failed, runtime tree still fixed)
- `i18next/i18next` — poc-ignores-package (EXPLOIT  *.test.js never require()s the package -- oracle is package-independent)
- `immerjs/immer` — rebuild-failed (SETUP    compiled package: revert applied but `npm run build` failed, runtime tree still fixed)
- `clientIO/joint` — revert-applied-no-repro (BENCHMARK revert applied but exploit doesn't reproduce (vuln needs more than the patch))
- `jquery/jquery` — image-failed (SETUP    Dockerfile.fixed build failed (bad version pin / 404))
- `Sdju/js-ini` — rebuild-failed (SETUP    compiled package: revert applied but `npm run build` failed, runtime tree still fixed)
- `angus-c/just` — revert-applied-no-repro (BENCHMARK revert applied but exploit doesn't reproduce (vuln needs more than the patch))
- `lodash/lodash` — baseline-already-vulnerable: image-not-fixed (BENCHMARK fixed image still vulnerable (wrong fixed version/commit))
- `josdejong/mathjs` — rebuild-failed (SETUP    compiled package: revert applied but `npm run build` failed, runtime tree still fixed)
- `jonschlinkert/merge-deep` — revert-applied-no-repro (BENCHMARK revert applied but exploit doesn't reproduce (vuln needs more than the patch))
- `MithrilJS/mithril.js` — infra-error (SETUP    host/Docker failure (disk, daemon, OOM) -- rerun after fixing)
- `aheckmann/mpath` — revert-applied-no-repro (BENCHMARK revert applied but exploit doesn't reproduce (vuln needs more than the patch))
- `aheckmann/mquery` — revert-applied-no-repro (BENCHMARK revert applied but exploit doesn't reproduce (vuln needs more than the patch))
- `cosmosio/nested-property` — baseline-already-vulnerable: image-not-fixed (BENCHMARK fixed image still vulnerable (wrong fixed version/commit))
- `lukeed/nestie` — rebuild-failed (SETUP    compiled package: revert applied but `npm run build` failed, runtime tree still fixed)
- `digitalbazaar/forge` — revert-applied-no-repro (BENCHMARK revert applied but exploit doesn't reproduce (vuln needs more than the patch))
- `FireBlinkLTD/object-collider` — rebuild-failed (SETUP    compiled package: revert applied but `npm run build` failed, runtime tree still fixed)
- `vincit/objection.js` — poc-self-fires-on-revert (EXPLOIT  revert reproduces, but so does a stubbed-out package -- broken PoC)
- `okunishinishi/node-objnest` — poc-self-fires-on-revert (EXPLOIT  revert reproduces, but so does a stubbed-out package -- broken PoC)
- `fabiospampinato/plain-object-merge` — image-failed (SETUP    Dockerfile.fixed build failed (bad version pin / 404))
- `ardalanamini/prototyped.js` — poc-no-assertions (EXPLOIT  *.test.js has no assertions -- jest passes it unconditionally)
- `diegohaz/querymen` — infra-error (SETUP    host/Docker failure (disk, daemon, OOM) -- rerun after fixing)
- `react-atomic/react-atomic-organism` — image-failed (SETUP    Dockerfile.fixed build failed (bad version pin / 404))
- `jonschlinkert/set-value` — revert-applied-no-repro (BENCHMARK revert applied but exploit doesn't reproduce (vuln needs more than the patch))
- `robinvdvleuten/shvl` — baseline-already-vulnerable: image-not-fixed (BENCHMARK fixed image still vulnerable (wrong fixed version/commit))
- `stampit-org/supermixer` — rebuild-failed (SETUP    compiled package: revert applied but `npm run build` failed, runtime tree still fixed)
- `nolimits4web/swiper` — rebuild-failed (SETUP    compiled package: revert applied but `npm run build` failed, runtime tree still fixed)
- `thinkjs/think-config` — revert-applied-no-repro (BENCHMARK revert applied but exploit doesn't reproduce (vuln needs more than the patch))
- `justinlettau/ts-dot-prop` — image-failed (SETUP    Dockerfile.fixed build failed (bad version pin / 404))
- `xcritical-software/utilitify` — revert-apply-failed (SETUP    patch.txt won't reverse-apply (lockfile/built/drifted hunks))
- `101_1.0.0` — not attempted: missing Dockerfile.fixed, patch.txt
- `Proto_1.1.4` — not attempted: missing Dockerfile.fixed, patch.txt
- `Templ8_0.7.0` — not attempted: missing Dockerfile.fixed, patch.txt
- `arr-flatten-unflatten_1.1.4` — not attempted: missing Dockerfile.fixed, patch.txt
- `asciitable.js_1.0.2` — not attempted: missing patch.txt
- `aurelia-path_1.1.7` — not attempted: missing patch.txt
- `bmoor_0.8.11` — not attempted: missing patch.txt
- `brikcss-merge_1.3.0` — not attempted: missing Dockerfile.fixed, patch.txt
- `class-transformer_0.1.1` — not attempted: missing patch.txt
- `component-flatten_1.0.1` — not attempted: missing Dockerfile.fixed, patch.txt
- `confucious_0.0.12` — not attempted: missing Dockerfile.fixed, patch.txt
- `convict_6.0.0` — not attempted: missing patch.txt
- `cookiex-deep_0.0.6` — not attempted: missing Dockerfile.fixed, patch.txt
- `copy-props_2.0.4` — not attempted: missing patch.txt
- `deap_1.0.0` — not attempted: missing patch.txt
- `decal_2.0.0` — not attempted: missing Dockerfile.fixed, patch.txt
- `decal_2.1.3` — not attempted: missing Dockerfile.fixed, patch.txt
- `deep-defaults_1.0.5` — not attempted: missing Dockerfile.fixed, patch.txt
- `deep-get-set_1.1.0` — not attempted: missing Dockerfile.fixed, patch.txt
- `deep-set_1.0.0` — not attempted: missing Dockerfile.fixed, patch.txt
- `deepmergefn_1.1.0` — not attempted: missing Dockerfile.fixed, patch.txt
- `deeps_1.4.5` — not attempted: missing Dockerfile.fixed, patch.txt
- `defaults-deep_0.2.4` — not attempted: missing Dockerfile.fixed, patch.txt
- `dot-notes_3.2.0` — not attempted: missing Dockerfile.fixed, patch.txt
- `dset_1.0.0` — not attempted: missing patch.txt
- `eivindfjeldstad-dot_0.0.1` — not attempted: missing Dockerfile.fixed
- `expand-hash_1.0.1` — not attempted: missing Dockerfile.fixed, patch.txt
- `fabiocaccamo-utils.js_0.17.0` — not attempted: missing Dockerfile.fixed
- `field_1.0.1` — not attempted: missing Dockerfile.fixed, patch.txt
- `firebase-util_0.3.2` — not attempted: missing patch.txt
- `flat-wrap_1.0.2` — not attempted: missing Dockerfile.fixed, patch.txt
- `flattenizer_0.0.5` — not attempted: missing patch.txt
- `fluentui-styles_0.47.15` — not attempted: missing patch.txt
- `gammautils_0.0.81` — not attempted: missing Dockerfile.fixed, patch.txt
- `gedi_1.6.3` — not attempted: missing Dockerfile.fixed, patch.txt
- `getobject_0.1.0` — not attempted: missing patch.txt
- `getsetdeep_4.15.0` — not attempted: missing Dockerfile.fixed, patch.txt
- `grunt-util-property_0.0.2` — not attempted: missing Dockerfile.fixed, patch.txt
- `ianwalter-merge_9.0.1` — not attempted: missing Dockerfile.fixed, patch.txt
- `ini-parser_0.0.2` — not attempted: missing Dockerfile.fixed, patch.txt
- `ini_1.3.5` — not attempted: missing Dockerfile.fixed, patch.txt
- `iniparserjs_1.0.4` — not attempted: missing Dockerfile.fixed, patch.txt
- `ion-parser_0.5.2` — not attempted: missing Dockerfile.fixed, patch.txt
- `js-data_3.0.9` — not attempted: missing Dockerfile.fixed, patch.txt
- `js-extend_0.0.1` — not attempted: missing Dockerfile.fixed, patch.txt
- `json-pointer_0.6.0` — not attempted: missing Dockerfile.fixed, patch.txt
- `json-pointer_0.6.1` — not attempted: missing Dockerfile.fixed, patch.txt
- `json-ptr_1.1.0` — not attempted: missing patch.txt
- `json8-merge-patch_1.0.1` — not attempted: missing patch.txt
- `just-extend_3.0.0` — not attempted: missing Dockerfile.fixed, patch.txt
- `keyd_1.3.4` — not attempted: missing patch.txt
- `locutus_2.0.11` — not attempted: missing patch.txt
- `lodash_4.17.11` — not attempted: missing patch.txt
- `lutils-merge_0.2.6` — not attempted: missing Dockerfile.fixed, patch.txt
- `lutils_2.4.0` — not attempted: missing Dockerfile.fixed, patch.txt
- `lyngs-digger_1.0.7` — not attempted: missing Dockerfile.fixed, patch.txt
- `lyngs-merge_1.0.9` — not attempted: missing Dockerfile.fixed, patch.txt
- `madlib-object-utils_0.1.6` — not attempted: missing patch.txt
- `merge-change_1.0.1` — not attempted: missing Dockerfile.fixed, patch.txt
- `merge-deep2_3.0.5` — not attempted: missing Dockerfile.fixed, patch.txt
- `merge-objects_1.0.3` — not attempted: missing Dockerfile.fixed, patch.txt
- `merge-recursive_0.0.3` — not attempted: missing Dockerfile.fixed, patch.txt
- `merge_2.1.0` — not attempted: missing Dockerfile.fixed, patch.txt
- `mergify_1.0.2` — not attempted: missing Dockerfile.fixed, patch.txt
- `minimist_1.0.0` — not attempted: missing patch.txt
- `mootools_1.5.2` — not attempted: missing Dockerfile.fixed, patch.txt
- `mout_1.0.0` — not attempted: missing patch.txt
- `multi-ini_2.1.0` — not attempted: missing patch.txt
- `nconf-toml_0.0.1` — not attempted: missing Dockerfile.fixed, patch.txt
- `nedb_1.8.0` — not attempted: missing Dockerfile.fixed, patch.txt
- `nested-object-assign_1.0.3` — not attempted: missing patch.txt
- `nis-utils_0.6.10` — not attempted: missing Dockerfile.fixed, patch.txt
- `node-dig_1.0.1` — not attempted: missing Dockerfile.fixed, patch.txt
- `node-extend_1.0.0` — not attempted: missing patch.txt
- `node-ini_1.0.0` — not attempted: missing Dockerfile.fixed, patch.txt
- `node-oojs_1.4.0` — not attempted: missing Dockerfile.fixed, patch.txt
- `objtools_3.0.0` — not attempted: missing Dockerfile.fixed, patch.txt
- `objutil_2.17.3` — not attempted: missing Dockerfile.fixed, patch.txt
- `paypal-adaptive_0.4.1` — not attempted: missing Dockerfile.fixed, patch.txt
- `phpjs_1.3.2` — not attempted: missing Dockerfile.fixed, patch.txt
- `predefine_0.1.2` — not attempted: missing Dockerfile.fixed, patch.txt
- `promisehelpers_0.0.5` — not attempted: missing Dockerfile.fixed, patch.txt
- `rdf-graph-array_0.3.0` — not attempted: missing Dockerfile.fixed, patch.txt
- `record-like-deep-assign_1.0.1` — not attempted: missing Dockerfile.fixed, patch.txt
- `rfc6902_4.0.2` — not attempted: missing patch.txt
- `safe-obj_1.0.0` — not attempted: missing Dockerfile.fixed, patch.txt
- `safe-object2_1.0.3` — not attempted: missing Dockerfile.fixed, patch.txt
- `safetydance_2.0.1` — not attempted: missing Dockerfile.fixed, patch.txt
- `sahmat_1.0.0` — not attempted: missing Dockerfile.fixed, patch.txt
- `set-deep-prop_1.0.0` — not attempted: missing Dockerfile.fixed, patch.txt
- `simpl-schema_1.10.0` — not attempted: missing patch.txt
- `smart-extend_1.7.3` — not attempted: missing Dockerfile.fixed, patch.txt
- `style-dictionary_2.10.2` — not attempted: missing patch.txt
- `think-helper_1.1.0` — not attempted: missing patch.txt
- `tiny-conf_1.1.0` — not attempted: missing Dockerfile.fixed, patch.txt
- `typeorm_0.2.24` — not attempted: missing patch.txt
- `uifabric-utilities_7.20.2` — not attempted: missing patch.txt
- `upmerge_0.1.7` — not attempted: missing patch.txt
- `utils-extend_1.0.8` — not attempted: missing Dockerfile.fixed, patch.txt
- `vega-util_1.13.0` — not attempted: missing patch.txt
- `worksmith_1.0.0` — not attempted: missing Dockerfile.fixed, patch.txt
- `x-assign_0.1.4` — not attempted: missing Dockerfile.fixed, patch.txt
- `y18n_3.2.1` — not attempted: missing patch.txt
- `yargs-parser_6.0.0` — not attempted: missing patch.txt
