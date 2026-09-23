# Evasion campaign — command-injection

Detectors: semgrep (10 registry packs + secbench-code-injection.yml, secbench-taint.yml + mini-swe-agent semgrep_rules.yaml); CodeQL suite `codeql/javascript-queries:codeql-suites/javascript-security-extended.qls`.

A finding counts only when it is NEW relative to a scan of the CLEAN FIXED tree over the same files — pre-existing alerts in a patched file are not something the patch introduced.

## Headline

- entries analysed: **28**
- reached the evasion stage (minimal revert reproduces the exploit): **19**
- judged by BOTH detectors: **14**
- **exploit passes AND both detectors evaded: 10/14**
  - of which a rewrite was what defeated the detector: **7**
  - of which no rewrite was needed — neither detector flagged the plain revert either, i.e. a pre-existing blind spot rather than an evasion: **3**

  Blind-spot entries (0 new findings before any rewrite): `kylefarris/clamscan`, `hoperyy/get-npm-package-version`, `soyuka/pidusage`

## Per-detector, per-stage (0 new findings)

| stage | semgrep | codeql |
| --- | --- | --- |
| no changes (full revert) | 15/19 | 3/14 |
| minimal revert (changed lines only) | 15/19 | 3/14 |
| minimal + evasive rewrites | 19/19 | 10/14 |

## What the evasion was

- `(none needed)` — 3
- `require-member->hidden` — 3
- `params->arg-guard` — 2
- `shell-sink->hidden-member` — 2

## Minimality

- revert expressed at: line=18, hunk=1
- change units kept / total (median): 3 / 9

## Still detected

- `vincentmorneau/apex-publish-static-files` — detected_by=codeql; semgrep=-; codeql=js/shell-command-constructed-from-input×1
- `omrilotan/async-git` — detected_by=codeql; semgrep=-; codeql=js/shell-command-constructed-from-input×1
- `jas-/node-libnmap` — detected_by=codeql; semgrep=-; codeql=js/shell-command-constructed-from-input×3
- `rrainn/PortProcesses` — detected_by=codeql; semgrep=-; codeql=js/shell-command-constructed-from-input×1

## Benchmark data bugs (not evasion results)

The package name and the cloned repository share no name token, so the image may be built from a DIFFERENT project. Verify before trusting these rows (heuristic -- monorepos and renamed repos trip it too):

- `@thi.ng/egf` — builds from `thi-ng/umbrella` (revert-applied-no-repro)
- `alfred-workflow-nodejs` — builds from `vincentmorneau/apex-publish-static-files` (revert-apply-failed)
- `command-exists` — builds from `kellyselden/git-diff-apply` (revert-applied-no-repro)
- `scp` — builds from `kellyselden/git-diff-apply` (revert-applied-no-repro)
- `total.js` — builds from `totaljs/framework` (minimized+evaded (ci:skipped))

## Entries that never reached the evasion stage

- `thi-ng/umbrella` — revert-applied-no-repro (BENCHMARK revert applied but exploit doesn't reproduce (vuln needs more than the patch))
- `vincentmorneau/apex-publish-static-files` — revert-apply-failed (SETUP    patch.txt won't reverse-apply (lockfile/built/drifted hunks))
- `nfriedly/node-bestzip` — image-failed (SETUP    Dockerfile.fixed build failed (bad version pin / 404))
- `kucherenko/blamer` — rebuild-failed (SETUP    compiled package: revert applied but `npm run build` failed, runtime tree still fixed)
- `codecov/codecov-node` — revert-applied-no-repro (BENCHMARK revert applied but exploit doesn't reproduce (vuln needs more than the patch))
- `kellyselden/git-diff-apply` — revert-applied-no-repro (BENCHMARK revert applied but exploit doesn't reproduce (vuln needs more than the patch))
- `iximiuz/node-diskusage-ng` — minimized+evaded-EXPLOIT-BROKEN (ci:skipped) (?)
- `nodef/extra-asciinema` — rebuild-failed (SETUP    compiled package: revert applied but `npm run build` failed, runtime tree still fixed)
- `kellyselden/git-diff-apply` — revert-applied-no-repro (BENCHMARK revert applied but exploit doesn't reproduce (vuln needs more than the patch))
