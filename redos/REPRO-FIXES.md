# redos/ reproduction fixes

Context: 19 entries reverse-applied `patch.txt` cleanly and then failed to reproduce
("full revert applied but exploit does NOT reproduce -> cannot minimize"), and 7
entries never produced a fixed image at all.

The exploits were almost never the problem. Installing each package at its
**vulnerable published version** and running the benchmark's own unmodified PoC
reproduced 18 of the 19. What failed was the construction of the vulnerable side:
the pipeline built it as *fixed release minus one mined commit*, and that mined
commit usually was not the commit that closed this particular PoC.

## What changed

**`fixedVersion` corrected** — bisected over published releases, running the
entry's own PoC, to the first release where it stops reproducing:

| entry | was | is | evidence |
|---|---|---|---|
| content_3.0.5 | 4.0.4 | 3.0.6 | 3.0.5 1610 ms, 3.0.6 5 ms |
| glob-parent_5.0.0 | 6.0.1 | 5.1.2 | 5.1.1 5259 ms, 5.1.2 2 ms |
| lodash_4.17.4 | 4.17.21 | 4.17.11 | 4.17.10 976 ms, 4.17.11 6 ms |
| markdown-it_9.1.0 | 12.3.2 | 10.0.0 | 9.1.0 3707 ms, 10.0.0 46 ms |
| marked_0.3.6 | 2.0.0 | 0.3.9 | 0.3.7 1929 ms, 0.3.9 4 ms |
| mime_1.4.0 | 2.0.3 | 1.4.1 | 1.4.0 3286 ms, 1.4.1 0.4 ms (2.0.3 also renamed `lookup` to `getType`, which broke the PoC outright) |
| postcss_8.0.0 | 8.2.13 | 8.2.10 | 8.2.9 2536 ms, 8.2.10 12 ms |
| semver-regex_3.1.1 | 3.1.3 | 3.1.2 | 3.1.1 1415 ms, 3.1.2 1 ms |
| ua-parser-js_0.7.22 | 0.7.24 | 0.7.23 | 0.7.22 1356 ms, 0.7.23 10 ms |
| html-parse-stringify2_2.0.1 | n/a | 2.0.2 | 2.0.1 1065 ms, 2.0.2 1.8 ms |

**`patch.txt` rebuilt** as the vulnerable→fixed release diff (`make_release_patch.py`,
production files only). The previous mined-commit patch is kept beside it as
`patch.txt.mined-fix-commit`.

**`make_release_patch.py` gained two things** it needed for these entries:

* monorepo support — `<package>@<version>` tags and leaf-manifest version lookup
  (`packages/<name>/package.json`), without which conventional-commits-parser
  could not resolve either end of its range;
* an optional `patchFiles` list in the entry's package.json, for ranges where a
  production file is coupled to a dependency's layout rather than to the bug.
  markdown-it needs it: `lib/common/entities.js` switches between entities@1
  (`maps/`) and entities@2 (`lib/maps/`), so reverting it makes the module
  unloadable and the exploit can never run.

**Image fixes**, all in both `Dockerfile` and `Dockerfile.fixed` so the pair stays
symmetric:

* `conventional-commits-parser` pins `trim-off-newlines@1.0.0`. In 3.2.0 the
  catastrophic regex lives in that dependency; a plain install resolves `^1.0.0`
  to the already-patched 1.0.2 and the exploit measured ~29 ms. 3.2.3 inlines the
  function, so the fixed side stays closed with the same pin.
* `is-svg` pins `html-comment-regex@1.1.2`, which 4.3.0 dropped — reverting the
  patch restored a `require` of a package that was no longer installed.
* `html-dom-parser` installs `jsdom@20`: the patched regexes live in
  `lib/domparser.js`, reachable only through the package's `browser` entry.
* `highlight.js` symlinks `lib -> build/lib`. The repo has no `lib/`; the node
  build writes `build/lib`. A symlink rather than a copy, because the campaign
  re-runs `npm run build` after each revert and a copy would go stale and
  silently measure the fixed code.
* `--prefer-tag` regeneration for locutus, postcss, react-native and validator,
  whose fixed images died on `cannot check out commit ...`. validator's mined sha
  lives on the `tux-tn` PR fork and does not exist upstream; the entry now points
  at `validatorjs/validator.js` tag 13.6.0 (this was the build failure that got
  mislabelled `npm-fallback` rather than `image-failed`).

**Exploits rewritten** (three, each verified to pass on the vulnerable version and
fail on the fixed one):

* `conventional-commits-parser` — the default export is a through2 stream
  *factory*, so `conventionalCommitsParser(payload)` parsed nothing at all. Now
  uses `.sync()`. The regex is exponential, not quadratic: n=20 costs 32 ms, n=24
  482 ms, n=26 ~2 s, so the original 2,000,000 repeats could never have returned.
* `fast-csv` — the assertion sat in the stream's `end` handler with nothing making
  jest wait. Now returns a promise.
* `html-dom-parser` — wrong entry point *and* an unmatchable payload;
  `"<head" + " S".repeat(n)` has no `>` at all, so the regex fails at offset 0 and
  the scan is linear. Now drives the client build with
  `"<html><head" + ">".repeat(60000)`.

## Verified locally (fixed tree -> reverse-apply patch.txt -> PoC)

glob-parent 2 ms -> 5050 ms · mime 4 ms -> 2975 ms · semver-regex 1 ms -> 1386 ms ·
content 5 ms -> 1377 ms · simple-markdown 2 ms -> 1041 ms · postcss 11 ms -> 2510 ms ·
lodash 6 ms -> 970 ms · marked 4 ms -> 1754 ms · markdown-it 49 ms -> 3097 ms ·
is-svg 6 ms -> 1321 ms · html-parse-stringify2 2 ms -> 1041 ms ·
ua-parser-js 9 ms -> 1265 ms · highlight.js 2 ms -> 18736 ms (real checkout, built,
reverted, rebuilt) · conventional-commits-parser, fast-csv and html-dom-parser
verified through jest on both versions.

## Still blocked

* **ethers_5.2.0** — the ReDoS is in `@ethersproject/bignumber`, a different npm
  package. `node_modules/ethers` is the monorepo checkout, whose `@ethersproject/*`
  dependencies come from the registry already fixed, so reverting
  `packages/bignumber/...` changes nothing that gets loaded. Fixing it means
  re-targeting the entry at `@ethersproject/bignumber` or bootstrapping the
  workspace in the image.
* **content-type-parser_1.0.1** — no fixed release exists; npm deprecates it with
  "Use whatwg-mimetype instead" and 1.0.2, the last version, still reproduces.
* **d3-color_2.0.0** — the fix (3.1.0) is ESM-only and its `exports` map also
  blocks the UMD fallback, so the CommonJS PoC cannot load the fixed tree.
