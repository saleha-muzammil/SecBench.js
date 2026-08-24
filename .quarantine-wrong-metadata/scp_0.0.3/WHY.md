# command-injection/scp_0.0.3

The `Dockerfile.fixed` and `patch.txt` here were built from
**kellyselden/git-diff-apply**, not from `scp`. CVE-2019-10776
(GHSA-84cm-v6jp-gjmr) is git-diff-apply's advisory: "OS command injection in
git-diff-apply", affected <= 0.22.1, first patched 0.22.2. It was never an
`scp` advisory. The row in repositories.csv had inherited it, and the fixed
image therefore cloned a completely different project into
`node_modules/scp`.

The `scp` PoC in the benchmark folder is genuine -- it targets the real package
(`require("scp")`, `file: "& touch scp; #"`). But there is nothing to build a
FIXED image from:

  * canonical repo: https://github.com/ecto/node-scp (per the npm registry)
  * last commit:    2014-04-04
  * latest version: 0.0.3, which is also the vulnerable version in this entry
  * advisories:     none in the GitHub Advisory Database for npm/scp

The package was abandoned without a fix, so no `fixed_version` and no fix
commit exist. These files are parked here rather than deleted; the entry now
reports as "missing Dockerfile.fixed, patch.txt" instead of producing a
confident verdict about the wrong project.

Restore with:
    mv Dockerfile.fixed patch.txt ../../command-injection/scp_0.0.3/
