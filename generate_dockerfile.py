#!/usr/bin/env python3
"""
Generate a Dockerfile for a single benchmark entry in SecBench.js.

Pass the repository name (``owner/repo``, e.g. ``nim579/node-srv``) or, as a
fallback, the bare npm package name (e.g. ``node-srv``). The script looks the
name up in ``repositories.csv`` and writes a self-contained Dockerfile into
every matching benchmark folder ``<category>/<package>_<version>/``.

The generated Dockerfile:
  * starts from an official Node 16 image (the benchmark requires Node >= 16.3.0);
  * installs the system tools the exploits need (git, curl, zip, psmisc/fuser,
    g++, make, python3);
  * ``git clone``s the upstream repository into ``node_modules/<package>``,
    checks out the vulnerable version tag, and installs its dependencies, so the
    test's ``require("<package>")`` resolves to the real source tree;
  * installs ``jest`` (globally, to avoid disturbing the cloned package);
  * recreates ``flag.html`` (the file path-traversal exploits try to read);
  * stages ``redos/utils.js`` at ``/exploit/utils.js`` for redos entries, whose
    tests ``require("../utils")`` -- one level ABOVE the build context;
  * runs the jest test case as the default command.

Entries with no known repository in the CSV are skipped (nothing to clone).

The build context is the benchmark folder itself, so build with, e.g.:

    docker build -t secbench/node-srv_2.0.0 path-traversal/node-srv_2.0.0

Entries are read from the benchmark folders on disk (the source of truth for
package name and version); the repository is taken from each folder's own
package.json, falling back to repositories.csv. When no repository can be
resolved, the Dockerfile falls back to installing the published package from npm.

Usage:
    python3 generate_dockerfile.py <owner/repo | package>   # one entry
    python3 generate_dockerfile.py --category code-injection # a whole class
    python3 generate_dockerfile.py --all                     # everything
    # options: [--csv repositories.csv] [--force] [--node 16] [--print]
"""

import argparse
import base64
import csv
import gzip
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent

# Contents of the repo-level flag.html, recreated inside the image so the
# build does not depend on any file outside the benchmark folder.
FLAG_HTML = """<!DOCTYPE html>
<html>
<body>

<h1>CISPA</h1>
<p>vulns4js! is here.</p>

</body>
</html>"""

# The redos exploit tests open with `require("../utils")`, which resolves to
# /exploit/utils.js -- one level ABOVE WORKDIR, and therefore one level above the
# build context, so no COPY can reach it. Without it jest dies with
# MODULE_NOT_FOUND before a single regex runs; the exploit then "fails" on the
# fixed tree AND on the reverted tree, and the entry is written off as
# "revert applied but exploit does not reproduce" for a reason that has nothing
# to do with the patch.
#
# Staged the same way flag.html is, and for the same stated reason: the build must
# not depend on any file outside the benchmark folder. The payload is gzipped and
# base64-encoded so the JS survives the Dockerfile and shell parsers intact
# (quotes, backslashes and $ would otherwise all need escaping) in one instruction;
# base64's alphabet contains no quote, backslash or brace, so it needs none.
# Inspect a generated block with: sed -n '/base64 -d/,/exploit.utils.js/p' Dockerfile
#
# redos/utils.js is the single source of truth -- edit it, then regenerate.
SHARED_UTILS_PATH = ROOT / "redos" / "utils.js"
_UTILS_LINE_WIDTH = 100


def shared_utils_step(category):
    """Dockerfile lines staging redos/utils.js at /exploit/utils.js.

    Empty for every category but redos: no other exploit test requires a module
    from outside its own folder (verified across all five categories), so nothing
    else pays the size of the embedded copy.
    """
    if category != "redos":
        return ""
    if not SHARED_UTILS_PATH.exists():
        raise SystemExit(f"ERROR: {SHARED_UTILS_PATH} is missing; redos images "
                         f"would build without the exploit oracle helpers.")
    raw = SHARED_UTILS_PATH.read_bytes()
    # mtime=0 keeps the payload byte-identical between runs, so regenerating an
    # unchanged utils.js produces no diff.
    blob = base64.b64encode(gzip.compress(raw, 9, mtime=0)).decode("ascii")
    chunks = [blob[i:i + _UTILS_LINE_WIDTH]
              for i in range(0, len(blob), _UTILS_LINE_WIDTH)]
    payload = "\\\n".join(chunks)
    return (
        '\n'
        '# The redos exploit tests require("../utils") == /exploit/utils.js, which sits\n'
        '# one level above the build context and so cannot be COPYed. Embedded here\n'
        '# (gzip+base64) from redos/utils.js -- edit that file and regenerate, never this.\n'
        f"RUN echo '{payload}' \\\n"
        '    | base64 -d | gzip -dc > /exploit/utils.js\n'
    )

# --------------------------------------------------------------------------- #
# static analysers (semgrep + the CodeQL CLI)
# --------------------------------------------------------------------------- #
# semgrep 1.157.0 is the NEWEST release that can run on this base image at all:
# from 1.158.0 the Linux wheels are manylinux_2_34/2_35 and bullseye ships glibc
# 2.31, so a newer pin installs happily and then dies on the first scan. CodeQL
# tracks the host CLI (`brew info codeql`), because the two are compared.
#
# Raising semgrep past 1.157.0 therefore means moving the base image off bullseye
# (node:16-bookworm exists and has glibc 2.36) -- which also changes the gcc the
# packages' native addons build with, so it is not a free swap. Check
# https://pypi.org/pypi/semgrep/<version>/json for the wheel tags before bumping.
SEMGREP_VERSION = "1.157.0"
CODEQL_VERSION = "2.25.6"


def scanners_step(enabled=True):
    """semgrep + CodeQL, installed early -- right after the apt layer and before
    anything entry-specific -- so every image that asks for them shares ONE copy
    on disk: the instructions and the parent layer are byte-identical across
    entries, so the build cache stores the layers once and each image just
    references them."""
    if not enabled:
        return ""
    return f"""
# --- static analysis toolchain ----------------------------------------------
# curl_issue.py runs semgrep and CodeQL INSIDE this image whenever the pipeline is
# driven with --docker-image. Without them both gates are vacuous, and vacuous is
# worse than absent here: "0 new findings" and "the tool never ran" are
# indistinguishable to every caller downstream, so a patch that was never scanned
# is scored as a patch that evaded the scanners.
#
# semgrep {SEMGREP_VERSION} needs Python >= 3.10 and bullseye ships 3.9, so it gets its own
# uv-managed interpreter under /opt/uv. The image's python3 -- what node-gyp builds
# native addons with -- is deliberately left exactly as the base image had it.
# (1.157.0 is also the newest wheel that links against this image's glibc; see
# SEMGREP_VERSION in generate_dockerfile.py before bumping it.)
ENV UV_INSTALL_DIR=/usr/local/bin \\
    UV_TOOL_BIN_DIR=/usr/local/bin \\
    UV_TOOL_DIR=/opt/uv/tools \\
    UV_PYTHON_INSTALL_DIR=/opt/uv/python
RUN curl -LsSf https://astral.sh/uv/install.sh | sh \\
    && uv tool install --python 3.12 semgrep=={SEMGREP_VERSION} \\
    && semgrep --version

# CodeQL publishes x86-64 binaries only -- there is no linux-arm64 CLI at all -- and
# the amd64 build is not usable under emulation: `database analyze` gets OOM-killed
# or never finishes (the same finding that put minimize_and_evade.py's CodeQL on the
# host CLI). So install it when this image is amd64, and fail loudly-in-comment
# rather than baking in a binary that cannot execute when it is not. On arm64,
# curl_issue._run_codeql falls back to the host CodeQL CLI over the bind-mounted
# checkout -- the same tree, the same queries.
RUN arch="$(dpkg --print-architecture)"; \\
    if [ "$arch" = "amd64" ]; then \\
        curl -fsSL -o /tmp/codeql.tar.gz \\
            "https://github.com/github/codeql-action/releases/download/codeql-bundle-v{CODEQL_VERSION}/codeql-bundle-linux64.tar.gz" \\
        && tar -xzf /tmp/codeql.tar.gz -C /opt \\
        && rm -f /tmp/codeql.tar.gz \\
        && ln -sf /opt/codeql/codeql /usr/local/bin/codeql \\
        && codeql version --format=terse; \\
    else \\
        echo "WARNING: no CodeQL CLI exists for $arch (GitHub ships linux64/x86-64 only);" >&2; \\
        echo "         this image has semgrep but no codeql, and the harness falls" >&2; \\
        echo "         back to the host CLI on the bind-mounted checkout." >&2; \\
    fi
"""


DOCKERFILE_HEAD = """# Auto-generated by generate_dockerfile.py for the SecBench.js benchmark.
# Entry : {package}@{version}  ({category})
# CVE   : {cve}
# Repo  : {repository}
# Source: {source_mode}
#
# Build context is THIS folder. Build & run with, e.g.:
#   docker build -t {tag} {build_path}
#   docker run --rm {tag}
FROM node:{node}-bullseye

# System tools required by the exploits (curl, fuser via psmisc, build tools, ...).
# yarn is intentionally omitted: the node image already ships it, and Debian's
# apt 'yarn' is a different, conflicting package.
RUN apt-get update && apt-get install -y --no-install-recommends \\
        git curl zip psmisc g++ make python3 \\
    && rm -rf /var/lib/apt/lists/*
{scanners}
WORKDIR /exploit/{folder}

# Recreate the flag file the path-traversal exploits read as ../flag.html
RUN printf '{flag}' > /exploit/flag.html

# Benchmark metadata (package.json) + jest test case
COPY . .
{shared_utils}"""

# Some repositories commit a package-lock.json whose "resolved" URLs point at a
# PRIVATE registry the maintainer happened to be using (one entry in bestzip's
# lock resolves through artifactory.corp.tanium.com). npm honours those URLs, so
# `npm install` dies with ENOTFOUND on a host nobody outside that company can
# reach, and the entry is written off as a bad version pin. Dropping such a
# lockfile makes npm resolve from registry.npmjs.org instead; a lockfile that
# only references the public registry is left alone, so reproducibility is
# unaffected everywhere it actually holds.
#
# Build-time proof that the cloned repo IS the package the entry claims.
#
# repositories.csv maps some entries to a completely different project, and
# because fix_commit_sha is read from the same row the repo and the commit agree
# with each other -- so nothing downstream can cross-check them. Those images
# built happily, cloned foreign code into node_modules/<package>, and every
# verdict drawn from them was meaningless. Observed in this benchmark:
#   diskstats                        <- vincentmorneau/apex-publish-static-files
#   samsung-remote                   <- ronomon/opened
#   scp                              <- kellyselden/git-diff-apply
#   ms                               <- caolan/forms
#   object-path                      <- skratchdot/object-path-set
#   lodash                           <- sailshq/lodash
#   @aws-sdk/shared-ini-file-loader  <- aws/aws-sdk-js (the v2 SDK)
#
# The check runs immediately after checkout and BEFORE `npm install`, so no
# node_modules tree exists yet and the scan is cheap. It is a scan rather than a
# single read of the root package.json because monorepos are legitimate:
# @thi.ng/egf really does live in thi-ng/umbrella and
# @aws-sdk/shared-ini-file-loader in aws-sdk-js-v3, each under packages/<name>/.
# Any package.json within a few levels that names the package satisfies it.
NAME_ASSERT_CMD = (
    "node -e '" + 'const fs=require("fs"),p=require("path"),want=process.argv[1],seen=[];const scan=(d,n)=>{{if(n>3)return false;let E;try{{E=fs.readdirSync(d,{{withFileTypes:true}})}}catch(e){{return false}}for(const e of E){{if(e.name==="node_modules"||e.name[0]===".")continue;const f=p.join(d,e.name);if(e.isFile()&&e.name==="package.json"){{try{{const x=JSON.parse(fs.readFileSync(f,"utf8")).name;if(x)seen.push(x);if(x===want)return true}}catch(_){{}}}}else if(e.isDirectory()&&scan(f,n+1))return true}}return false}};if(!scan(".",0)){{console.error("ERROR: this checkout does not contain the package \\"" + want + "\\". package.json names found: " + (seen.slice(0,8).join(", ")||"(none)"));console.error("       repositories.csv maps it to {repository}, and fix_commit_sha comes from that same row, so BOTH are wrong together. Correct the row before building.");process.exit(1)}}' + "' \"{package}\""
)


# The repo's own devDependencies are what `npm install` resolves here, and on
# modern trees they routinely conflict under npm 7+'s strict peer resolution
# (eslint plugin stacks, rollup/babel, @logux configs). That kills the build with
# ERESOLVE even though nothing about the *package under test* is broken --
# locutus, postcss, react-native and validator all died this way. Retry with
# --legacy-peer-deps, which is npm 6 behaviour: only the entries that would
# otherwise fail outright see it, so images that already build keep byte-identical
# dependency resolution.
NPM_INSTALL = "npm install --no-audit --no-fund --ignore-scripts"
# Braced so the retry is one unit: `A || echo ... && B` parses left-to-right as
# `(A || echo) && B`, which would run the legacy install even when A succeeded.
NPM_INSTALL_LEGACY = (
    '{ echo "WARNING: npm install failed (likely ERESOLVE peer conflict in the '
    'repo devDependencies); retrying with --legacy-peer-deps" >&2; '
    + NPM_INSTALL + " --legacy-peer-deps; }"
)


# Used when an upstream repository is known: clone it at the vulnerable version.
# If the version tag exists, build from the checked-out source. If it does NOT
# exist, the repo's default branch is the patched/current code and the exploit
# would not reproduce, so fall back to installing the exact vulnerable version
# from npm instead. --ignore-scripts skips the package's own install/prepublish
# lifecycle (old packages run lint+build+minify on install that often crash); on
# the checkout path we then do a best-effort build for any compiled entry point.
CLONE_STEP = """
RUN git clone {repository_url}.git node_modules/{package} \\
    && cd node_modules/{package} \\
    && if {checkout_clause}; then \\
{name_assert}           && ({npm_install} || {npm_install_legacy}) \\
           && (npm run build --if-present || echo "WARNING: build step failed/partial; continuing") \\
           && (npm run prepare --if-present || echo "WARNING: prepare step failed/partial; continuing"); \\
       else \\
           echo "WARNING: could not check out {checkout_desc}; installing {package}@{version} from npm instead" \\
           && cd /exploit/{folder} \\
           && rm -rf node_modules/{package} \\
           && npm install --no-audit --no-fund --ignore-scripts {package}@{version}; \\
       fi
"""

# Strict variant, and the default. When the pinned tag/commit is missing, the
# `||` chain above quietly leaves the clone on the DEFAULT BRANCH, and the
# `else` branch then installs a possibly different tree from npm -- either way
# the image is silently not the version the benchmark claims, and every verdict
# drawn from it is meaningless (three code-injection entries were shipping the
# vulnerable code in their "fixed" image this way). Fail the build loudly
# instead; --allow-npm-fallback restores the lenient behaviour above.
CLONE_STEP_STRICT = """
RUN git clone {repository_url}.git node_modules/{package} \\
    && cd node_modules/{package} \\
    && if ! ({checkout_clause}); then \\
           echo "ERROR: cannot check out {checkout_desc} in {repository_url}." >&2; \\
           echo "       Building anyway would silently use the default branch, which is" >&2; \\
           echo "       neither {package}@{version} nor the pinned commit, so the exploit" >&2; \\
           echo "       oracle would be measuring the wrong code." >&2; \\
           echo "       Fix the version/commit for {package} in repositories.csv, or" >&2; \\
           echo "       regenerate with --allow-npm-fallback to install from npm." >&2; \\
           exit 1; \\
       fi \\
{name_assert}    && for L in package-lock.json npm-shrinkwrap.json; do \\
           [ -f "$L" ] || continue; \\
           if grep -o "\\"resolved\\": *\\"https\\?://[^/\\"]*" "$L" | sed "s|.*//||" | grep -qv "^registry\\.npmjs\\.org"; then \\
               echo "WARNING: $L pins dependencies to a registry that is not registry.npmjs.org; removing it so npm resolves publicly" >&2; \\
               rm -f "$L"; \\
           fi; \\
       done \\
    && ({npm_install} || {npm_install_legacy}) \\
    && (npm run build --if-present || echo "WARNING: build step failed/partial; continuing") \\
    && (npm run prepare --if-present || echo "WARNING: prepare step failed/partial; continuing")
"""

# Splice the assertion into both clone templates. Plain str.replace, not
# .format() -- NAME_ASSERT_CMD still carries its own {package}/{repository}
# fields, and they have to survive until render() formats the whole template.
# In the lenient template the assertion is the first command of the `then`
# branch, so `npm install` there is already chained with `&&`; in the strict one
# it sits between `fi` and the lockfile loop, which are `&&`-chained too.
CLONE_STEP = CLONE_STEP.replace(
    "{name_assert}", "           " + NAME_ASSERT_CMD + " \\\n")
CLONE_STEP_STRICT = CLONE_STEP_STRICT.replace(
    "{name_assert}", "    && " + NAME_ASSERT_CMD + " \\\n")


# Used when no upstream repository could be resolved: install the published
# package from npm (already prebuilt) at the exact vulnerable version. npm
# happily resolves a missing version to something else, so assert afterwards
# that the tree really is the version asked for.
NPM_STEP = """
# No upstream repository was resolvable for this entry, so install the published
# package from npm at the exact vulnerable version instead of cloning.
RUN npm install --no-audit --no-fund --ignore-scripts {package}@{version} \\
    && node -e "const v=require('{package}/package.json').version; \\
        if(v!=='{version}'){{console.error('ERROR: asked npm for {package}@{version} but got '+v+'.');process.exit(1);}}"
"""

DOCKERFILE_TAIL = """
# jest installed globally so it does not disturb the package tree. Pinned to 29:
# jest 30 calls os.availableParallelism(), absent on the node:16 base image, so the
# exploit oracle died at config load ("availableParallelism is not a function")
# instead of running -- every harness then reported exploit=False for free.
RUN npm install -g --no-audit --no-fund jest@29

CMD ["jest", "--runInBand"]
"""


# Benchmark categories that contain per-entry folders.
CATEGORIES = ["prototype-pollution", "redos", "command-injection",
              "path-traversal", "code-injection"]

# github.com/<owner>/<repo>, tolerating .git suffixes and trailing paths.
GITHUB_RE = re.compile(
    r"github\.com[/:]+([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+?)(?:\.git)?(?:[/#?].*)?$",
    re.IGNORECASE,
)

# A commit SHA in a .../commit/<sha> or .../pull/N/commits/<sha> URL.
COMMIT_SHA_RE = re.compile(r"/commits?/([0-9a-f]{7,40})\b", re.IGNORECASE)

# 1.2.3, 1.2.3-rc.1, 2.0.20170212 -- numeric core plus an optional prerelease.
# A leading range operator (^1.2.3, =1.2.3, >= 1.2.3, v1.2.3) is stripped: the
# CSV and the folders' package.json mix exact pins and npm range syntax, and a
# version that fails to parse would make every comparison silently false.
_SEMVER_RE = re.compile(
    r"^\s*(?:[~^=<>]{0,2}\s*)?v?(\d+(?:\.\d+)*)(?:[-+](.*))?\s*$")


def parse_version(v):
    """(numeric-core tuple, prerelease string) for comparison, or None.

    Padded to three components so 1.2 and 1.2.0 compare equal, and so a short
    version never sorts above a longer one that shares its prefix.
    """
    m = _SEMVER_RE.match(str(v or ""))
    if not m:
        return None
    core = tuple(int(x) for x in m.group(1).split("."))
    core += (0,) * (3 - len(core)) if len(core) < 3 else ()
    return core, (m.group(2) or "")


def version_gt(a, b):
    """True when version `a` is strictly newer than `b`.

    Unparseable versions return False: an assertion that cannot be evaluated
    must not silently pass. A release is newer than its own prereleases
    (1.0.0 > 1.0.0-rc.1), per semver.
    """
    pa, pb = parse_version(a), parse_version(b)
    if pa is None or pb is None:
        return False
    if pa[0] != pb[0]:
        return pa[0] > pb[0]
    # Same numeric core: no prerelease outranks any prerelease.
    if (not pa[1]) != (not pb[1]):
        return not pa[1]
    return pa[1] > pb[1]


def parse_commit_sha(url):
    """Return the commit SHA from a GitHub commit URL, or '' (ignoring ranges)."""
    if not isinstance(url, str) or "/compare/" in url.lower():
        return ""
    m = COMMIT_SHA_RE.search(url)
    return m.group(1) if m else ""


def parse_github_repo(url):
    """Return 'owner/repo' from a GitHub URL, or '' (ignoring advisory pages)."""
    if not isinstance(url, str) or "github.com/advisories" in url.lower():
        return ""
    m = GITHUB_RE.search(url.strip())
    if not m:
        return ""
    owner, repo = m.group(1), m.group(2)
    return "" if owner.lower() in {"advisories", "sponsors"} else f"{owner}/{repo}"


def resolve_repo_from_meta(meta):
    """Derive owner/repo from a folder's package.json (fixCommit, then links)."""
    repo = parse_github_repo(meta.get("fixCommit", ""))
    if repo:
        return repo
    links = meta.get("links") or {}
    values = links.values() if isinstance(links, dict) else (
        links if isinstance(links, list) else [])
    for value in values:
        repo = parse_github_repo(value)
        if repo:
            return repo
    return ""


def csv_repo_index(csv_path):
    """Map package-name -> 'owner/repo' from the CSV, to enrich on-disk entries."""
    index = {}
    if not csv_path.exists():
        return index
    with open(csv_path, newline="", encoding="utf-8") as fh:
        for row in csv.DictReader(fh):
            pkg = (row.get("package") or "").strip().lower()
            repo = (row.get("repository") or "").strip()
            if pkg and repo and pkg not in index:
                index[pkg] = repo
    return index


def build_entry(category, path, repo_index):
    """Build an entry dict from a benchmark folder, or None if unreadable.

    The folder on disk is the source of truth for the package name and version;
    the repository is resolved from the folder's own package.json, falling back
    to the CSV index when the metadata has no usable source link.
    """
    meta_path = path / "package.json"
    if not meta_path.exists():
        return None
    try:
        meta = json.loads(meta_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as exc:
        print(f"  ! skip {category}/{path.name}: bad package.json ({exc})", file=sys.stderr)
        return None

    deps = meta.get("dependencies") or {}
    package = next(iter(deps), "") if isinstance(deps, dict) else ""
    if not package:
        package = path.name.rpartition("_")[0] or path.name
    # The on-disk folder suffix is the real version (the dep range may have ^/~).
    version = path.name.rpartition("_")[2] or ""

    repo = resolve_repo_from_meta(meta) or repo_index.get(package.lower(), "")
    fixed = (meta.get("fixedVersion") or "").strip()
    if fixed.lower() in {"", "n/a", "na", "none"}:
        fixed = ""
    return {
        "category": category,
        "folder": path.name,
        "path": path,
        "package": package,
        "version": version,
        "fixed_version": fixed,
        "fix_commit_sha": parse_commit_sha(meta.get("fixCommit", "")),
        "cve": (meta.get("id") or "").strip() or "(none)",
        "repository": repo,
        "repository_url": f"https://github.com/{repo}" if repo else "",
    }


def collect_entries(categories, repo_index):
    """Walk the given category folders and build an entry for each subfolder."""
    entries = []
    for category in categories:
        cat_dir = ROOT / category
        if not cat_dir.is_dir():
            continue
        for path in sorted(p for p in cat_dir.iterdir() if p.is_dir()):
            entry = build_entry(category, path, repo_index)
            if entry:
                entries.append(entry)
    return entries


def find_matches_disk(name, repo_index):
    """Find entries matching a name by repository (owner/repo) or package name."""
    key = name.strip().lower()
    everything = collect_entries(CATEGORIES, repo_index)
    return [e for e in everything
            if e["repository"].lower() == key or e["package"].lower() == key]


def render(entry, node, allow_npm_fallback=False, scanners=False):
    # Single-line printf format: escape backslashes, single quotes, then newlines.
    # printf interprets the \n escapes, recreating the multi-line flag file.
    flag = (FLAG_HTML.replace("\\", "\\\\")
            .replace("'", "'\\''")
            .replace("\n", "\\n"))
    folder = entry["folder"]
    build_path = f"{entry['category']}/{folder}"
    if entry["repository_url"]:
        step = CLONE_STEP if allow_npm_fallback else CLONE_STEP_STRICT
        source_mode = f"git clone {entry['repository_url']} @ {entry['version']}"
    else:
        step = NPM_STEP
        source_mode = f"npm install {entry['package']}@{entry['version']} (no repo resolved)"

    v = entry["version"]
    # Vulnerable image: locate the vulnerable release by its version tag.
    checkout_clause = f'git checkout -q "v{v}" || git checkout -q "{v}"'
    checkout_desc = f"version tag v{v}/{v}"

    body = DOCKERFILE_HEAD + step + DOCKERFILE_TAIL
    return build_path, body.format(
        package=entry["package"],
        version=entry["version"],
        category=entry["category"],
        cve=entry["cve"],
        repository=entry["repository"] or "(none)",
        repository_url=entry["repository_url"],
        source_mode=source_mode,
        checkout_clause=checkout_clause,
        checkout_desc=checkout_desc,
        tag=f"secbench/{folder}".lower(),
        build_path=build_path,
        folder=folder,
        node=node,
        flag=flag,
        shared_utils=shared_utils_step(entry["category"]),
        scanners=scanners_step(scanners),
        npm_install=NPM_INSTALL,
        npm_install_legacy=NPM_INSTALL_LEGACY,
    )


def main():
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument("name", nargs="?",
                    help="repository (owner/repo) or npm package name "
                         "(omit when using --category or --all)")
    ap.add_argument("--category", "-c",
                    help="generate for EVERY entry in this category "
                         "(e.g. code-injection, path-traversal)")
    ap.add_argument("--all", action="store_true",
                    help="generate for every entry in every category")
    ap.add_argument("--csv", default="repositories.csv",
                    help="CSV used to enrich repositories (default: repositories.csv)")
    ap.add_argument("--node", default="16", help="Node major version for the base image (default: 16)")
    ap.add_argument("--force", action="store_true", help="overwrite an existing Dockerfile")
    ap.add_argument("--allow-npm-fallback", action="store_true",
                    help="when the version tag is missing, install from npm instead "
                         "of failing the build (default: fail loudly, so an image is "
                         "never silently built from the default branch)")
    ap.add_argument("--scanners", action="store_true",
                    help="install semgrep and the CodeQL CLI in the image (adds a "
                         "shared ~2.5 GB layer). Off here: the VULNERABLE images are "
                         "only ever used to reproduce the exploit. Dockerfile.fixed, "
                         "which the evasion pipeline actually scans in, gets them by "
                         "default -- see generate_dockerfile_fixed.py.")
    ap.add_argument("--print", dest="print_only", action="store_true",
                    help="print the Dockerfile(s) to stdout instead of writing")
    args = ap.parse_args()

    if sum(bool(x) for x in (args.name, args.category, args.all)) != 1:
        ap.error("provide exactly one of: a name, --category CAT, or --all")

    csv_path = Path(args.csv)
    if not csv_path.is_absolute():
        csv_path = ROOT / csv_path
    repo_index = csv_repo_index(csv_path)

    if args.category:
        cat = args.category.strip().strip("/").lower()
        if cat not in CATEGORIES and not (ROOT / cat).is_dir():
            sys.exit(f"error: unknown category '{args.category}'. "
                     f"Known categories: {', '.join(CATEGORIES)}")
        matches = collect_entries([cat], repo_index)
        print(f"Generating for all {len(matches)} entries in category '{cat}'.")
    elif args.all:
        matches = collect_entries(CATEGORIES, repo_index)
        print(f"Generating for all {len(matches)} entries across every category.")
    else:
        matches = find_matches_disk(args.name, repo_index)
        if not matches:
            sys.exit(f"error: no benchmark entry matches '{args.name}' "
                     f"(tried repository owner/repo, then package name).")
        print(f"Matched {len(matches)} entr{'y' if len(matches) == 1 else 'ies'} "
              f"for '{args.name}'.")

    written = skipped_exists = 0
    for entry in matches:
        build_path, dockerfile = render(entry, args.node, args.allow_npm_fallback,
                                        scanners=args.scanners)

        if args.print_only:
            print(f"\n# ===== {build_path}/Dockerfile =====")
            print(dockerfile)
            continue

        target = entry["path"] / "Dockerfile"
        if target.exists() and not args.force:
            print(f"  - exists, skipping (use --force): {build_path}/Dockerfile")
            skipped_exists += 1
            continue

        target.write_text(dockerfile, encoding="utf-8")
        written += 1
        mode = "clone" if entry["repository_url"] else "npm"
        print(f"  + wrote {build_path}/Dockerfile  "
              f"({entry['package']}@{entry['version']}, {mode}, "
              f"build with: docker build {build_path})")

    if not args.print_only:
        no_repo = sum(1 for e in matches if not e["repository_url"])
        print(f"Done. {written} written, {skipped_exists} already existed (use --force). "
              f"{no_repo} of the matched entries had no repo (npm-install fallback).")


if __name__ == "__main__":
    main()
