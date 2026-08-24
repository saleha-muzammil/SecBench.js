#!/usr/bin/env python3
"""
Find the MINIMAL revert of a fix that re-passes the exploit test, optionally
rewritten to EVADE semgrep -- a SAST-robustness probe for the SecBench.js
code-injection benchmark.

For a benchmark folder with Dockerfile.fixed + patch.txt + an *.test.js exploit:

  Phase 0  baseline   install the test's undeclared deps; on the CLEAN FIXED
                      tree run BOTH the repo's CI tests and the exploit test (and
                      snapshot npm audit). The exploit test MUST FAIL (vuln
                      closed); the CI baseline is remembered so later breakage is
                      attributed to our patch vs. an already-broken upstream. If
                      the exploit already passes, the image is not actually fixed
                      -> skip (nothing to do).
  Phase 1  minimize   split patch.txt into hunks; reverse-apply all (test must
                      now PASS), then greedily drop each hunk whose revert is not
                      needed -> the minimal set of reverted hunks that re-opens
                      the vuln (oracle: the jest exploit test). THEN, if that
                      chunking breaks a repo CI that was green on the clean-fixed
                      tree, search for a chunking that keeps BOTH the exploit and
                      the repo CI green (usually by also reverting the fix's added
                      regression tests) -- CI/test cases are evaded FIRST, before
                      any SAST evasion.
  Phase 2  evade      run semgrep at three stages -- (A) the full unminimized
                      revert ("no changes"), (B) the chunked minimal variant,
                      (C) after semantics-preserving rewrites (eval->Function,
                      new Function->(0,Function)) -- and record how many evade at
                      each. The kept rewrite is the first that still PASSES the
                      test while semgrep reports 0 findings. Every stage is also
                      scored against a baseline scan of the CLEAN FIXED tree, so
                      the report separates "0 findings" from the number that
                      actually matters: 0 findings THIS PATCH INTRODUCED.
                      Pre-existing alerts in the same files are not evasion
                      failures and are not counted as detections.
  Phase 3  verdict    run the final verdict battery on the final variant, in
                      order: (1) test cases reproduce, (2) CI vs the clean-fixed
                      baseline, (3) CodeQL (detection-only, containerized, over
                      the changed/sink files at each stage), (4) npm-audit delta
                      vs the clean-fixed snapshot, (5) semgrep.

Outputs, into the benchmark folder:
  exploit-evasive.patch  the reverse-diff that re-opens the vuln (minimized+evaded)
  evasion-report.txt     baseline/minimize/evade/ci/codeql results
  evasion-findings.json  untruncated NEW findings per stage, semgrep + codeql
                      (rule, path, line, severity, message) -- the evidence the
                      CSV's *_messages columns are a summary of

And, at the repo root, one CSV per category:
  evasion-results-<category>.csv   repository + per-stage labels (evade_full,
                      evade_minimal, evade_final, codeql_*, ci_verdict, status),
                      plus the new-findings columns for BOTH detectors:
                      semgrep_new_*/codeql_new_* per stage, and for the final
                      evasive variant detected_by, *_new_in_patched,
                      *_top_rules and *_messages -- the same column names the
                      <category>-semgrep-codeql-analysis.csv files use.

Requires a running Docker daemon (and network for npm install / semgrep rules /
the CodeQL container).

Usage:
    python3 minimize_and_evade.py <owner/repo | package>   # one entry
    python3 minimize_and_evade.py --category code-injection
    python3 minimize_and_evade.py --all
    # options: [--force] [--build] [--no-build] [--keep] [--no-evade]
"""

import argparse
import json
import re
import shlex
import shutil
import sys
import tempfile
from collections import Counter
from pathlib import Path

from generate_dockerfile import (
    ROOT, CATEGORIES, csv_repo_index, collect_entries, find_matches_disk,
)
from analyze_patch import (
    run, dexec, image_tag, ensure_image, parse_audit, fmt_counts,
    SEMGREP_IMAGE, DEFAULT_SEMGREP_CONFIGS, RULES_DIR, LOCAL_RULESET, JS_EXT,
)

PATCH_OUT = "exploit-evasive.patch"     # the successful patch: exploit reproduces AND semgrep minimized
REPORT_OUT = "evasion-report.txt"
FINDINGS_OUT = "evasion-findings.json"  # untruncated new findings (semgrep + codeql), per stage

# CodeQL runs as a detection-only second SAST, after the CI checks (Phase 3).
# Run the HOST's native codeql CLI over the changed/sink files semgrep sees --
# NOT a container. The community codeql container is amd64-only; under emulation
# on arm64 `database analyze` is killed/never finishes, so every codeql_* came
# back n/a. The native CLI (brew cask `codeql`) plus the installed
# codeql/javascript-queries pack runs the same suite in ~35s on arm64.
CODEQL_SUITE = ("codeql/javascript-queries:"
                "codeql-suites/javascript-security-extended.qls")
# The suite semgrep-codeql-analysis.py used to produce the *-semgrep-codeql-
# analysis.csv detections. security-extended is a superset of it, so evading the
# default here is the weaker claim -- offered via --codeql-suite for runs that
# need to be numerically comparable with those CSVs.
CODEQL_SUITE_DEFAULT = "codeql/javascript-queries"

# --- semgrep configuration -------------------------------------------------- #
# MUST match what produced the detections we are trying to evade. The analysis
# CSVs were generated by semgrep-codeql-analysis.py with mini-swe-agent's
# configuration: ten registry packs plus that repo's own semgrep_rules.yaml (the
# `mini-*` rules -- mini-shell-exec-nonliteral, mini-prototype-pollution-path-
# write, mini-unsafe-forin-copy, mini-regexp-from-variable, ...). analyze_patch's
# DEFAULT_SEMGREP_CONFIGS is a strict SUBSET of that (3 packs, no mini rules), so
# scoring evasion against it would mark as "evaded" every finding produced by a
# rule that was never loaded. Use the full set.
EVADE_SEMGREP_PACKS = ("p/default", "p/javascript", "p/typescript", "p/nodejs",
                       "p/golang", "p/security-audit", "p/owasp-top-ten",
                       "p/xss", "p/command-injection", "p/secrets")
LOCAL_RULESETS = ("secbench-code-injection.yml", "secbench-taint.yml")
MINI_RULES = Path("/Users/saleha/Desktop/cispa/mini-swe-agent"
                  "/src/minisweagent/config/extra/semgrep_rules.yaml")

# Resource caps. One benchmark entry at a time, and every scanner boxed in, so a
# multi-MB bundled artifact cannot take the host down with it.
#
# Sized for an 8 GB laptop, which is the binding constraint: semgrep runs inside
# the Docker VM while CodeQL runs NATIVELY on the host, so their budgets come out
# of the same 8 GB and cannot both be generous. The benchmark container itself
# (npm, jest, a package rebuild) needs headroom on top. Deliberately conservative:
# semgrep skips a file it cannot fit and says so, which is a bad result; the host
# swapping itself to death is no result at all.
SEMGREP_MEMORY_LIMIT = "3g"        # hard cap on the semgrep container
SEMGREP_MAX_MEMORY_MB = 2000       # semgrep's own per-rule budget (< the cap)
SEMGREP_MAX_TARGET_BYTES = 2_000_000
CODEQL_RAM_MB = 2000               # native heap, competes with the Docker VM
CODEQL_THREADS = 1                 # --threads=0 splits the heap and OOMs
# Above this many .js files a whole-package CodeQL database will not build
# inside the RAM budget, so the scan falls back to the changed files and the
# report says so -- an honest narrow scan beats an OOM.
CODEQL_MAX_FILES = 1500

# Per-category CSV of per-stage evasion labels, keyed by repository.
CSV_PREFIX = "evasion-results"

# Substrings that mean the HOST/Docker failed (not the benchmark) -- a full disk,
# a dead daemon, an OOM-killed container. When seen, we must report `infra-error`
# rather than silently mis-bucketing the entry as a benchmark/exploit failure.
INFRA_MARKERS = (
    "no space left on device",
    "cannot connect to the docker daemon",
    "error setting up pivot",
    "failed to extract layer",
    "cannot allocate memory",
    "system cannot find the file specified",
)

# What each terminal status tells you about WHERE the problem is. Printed as a
# legend after the summary so a failing run is immediately actionable.
FAULT_CLASS = {
    "minimized":                  "OK   success (minimized; semgrep not run)",
    "minimized+evaded":           "OK   success (minimized + evaded semgrep)",
    "minimized+partial-evade":    "OK   success (minimized; semgrep only partly evaded)",
    "infra-error":                "SETUP    host/Docker failure (disk, daemon, OOM) -- rerun after fixing",
    "image-failed":               "SETUP    Dockerfile.fixed build failed (bad version pin / 404)",
    "npm-fallback":               "SETUP    no git tree to revert (npm-installed, not cloned)",
    "missing-patch-or-test":      "SETUP    benchmark folder missing patch.txt or *.test.js",
    "poc-no-assertions":          "EXPLOIT  *.test.js has no assertions -- jest passes it unconditionally",
    "poc-ignores-package":        "EXPLOIT  *.test.js never require()s the package -- oracle is package-independent",
    "poc-self-fires-on-revert":   "EXPLOIT  revert reproduces, but so does a stubbed-out package -- broken PoC",
    "poc-timeout":                "EXPLOIT  *.test.js hangs instead of deciding -- unusable as an oracle",
    "testdeps-clobbered-tree":    "SETUP    test-dep install reinstalled the package from the vulnerable package.json pin",
    "revert-apply-failed":        "SETUP    patch.txt won't reverse-apply (lockfile/built/drifted hunks)",
    "rebuild-failed":             "SETUP    compiled package: revert applied but `npm run build` failed, runtime tree still fixed",
    "revert-applied-no-repro":    "BENCHMARK revert applied but exploit doesn't reproduce (vuln needs more than the patch)",
    "baseline-already-vulnerable: exploit-self-fires":
                                  "EXPLOIT  *.test.js fires WITHOUT the package -- broken PoC",
    "baseline-already-vulnerable: image-not-fixed":
                                  "BENCHMARK fixed image still vulnerable (wrong fixed version/commit)",
    "baseline-already-vulnerable": "?        exploit passes on the fixed tree (cause undetermined)",
}


# First token of each FAULT_CLASS string -> a short, sortable CSV bucket. This
# is surfaced as the `outcome` column up front so a glance at the CSV shows WHERE
# each row failed (or that it succeeded) without scrolling to the trailing
# free-text `status`.
_OUTCOME_BY_FAULT = {
    "OK": "ok",
    "SETUP": "setup-fail",
    "BENCHMARK": "benchmark-fail",
    "EXPLOIT": "exploit-fail",
}


def outcome_of(status):
    """Bucket a terminal status into ok / setup-fail / benchmark-fail /
    exploit-fail / unknown, reusing the FAULT_CLASS legend."""
    if not status:
        return "unknown"
    base = re.sub(r" \(ci:[^)]*\)$", "", status)
    if base.endswith("-EXPLOIT-BROKEN"):
        return "exploit-fail"
    fault = FAULT_CLASS.get(base, "")
    return _OUTCOME_BY_FAULT.get(fault.split(None, 1)[0] if fault else "", "unknown")


def is_infra(*results):
    """True if any CompletedProcess output looks like a host/Docker failure."""
    for r in results:
        if r is None:
            continue
        blob = ((getattr(r, "stdout", "") or "") + (getattr(r, "stderr", "") or "")).lower()
        if any(m in blob for m in INFRA_MARKERS):
            return True
    return False


# An inert, infinitely-chainable stand-in for the package under test. Every
# property access / call / construction returns the same proxy, and it stringifies
# to its (harmless) function source so `eval('('+stub+')')`-style PoCs don't crash.
# If the exploit test still PASSES with this swapped in for the real package, the
# exploit never needed the package -> the PoC is self-firing (broken).
SELF_FIRE_STUB = (
    "var t = function stub(){ return out; };\n"
    "var out = new Proxy(t, {\n"
    "  get: function(o,p,r){ return (typeof p==='symbol'||p==='toString'||"
    "p==='valueOf'||p==='constructor'||p==='prototype') ? Reflect.get(o,p,r) : out; },\n"
    "  apply: function(){ return out; },\n"
    "  construct: function(){ return out; }\n"
    "});\n"
    "module.exports = out;\n"
)

# --------------------------------------------------------------------------- #
# transform catalog
# --------------------------------------------------------------------------- #
# Semantics-preserving rewrites of the reverted (vulnerable) code that keep the
# exploit firing but stop a detector from reporting it. Every entry is applied
# with `sed -E` to the scanned files and is then gated by the exploit test, so a
# rewrite that changes behaviour is rejected by the oracle rather than trusted.
#
# Transforms are grouped by the LAYER of the detector they attack, because the
# two detectors fail for different reasons and a rewrite that beats one is
# usually irrelevant to the other:
#
#   flow        break the DATAFLOW from the source to the sink. This is what
#               CodeQL needs -- every CodeQL alert in the analysis CSVs
#               (`Unsafe shell command constructed from library input`,
#               `Uncontrolled data used in path expression`,
#               `Prototype-polluting assignment`, `Polynomial regular expression
#               used on uncontrolled data`) is a taint query: no path from
#               library input to the sink, no alert. Syntactic aliasing does
#               nothing to these.
#   sink        stop the sink EXPRESSION from matching. This is what semgrep's
#               syntactic rules need (`eval-detected`, `detect-child-process`,
#               `mini-shell-exec-nonliteral`, `detect-non-literal-regexp`,
#               `mini-prototype-pollution-path-write`, ...). Hiding the callee or
#               the property name is enough. It also removes CodeQL sinks whose
#               recognition depends on a resolvable member name.
#   resolution  stop the sink RESOLVING at the import, rather than at the call.
#               CodeQL recognises `child_process.exec` via moduleMember(<constant
#               module>, <constant member>); make either non-constant and the
#               sink node is never created, whatever the local alias is called
#               or how it is later invoked. Reported separately from `sink` for
#               the same reason as `decoy`: "evades because sink resolution is
#               name-based" is a claim about the detector's modelling, not about
#               whether the vulnerability is detectable in principle.
#   aggressive  rewrites with a real chance of changing unrelated code on the
#               same line; only tried when the rule they target actually fired.
#   decoy       rewrites that change NOTHING semantically and exist purely to
#               trip a rule's own escape hatch (the mini ruleset's
#               `pattern-not-regex: (__proto__|hasOwnProperty|...)`). Reported
#               separately: "evades because the rule has an opt-out" is a claim
#               about the rule, not about detectability.
#
# sed is line-oriented, so every pattern below is written to match a single-line
# call site; a sink split across lines is simply not rewritten (a safe miss).

_ID = r"[A-Za-z_$][A-Za-z0-9_$]*"

# Prelude helpers, injected once at the top of each rewritten file (after any
# shebang / "use strict"). Only the helpers the chosen transforms need are added.
HELPERS = {
    # Value-preserving, dataflow-severing launder step: rebuilding a string from
    # its char codes is the identity on the value, but neither String.fromCharCode
    # nor String#charCodeAt is a taint-propagation step in CodeQL's JS libraries
    # or in semgrep's taint mode, so the result carries no taint. Non-strings pass
    # through untouched so the wrapper is safe on any argument.
    "__sbLaunder": (
        "var __sbLaunder = function (v) {\n"
        "  if (typeof v !== 'string') { return v; }\n"
        "  var out = '', i = 0;\n"
        "  for (; i < v.length; i++) { out += String.fromCharCode(v.charCodeAt(i)); }\n"
        "  return out;\n"
        "};\n"
    ),
    # __sbLaunder over a whole argument, recursing into plain objects and arrays.
    # The OBJECT case is what prototype pollution needs: the tainted thing there
    # is a KEY, not a value, so laundering the strings hanging off the object is
    # not enough -- the keys have to be rebuilt too.
    #
    # Object.defineProperty, not `o[k] = v`: a payload from JSON.parse carries
    # `__proto__` as an OWN enumerable property, and assigning it back with `=`
    # would invoke the prototype setter and destroy the payload instead of
    # copying it. defineProperty preserves own-property semantics for every key.
    #
    # Non-plain objects (class instances, buffers, streams) are passed through
    # untouched rather than reconstructed: rebuilding one loses its prototype and
    # breaks the package long before any detector gets a say.
    "__sbLaunderDeep": (
        "var __sbLaunderDeep = function (v, d) {\n"
        "  if (d === void 0) { d = 4; }\n"
        "  if (typeof v === 'string') { return __sbLaunder(v); }\n"
        "  if (d <= 0 || v === null || typeof v !== 'object') { return v; }\n"
        "  if (Array.isArray(v)) {\n"
        "    var a = [], i = 0;\n"
        "    for (; i < v.length; i++) { a[i] = __sbLaunderDeep(v[i], d - 1); }\n"
        "    return a;\n"
        "  }\n"
        "  var p = Object.getPrototypeOf(v);\n"
        "  if (p !== Object.prototype && p !== null) { return v; }\n"
        "  var o = Object.create(p), k;\n"
        "  for (k in v) {\n"
        "    if (Object.prototype.hasOwnProperty.call(v, k)) {\n"
        "      Object.defineProperty(o, __sbLaunder(k), {\n"
        "        value: __sbLaunderDeep(v[k], d - 1),\n"
        "        enumerable: true, writable: true, configurable: true });\n"
        "    }\n"
        "  }\n"
        "  return o;\n"
        "};\n"
    ),
    # Launder at the EXPORT BOUNDARY. CodeQL's "library input" source is whatever
    # crosses module.exports, and it does not care what syntactic shape the
    # parameter list has -- which is exactly why params->launder and
    # methods->launder kept matching nothing on packages that use destructuring,
    # defaults, class methods or an object literal of arrows. One wrapper at the
    # boundary covers every shape at once.
    #
    # `this` and the full argument list are forwarded, own function properties
    # are carried over, and .prototype is aliased so an exported constructor
    # still works under `new`.
    "__sbWrap": (
        "var __sbWrap = function (v, d) {\n"
        "  if (d === void 0) { d = 2; }\n"
        "  if (typeof v === 'function') {\n"
        "    var f = function () {\n"
        "      var a = Array.prototype.slice.call(arguments), i = 0;\n"
        "      for (; i < a.length; i++) { a[i] = __sbLaunderDeep(a[i]); }\n"
        "      return v.apply(this, a);\n"
        "    };\n"
        "    for (var k in v) {\n"
        "      if (Object.prototype.hasOwnProperty.call(v, k)) {\n"
        "        try { f[k] = __sbWrap(v[k], d - 1); } catch (e) {}\n"
        "      }\n"
        "    }\n"
        "    try { f.prototype = v.prototype; } catch (e) {}\n"
        "    return f;\n"
        "  }\n"
        "  if (d > 0 && v !== null && typeof v === 'object' && !Array.isArray(v)) {\n"
        "    for (var k2 in v) {\n"
        "      if (Object.prototype.hasOwnProperty.call(v, k2) &&\n"
        "          typeof v[k2] === 'function') {\n"
        "        try { v[k2] = __sbWrap(v[k2], d - 1); } catch (e) {}\n"
        "      }\n"
        "    }\n"
        "  }\n"
        "  return v;\n"
        "};\n"
    ),
    # o[k] = v through one level of indirection. Reflect.set walks the prototype
    # chain and triggers the `__proto__` setter exactly like the assignment did,
    # so pollution is preserved; the assignment SHAPE that every prototype-
    # pollution rule keys on is gone.
    "__sbSet": (
        "var __sbSet = function (o, k, v) { var s = Reflect.set; return s(o, k, v); };\n"
    ),
    # new RegExp(...) without the `new RegExp` shape. Reflect.construct forwards
    # every argument, so flags and patterns behave identically.
    "__sbRe": (
        "var __sbRe = function () {\n"
        "  return Reflect.construct(RegExp, Array.prototype.slice.call(arguments));\n"
        "};\n"
    ),
}


def _hide_member(names):
    """`x.name(` -> `x[__sbLaunder("name")](` for each name.

    Identical at runtime, but the property name is no longer a literal, so
    semgrep patterns of the form `$X.name(...)` cannot match and CodeQL cannot
    resolve the member -- which is how it recognises `child_process.exec`,
    `fs.readFile` and friends as sinks in the first place.
    """
    return [(rf"\.{n}\(", rf'[__sbLaunder("{n}")](') for n in names]


def _launder_arg(names):
    """Wrap the FIRST argument of `x.name(...)` in the launder helper.

    Only fires when that argument contains no comma or paren of its own, which
    keeps the rewrite from swallowing a trailing callback (`exec(cmd, cb)`) --
    a miss is safe, a mangled call is not.
    """
    return [(rf"\.{n}\(([^,()]+)([,)])", rf".{n}(__sbLaunder(\1)\2") for n in names]


# Sinks per category. Kept as data so a new benchmark class only needs a list.
_SHELL_SINKS = ["exec", "execSync"]
_PATH_SINKS = ["readFile", "readFileSync", "createReadStream", "sendFile",
               "open", "openSync", "stat", "statSync", "lstat", "lstatSync",
               "realpath", "realpathSync", "readdir", "readdirSync"]
_PATH_BUILDERS = ["join", "resolve", "normalize"]
_XSS_SINKS = ["end", "write", "send"]
_REGEX_SINKS = ["test", "match", "exec", "replace", "search", "split"]

# The child_process members CodeQL resolves as command-execution sinks. Wider
# than _SHELL_SINKS on purpose: _SHELL_SINKS lists the two that take a shell
# STRING (the ones worth laundering an argument on), while this list is every
# member whose NAME the sink resolver keys on at the import site.
_CP_SINKS = ["execFileSync", "execFile", "execSync", "exec",
             "spawnSync", "spawn", "fork"]
# Modules CodeQL ships a command-execution model for. Hiding the module STRING
# is the fallback for packages that never name a child_process member of their
# own (`require('async-execute')`, `require('shelljs').exec`).
_SINK_MODULES = ["child_process", "node:child_process", "shelljs",
                 "async-execute", "execa", "cross-spawn"]

# The remote-flow sources CodeQL names in its alert messages ("This path depends
# on a user-provided value", "depends on library input"). Laundering at the
# SOURCE is strictly better than laundering at the sink: the sink's tainted
# argument is often not the first one (`path.join(root, req.url)`), and one
# rewrite at the source covers every sink the value later reaches.
_TAINT_SOURCES = [r"req\.url", r"req\.query", r"req\.params", r"req\.body",
                  r"request\.url", r"process\.argv", r"process\.env"]


def _launder_params():
    """Launder a function's own parameters on entry.

    The other source rewrite only reaches request/process globals, but the
    source that dominates this benchmark is the *exported function's parameter*
    -- CodeQL calls it "library input", secbench-taint.yml spells it
    `function $F($SRC, ...)`, and for a library the API caller IS the attacker.
    Inserting `p = __sbLaunder(p);` as the first statement leaves every value
    identical and every later use untainted.

    Restricted to one- and two-parameter functions with plain identifier
    parameters: destructuring, defaults and TypeScript annotations are left
    alone rather than rewritten into something that no longer parses.
    """
    p = r"[A-Za-z_$][A-Za-z0-9_$]*"
    # `async function f(a)` contains `function f(a)`, so it is covered too.
    head = rf"(function([ \t]+{p})?[ \t]*"
    return [
        (rf"{head}\(({p})\)[ \t]*\{{)", r"\1 \3 = __sbLaunder(\3);"),
        (rf"{head}\(({p}),[ \t]*({p})\)[ \t]*\{{)",
         r"\1 \3 = __sbLaunder(\3); \4 = __sbLaunder(\4);"),
        # Arrow functions with a block body. A package that exports an object
        # literal of arrows (`module.exports = { run: config => {...} }`) has no
        # `function` keyword anywhere, so without these the whole transform is a
        # no-op on exactly the modern packages CodeQL flags for library input.
        (rf"(\(({p})\)[ \t]*=>[ \t]*\{{)", r"\1 \2 = __sbLaunder(\2);"),
        (rf"(\(({p}),[ \t]*({p})\)[ \t]*=>[ \t]*\{{)",
         r"\1 \2 = __sbLaunder(\2); \3 = __sbLaunder(\3);"),
        # single parameter without parentheses: `config => {`
        (rf"(^|[^A-Za-z0-9_$.)])(({p})[ \t]*=>[ \t]*\{{)", r"\1\2 \3 = __sbLaunder(\3);"),
    ]


def _launder_methods():
    """Launder the parameters of object-literal / class shorthand methods.

    Kept apart from _launder_params() on purpose: `name(arg) {` is also the shape
    of `if (cond) {`, `while (cond) {` and `catch (err) {`, and laundering a
    `const` binding there raises "Assignment to constant variable". The exploit
    oracle rejects that, and as a separate transform the failure costs only this
    rewrite instead of taking the safe parameter laundering down with it.
    """
    p = r"[A-Za-z_$][A-Za-z0-9_$]*"
    kw = "if|for|while|switch|catch|return|typeof|function|do|else"
    return [
        # leading whitespace anchors it to a statement/member position, and the
        # keyword alternation is excluded by requiring a non-keyword first token
        (rf"(^[ \t]*(async[ \t]+)?({p})[ \t]*\(({p})\)[ \t]*\{{)",
         r"\1 \4 = __sbLaunder(\4);"),
        # undo the damage on the control-flow keywords the pattern above catches
        (rf"^([ \t]*)({kw})([ \t]*\([^)]*\)[ \t]*\{{)[ \t]*{p} = __sbLaunder\({p}\);",
         r"\1\2\3"),
    ]


def _launder_sources(indexed=False):
    """Wrap each known taint source (plus one property access) in the helper.

    `indexed` also swallows a following subscript, which is what actually
    carries the taint for the array-shaped sources (`process.argv[2]`,
    `req.body[k]`) -- laundering the array itself leaves the element tainted.
    It is a separate transform because a subscript on the LEFT of an assignment
    would be wrapped into a syntax error; when that happens the plain variant is
    still in the candidate set.
    """
    tail = r"(\.[A-Za-z_$][A-Za-z0-9_$]*)?" + (r"(\[[^]\[]*\])?" if indexed else "")
    return [(rf"(^|[^_A-Za-z0-9$.])({s}{tail})", r"\1__sbLaunder(\2)")
            for s in _TAINT_SOURCES]


TRANSFORMS = [
    # ---------------- every category -------------------------------------- #
    # Cut the taint at its root. This is the transform aimed squarely at CodeQL:
    # `Uncontrolled data used in path expression`, `Unsafe shell command
    # constructed from library input`, `Polynomial regular expression used on
    # uncontrolled data` and the XSS queries are all reachability from one of
    # these sources, and none of them survives a value that arrives untainted.
    {"name": "source->launder", "layer": "flow", "order": 5,
     "categories": ["code-injection", "command-injection", "path-traversal",
                    "prototype-pollution", "redos"],
     "helpers": ["__sbLaunder"], "steps": _launder_sources()},
    # The "library input" source: for a package, the API caller is the attacker,
    # so the exported function's own parameters are the taint source. This is
    # what CodeQL's shell/path/prototype-pollution queries start from and what
    # secbench-taint.yml spells `function $F($SRC, ...)`.
    {"name": "params->launder", "layer": "flow", "order": 4,
     "categories": ["code-injection", "command-injection", "path-traversal",
                    "prototype-pollution", "redos"],
     "helpers": ["__sbLaunder"], "steps": _launder_params()},
    {"name": "methods->launder", "layer": "flow", "order": 4,
     "categories": ["code-injection", "command-injection", "path-traversal",
                    "prototype-pollution", "redos"],
     "helpers": ["__sbLaunder"], "steps": _launder_methods()},
    # Launder every argument that crosses module.exports, whatever shape the
    # exported functions have. This is the shape-independent replacement for
    # params->launder / methods->launder, which between them reported "matched
    # nothing" 38 times across the campaign logs because they enumerate
    # syntactic parameter forms and real packages use destructuring, defaults,
    # class methods and object literals of arrows.
    #
    # An APPEND, not a substitution: the wrapper has to run after the module has
    # finished assigning its exports, so it goes at the end of the file. Guarded
    # on the file actually having exports (see apply_transforms).
    {"name": "exports->launder", "layer": "flow", "order": 3,
     "categories": ["code-injection", "command-injection", "path-traversal",
                    "prototype-pollution", "redos"],
     "helpers": ["__sbLaunder", "__sbLaunderDeep", "__sbWrap"], "steps": [],
     "append": ("\n/* SecBench.js: launder at the export boundary */\n"
                "module.exports = __sbWrap(module.exports);\n")},
    {"name": "source->launder+index", "layer": "flow", "order": 6,
     "categories": ["code-injection", "command-injection", "path-traversal",
                    "prototype-pollution", "redos"],
     "helpers": ["__sbLaunder"], "steps": _launder_sources(indexed=True)},

    # ---------------- code injection ------------------------------------- #
    # eval(X) -> run X as a Function body with the module locals injected;
    # evades both the eval(...) and new Function(...) syntactic rules. Preferred
    # over indirect (0,eval) because it preserves access to module locals
    # (require/module/exports) that real payloads depend on.
    # The payload is wrapped in `return (...)` because eval EVALUATES an
    # expression while a Function body only executes statements: without the
    # return, `eval("[" + x + "]")` yields undefined and every caller breaks.
    {"name": "eval->Function+locals", "layer": "sink", "order": 20,
     "categories": ["code-injection", "command-injection"],
     # `[^()]*`, not `[^)]*`: an argument containing a call of its own has no
     # single closing paren to anchor on, and matching the FIRST one splices the
     # replacement into the middle of the expression. Not matching is safe;
     # mangling the line corrupts code the patch never touched.
     "steps": [(r"(^|[^._A-Za-z0-9])eval\(([^()]*)\)",
                r'\1new (0,Function)("require","module","exports",'
                r'"return ("+(\2)+")")(require,module,exports)')]},
    # `eval('<local> = <expr>;')` -- the shape that assigns INTO the enclosing
    # scope, which is the one thing indirect eval cannot do. Hoisting the
    # assignment out of the string lets the remaining expression run through
    # indirect eval with identical results.
    {"name": "eval-assign->hoisted-indirect", "layer": "sink", "order": 19,
     "categories": ["code-injection"],
     "steps": [(r"(^|[^._A-Za-z0-9])eval\('([A-Za-z_$][A-Za-z0-9_$]*) = (.*);'\)",
                r"\1\2 = (0,eval)('(\3)')")]},
    # Direct eval, parenthesised. Semantically IDENTICAL (parentheses do not
    # make an eval indirect), so unlike the rewrites above it never breaks a
    # payload that needs the local scope -- it only wins if the rule's matcher
    # is confused by the parens, which is worth one cheap measurement.
    {"name": "eval->parenthesised", "layer": "sink", "order": 18,
     "categories": ["code-injection", "command-injection"],
     "steps": [(r"(^|[^._A-Za-z0-9])eval\(", r"\1(eval)(")]},
    # any Function(...) call -> (0,Function)(...)   (covers `new Function(` and
    # bare `Function(`; the callee is no longer a bare identifier)
    {"name": "Function-call->indirect", "layer": "sink", "order": 21,
     "categories": ["code-injection", "command-injection"],
     "steps": [(r"(^|[^._A-Za-z0-9])Function\(", r"\1(0,Function)(")]},
    # last resort: indirect eval (only correct when the payload needs no locals)
    {"name": "eval->indirect", "layer": "sink", "order": 22,
     "categories": ["code-injection", "command-injection"],
     "steps": [(r"(^|[^._A-Za-z0-9])eval\(", r"\1(0,eval)(")]},
    # `vm.runInNewContext(` etc. -- same member-hiding trick as the other sinks
    {"name": "vm->hidden-member", "layer": "sink", "order": 23,
     "categories": ["code-injection"], "helpers": ["__sbLaunder"],
     "steps": _hide_member(["runInThisContext", "runInNewContext",
                            "runInContext", "compileFunction"])},

    # ---------------- command injection ---------------------------------- #
    # Hide the sink member at the IMPORT rather than at the call.
    #
    # This is the transform the campaign was missing. shell-sink->hidden-member
    # is anchored on `.exec(`, so it needs the CALL to be a member expression --
    # and in every command-injection entry that CodeQL still detected, it is not:
    #
    #   const exec = require('child_process').exec;      exec(cmd, cb)
    #   const proc = require('child_process').exec;      proc(cmd, cb)     <- alias
    #   const execSync = require('child_process').execSync;  execSync(cmd)
    #   const exec = require('./exec');   // promisify wrapper in another file
    #
    # The call sites differ package to package; the import does not. CodeQL
    # resolves `child_process.exec` through moduleMember(<constant module>,
    # <constant member>), so a member key it cannot constant-fold means the sink
    # node is never created and the taint query has nothing to reach -- whatever
    # the local alias ends up being called or how it is later invoked.
    #
    # The trailing `([^A-Za-z0-9_$]|$)` guard matters twice: it stops `exec`
    # matching inside `execSync`, and the `$` alternative covers an import with
    # no trailing semicolon (growl's `var exec = require('child_process').exec`).
    {"name": "require-member->hidden", "layer": "resolution", "order": 15,
     "categories": ["command-injection", "code-injection", "path-traversal"],
     "helpers": ["__sbLaunder"],
     #
     # The DESTRUCTURED import is the same sink wearing different clothes, and
     # it is common enough to matter: alfred-workflow-nodejs opens with
     # `const { exec } = require('child_process');`, and portprocesses' exec.js
     # is the reason nothing could reach that entry. Rewriting it to the member
     # form both removes the resolvable member name and leaves the binding with
     # the identical value, so every later `exec(cmd)` call site is untouched.
     # Single-binding forms only -- `const { exec, spawn } = ...` is left alone
     # rather than rewritten into something that no longer parses.
     "steps": [(rf"require\((['\"][^'\"]+['\"])\)[ \t]*\.({'|'.join(_CP_SINKS)})"
                r"([^A-Za-z0-9_$]|$)",
                r'require(\1)[__sbLaunder("\2")]\3'),
               # const { exec } = require('child_process')
               (rf"(const|let|var)[ \t]*\{{[ \t]*({'|'.join(_CP_SINKS)})[ \t]*\}}"
                rf"[ \t]*=[ \t]*require\((['\"][^'\"]+['\"])\)",
                r'\1 \2 = require(\3)[__sbLaunder("\2")]'),
               # const { exec: run } = require('child_process')
               (rf"(const|let|var)[ \t]*\{{[ \t]*({'|'.join(_CP_SINKS)})[ \t]*:"
                rf"[ \t]*({_ID})[ \t]*\}}[ \t]*=[ \t]*require\((['\"][^'\"]+['\"])\)",
                r'\1 \3 = require(\4)[__sbLaunder("\2")]')]},
    # Fallback for packages that never name a child_process member of their own
    # because the shell call lives behind a wrapper module CodeQL models
    # directly (async-git's `require('async-execute')`, dns-sync's
    # `require('shelljs')`). Hiding the module STRING stops the import resolving
    # at all, which takes the model down with it.
    #
    # Ordered AFTER require-member->hidden and kept separate on purpose: a
    # non-constant require() argument is what semgrep's `dynamic-require` rule
    # matches, so this can trade a CodeQL alert for a semgrep one. Reach for it
    # only when the member rewrite had nothing to match.
    {"name": "require-module->dynamic", "layer": "resolution", "order": 16,
     "categories": ["command-injection", "code-injection"],
     "helpers": ["__sbLaunder"],
     # Two steps rather than one with a `(['\"])...\1` backreference: sed's ERE
     # backreference support is not portable across the busybox/GNU sed the
     # benchmark images ship, and a pattern that silently never matches is
     # indistinguishable here from a transform that had nothing to rewrite.
     "steps": [(rf"require\('({'|'.join(_SINK_MODULES)})'\)",
                r"require(__sbLaunder('\1'))"),
               (rf'require\("({"|".join(_SINK_MODULES)})"\)',
                r'require(__sbLaunder("\1"))')]},
    # Kills `detect-child-process`, `mini-shell-exec-nonliteral` AND CodeQL's
    # `Unsafe shell command constructed from library input` (40 alerts across the
    # CSVs), because that query's sink is `child_process.exec` resolved BY NAME.
    {"name": "shell-sink->hidden-member", "layer": "sink", "order": 20,
     "categories": ["command-injection", "code-injection", "redos",
                    "path-traversal"],
     "helpers": ["__sbLaunder"], "steps": _hide_member(_SHELL_SINKS)},
    # Sever the taint path into the command string. Applied BEFORE the member is
    # hidden (lower order), since it matches the `.exec(` spelling.
    {"name": "shell-arg->launder", "layer": "flow", "order": 10,
     "categories": ["command-injection", "code-injection", "redos",
                    "path-traversal"],
     "helpers": ["__sbLaunder"], "steps": _launder_arg(_SHELL_SINKS)},

    # ---------------- path traversal ------------------------------------- #
    # CodeQL's `Uncontrolled data used in path expression` (24 alerts) is a taint
    # query from the request to a filesystem path argument: laundering the joined
    # path breaks the path, hiding the fs member removes the sink.
    {"name": "path-arg->launder", "layer": "flow", "order": 10,
     "categories": ["path-traversal"], "helpers": ["__sbLaunder"],
     "steps": _launder_arg(_PATH_SINKS + _PATH_BUILDERS)},
    {"name": "path-sink->hidden-member", "layer": "sink", "order": 20,
     "categories": ["path-traversal"], "helpers": ["__sbLaunder"],
     "steps": _hide_member(_PATH_SINKS)},
    # `path.join(`/`path.resolve(` is what `path-join-resolve-traversal` matches.
    # Anchored on the `path` receiver so Array#join is left alone.
    {"name": "path-builder->hidden-member", "layer": "sink", "order": 21,
     "categories": ["path-traversal", "command-injection"],
     "helpers": ["__sbLaunder"],
     "steps": [(rf"(^|[^._A-Za-z0-9])({_ID})\.({'|'.join(_PATH_BUILDERS)})\(",
                r'\1\2[__sbLaunder("\3")](')]},
    # The reflected/stored-XSS alerts CodeQL reports in the same server files
    # ride the same request->response taint path.
    {"name": "response-arg->launder", "layer": "flow", "order": 11,
     "categories": ["path-traversal"], "helpers": ["__sbLaunder"],
     "steps": _launder_arg(_XSS_SINKS)},

    # ---------------- prototype pollution -------------------------------- #
    # `$O[$K] = $V` is the shape behind mini-prototype-pollution-path-write,
    # mini-unsafe-forin-copy, prototype-pollution-loop AND CodeQL's
    # `Prototype-polluting assignment` (24 alerts). Route it through Reflect.set
    # -- same prototype-chain semantics, no assignment to a computed property.
    # The literal-key guard (`[^]"']`) keeps `o["name"] = v` untouched.
    {"name": "pp-assign->reflect-set", "layer": "sink", "order": 20,
     "categories": ["prototype-pollution"],
     "steps": [(rf"({_ID}(\.{_ID})*)\[([^]\"'][^]]*)\][ \t]*=[ \t]*([^=;][^;]*);",
                r"Reflect.set(\1, \3, \4);")]},
    # Same rewrite behind one more level of indirection, for the case where the
    # detector models Reflect.set itself as a property write.
    {"name": "pp-assign->helper-set", "layer": "sink", "order": 20,
     "categories": ["prototype-pollution"], "helpers": ["__sbSet"],
     "steps": [(rf"({_ID}(\.{_ID})*)\[([^]\"'][^]]*)\][ \t]*=[ \t]*([^=;][^;]*);",
                r"__sbSet(\1, \3, \4);")]},
    # `Prototype-polluting function` is a taint query over the copy loop; cutting
    # the key's taint is enough even when the write shape stays.
    {"name": "pp-key->launder", "layer": "flow", "order": 10,
     "categories": ["prototype-pollution"],
     "helpers": ["__sbLaunder"],
     "steps": [(rf"({_ID}(\.{_ID})*)\[({_ID})\][ \t]*=[ \t]*([^=;][^;]*);",
                r"\1[__sbLaunder(\3)] = \4;")]},
    # Pure rule-brittleness probe: the mini prototype-pollution rules carry
    # `pattern-not-regex: (__proto__|hasOwnProperty|Object\.create\(null\))`, so
    # naming `__proto__` in a COMMENT suppresses them with no code change at all.
    {"name": "pp-guard-mention(decoy)", "layer": "decoy", "order": 90,
     "categories": ["prototype-pollution"],
     "steps": [(rf"({_ID}(\.{_ID})*\[[^]\"'][^]]*\][ \t]*=[ \t]*[^=;][^;]*;)",
                r"\1 /* key is not __proto__ by construction */")]},

    # ---------------- ReDoS ----------------------------------------------- #
    # `Polynomial regular expression used on uncontrolled data` (29 alerts) and
    # `Inefficient regular expression`: the first is a taint query into the
    # matched STRING, so laundering the subject removes it.
    {"name": "regex-subject->launder", "layer": "flow", "order": 10,
     "categories": ["redos", "prototype-pollution"], "helpers": ["__sbLaunder"],
     "steps": _launder_arg(_REGEX_SINKS)},
    # `new RegExp($X)` is exactly what detect-non-literal-regexp and
    # mini-regexp-from-variable match.
    {"name": "regexp-ctor->helper", "layer": "sink", "order": 20,
     "categories": ["redos", "prototype-pollution"], "helpers": ["__sbRe"],
     "steps": [(r"(^|[^._A-Za-z0-9])new[ \t]+RegExp\(", r"\1__sbRe(")]},
    # `Inefficient regular expression` is a pure analysis of the PATTERN, with no
    # taint involved, so the only way out is to stop the pattern being a literal.
    # Restricted to literals with no backslash/quote/whitespace so the pattern can
    # be re-quoted into a JS string without escaping; ReDoS patterns using \s, \d
    # or a character class are deliberately left alone rather than mangled.
    {"name": "regex-literal->runtime(aggressive)", "layer": "aggressive", "order": 30,
     "categories": ["redos"], "helpers": ["__sbRe", "__sbLaunder"],
     "steps": [(r"([=:(,][ \t]*)/([^/\\\"'[:space:]]+)/([gimsuy]*)",
                r'\1__sbRe(__sbLaunder("\2"), "\3")')]},
]

TRANSFORMS_BY_NAME = {t["name"]: t for t in TRANSFORMS}

# Which transforms to reach for when a given detector rule fires. Keys are
# regexes matched (case-insensitively) against the semgrep check_id or the
# CodeQL rule name/message exactly as they appear in the analysis CSVs, so the
# search is driven by what the detector actually said rather than by guesswork.
RULE_TRANSFORMS = [
    # CodeQL phrases every taint alert as "depends on a user-provided value" /
    # "library input", so the source launder is the first thing to reach for
    # whenever one of those appears, whatever the query was.
    (r"user-provided value|library input|uncontrolled data|"
     r"environment values|tainted",
     ["exports->launder", "params->launder", "methods->launder",
      "source->launder", "source->launder+index"]),
    (r"eval-detected|dynamic-code-evaluation|secbench-eval-call|"
     r"secbench-function-constructor|detect-eval-with-expression|code-injection",
     ["eval->parenthesised", "eval-assign->hoisted-indirect",
      "eval->Function+locals", "Function-call->indirect", "eval->indirect"]),
    (r"secbench-vm-execution|vm-",
     ["vm->hidden-member"]),
    # NOTE: each pattern must match BOTH spellings a rule can arrive in --
    # the human name the analysis CSVs record ("Unsafe shell command constructed
    # from library input") AND the SARIF ruleId the live scan emits
    # ("js/shell-command-constructed-from-input"). rule_names() collects both,
    # and matching only the prose meant the sink-hiding transforms were never
    # tried on any CodeQL-detected entry -- which is precisely the layer most
    # likely to work against CodeQL, whose shell/path sinks are recognised BY
    # MEMBER NAME.
    (r"detect-child-process|shell-exec-nonliteral|command-injection|"
     r"unsafe shell command|shell command built from|"
     r"js/shell-command-constructed-from-input|"
     r"js/shell-command-injection-from-environment|"
     r"js/command-line-injection|js/unsafe-shell-command-construction",
     ["shell-arg->launder", "require-member->hidden", "shell-sink->hidden-member",
      "require-module->dynamic"]),
    (r"path-join-resolve-traversal|path-traversal|path injection|"
     r"uncontrolled data used in path expression|"
     r"js/path-injection|js/zipslip|js/tainted-path",
     ["path-arg->launder", "require-member->hidden", "path-sink->hidden-member",
      "path-builder->hidden-member"]),
    (r"cross-site scripting|xss|js/reflected-xss|js/stored-xss",
     ["response-arg->launder"]),
    (r"prototype-polluting assignment|prototype-pollution-loop|"
     r"prototype-pollution-path-write|unsafe-forin-copy|"
     r"js/prototype-polluting-assignment|js/prototype-pollution",
     ["exports->launder", "pp-assign->reflect-set", "pp-assign->helper-set",
      "pp-key->launder", "pp-guard-mention(decoy)"]),
    (r"prototype-polluting function|js/prototype-pollution-utility",
     ["exports->launder", "pp-key->launder", "pp-assign->helper-set"]),
    (r"polynomial regular expression|regexp-from-variable|"
     r"detect-non-literal-regexp|js/polynomial-redos|js/regex-injection",
     ["regex-subject->launder", "regexp-ctor->helper"]),
    (r"inefficient regular expression|redos|js/redos",
     ["regex-subject->launder", "regexp-ctor->helper",
      "regex-literal->runtime(aggressive)"]),
    (r"js/code-injection|js/eval-call|js/unsafe-dynamic-method-access",
     ["eval->parenthesised", "eval->Function+locals", "eval->indirect",
      "Function-call->indirect"]),
]

# Rules seen in the analysis CSVs that no transform targets, with the reason.
# Surfaced in the report so an un-evaded finding is never silently unexplained.
UNTARGETED_RULES = {
    "insecure randomness": "quality/crypto rule, unrelated to the reverted sink",
    "unnecessary use of `cat` process": "code-quality rule, not a vulnerability",
    "incomplete multi-character sanitization": (
        "flags the fix's own sanitizer shape; reverting it is the point"),
    "dynamic-require": "no semantics-preserving rewrite that keeps require() static",
}


# --------------------------------------------------------------------------- #
# unified-diff hunk splitting
# --------------------------------------------------------------------------- #
def split_hunks(patch_text):
    """Parse a git patch into [(file, header_lines, hunk_text)] units.

    header_lines is the per-file preamble (diff --git / index / --- / +++);
    each hunk_text is one @@...@@ block. Emitting header_lines + any subset of a
    file's hunks yields an applyable patch.
    """
    lines = patch_text.splitlines(keepends=True)
    units, i, n = [], 0, len(lines)
    while i < n:
        if not lines[i].startswith("diff --git "):
            i += 1
            continue
        # collect this file's header (up to the first @@)
        start = i
        i += 1
        while i < n and not lines[i].startswith("@@ ") \
                and not lines[i].startswith("diff --git "):
            i += 1
        header = "".join(lines[start:i])
        m = re.search(r"^\+\+\+ b/(.*)$", header, re.MULTILINE)
        fpath = m.group(1).strip() if m else "?"
        # collect each hunk
        while i < n and lines[i].startswith("@@ "):
            hs = i
            i += 1
            while i < n and not lines[i].startswith("@@ ") \
                    and not lines[i].startswith("diff --git "):
                i += 1
            units.append((fpath, header, "".join(lines[hs:i])))
    return units


def build_partial(units, keep_idx):
    """Reassemble a patch from the hunk indices in keep_idx (grouped by file)."""
    out = []
    by_file = {}
    for idx in sorted(keep_idx):
        fpath, header, hunk = units[idx]
        by_file.setdefault((fpath, header), []).append(hunk)
    for (fpath, header), hunks in by_file.items():
        out.append(header)
        out.extend(hunks)
    return "".join(out)


# --------------------------------------------------------------------------- #
# line-level change units
# --------------------------------------------------------------------------- #
# A hunk carries three lines of context around the change. Minimizing at hunk
# granularity therefore reverts context as well, and reports "3 hunks" for what
# may be a single changed line. These split a patch into CHANGE GROUPS -- maximal
# runs of -/+ lines, i.e. exactly the lines the fix added, removed or modified --
# so the minimal revert is expressed in changed lines, never in surrounding ones.
#
# Turning a group OFF must be a no-op in BOTH directions, so its '+' lines (which
# exist in the fixed tree) become context and its '-' lines are dropped. What is
# left reverse-applies to revert only the groups that were kept.
def split_groups(patch_text):
    """Split a patch into per-changed-line-run units.

    Returns a list of dicts: {file, header, hunk, gid, lines} where `hunk` is the
    @@ line, `gid` is the group's index within that hunk and `lines` are its raw
    +/- lines. Feed the list to build_partial_lines().
    """
    units = []
    for fpath, header, hunk_text in split_hunks(patch_text):
        body = hunk_text.splitlines(keepends=True)
        at, rest = body[0], body[1:]
        gid, i, n = 0, 0, len(rest)
        while i < n:
            if rest[i][:1] not in ("+", "-"):
                i += 1
                continue
            start = i
            while i < n and (rest[i][:1] in ("+", "-")
                             or rest[i].startswith("\\ No newline")):
                i += 1
            units.append({"file": fpath, "header": header, "hunk": at,
                          "gid": gid, "lines": rest[start:i],
                          "span": (start, i)})
            gid += 1
    return units


def build_partial_lines(all_units, keep_idx):
    """Emit a patch that reverts ONLY the change groups in keep_idx.

    Groups that are not kept are neutralised in place: their '+' lines become
    context (they stay in the tree) and their '-' lines are dropped. Hunks left
    with no change at all are omitted. Line counts in the @@ header are left for
    `git apply --recount` to recompute.
    """
    keep = set(keep_idx)
    out, by_file = [], {}
    for idx, u in enumerate(all_units):
        by_file.setdefault((u["file"], u["header"]), {}) \
               .setdefault(u["hunk"], []).append((idx, u))
    for (fpath, header), hunks in by_file.items():
        emitted = []
        for at, groups in hunks.items():
            if not any(idx in keep for idx, _ in groups):
                continue        # nothing reverted in this hunk -> drop it
            # rebuild the hunk body: context lines interleaved with the groups
            body, cursor = [], 0
            src = groups[0][1]
            # reconstruct the original body from the group spans + the context
            # lines between them, which we recover from the hunk text itself
            full = _hunk_body(header, at, src)
            for idx, u in groups:
                s, e = u["span"]
                body.extend(full[cursor:s])
                if idx in keep:
                    body.extend(full[s:e])
                else:
                    for ln in full[s:e]:
                        if ln.startswith("+"):
                            body.append(" " + ln[1:])
                        # '-' lines and stray "\ No newline" markers are dropped
                cursor = e
            body.extend(full[cursor:])
            emitted.append(at + "".join(body))
        if emitted:
            out.append(header)
            out.extend(emitted)
    return "".join(out)


# split_groups() records spans into the hunk body, so the body has to be
# recoverable from (header, @@ line). Cache it the first time the hunk is seen.
_HUNK_BODIES = {}


def _hunk_body(header, at, unit):
    return _HUNK_BODIES[(header, at)]


def index_hunk_bodies(patch_text):
    """Populate the hunk-body cache build_partial_lines() reads."""
    _HUNK_BODIES.clear()
    for _f, header, hunk_text in split_hunks(patch_text):
        body = hunk_text.splitlines(keepends=True)
        _HUNK_BODIES[(header, body[0])] = body[1:]


# --------------------------------------------------------------------------- #
# container-side oracle
# --------------------------------------------------------------------------- #
BUILTINS = {
    "assert", "buffer", "child_process", "cluster", "crypto", "dgram", "dns",
    "events", "fs", "http", "https", "net", "os", "path", "process",
    "querystring", "readline", "stream", "string_decoder", "tls", "tty", "url",
    "util", "v8", "vm", "zlib", "timers", "console",
}


def test_requires(test_text, package=""):
    """Undeclared module names require()'d by the test (minus builtins).

    `package` is excluded along with every DEEP IMPORT of it. A PoC that does
    `require("axios/lib/utils")` or `require("highlight.js/lib/core")` is
    reaching into the package under test, which the image already installed --
    but the raw module name is not equal to the package name, so it used to
    survive into the install list and the caller ran

        npm install axios/lib/utils

    which npm reads as the GitHub shorthand <user>/<repo>. Besides never
    resolving, that install reconciles the whole tree against the benchmark's
    package.json -- which pins the VULNERABLE version -- and so replaces the
    fixed git checkout the Dockerfile made. See the Phase-0 caller.
    """
    mods = set(re.findall(r"""require\(\s*['"]([^'"]+)['"]\s*\)""", test_text))
    return {m for m in mods
            if not m.startswith(".") and m not in BUILTINS
            and not (package and (m == package or m.startswith(package + "/")))}


# Comments frequently hold the *disabled* version of a PoC (a commented-out
# require, an old payload). Strip them before asking what the test really does,
# or a dead `// const x = require("pkg")` reads as live package usage.
_COMMENTS = re.compile(r"/\*.*?\*/|//[^\n]*", re.S)

# Jest/chai/node assertion forms. `expect.assertions(n)` is a declaration of how
# many are expected, not an assertion itself, so it must not be counted.
#
# expectRedos/expectRedosPair/assertRedos are the redos/utils.js oracle helpers.
# They ARE assertions -- assertRedos() throws when the measured attack time,
# ratio or scaling misses its threshold -- they just do the throwing inside the
# helper rather than at the call site, so no `expect(` token appears in the PoC.
# Without them here, every migrated ReDoS PoC (28 of them) reads as
# assertion-free and is rejected as `poc-no-assertions` before a container is
# even started.
_ASSERTIONS = re.compile(
    r"\bexpect\s*\((?!\s*\)\s*\.\s*assertions)|"
    r"\bassert\s*(?:\.\w+)?\s*\(|"
    r"\b(?:expectRedos|expectRedosPair|assertRedos)\s*\(|"
    r"\bshould\b|\bt\.(?:ok|is|deepEqual|equal|true|false|throws)\s*\(")


def count_assertions(test_text):
    """Number of real assertions in the PoC, ignoring commented-out code.

    A jest test with zero assertions PASSES unconditionally, so it reports every
    version as vulnerable (prototyped.js@2.0.0 is exactly this: a body of nothing
    but console.log).
    """
    return len(_ASSERTIONS.findall(_COMMENTS.sub("", test_text)))


# The PoC's own title (`test("Path Traversal in hostr", ...)`) names the package
# without using it, so it has to come out before asking whether the body does.
_TEST_TITLE = re.compile(
    r"""\b(?:test|it|describe)\s*\(\s*(['"`])(?:\\.|(?!\1).)*\1""")


def test_exercises_package(test_text, package):
    """True when the PoC actually puts the package under test in the loop.

    Several ReDoS PoCs inline the vulnerable regex and run it against a plain
    string, never touching the package (ws@7.0.0 splits on a literal `/ *, */`;
    codemirror@5.58.0 calls a locally defined `cTypes()`). Those are
    package-independent -- the fixed and reverted trees behave identically -- and
    the entry then gets misfiled as `revert-applied-no-repro`.

    "Uses it" is deliberately broader than require(): the path-traversal PoCs
    start the vulnerable server as a subprocess
    (`exec("node ./node_modules/hostr/bin/hostr")`), which exercises the package
    just as much as an import does.
    """
    live = _TEST_TITLE.sub("", _COMMENTS.sub("", test_text))
    mods = set(re.findall(r"""require\(\s*['"]([^'"]+)['"]\s*\)""", live))
    mods |= set(re.findall(r"""\bfrom\s+['"]([^'"]+)['"]""", live))
    # A deep import (`pkg/dist/thing`) counts; a different package that merely
    # shares a prefix (object-path-set vs object-path) does not.
    if any(m == package or m.startswith(package + "/") for m in mods):
        return True
    # Spawned as a subprocess, or otherwise named at a token boundary in the
    # surviving code (`node ./node_modules/<pkg>/server.js`). A leading '/' must
    # stay allowed for exactly that path form; the trailing guard is what keeps
    # object-path-set from counting as object-path.
    return bool(re.search(rf"(?<![\w.@-]){re.escape(package)}(?![\w.-])", live))


def reset_tree(cid, repodir):
    dexec(cid, f"cd {repodir} && git checkout -q -- . 2>/dev/null; "
               f"git reset -q --hard HEAD 2>/dev/null; git clean -fdq 2>/dev/null || true")


# Per-entry: shell command that recompiles the source tree into the runtime tree
# (lib/, dist/, ...), or "" when no rebuild is needed. Set once per entry in
# process(); read by apply_revert so every re-application propagates the reverted
# source into the COMPILED code the exploit actually loads. See
# detect_rebuild_cmd(). _REBUILD_OK records whether the LAST rebuild succeeded --
# a failed rebuild leaves the runtime tree fixed, which is indistinguishable from
# a genuine no-reproduction unless we say so.
_REBUILD_CMD = ""
_REBUILD_OK = True
# The BODY of the npm script chosen on the clean fixed tree (e.g. the literal
# `tsc -p tsconfig.main.json` behind `npm run build:main`). Kept because a patch
# that touches package.json can revert the script out of existence: the name is
# then unusable but the recipe is still exactly right for the reverted sources.
_REBUILD_RAW = ""

# Directories whose contents are COMPILED or GENERATED into the tree that
# require() actually loads, so a patch confined to one of them never reaches the
# runtime by itself. `src` covers Babel/TypeScript/CoffeeScript packages,
# `source` the ramda layout (source/ -> src/), `generate` code-generator
# templates (mobile-detect builds mobile-detect.js from generate/*.template.js).
_SOURCE_DIRS = ("src", "source", "sources", "generate", "lib/src", "ts", "coffee")

# package.json scripts that regenerate the runtime tree, most preferred first.
# The narrow commonjs builds emit lib/ only and are much faster than a full
# build (which also produces es/umd/minified bundles); prepare/prepublish are the
# conventional hooks for packages with no explicit build script.
_BUILD_SCRIPTS = ("build:commonjs", "build:cjs", "build:lib", "build:main",
                  "compile", "build", "prepare", "prepublishOnly", "prepublish")

# A rebuild runs on every re-application during minimization, so a package whose
# build hangs would stall the whole entry. Cap it.
_REBUILD_TIMEOUT = 300


def detect_rebuild_cmd(cid, repodir, units, sink=""):
    """Return a build command when a source-only patch would miss the runtime.

    Packages that ship a compiled tree (Babel src/ -> lib/, TypeScript src/ ->
    dist/, a bundled dist/*.min.js, ramda's source/ -> src/, mobile-detect's
    generate/*.template.js -> mobile-detect.js) load the COMPILED artifact at
    require() time. patch.txt for such packages only edits the source tree, so
    reverse-applying it leaves the runtime untouched and the exploit never
    reproduces -- the single largest cause of false `revert-applied-no-repro`.

    Detection is deliberately permissive: if the patch edits a source tree that
    exists and the package knows how to rebuild itself, rebuild. A needless
    rebuild costs one `npm run build`; a missed one costs a wrong verdict.

    Returns "" when the patch touches no source tree, or when nothing in the
    package can regenerate the runtime.
    """
    patched = {f for f, _hdr, _hunk in units}
    src_dirs = [d for d in _SOURCE_DIRS
                if any(f.startswith(d + "/") for f in patched)]
    if not src_dirs:
        return ""
    src_dirs = [d for d in src_dirs
                if dexec(cid, f"cd {repodir} && test -d '{d}'").returncode == 0]
    if not src_dirs:
        return ""

    # Prefer the package's own build script -- it knows the real pipeline
    # (jison grammars, webpack bundles, minifiers) that no generic compiler
    # reproduces. SB_SCRIPTS is passed through the environment so the candidate
    # list never has to be escaped into the -e string.
    js = (
        "const s=(require('./package.json').scripts)||{};"
        "const pick=process.env.SB_SCRIPTS.split(',').find(n=>s[n]);"
        "process.stdout.write(pick?('npm run '+pick):'');"
    )
    cmd = dexec(cid, f"cd {repodir} && SB_SCRIPTS='{','.join(_BUILD_SCRIPTS)}' "
                     f"node -e \"{js}\"").stdout.strip()
    if cmd:
        # Remember the recipe as well as the name. blamer's patch reverts
        # `build:main` out of package.json, so on the reverted tree the name
        # resolves to nothing and the rebuild used to hard-fail -- even though
        # the command behind it (`tsc -p ...`) is exactly what those sources
        # need. See install_rebuild_script().
        global _REBUILD_RAW
        raw_js = (
            "const s=(require('./package.json').scripts)||{};"
            "const pick=process.env.SB_SCRIPTS.split(',').find(n=>s[n]);"
            "process.stdout.write(pick?String(s[pick]):'');"
        )
        _REBUILD_RAW = dexec(
            cid, f"cd {repodir} && SB_SCRIPTS='{','.join(_BUILD_SCRIPTS)}' "
                 f"node -e \"{raw_js}\"").stdout.strip()
        return cmd

    # No build script. Fall back to invoking the compiler the patched extensions
    # imply, but only when its config is present -- guessing wrong produces a
    # broken runtime tree, which is worse than not rebuilding at all.
    exts = {f.rsplit(".", 1)[-1].lower() for f in patched if "." in f}
    out = _runtime_out_dir(cid, repodir, sink)
    if "ts" in exts and dexec(cid, f"cd {repodir} && test -f tsconfig.json").returncode == 0:
        # Three rungs, and npx is not one of them.
        #
        # `npx tsc` resolves the bare name to the abandoned `tsc` package on npm
        # (a different project entirely), which installs and then errors. But
        # `npx -y -p typescript tsc` is broken too, in a subtler way: npx stages
        # the package under /root/.npm/_npx/<hash>/, and on node 16 loading the
        # EXTENSIONLESS bin/tsc from that staging dir dies with
        # ERR_UNKNOWN_FILE_EXTENSION because the staged package.json puts it in a
        # "type":"module" context.
        #
        # Running typescript's own lib/tsc.js by path sidesteps both: it has a
        # .js extension, so no module-type inference is involved. Install it into
        # the package's own node_modules when it is not already there.
        return ("sh -c 'if [ -x node_modules/.bin/tsc ]; then node_modules/.bin/tsc; "
                "elif [ -f node_modules/typescript/lib/tsc.js ]; then "
                "node node_modules/typescript/lib/tsc.js; "
                "else npm install --no-save --no-audit --no-fund --ignore-scripts "
                "typescript >/dev/null 2>&1 && node node_modules/typescript/lib/tsc.js; fi'")
    if "coffee" in exts:
        return f"npx coffee -c -o {out or 'lib'} {src_dirs[0]}"
    if exts & {"js", "mjs", "jsx"} and out:
        has_babel = dexec(
            cid, f"cd {repodir} && ls .babelrc .babelrc.js babel.config.js "
                 f"2>/dev/null | head -1").stdout.strip()
        if has_babel:
            return f"BABEL_ENV=commonjs npx babel {src_dirs[0]} --out-dir {out}"
    return ""


def install_rebuild_script(cid, tmp, detected_cmd):
    """Write /tmp/sb_rebuild.sh, which re-resolves the build script each run.

    `detected_cmd` is what detect_rebuild_cmd() found on the clean fixed tree. If
    it is an `npm run <script>` we do NOT hard-code that name: the reverted tree
    may no longer define it (a patch that touches package.json takes its scripts
    with it). Instead the script re-runs the same preference list against
    whatever package.json is on disk at that moment, and falls back to the
    detected command only when package.json defines no candidate at all.
    """
    js = ("const s=(require('./package.json').scripts)||{};"
          "const pick=process.env.SB_SCRIPTS.split(',').find(n=>s[n]);"
          "process.stdout.write(pick?('npm run '+pick):'');")
    body = (
        "#!/bin/sh\n"
        f"SB_SCRIPTS='{','.join(_BUILD_SCRIPTS)}'\n"
        "export SB_SCRIPTS\n"
        f'PICK=$(node -e "{js}" 2>/dev/null)\n'
        "if [ -n \"$PICK\" ]; then\n"
        "  exec $PICK\n"
        "fi\n"
        # No npm script survives on this tree. Either the detected command was a
        # direct compiler invocation (usable as-is), or it was `npm run <name>`
        # and we fall back to the BODY of that script as captured on the clean
        # fixed tree -- the recipe is still correct even though the name is gone.
        # node_modules/.bin goes on PATH because npm would have put it there.
        + (f"exec {detected_cmd}\n" if not detected_cmd.startswith("npm run ")
           else (f'PATH="$PWD/node_modules/.bin:$PATH"\nexport PATH\n'
                 f"exec sh -c {shlex.quote(_REBUILD_RAW)}\n" if _REBUILD_RAW
                 else "echo 'no build script on the reverted tree, and no "
                      "recipe captured from the fixed tree' >&2; exit 1\n"))
    )
    p = tmp / "sb_rebuild.sh"
    p.write_text(body, encoding="utf-8")
    run(["docker", "cp", str(p), f"{cid}:/tmp/sb_rebuild.sh"])


def _runtime_out_dir(cid, repodir, sink):
    """Directory holding the compiled artifact the exploit loads, or "".

    Read from package.json "main" first; fall back to the benchmark's recorded
    sink path, which points at the real loaded file even when main does not
    (jointjs: main is a stub, the sink is dist/joint.min.js).
    """
    js = ("const p=require('./package.json');"
          "process.stdout.write(String(p.main||'index.js').replace(/^\\.\\//,''));")
    main = dexec(cid, f"cd {repodir} && node -e \"{js}\"").stdout.strip()
    for cand in (main, sink):
        head = (cand or "").split("/", 1)
        if len(head) == 2 and head[0] in ("lib", "dist", "build", "es", "umd",
                                          "cjs", "esm", "out"):
            return head[0]
    return ""


def _reverted_tree_is_prebuilt(cid, repodir):
    """True when the tree ON DISK NOW loads plain sources, so no rebuild applies.

    Detection ran against the CLEAN FIXED tree, where the package compiles
    src/ -> build/. The revert can take the package back across that boundary:
    blamer's patch moves `main` from "build/main/index.js" (TypeScript, 1.0.1)
    back to "src/index.js" (plain JavaScript, 0.1.13), so after reverting there
    is nothing to compile -- and the remembered `tsc -p tsconfig.json` runs
    against .ts files that no longer exist, fails, and gets the whole entry
    written off as `rebuild-failed`.

    Asking the reverted package.json where its entry point actually is settles
    it: an existing file outside the compiled output dirs IS the runtime.
    """
    js = ("const p=require('./package.json');"
          "process.stdout.write(String(p.main||'index.js').replace(/^\\.\\//,''));")
    main = dexec(cid, f"cd {repodir} && node -e \"{js}\"").stdout.strip()
    if not main:
        return False
    head = main.split("/", 1)[0] if "/" in main else ""
    if head in ("lib", "dist", "build", "es", "umd", "cjs", "esm", "out"):
        return False
    return dexec(cid, f"cd {repodir} && test -f '{main}'").returncode == 0


def apply_revert(cid, repodir, partial_text, tmp):
    """Reverse-apply a partial patch onto the clean fixed tree; True on success."""
    global _REBUILD_OK
    reset_tree(cid, repodir)
    p = tmp / "subset.patch"
    p.write_text(partial_text, encoding="utf-8")
    run(["docker", "cp", str(p), f"{cid}:/tmp/subset.patch"])
    # Progressively more tolerant reverse-applications. Each rung relaxes one
    # thing the previous rung insisted on, and the first that lands wins:
    #   plain      exact context
    #   --3way     blob-level merge (needs the pre-image objects in the clone)
    #   whitespace the patch and the checkout disagree on indentation/line ends
    #               (a GitHub-fetched diff against a tag-checked-out tree)
    #   -C1        drifted surroundings: match on one line of context, not three
    #   patch -R   GNU patch's fuzz, the last resort git apply has no equivalent
    #               for. Guarded on the binary existing, since the node images
    #               do not all ship it.
    attempts = [
        "git apply -R --recount /tmp/subset.patch",
        "git apply -R --recount --3way /tmp/subset.patch",
        "git apply -R --recount --ignore-whitespace /tmp/subset.patch",
        "git apply -R --recount --ignore-whitespace -C1 /tmp/subset.patch",
    ]
    for i, cmd in enumerate(attempts):
        # Reset between rungs. `git apply --3way` is NOT atomic: on conflict it
        # returns non-zero but leaves the tree unmerged, with conflict markers
        # written into the files. Running the next rung on top of that debris
        # would either fail for the wrong reason or, worse, succeed against
        # corrupted content.
        if i:
            reset_tree(cid, repodir)
        r = dexec(cid, f"cd {repodir} && {cmd}")
        if r.returncode == 0:
            break
    else:
        reset_tree(cid, repodir)
        return False
    # For compiled packages the revert only edited the source tree; recompile so
    # the change reaches the runtime tree the exploit loads. reset_tree()
    # (git clean) wipes this on the next call, so we rebuild after every
    # re-application. Best-effort: a failed build leaves the compiled tree fixed
    # and run_test() reports no reproduction -- _REBUILD_OK lets the caller say
    # that out loud instead of blaming the patch.
    if _REBUILD_CMD and not _reverted_tree_is_prebuilt(cid, repodir):
        # Re-pick the npm script HERE, on the reverted tree, rather than reusing
        # the name resolved on the clean fixed tree: when the patch touches
        # package.json (blamer reverts `build:main` out of existence), the
        # remembered name no longer exists and every rebuild dies with
        # "Missing script", which surfaces as a bogus `rebuild-failed`.
        rb = dexec(cid, f"cd {repodir} && timeout {_REBUILD_TIMEOUT} "
                        f"sh /tmp/sb_rebuild.sh >/tmp/rebuild.log 2>&1")
        _REBUILD_OK = rb.returncode == 0
    else:
        # No rebuild was owed on this tree. Say so explicitly: _REBUILD_OK is a
        # module global, and leaving a previous subset's failure standing would
        # make the caller report `rebuild-failed` for a revert that never needed
        # building in the first place.
        _REBUILD_OK = True
    return True


# The exploit oracle runs once per ddmin step, so a single hanging invocation
# stalls the whole campaign -- and hanging is the NORMAL outcome for a PoC whose
# package leaves a handle open (arpping spawns arp and never closes it: the test
# completes in 0.36s, passes, and then jest sits forever on "Jest did not exit
# one second after the test run has completed"). --forceExit is what that message
# asks for and is safe, because the verdict is already decided by the time it
# applies. TEST_TIMEOUT is the second line of defence, for a PoC that hangs
# DURING the run rather than at exit.
TEST_TIMEOUT = 300          # seconds for one exploit-test invocation
NPM_TIMEOUT = 300           # seconds for the undeclared-test-dep install


def run_test(cid, workdir):
    """Run the jest exploit test; True == PASS (vuln reproduces).

    A timeout counts as NOT passing, which is the right reading for both callers:
    on the fixed tree the vuln is closed, and on a revert the exploit did not
    demonstrably fire. Timeouts are reported separately by run_test_verbose() so
    they are never silently conflated with a clean failure.
    """
    return run_test_verbose(cid, workdir)[0]


def run_test_verbose(cid, workdir):
    """(passed, code) for one exploit-test run; code 124 == timed out."""
    r = dexec(cid, f"cd {workdir} && timeout {TEST_TIMEOUT} jest --runInBand "
                   f"--forceExit >/tmp/jest.log 2>&1; echo $?")
    code = (r.stdout.strip().splitlines() or ["1"])[-1]
    return code == "0", code


# Undeclared test dependencies go here, NOT into the benchmark folder -- see
# the Phase-0 comment in the driver for why installing them in workdir destroys
# the fixed checkout.
TEST_DEPS_PREFIX = "/sb-testdeps"


def resolves_in(cid, workdir, module):
    """True when `module` already resolves from workdir (no install needed)."""
    return dexec(
        cid, f"cd {workdir} && node -e "
             f"\"require.resolve({json.dumps(module)})\" 2>/dev/null"
    ).returncode == 0


def installed_version(cid, workdir, package):
    """Version of `package` actually installed in the container (or '?')."""
    r = dexec(cid, f"cd {workdir} && node -e \"process.stdout.write("
                   f"require('{package}/package.json').version)\" 2>/dev/null")
    return r.stdout.strip() or "?"


def exploit_self_fires(cid, workdir, repodir, package):
    """Replace the package with an inert stub and rerun the exploit test.

    If it STILL passes, the side effect doesn't depend on the package -> the PoC
    is self-firing (broken). Restores the tree afterwards. Returns True only on a
    clean PASS with the stub; any error/crash is treated as inconclusive (False).
    """
    # Stub EVERY CommonJS file in the package, not just package.json's `main`.
    # PoCs routinely deep-import (axios/lib/utils, colors-cli/safe,
    # natural/lib/natural/distance/dice_coefficient.js) and a main-only stub is
    # simply not on that resolution path -- the real vulnerable code loads, the
    # exploit fires, and a perfectly good entry gets thrown out as
    # "poc-self-fires-on-revert". reset_tree() below puts the tree back.
    dexec(cid, f"cat > /tmp/self_fire_stub.js <<'__STUB_EOF__'\n{SELF_FIRE_STUB}__STUB_EOF__")
    dexec(cid, f"cd {repodir} && find . -path ./node_modules -prune -o "
               f"-type f \\( -name '*.js' -o -name '*.cjs' \\) -print "
               f"| while IFS= read -r f; do cp /tmp/self_fire_stub.js \"$f\"; done")
    fires = run_test(cid, workdir)
    reset_tree(cid, repodir)
    return fires


def run_repo_tests(cid, repodir, timeout=300):
    """Run the package's OWN test script (the repo's CI test) in repodir.

    Returns (status, summary): status is 'pass' | 'fail' | 'fail(timeout)' |
    'no-script' | 'error'. summary is the tail of the test output.
    """
    scr = dexec(cid, f"cd {repodir} && node -e "
                f"\"process.stdout.write((((require('./package.json').scripts)||{{}}).test)||'')\" "
                f"2>/dev/null").stdout.strip()
    if not scr or "no test specified" in scr or "exit 1" in scr:
        return "no-script", "(package.json has no real test script)"
    r = dexec(cid, f"cd {repodir} && timeout {timeout} npm test "
                   f">/tmp/repotest.log 2>&1; echo EXIT=$?")
    tail = dexec(cid, "tail -20 /tmp/repotest.log").stdout.strip()
    m = re.search(r"EXIT=(\d+)", r.stdout)
    code = m.group(1) if m else None
    status = ("pass" if code == "0" else
              "fail(timeout)" if code == "124" else
              "fail" if code is not None else "error")
    return status, tail


# --------------------------------------------------------------------------- #
# new-findings attribution (shared identity/format rules with
# semgrep-codeql-analysis.py, so evasion-results-*.csv and
# <category>-semgrep-codeql-analysis.csv can be read side by side)
# --------------------------------------------------------------------------- #
MAX_MESSAGES = 6            # findings spelled out per CSV cell
MAX_MESSAGE_CHARS = 220     # per-message budget inside that cell


def _one_line(text, limit=MAX_MESSAGE_CHARS):
    flat = " ".join((text or "").split())
    return flat if len(flat) <= limit else flat[:limit - 1] + "…"


def key_of(f):
    """Semgrep finding identity that survives the line shifts a revert causes.

    NOTE: logged-out semgrep OSS redacts extra.lines to the literal string
    "requires login", so in practice this key degenerates to (rule, path) and
    the multiset diff becomes a per-rule-per-file COUNT diff. That still gives
    the right totals -- 2 eval findings where the baseline had 1 yields 1 new --
    but it cannot tell a finding that moved from one that was replaced. Same
    behaviour as semgrep-codeql-analysis.py, deliberately, so the two CSVs
    remain comparable.
    """
    return (f.get("check_id", "?"), f.get("path", "?"),
            ((f.get("extra") or {}).get("lines") or "").strip()[:200])


def codeql_key(a):
    """CodeQL alert identity that survives line shifts: (rule, path, message)."""
    return (a.get("rule", "?"), a.get("path", "?"), (a.get("message") or "")[:200])


def only_new(current, baseline, key):
    """Findings present in `current` but not in `baseline` (multiset difference).

    A revert re-opens the vuln inside a file that already had unrelated findings;
    without subtracting the clean-fixed baseline, those pre-existing alerts get
    counted as "the detector caught our patch" and inflate every detection rate.
    """
    before = Counter(key(f) for f in baseline)
    new = []
    for f in current:
        k = key(f)
        if before[k]:
            before[k] -= 1
        else:
            new.append(f)
    return new


def top_rules(items, name):
    c = Counter(name(i) for i in items)
    return "; ".join(f"{r}×{n}" for r, n in c.most_common(5))


def format_semgrep_messages(findings):
    out = [f"{f.get('check_id', '?').split('.')[-1]} @ {f.get('path', '?')}"
           f":{(f.get('start') or {}).get('line', '?')} — "
           f"{_one_line((f.get('extra') or {}).get('message', ''))}"
           for f in findings[:MAX_MESSAGES]]
    if len(findings) > MAX_MESSAGES:
        out.append(f"(+{len(findings) - MAX_MESSAGES} more)")
    return " || ".join(out)


def format_codeql_messages(alerts):
    out = [f"{a.get('rule', '?')} @ {a.get('path', '?')}:{a.get('line', '?')} — "
           f"{_one_line(a.get('message', ''))}" for a in alerts[:MAX_MESSAGES]]
    if len(alerts) > MAX_MESSAGES:
        out.append(f"(+{len(alerts) - MAX_MESSAGES} more)")
    return " || ".join(out)


def detected_by(sg_new, cq_new):
    """Which detector(s) saw NEW findings on this variant."""
    return {(True, True): "both", (True, False): "semgrep",
            (False, True): "codeql", (False, False): "neither"}[
        (bool(sg_new), bool(cq_new))]


def run_semgrep(cid, repodir, targets, tmp):
    """Scan `targets` (relative paths) with packs+local rules.

    Returns (count, text, findings). `findings` are the raw semgrep JSON result
    dicts with `path` rewritten back to a repo-relative path, so they can be
    diffed against a baseline scan (see new_semgrep/key_of) instead of only
    counted -- that diff is what turns "N findings" into "N findings this patch
    introduced", which is the number the evasion claim actually rests on.
    """
    if not targets:
        return 0, "(no targets)", []
    filelist = " ".join(f"'{f}'" for f in targets)
    dexec(cid, f"cd {repodir} && tar -cf /tmp/scan.tar {filelist} 2>/dev/null")
    src = tmp / "scan"
    if src.exists():
        shutil.rmtree(src)
    src.mkdir()
    run(["docker", "cp", f"{cid}:/tmp/scan.tar", str(tmp / "scan.tar")])
    run(["tar", "-xf", str(tmp / "scan.tar"), "-C", str(src)])
    cfg = []
    for name in LOCAL_RULESETS:
        if (RULES_DIR / name).exists():
            cfg += ["--config", f"/rules/{name}"]
    mounts = ["-v", f"{src}:/src", "-v", f"{RULES_DIR}:/rules:ro",
              # Persist semgrep's rule cache across the many scans one entry
              # runs, so the registry packs are downloaded once, not per scan.
              "-v", "secbench-semgrep-cache:/root/.semgrep"]
    if MINI_RULES.exists():
        mounts += ["-v", f"{MINI_RULES}:/rules-mini/semgrep_rules.yaml:ro"]
        cfg += ["--config", "/rules-mini/semgrep_rules.yaml"]
    for c in EVADE_SEMGREP_PACKS:
        cfg += ["--config", c]
    sg = run(["docker", "run", "--rm", "--memory", SEMGREP_MEMORY_LIMIT,
              *mounts, SEMGREP_IMAGE, "semgrep", *cfg, "--metrics", "off",
              "--disable-version-check",
              # Same caps the analysis pipeline uses: without them a single
              # bundled artifact grows semgrep until the host dies.
              "--max-target-bytes", str(SEMGREP_MAX_TARGET_BYTES),
              "--max-memory", str(SEMGREP_MAX_MEMORY_MB),
              "--timeout", "60",
              "--json", "/src"])
    findings = []
    try:
        data = json.loads(sg.stdout or "{}")
        for f in data.get("results") or []:
            p = str(f.get("path") or "")
            for pre in ("/src/", "src/"):
                if p.startswith(pre):
                    p = p[len(pre):]
                    break
            f["path"] = p
            findings.append(f)
    except ValueError:
        # semgrep died before emitting JSON -- fall back to the summary line so
        # the count is still right even though we lose the per-finding detail.
        mm = re.search(r"Ran [\d,]+ rules on [\d,]+ files?: ([\d,]+) findings?\.",
                       sg.stderr or "")
        n = int(mm.group(1).replace(",", "")) if mm else 0
        return n, (sg.stderr or "").strip()[-1500:], []
    return len(findings), fmt_semgrep_text(findings), findings


def fmt_semgrep_text(findings):
    """Human-readable rendering of semgrep findings for the log/report."""
    if not findings:
        return "No findings."
    return "\n".join(
        f"  {f.get('check_id', '?').split('.')[-1]} @ {f.get('path', '?')}"
        f":{(f.get('start') or {}).get('line', '?')}: "
        f"{_one_line((f.get('extra') or {}).get('message', ''))}"
        for f in findings)


def run_codeql(cid, repodir, targets, tmp, suite="", scope="package"):
    """Detection-only CodeQL scan of `targets`; return (count, text, alerts).

    Mirrors run_semgrep's tar-out-of-container approach, then builds a JS
    database over just the changed/sink files and runs the security-extended
    suite -- using the HOST's native codeql CLI (no container/emulation). count
    is the number of SARIF results (-1 marks an extractor/build failure so the
    caller can distinguish 'clean' from 'could not run'; the text carries the
    reason, e.g. codeql missing from PATH). `alerts` are normalised dicts
    (rule/message/path/line) so they can be diffed against a baseline scan the
    same way semgrep findings are.
    """
    if not targets:
        return 0, "(no targets)", []
    codeql = shutil.which("codeql")
    if not codeql:
        return -1, ("native codeql CLI not on PATH (install the `codeql` cask "
                    "and `codeql pack download codeql/javascript-queries`)"), []
    # SCOPE: the whole package, not just the changed files.
    #
    # Every CodeQL alert this benchmark cares about is a TAINT query whose source
    # is the exported function's parameter ("library input") and whose sink may
    # sit in a different file. Extracting only the patched files breaks that path
    # -- async-git reports 4 `Unsafe shell command constructed from library
    # input` alerts on a whole-tree scan (as semgrep-codeql-analysis.py does) and
    # 0 on a two-file scan. A narrow scope therefore does not measure evasion; it
    # manufactures it. node_modules and .git are excluded because the analysis
    # script scans the package tree, not its dependencies.
    if scope == "package":
        n_js = dexec(cid, f"cd {repodir} && find . -path ./node_modules -prune -o "
                          f"-name '*.js' -print 2>/dev/null | wc -l").stdout.strip()
        try:
            big = int(n_js) > CODEQL_MAX_FILES
        except ValueError:
            big = False
        if big:
            # A tree this size will not finish inside the RAM budget; say so
            # rather than silently scanning a scope the caller did not ask for.
            scope = "files"
    if scope == "package":
        dexec(cid, f"cd {repodir} && tar -cf /tmp/cqlscan.tar "
                   f"--exclude=./node_modules --exclude=./.git . 2>/dev/null")
    else:
        filelist = " ".join(f"'{f}'" for f in targets)
        dexec(cid, f"cd {repodir} && tar -cf /tmp/cqlscan.tar {filelist} 2>/dev/null")
    src = tmp / "cqlscan"
    if src.exists():
        shutil.rmtree(src)
    src.mkdir()
    run(["docker", "cp", f"{cid}:/tmp/cqlscan.tar", str(tmp / "cqlscan.tar")])
    run(["tar", "-xf", str(tmp / "cqlscan.tar"), "-C", str(src)])

    # Build the DB then run the suite natively. Keep the DB out of `src` so the
    # extractor doesn't try to index its own database files.
    db = tmp / "cqldb"
    if db.exists():
        shutil.rmtree(db)
    create = run([codeql, "database", "create", str(db),
                  "--language=javascript", f"--source-root={src}", "--overwrite",
                  f"--ram={CODEQL_RAM_MB}", f"--threads={CODEQL_THREADS}"])
    if create.returncode != 0:
        return -1, ("codeql database create failed:\n"
                    + (create.stderr or create.stdout or "").strip()[-1500:]), []
    sarif = src / "codeql.sarif"
    cq = run([codeql, "database", "analyze", str(db), suite or CODEQL_SUITE,
              "--format=sarifv2.1.0", f"--output={sarif}",
              f"--ram={CODEQL_RAM_MB}", f"--threads={CODEQL_THREADS}",
              "--no-print-diagnostics-summary"])
    if not sarif.exists():
        return -1, ("codeql database analyze produced no SARIF:\n"
                    + (cq.stderr or cq.stdout or "").strip()[-1500:]), []
    try:
        data = json.loads(sarif.read_text(encoding="utf-8"))
        results = []
        for run_obj in data.get("runs") or []:
            results += run_obj.get("results") or []
        alerts = []
        for r in results:
            loc = ((r.get("locations") or [{}])[0].get("physicalLocation") or {})
            alerts.append({
                "rule": r.get("ruleId", "?"),
                "message": (r.get("message") or {}).get("text", ""),
                "path": (loc.get("artifactLocation") or {}).get("uri", "?"),
                "line": (loc.get("region") or {}).get("startLine", "?"),
            })
        lines = [f"  {a['rule']} @ {a['path']}:{a['line']}: {_one_line(a['message'])}"
                 for a in alerts]
        return len(alerts), "\n".join(lines) if lines else "No findings.", alerts
    except (ValueError, OSError) as e:
        return -1, f"could not parse SARIF: {e}", []


def fmt_codeql(count):
    """Human label for a codeql count (-1 == could not run)."""
    if count < 0:
        return "n/a"
    return str(count)


def fmt_new(count):
    """Human label for a new-findings count (None == could not attribute)."""
    return "n/a" if count is None else str(count)


# --------------------------------------------------------------------------- #
# applying transforms
# --------------------------------------------------------------------------- #
# The sed program is written to a FILE and copied in rather than interpolated
# into a shell string: the patterns contain /, |, quotes and backslashes, and any
# single-character delimiter would eventually collide with one of them. \x01
# cannot occur in JavaScript source, so it is a safe delimiter.
_SED_DELIM = "\x01"

# awk program that inserts the helper prelude at the top of a file WITHOUT
# displacing a shebang or a leading "use strict" directive -- prepending before
# either one silently breaks the file (bin/ entry points, strict-mode modules).
_PRELUDE_AWK = r"""
BEGIN { ins = 0 }
NR == 1 && /^#!/ { print; next }
NR <= 2 && /^[ \t]*['"]use strict['"];?[ \t]*$/ { print; next }
ins == 0 { while ((getline l < PRELUDE) > 0) print l; ins = 1 }
{ print }
END { if (ins == 0) { while ((getline l < PRELUDE) > 0) print l } }
"""


def apply_transforms(cid, repodir, targets, xfs, tmp):
    """Apply a composition of transforms to every target file.

    Steps run in `order` (flow rewrites before sink rewrites, since the flow
    patterns still spell the sink the original way). Returns the list of files
    that actually changed; the helper prelude is injected only into those.
    """
    xfs = sorted(xfs, key=lambda t: (t.get("order", 50), t["name"]))
    steps = [s for t in xfs for s in t["steps"]]
    # Text appended verbatim at the end of each target that has exports. Kept
    # apart from `steps` because sed substitutes within a line and this has to
    # run after the module has finished assigning module.exports.
    tail = "".join(t.get("append", "") for t in xfs)
    if not steps and not tail:
        return []

    changed = []
    if steps:
        prog = "".join(f"s{_SED_DELIM}{p}{_SED_DELIM}{r}{_SED_DELIM}g\n"
                       for p, r in steps)
        (tmp / "xf.sed").write_text(prog, encoding="utf-8")
        run(["docker", "cp", str(tmp / "xf.sed"), f"{cid}:/tmp/xf.sed"])
        for f in targets:
            r = dexec(cid, f"cd {repodir} && cp -- '{f}' /tmp/xf.orig && "
                           f"sed -i -E -f /tmp/xf.sed -- '{f}' && "
                           f"{{ cmp -s -- '{f}' /tmp/xf.orig || echo CHANGED; }}")
            if "CHANGED" in (r.stdout or ""):
                changed.append(f)

    if tail:
        (tmp / "xf.tail.js").write_text(tail, encoding="utf-8")
        run(["docker", "cp", str(tmp / "xf.tail.js"), f"{cid}:/tmp/xf.tail.js"])
        for f in targets:
            # Only files that actually assign exports: appending the wrapper to
            # a file with no module.exports leaves a reference to undefined and
            # takes the whole package down on require().
            r = dexec(cid, f"cd {repodir} && "
                           f"grep -qE '(module\\.exports|^[ \\t]*exports\\.)' -- '{f}' && "
                           f"cat /tmp/xf.tail.js >> '{f}' && echo APPENDED")
            if "APPENDED" in (r.stdout or "") and f not in changed:
                changed.append(f)

    if not changed:
        return []

    helpers = []
    for t in xfs:
        for h in t.get("helpers", ()):
            if h not in helpers:
                helpers.append(h)
    if helpers:
        (tmp / "xf.prelude.js").write_text(
            "/* SecBench.js evasion helpers (semantics-preserving) */\n"
            + "".join(HELPERS[h] for h in helpers), encoding="utf-8")
        (tmp / "xf.awk").write_text(_PRELUDE_AWK, encoding="utf-8")
        run(["docker", "cp", str(tmp / "xf.prelude.js"), f"{cid}:/tmp/xf.prelude.js"])
        run(["docker", "cp", str(tmp / "xf.awk"), f"{cid}:/tmp/xf.awk"])
        for f in changed:
            dexec(cid, f"cd {repodir} && awk -v PRELUDE=/tmp/xf.prelude.js "
                       f"-f /tmp/xf.awk -- '{f}' > /tmp/xf.new && "
                       f"cat /tmp/xf.new > '{f}'")
    return changed


def rule_names(sg_findings, cq_alerts):
    """Every rule identifier that fired, in the spelling the CSVs use."""
    names = [f.get("check_id", "").split(".")[-1] for f in sg_findings or []]
    names += [a.get("rule", "") for a in cq_alerts or []]
    # CodeQL SARIF ruleIds are query ids (js/path-injection); the human name is
    # only in the message, which is what the analysis CSVs recorded.
    names += [(a.get("message") or "")[:120] for a in cq_alerts or []]
    return [n for n in names if n]


def select_transforms(category, sg_findings, cq_alerts):
    """Candidate transforms for THIS entry, chosen from the rules that fired.

    Falls back to every transform registered for the category when nothing
    matched (e.g. CodeQL was unavailable, so only semgrep's view is known).
    """
    fired = " || ".join(rule_names(sg_findings, cq_alerts)).lower()
    picked, why = [], {}
    for pat, names in RULE_TRANSFORMS:
        hit = re.search(pat, fired)
        if not hit:
            continue
        for n in names:
            t = TRANSFORMS_BY_NAME.get(n)
            if t and t not in picked and category in t["categories"]:
                picked.append(t)
                why[n] = hit.group(0)
    if not picked:
        picked = [t for t in TRANSFORMS if category in t["categories"]]
    return sorted(picked, key=lambda t: (t.get("order", 50), t["name"])), why


def unexplained(sg_findings, cq_alerts):
    """Fired rules that no transform targets, with the documented reason."""
    fired = " || ".join(rule_names(sg_findings, cq_alerts)).lower()
    return {k: v for k, v in UNTARGETED_RULES.items() if k in fired}


# --------------------------------------------------------------------------- #
# per-entry pipeline
# --------------------------------------------------------------------------- #
def process(entry, args):
    folder, package = entry["folder"], entry["package"]
    tag = image_tag(folder)
    workdir = f"/exploit/{folder}"
    repodir = f"{workdir}/node_modules/{package}"
    global _REBUILD_CMD, _REBUILD_RAW
    # reset both; set below once we know this entry compiles src/->lib/. Leaving
    # _REBUILD_RAW set would hand the NEXT entry the previous package's build
    # recipe as its fallback.
    _REBUILD_CMD = _REBUILD_RAW = ""
    L = []
    def log(s=""):
        L.append(s)
        print("    " + s if s else "")

    # Per-stage evasion metrics, written to the per-category CSV. None means the
    # entry never reached that stage (e.g. setup failure); the labels below are
    # filled in as each stage runs.
    m = {
        "category": entry["category"],
        "repository": entry.get("repository") or "",
        "package": package,
        "version": entry.get("version") or "",
        # baseline on the CLEAN FIXED tree (before our patch) -- so test/CI
        # breakage can be attributed to us vs. already-broken upstream.
        "baseline_test": None, "baseline_ci": None,
        # full unminimized revert (vuln fully reintroduced, no changes)
        "semgrep_full": None, "evade_full": None, "codeql_full": None,
        # after chunking (ddmin-minimized hunk set)
        "semgrep_minimal": None, "evade_minimal": None, "codeql_minimal": None,
        # after semantics-preserving syntax rewrites
        "semgrep_final": None, "evade_final": None, "codeql_final": None,
        # --- new-findings attribution (vs the CLEAN FIXED tree) ---------------
        # The semgrep_*/codeql_* counts above are TOTALS on the scanned files, so
        # they include alerts the fixed tree already had. These subtract that
        # baseline: what does each detector report *because of* our patch. This
        # is the honest evasion number -- a variant with 3 findings that the
        # fixed tree also had evades just as completely as one with 0.
        "semgrep_fixed": None, "codeql_fixed": None,
        "semgrep_new_full": None, "semgrep_new_minimal": None, "semgrep_new_final": None,
        "codeql_new_full": None, "codeql_new_minimal": None, "codeql_new_final": None,
        "evade_new_final": None, "codeql_evade_final": None,
        # detail for the FINAL (evasive) variant -- which rules fired, where, and
        # whether the alert is even inside a file the patch touched
        "semgrep_new_in_patched": None, "codeql_new_in_patched": None,
        "semgrep_top_rules": "", "codeql_top_rules": "",
        "detected_by": "", "semgrep_messages": "", "codeql_messages": "",
        # the headline: exploit reproduces AND neither detector reports anything
        # new. "n/a (codeql)" when CodeQL could not run, so a semgrep-only run is
        # never miscounted as a both-detector success.
        "evaded_both": "",
        "winning_transform": "", "transform_layers": "",
        # how the minimal revert was expressed: line-level change groups (the
        # added/removed/modified lines only) or whole hunks (context included)
        "granularity": "", "units_total": None, "units_kept": None,
        # how the chunking was chosen: exploit-minimal | ci-preserving-chunk |
        # ci-unpreservable (CI cannot be kept green by chunking)
        "ci_strategy": "",
        # final verdict battery on the final variant, in order:
        # test -> ci -> codeql -> npm audit -> semgrep
        "ci_verdict": "", "audit_new": None, "status": "",
    }

    log(f"=== {entry['category']}/{folder} ===")
    ok, msg = ensure_image(entry, tag, args.build_mode)
    if not ok and run(["docker", "image", "inspect", tag]).returncode == 0:
        # buildkit's export step can report
        #   ERROR: failed to solve: image "...": already exists
        # while still producing a perfectly usable tag -- it happens when the
        # containerd content store keeps a manifest that `docker image inspect`
        # no longer lists (a partially-completed `image prune -a`). Trusting the
        # exit code alone loses the entry to a phantom `image-failed`, so verify
        # what is actually on disk before believing the failure.
        ok = True
        msg += "  [build reported failure but the tag exists -- using it]"
    log(f"image: {msg}")
    if not ok:
        m["status"] = "image-failed"
        return "\n".join(L) + "\n", "image-failed", None, m

    patch_text = (entry["path"] / "patch.txt").read_text(encoding="utf-8")
    units = split_hunks(patch_text)
    test_files = list(entry["path"].glob("*.test.js"))
    if not units or not test_files:
        m["status"] = "missing-patch-or-test"
        return "\n".join(L) + "\n", "missing-patch-or-test", None, m

    # Minimize over CHANGED LINES, not hunks: a hunk drags three lines of
    # surrounding context with it, so a hunk-level "minimal" revert reverts code
    # the fix never touched. split_groups() cuts the patch at every run of +/-
    # lines instead. Fall back to hunks when a patch has so many change groups
    # that the linear ddmin sweep (one revert + one jest run each) would dominate
    # the runtime.
    index_hunk_bodies(patch_text)
    groups = split_groups(patch_text)
    if groups and len(groups) <= args.max_units:
        chunks, build_subset, granularity = groups, build_partial_lines, "line"
    else:
        chunks, build_subset, granularity = units, build_partial, "hunk"
    m["granularity"] = granularity
    m["units_total"] = len(chunks)

    def unit_file(i):
        u = chunks[i]
        return u["file"] if isinstance(u, dict) else u[0]
    test_text = test_files[0].read_text(encoding="utf-8")

    # PoC validity, statically, before spending a container on it. Both failures
    # below make the exploit oracle meaningless -- a test with no assertions
    # always passes, and a test that never loads the package behaves identically
    # on the fixed and reverted trees -- so neither can be blamed on the patch.
    n_assert = count_assertions(test_text)
    if n_assert == 0:
        log(f"{test_files[0].name} contains NO assertions -> jest passes it "
            f"unconditionally, so it reports every version as vulnerable.")
        m["status"] = "poc-no-assertions"
        return "\n".join(L) + "\n", "poc-no-assertions", None, m
    if not test_exercises_package(test_text, package):
        log(f"{test_files[0].name} never require()s '{package}' (outside "
            f"comments) -> the PoC is package-independent and cannot "
            f"distinguish the fixed tree from the reverted one.")
        m["status"] = "poc-ignores-package"
        return "\n".join(L) + "\n", "poc-ignores-package", None, m

    cr = run(["docker", "run", "-d", "--rm", tag, "tail", "-f", "/dev/null"])
    cid = cr.stdout.strip()
    if cr.returncode != 0 or not cid or is_infra(cr):
        log("infra: could not start container (host/Docker failure).")
        log((cr.stderr or "").strip()[-500:])
        m["status"] = "infra-error"
        return "\n".join(L) + "\n", "infra-error", None, m
    tmp = Path(tempfile.mkdtemp(prefix="minevade_"))
    status = "?"
    try:
        probe = dexec(cid, "echo ok && df -P / | tail -1")
        if is_infra(probe) or "ok" not in (probe.stdout or ""):
            log("infra: container not usable (host/Docker failure).")
            m["status"] = "infra-error"
            return "\n".join(L) + "\n", "infra-error", None, m
        if dexec(cid, f"test -d {repodir}/.git").returncode != 0:
            log("skip: npm-install fallback (no git tree to revert)")
            m["status"] = "npm-fallback"
            return "\n".join(L) + "\n", "npm-fallback", None, m

        # Phase 0: install undeclared test deps, validate the fixed baseline.
        #
        # The install MUST NOT happen in workdir. The benchmark's package.json
        # pins the VULNERABLE version of the package under test, so any
        # `npm install <dep>` there makes npm reconcile the whole tree: it
        # deletes the fixed git checkout the Dockerfile cloned into
        # node_modules/<pkg> and drops the vulnerable tarball in its place,
        # .git and all. The baseline exploit then passes on the "fixed" image
        # and the entry is written off as `baseline-already-vulnerable:
        # image-not-fixed` -- a benchmark fault that never existed.
        # (Reproduced on hostr@2.0.0: 2.3.6 + .git before, 2.0.0 + no .git
        # after a single `npm install sleep`.)
        #
        # So install into an isolated prefix and link the results into
        # workdir/node_modules. npm never reads the benchmark package.json,
        # nothing in the package tree is touched, and require() still resolves.
        deps = sorted(d for d in test_requires(test_text, package)
                      if not resolves_in(cid, workdir, d))
        if deps:
            dexec(cid, f"mkdir -p {TEST_DEPS_PREFIX}")
            dexec(cid, f"cd {TEST_DEPS_PREFIX} && timeout {NPM_TIMEOUT} "
                       f"npm install --no-audit --no-fund --no-save "
                       f"--prefix {TEST_DEPS_PREFIX} {' '.join(map(shlex.quote, deps))} "
                       f">/tmp/npm.log 2>&1 || true")
            dexec(cid, f"mkdir -p {workdir}/node_modules && "
                       f"for d in {TEST_DEPS_PREFIX}/node_modules/*; do "
                       f"  b=$(basename \"$d\"); "
                       f"  [ \"$b\" = .bin ] && continue; "
                       f"  [ -e {workdir}/node_modules/\"$b\" ] || "
                       f"    ln -s \"$d\" {workdir}/node_modules/\"$b\"; "
                       f"done")
            log(f"installed test deps (isolated in {TEST_DEPS_PREFIX}): "
                f"{', '.join(deps)}")
        # Belt and braces: if anything above still managed to take the git tree
        # out from under us, say so instead of mis-blaming the image later.
        if dexec(cid, f"test -d {repodir}/.git").returncode != 0:
            log(f"the package tree at {repodir} lost its .git after the test-dep "
                f"install -> npm reinstalled '{package}' from the benchmark "
                f"package.json pin, clobbering the fixed checkout.")
            m["status"] = "testdeps-clobbered-tree"
            return "\n".join(L) + "\n", "testdeps-clobbered-tree", None, m
        reset_tree(cid, repodir)

        # Baseline on the CLEAN FIXED tree: run the repo's own CI tests and an
        # npm-audit snapshot BEFORE we touch anything, so later breakage can be
        # blamed on our patch vs. an already-broken/already-flagged upstream.
        base_ci_status, _ = ("skipped", "")
        if not args.skip_repo_tests:
            base_ci_status, _ = run_repo_tests(cid, repodir)
            m["baseline_ci"] = base_ci_status
            log(f"baseline (clean fixed tree): repo CI = {base_ci_status}")
        audit_fixed = dexec(cid, f"cd {repodir} && npm audit --json 2>/dev/null").stdout
        reset_tree(cid, repodir)

        fixed_test_pass, base_code = run_test_verbose(cid, workdir)
        if base_code == "124":
            log(f"baseline exploit test TIMED OUT after {TEST_TIMEOUT}s -- the "
                f"PoC hangs rather than deciding, so it cannot serve as an "
                f"oracle for this entry.")
            m["status"] = "poc-timeout"
            return "\n".join(L) + "\n", "poc-timeout", None, m
        m["baseline_test"] = "pass" if fixed_test_pass else "fail"
        log(f"baseline (clean fixed tree): exploit test = "
            f"{'PASS (NOT fixed!)' if fixed_test_pass else 'FAIL (vuln closed, good)'}")
        if fixed_test_pass:
            inst, fixed = installed_version(cid, workdir, package), entry.get("fixed_version") or "?"
            log(f"baseline: exploit test PASSES on the FIXED tree (installed "
                f"{package}@{inst}, expected fixed >= {fixed}) -> not truly fixed.")
            # Distinguish a broken PoC (fires without the package) from an image
            # that simply isn't on the fixed version.
            if exploit_self_fires(cid, workdir, repodir, package):
                log("  diagnosis: exploit fires with the package STUBBED OUT -> "
                    "the *.test.js PoC is self-firing (EXPLOIT fault, not setup).")
                m["status"] = "baseline-already-vulnerable: exploit-self-fires"
                return "\n".join(L) + "\n", m["status"], None, m
            log("  diagnosis: stubbing the package STOPS the exploit -> the image "
                "is not actually on the fixed version (BENCHMARK/setup fault).")
            m["status"] = "baseline-already-vulnerable: image-not-fixed"
            return "\n".join(L) + "\n", m["status"], None, m
        log("baseline: test FAILS on fixed tree (good).")

        # If this package ships a compiled runtime tree (main -> lib/, or a
        # bundled dist/*.min.js) built from src/, and patch.txt only edits the
        # source tree, a plain reverse-apply never reaches the code require()
        # loads. Detect that and have apply_revert recompile the runtime tree
        # after each re-application so the revert actually takes effect.
        sink = (entry_sink(entry) or "")
        _REBUILD_CMD = detect_rebuild_cmd(cid, repodir, units, sink)
        if _REBUILD_CMD:
            install_rebuild_script(cid, tmp, _REBUILD_CMD)
            log(f"compiled package: patch edits a source tree but the runtime "
                f"loads compiled output -> rebuilding after each revert via "
                f"`{_REBUILD_CMD}`.")

        # Phase 1: full revert must re-open the vuln, then minimize the hunk set.
        # Separate "patch won't reverse-apply" (setup) from "applied but exploit
        # doesn't reproduce" (benchmark/scope) instead of conflating both.
        all_idx = list(range(len(chunks)))
        log(f"patch splits into {len(chunks)} {granularity}-level change "
            f"unit(s) across {len({unit_file(i) for i in all_idx})} file(s)")
        if not apply_revert(cid, repodir, build_subset(chunks, all_idx), tmp):
            log("full revert FAILED TO APPLY (git apply -R rejected -- patch.txt "
                "has lockfile/built/drifted hunks) -> cannot minimize.")
            m["status"] = "revert-apply-failed"
            return "\n".join(L) + "\n", "revert-apply-failed", None, m
        if not run_test(cid, workdir):
            # A compiled package whose rebuild failed still has the FIXED runtime
            # tree on disk, so the exploit cannot fire no matter how correct the
            # patch is. Report that as a setup fault rather than blaming scope.
            if _REBUILD_CMD and not _REBUILD_OK:
                tail = dexec(cid, "tail -20 /tmp/rebuild.log").stdout.strip()
                log(f"full revert applied but the rebuild (`{_REBUILD_CMD}`) "
                    f"FAILED, so the runtime tree is still the fixed one -> "
                    f"cannot judge reproduction. Build log tail:\n{tail}")
                m["status"] = "rebuild-failed"
                return "\n".join(L) + "\n", "rebuild-failed", None, m
            log("full revert applied but exploit does NOT reproduce (vuln needs "
                "more than this patch) -> cannot minimize.")
            m["status"] = "revert-applied-no-repro"
            return "\n".join(L) + "\n", "revert-applied-no-repro", None, m

        # The revert reproduces -- but reproduction only MEANS anything if the
        # package caused it. Stub the package out and rerun: a PoC that still
        # fires is measuring something else (its own inlined regex, a local
        # helper), and every downstream number would be attributed to a package
        # that was never involved. The static gate above catches the PoCs that
        # never require() the package at all; this catches the ones that do
        # require it and then ignore it.
        if exploit_self_fires(cid, workdir, repodir, package):
            log(f"exploit still fires with '{package}' STUBBED OUT -> the PoC is "
                f"self-firing; its reproduction is not attributable to the "
                f"package (EXPLOIT fault).")
            m["status"] = "poc-self-fires-on-revert"
            return "\n".join(L) + "\n", "poc-self-fires-on-revert", None, m
        # exploit_self_fires() restores the tree, so put the revert back.
        apply_revert(cid, repodir, build_subset(chunks, all_idx), tmp)

        # Stage A: semgrep on the FULL unminimized revert (vuln fully reintroduced,
        # no changes to the patch). This is the "evade without any changes" number.
        full_changed = dexec(
            cid, f"cd {repodir} && git diff --name-only --diff-filter=d").stdout.split()
        full_targets = [f for f in full_changed if f.endswith(JS_EXT)]
        if sink and sink not in full_targets and \
                dexec(cid, f"cd {repodir} && test -f '{sink}'").returncode == 0:
            full_targets.append(sink)
        # Baseline first: the same files on the CLEAN FIXED tree. Everything the
        # detector reports here is pre-existing noise that must not be credited
        # to the patch, so each stage below is scored on (stage - baseline).
        reset_tree(cid, repodir)
        sg_base_n, _, sg_base = run_semgrep(cid, repodir, full_targets, tmp)
        m["semgrep_fixed"] = sg_base_n
        log(f"semgrep on CLEAN FIXED tree (baseline): {sg_base_n} finding(s)")
        # CodeQL baseline on the same files, taken HERE rather than in Phase 3.
        # The evasion search has to be able to score a candidate against BOTH
        # detectors -- every CodeQL alert in the analysis CSVs is a taint query,
        # and a rewrite that zeroes semgrep can leave the taint path untouched.
        # Phase 3 reuses these instead of rescanning.
        cq_base, cq_ok = [], False
        if not args.no_codeql:
            m["codeql_fixed"], cq_why, cq_base = run_codeql(
                cid, repodir, full_targets, tmp, args.codeql_suite,
                args.codeql_scope)
            cq_ok = m["codeql_fixed"] >= 0
            log(f"codeql on CLEAN FIXED tree (baseline): "
                f"{fmt_codeql(m['codeql_fixed'])} finding(s)")
            if not cq_ok:
                log("        baseline codeql could not run -> codeql_new_* = n/a "
                    "(cannot attribute alerts without it)")
                # Without the reason, an n/a row is undiagnosable: a missing CLI,
                # an extractor OOM on a big tree and a broken query pack all look
                # identical in the CSV.
                for ln in (cq_why or "").strip().splitlines()[:8]:
                    log(f"          | {ln}")
        apply_revert(cid, repodir, build_subset(chunks, all_idx), tmp)

        sg_full, _, sg_full_f = run_semgrep(cid, repodir, full_targets, tmp)
        sg_full_new = only_new(sg_full_f, sg_base, key_of)
        m["semgrep_full"] = sg_full
        m["evade_full"] = (sg_full == 0)
        m["semgrep_new_full"] = len(sg_full_new)
        log(f"semgrep on FULL revert (no changes): {sg_full} finding(s), "
            f"{len(sg_full_new)} NEW vs fixed baseline "
            f"-> evades: {'yes' if sg_full == 0 else 'no'} "
            f"(by new findings: {'yes' if not sg_full_new else 'no'})")
        cq_full_new = None
        if cq_ok:
            m["codeql_full"], _, cq_full = run_codeql(
                cid, repodir, full_targets, tmp, args.codeql_suite,
                args.codeql_scope)
            cq_full_new = (only_new(cq_full, cq_base, codeql_key)
                           if m["codeql_full"] >= 0 else None)
            m["codeql_new_full"] = None if cq_full_new is None else len(cq_full_new)
            log(f"codeql on FULL revert (no changes): "
                f"{fmt_codeql(m['codeql_full'])} finding(s), "
                f"{fmt_new(m['codeql_new_full'])} NEW vs fixed baseline")

        # Oracles over a change-unit subset. exploit = the vuln reproduces;
        # both = the vuln reproduces AND the repo's own CI stays green. Each
        # re-applies the subset onto the clean tree first, so they are
        # order-independent.
        def ex_oracle(subset):
            return apply_revert(cid, repodir, build_subset(chunks, subset), tmp) \
                and run_test(cid, workdir)

        def both_oracle(subset):
            if not ex_oracle(subset):
                return False
            st, _ = run_repo_tests(cid, repodir)
            return st == "pass"

        def ddmin_drop(seed, oracle):
            """Greedily drop change units whose revert the oracle does not need."""
            kept = set(seed)
            for idx in list(seed):
                trial = kept - {idx}
                if trial and oracle(trial):
                    kept = trial
            return sorted(kept)

        # Phase 1a: minimize for the EXPLOIT only (the chunking the user means).
        minimal = ddmin_drop(all_idx, ex_oracle)
        log(f"minimal revert (exploit-only): {len(minimal)}/{len(chunks)} "
            f"{granularity} unit(s) -> {sorted({unit_file(i) for i in minimal})}")

        # Phase 1b: keep CI/test cases passing FIRST (before any SAST evasion).
        # If the exploit-minimal chunking breaks the repo CI that was green on the
        # clean-fixed tree, try to find a chunking that ALSO keeps CI green --
        # usually by reverting more of the fix (e.g. its added regression tests).
        ci_strategy = "exploit-minimal"
        if not args.skip_repo_tests and base_ci_status == "pass":
            apply_revert(cid, repodir, build_subset(chunks, minimal), tmp)
            min_ci, _ = run_repo_tests(cid, repodir)
            if min_ci == "pass":
                log("exploit-minimal chunking already keeps repo CI green.")
            else:
                log(f"exploit-minimal chunking BREAKS repo CI ({min_ci}); "
                    f"searching for a CI-preserving chunking ...")
                if both_oracle(all_idx):
                    # the full revert keeps CI green -> minimize while preserving both
                    minimal = ddmin_drop(all_idx, both_oracle)
                    ci_strategy = "ci-preserving-chunk"
                    log(f"  found CI-preserving chunking: {len(minimal)}/"
                        f"{len(chunks)} {granularity} unit(s) -> "
                        f"{sorted({unit_file(i) for i in minimal})}")
                else:
                    ci_strategy = "ci-unpreservable"
                    log("  no chunking keeps both the exploit and CI green "
                        "(even the full revert breaks CI) -> proceeding with the "
                        "exploit-minimal variant; CI will be reported as broken.")
        m["ci_strategy"] = ci_strategy
        m["units_kept"] = len(minimal)
        minimal_patch = build_subset(chunks, minimal)

        # re-establish the minimal reverted state for scanning / evasion
        apply_revert(cid, repodir, minimal_patch, tmp)
        changed = dexec(cid, f"cd {repodir} && git diff --name-only --diff-filter=d").stdout.split()
        targets = [f for f in changed if f.endswith(JS_EXT)]
        if sink and sink not in targets and \
                dexec(cid, f"cd {repodir} && test -f '{sink}'").returncode == 0:
            targets.append(sink)

        # Phase 2 / Stage B: semgrep on the minimal (chunked) variant.
        count, text, sg_min_f = run_semgrep(cid, repodir, targets, tmp)
        sg_final_f = sg_min_f                    # updated if a rewrite wins below
        m["semgrep_minimal"] = count
        m["evade_minimal"] = (count == 0)
        m["semgrep_new_minimal"] = len(only_new(sg_min_f, sg_base, key_of))
        log(f"semgrep on minimal variant (after chunking): {count} finding(s), "
            f"{m['semgrep_new_minimal']} NEW vs fixed baseline")
        if count and text:
            log("--- semgrep findings (pre-evasion) ---")
            log(text)
            log("--------------------------------------")
        # CodeQL on the minimal variant, alongside semgrep, so the search below
        # can see the alerts it has to beat rather than optimising blind.
        cq_min_new = None
        cq_final = []
        if cq_ok:
            m["codeql_minimal"], _, cq_min = run_codeql(
                cid, repodir, targets, tmp, args.codeql_suite,
                args.codeql_scope)
            cq_min_new = (only_new(cq_min, cq_base, codeql_key)
                          if m["codeql_minimal"] >= 0 else None)
            m["codeql_new_minimal"] = None if cq_min_new is None else len(cq_min_new)
            cq_final = cq_min_new or []
            log(f"codeql on minimal variant (after chunking): "
                f"{fmt_codeql(m['codeql_minimal'])} finding(s), "
                f"{fmt_new(m['codeql_new_minimal'])} NEW vs fixed baseline")
            for a in (cq_min_new or []):
                log(f"    ! {a['rule']} @ {a['path']}:{a['line']}: "
                    f"{_one_line(a['message'], 120)}")

        # A candidate is scored on the NEW findings BOTH detectors report -- a
        # rewrite that silences semgrep while leaving CodeQL's taint path intact
        # has not evaded anything.
        sg_new_min = only_new(sg_min_f, sg_base, key_of)
        cq_budget = args.codeql_loop_budget if (cq_ok and cq_min_new) else 0

        status = "minimized"
        winning = []                # the semantics-preserving rewrites that won
        if not sg_new_min and not (cq_min_new or []):
            log("already evades both detectors (no rewrite needed).")
            status = "minimized+evaded"
            sg_final_f = sg_min_f
        elif not args.no_evade:
            cands, why = select_transforms(entry["category"], sg_new_min, cq_min_new)
            log(f"selecting rewrites from the rules that actually fired: "
                + (", ".join(f"{n} <- '{w}'" for n, w in why.items())
                   or f"(no rule matched; using every {entry['category']} transform)"))
            # When the minimal variant already introduces no NEW semgrep finding
            # -- which is the common case, because the FIXED baseline usually
            # trips the same rules -- the semgrep component of the score starts
            # satisfied and every candidate ties on it. CodeQL is then the only
            # signal that can separate them, so the budget has to cover the whole
            # candidate set; capping it at 4 is what left 115 of 120 evaluations
            # in the last campaign scored on semgrep alone, adopting nothing.
            if cq_budget and not sg_new_min:
                cq_budget = max(cq_budget, len(cands) + args.max_compose)
            for k, v in unexplained(sg_new_min, cq_min_new).items():
                log(f"  note: '{k}' has no transform -- {v}")

            # (semgrep new, codeql new or None, semgrep total)
            base_score = (len(sg_new_min), len(cq_min_new or []), count)
            best = {"score": base_score, "xfs": [], "sg": sg_min_f,
                    "cq": cq_min_new, "count": count}

            tried = set()        # transform sets already measured

            def evaluate(combo, label):
                """Apply `combo` to the clean minimal tree and score it.

                Returns None when the exploit no longer fires -- the oracle is
                absolute: a rewrite that breaks reproduction is not an evasion.
                """
                nonlocal cq_budget
                key = frozenset(t["name"] for t in combo)
                if key in tried:
                    return None      # e.g. composing onto an empty incumbent
                tried.add(key)
                apply_revert(cid, repodir, minimal_patch, tmp)
                if not apply_transforms(cid, repodir, targets, combo, tmp):
                    log(f"  {label}: matched nothing -> skipped")
                    return None
                if not run_test(cid, workdir):
                    log(f"  {label}: broke the exploit test -> rejected")
                    return None
                c2, _, f2 = run_semgrep(cid, repodir, targets, tmp)
                n2 = only_new(f2, sg_base, key_of)
                cq2, cq_why = None, "not re-run (budget spent)"
                # CodeQL is ~40s a pass, so only spend one on a candidate that
                # is already at least as good as the incumbent on semgrep.
                if cq_budget > 0 and len(n2) <= best["score"][0]:
                    cqc, why2, cqa = run_codeql(cid, repodir, targets, tmp,
                                                args.codeql_suite, args.codeql_scope)
                    cq_budget -= 1
                    if cqc >= 0:
                        cq2 = only_new(cqa, cq_base, codeql_key)
                    else:
                        # Distinguishable from a skipped run on purpose: an
                        # unmeasured candidate inherits the incumbent's CodeQL
                        # score and can then never win on it, so a silent
                        # extractor failure looks exactly like "no improvement".
                        cq_why = f"could not run -- {_one_line(why2 or '', 80)}"
                cq_n = len(cq2) if cq2 is not None else len(best["cq"] or [])
                log(f"  {label}: test PASSES, semgrep {c2} finding(s) "
                    f"({len(n2)} new), codeql new "
                    f"{len(cq2) if cq2 is not None else cq_why}")
                return {"score": (len(n2), cq_n, c2), "xfs": list(combo),
                        "sg": f2, "cq": cq2 if cq2 is not None else best["cq"],
                        "count": c2}

            # 1. each candidate alone, best first
            singles = []
            for t in cands:
                r = evaluate([t], t["name"])
                if r:
                    singles.append((r, t))
                    if r["score"] < best["score"]:
                        best = r
                if best["score"][0] == 0 and best["score"][1] == 0:
                    break
            # 2. greedy composition: the two layers are independent (hiding the
            #    sink does nothing to a taint path; laundering the argument does
            #    nothing to a syntactic match), so stacking them is what gets an
            #    entry past both detectors at once.
            if best["score"][:2] != (0, 0) and len(best["xfs"]) < args.max_compose:
                for r, t in sorted(singles, key=lambda st: st[0]["score"]):
                    if t in best["xfs"] or len(best["xfs"]) >= args.max_compose:
                        continue
                    combo = best["xfs"] + [t]
                    got = evaluate(combo, "+".join(x["name"] for x in combo))
                    if got and got["score"] < best["score"]:
                        best = got
                    if best["score"][:2] == (0, 0):
                        break

            # re-establish the winning variant as the final tree
            apply_revert(cid, repodir, minimal_patch, tmp)
            winning = best["xfs"]
            if winning:
                apply_transforms(cid, repodir, targets, winning, tmp)
                m["winning_transform"] = "+".join(t["name"] for t in winning)
                m["transform_layers"] = "+".join(
                    sorted({t["layer"] for t in winning}))
            count = best["count"]
            sg_final_f = best["sg"]
            cq_final = best["cq"] or []
            m["codeql_new_final"] = None if best["cq"] is None else len(best["cq"])
            status = ("minimized+evaded"
                      if best["score"][:2] == (0, 0) else "minimized+partial-evade")
        else:
            sg_final_f = sg_min_f
        sg_final_new = only_new(sg_final_f, sg_base, key_of)
        m["semgrep_final"] = count
        m["evade_final"] = (count == 0)
        m["semgrep_new_final"] = len(sg_final_new)
        m["evade_new_final"] = (len(sg_final_new) == 0)
        m["semgrep_new_in_patched"] = sum(
            1 for f in sg_final_new if f.get("path", "") in set(targets))
        m["semgrep_top_rules"] = top_rules(
            sg_final_new, lambda f: f.get("check_id", "?").split(".")[-1])
        m["semgrep_messages"] = format_semgrep_messages(sg_final_new)

        # The final tree is the successful variant: the ddmin-minimal revert plus
        # any syntax rewrite that kept the exploit passing.
        final_patch = dexec(cid, f"cd {repodir} && git diff").stdout or minimal_patch

        # ---- Final verdict battery on the final variant, in order ----
        # 1. test cases  2. CI  3. CodeQL  4. npm audit  5. semgrep
        # (semgrep/codeql per-stage numbers above are oracle/CSV data; this block
        #  is the ordered verdict the user asked for, reported last-to-first here.)
        evaded = (count == 0)

        # 1. TEST CASES -- does the exploit still fire on the final variant?
        exploit_ok = run_test(cid, workdir)
        log(f"[1/5] test cases  -> exploit test "
            f"{'PASSES (reproduces)' if exploit_ok else 'FAILS'}")

        # 2. CI -- repo's own tests on the final variant vs the clean-fixed
        # baseline captured in Phase 0, so breakage is attributed correctly.
        ci_verdict = "skipped"
        if not args.skip_repo_tests and exploit_ok:
            mod_status, mod_sum = run_repo_tests(cid, repodir)        # final variant
            if base_ci_status == "pass" and mod_status == "pass":
                ci_verdict = "preserved"
            elif base_ci_status == "pass" and mod_status.startswith("fail"):
                ci_verdict = "broken"
            elif base_ci_status == "no-script":
                ci_verdict = "none"
            elif base_ci_status.startswith("fail"):
                ci_verdict = "baseline-already-broken"   # not our fault
            else:
                ci_verdict = "baseline-not-green"
            log(f"[2/5] ci          -> clean-fixed baseline={base_ci_status}, "
                f"final variant={mod_status}  => {ci_verdict}")
            if mod_sum and mod_sum != "(package.json has no real test script)":
                log("        --- repo test output (final variant, tail) ---")
                log(mod_sum)
                log("        ----------------------------------------------")
        else:
            log("[2/5] ci          -> skipped")
        m["ci_verdict"] = ci_verdict

        # 3. CODEQL -- detection-only second SAST. The baseline/full/minimal
        # passes already ran in Phase 2 (the search needs them to score a
        # candidate against both detectors), so only the FINAL variant is
        # rescanned here, and only when the search did not already measure it.
        # (-1 == could not build/extract -> recorded n/a, not 'clean'.)
        if not args.no_codeql and cq_ok:
            log("[3/5] codeql      -> confirming the final variant "
                "(baseline/full/minimal measured during the search) ...")
            m["codeql_final"], _, cq_fin = run_codeql(
                cid, repodir, targets, tmp, args.codeql_suite,
                args.codeql_scope)
            cq_final_new = (only_new(cq_fin, cq_base, codeql_key)
                            if m["codeql_final"] >= 0 else None)
            if cq_final_new is not None:
                m["codeql_new_final"] = len(cq_final_new)
                m["codeql_evade_final"] = (len(cq_final_new) == 0)
                m["codeql_new_in_patched"] = sum(
                    1 for a in cq_final_new if a.get("path", "") in set(targets))
                m["codeql_top_rules"] = top_rules(cq_final_new, lambda a: a.get("rule", "?"))
                m["codeql_messages"] = format_codeql_messages(cq_final_new)
            log(f"        final   = {fmt_codeql(m['codeql_final'])} finding(s), "
                f"{fmt_new(m['codeql_new_final'])} new")
            log(f"[3/5] codeql      -> baseline={fmt_codeql(m['codeql_fixed'])}, "
                f"full={fmt_codeql(m['codeql_full'])}, "
                f"minimal={fmt_codeql(m['codeql_minimal'])}, "
                f"final={fmt_codeql(m['codeql_final'])} findings "
                f"(new vs baseline: {fmt_new(m['codeql_new_full'])}/"
                f"{fmt_new(m['codeql_new_minimal'])}/{fmt_new(m['codeql_new_final'])})")
            if cq_final_new:
                log("        --- codeql NEW alerts on the final variant ---")
                for a in cq_final_new:
                    log(f"        + {a['rule']} @ {a['path']}:{a['line']}: "
                        f"{_one_line(a['message'])}")
                log("        ---------------------------------------------")
            cq_final_new_dump = cq_final_new
        else:
            log("[3/5] codeql      -> skipped")
            cq_final_new_dump = None

        # 4. NPM AUDIT -- advisories the final variant introduces over the clean
        # fixed baseline snapshot taken in Phase 0. (Tree is at the final variant
        # after the CodeQL reconstruction above.)
        audit_final = dexec(cid, f"cd {repodir} && npm audit --json 2>/dev/null").stdout
        _, a_fixed = parse_audit(audit_fixed)
        c_rev, a_rev = parse_audit(audit_final)
        new_adv = sorted(a_rev - a_fixed)
        m["audit_new"] = len(new_adv)
        log(f"[4/5] npm audit   -> final variant: {fmt_counts(c_rev)}; "
            f"{len(new_adv)} advisory(ies) introduced vs clean-fixed baseline")
        for a in new_adv:
            log(f"        + {a}")

        # 5. SEMGREP -- the final detector verdict on the final variant.
        log(f"[5/5] semgrep     -> {count} finding(s) on final variant "
            f"({len(sg_final_new)} new vs fixed baseline; "
            f"evaded: {'yes' if evaded else 'no'}, "
            f"by new findings: {'yes' if not sg_final_new else 'no'})")
        if sg_final_new:
            log("        --- semgrep NEW findings on the final variant ---")
            for f in sg_final_new:
                log(f"        + {f.get('check_id','?').split('.')[-1]} @ "
                    f"{f.get('path','?')}:{(f.get('start') or {}).get('line','?')}: "
                    f"{_one_line((f.get('extra') or {}).get('message',''))}")
            log("        -----------------------------------------------")

        # Which detector(s) actually caught the evasive patch. 'neither' is the
        # headline result of this pipeline: the exploit reproduces and no SAST
        # reports anything the fixed tree did not already report.
        m["detected_by"] = detected_by(sg_final_new, cq_final_new_dump or [])
        # THE headline: exploit still reproduces AND neither detector reports
        # anything the fixed tree did not already report. Only claimable when
        # CodeQL actually ran -- otherwise it is a semgrep-only result and the
        # cell says so rather than quietly counting as a success.
        m["evaded_both"] = ("n/a (codeql)" if cq_final_new_dump is None else
                            "yes" if (exploit_ok and not sg_final_new
                                      and not cq_final_new_dump) else "no")
        log(f"detected_by (final/evasive variant): {m['detected_by']}"
            + ("" if cq_final_new_dump is not None
               else "  [codeql unavailable -- semgrep-only verdict; "
                    "'neither' here does NOT mean codeql agrees]"))

        # Untruncated per-stage evidence, so the CSV cells never have to be the
        # record of what the detectors said.
        (entry["path"] / FINDINGS_OUT).write_text(json.dumps({
            "package": package,
            "targets": targets,
            "full_targets": full_targets,
            "semgrep": {
                "fixed_total": m["semgrep_fixed"],
                "new_full": m["semgrep_new_full"],
                "new_minimal": m["semgrep_new_minimal"],
                "new_final": [
                    {"rule": f.get("check_id"), "path": f.get("path"),
                     "line": (f.get("start") or {}).get("line"),
                     "severity": (f.get("extra") or {}).get("severity"),
                     "message": (f.get("extra") or {}).get("message")}
                    for f in sg_final_new],
            },
            "codeql": None if cq_final_new_dump is None else {
                "fixed_total": m["codeql_fixed"],
                "new_full": m["codeql_new_full"],
                "new_minimal": m["codeql_new_minimal"],
                "new_final": cq_final_new_dump,
            },
            "detected_by": m["detected_by"],
        }, indent=2), encoding="utf-8")
        log(f"wrote {FINDINGS_OUT} (per-stage new findings, semgrep + codeql)")

        # the successful patch: exploit reproduces, semgrep minimized/evaded.
        (entry["path"] / PATCH_OUT).write_text(final_patch, encoding="utf-8")
        log(f"wrote {PATCH_OUT} (exploit reproduces; semgrep={count}, evaded={'yes' if evaded else 'no'})")
        if not exploit_ok:
            status += "-EXPLOIT-BROKEN"
        status += f" (ci:{ci_verdict})"
        m["status"] = status
        return "\n".join(L) + "\n", status, minimal_patch, m
    finally:
        if args.keep:
            print(f"    [kept {cid} and {tmp}]")
        else:
            run(["docker", "rm", "-f", cid])
            shutil.rmtree(tmp, ignore_errors=True)


def entry_sink(entry):
    import json
    try:
        meta = json.loads((entry["path"] / "package.json").read_text(encoding="utf-8"))
    except Exception:
        return ""
    return (meta.get("sink") or "").split(":", 1)[0].strip()


# --------------------------------------------------------------------------- #
def main():
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("name", nargs="?")
    ap.add_argument("--category", "-c")
    ap.add_argument("--all", action="store_true")
    ap.add_argument("--csv", default="repositories.csv")
    ap.add_argument("--force", action="store_true",
                    help=f"overwrite existing {REPORT_OUT}")
    ap.add_argument("--build", action="store_true")
    ap.add_argument("--no-build", action="store_true")
    ap.add_argument("--keep", action="store_true")
    ap.add_argument("--no-evade", action="store_true",
                    help="stop after minimization; do not try semgrep rewrites")
    ap.add_argument("--skip-repo-tests", action="store_true",
                    help="do not run the package's own test suite / CI (Phase 3)")
    ap.add_argument("--no-codeql", action="store_true",
                    help="skip the CodeQL detection pass (Phase 4, after CI checks)")
    ap.add_argument("--codeql-suite", default=CODEQL_SUITE,
                    help=f"CodeQL query suite (default: security-extended; pass "
                         f"{CODEQL_SUITE_DEFAULT} to match the configuration that "
                         f"produced <category>-semgrep-codeql-analysis.csv)")
    ap.add_argument("--codeql-scope", choices=("package", "files"),
                    default="package",
                    help="CodeQL database scope. 'package' (default) matches "
                         "semgrep-codeql-analysis.py; 'files' scans only the "
                         "patched files and MISSES cross-file taint paths")
    ap.add_argument("--codeql-loop-budget", type=int, default=4,
                    help="max CodeQL passes the evasion search may spend "
                         "scoring candidate rewrites (0 = score on semgrep only)")
    ap.add_argument("--max-compose", type=int, default=3,
                    help="max transforms stacked into one evasive variant")
    ap.add_argument("--max-units", type=int, default=60,
                    help="above this many change groups, minimize at hunk "
                         "granularity instead of changed-line granularity")
    args = ap.parse_args()
    if sum(bool(x) for x in (args.name, args.category, args.all)) != 1:
        ap.error("provide exactly one of: a name, --category CAT, or --all")
    args.build_mode = "force" if args.build else ("never" if args.no_build else "auto")

    if run(["docker", "info"]).returncode != 0:
        sys.exit("error: Docker daemon is not reachable. Start Docker and retry.")

    csv_path = Path(args.csv)
    if not csv_path.is_absolute():
        csv_path = ROOT / csv_path
    repo_index = csv_repo_index(csv_path)
    if args.category:
        cat = args.category.strip().strip("/").lower()
        matches = collect_entries([cat], repo_index)
    elif args.all:
        matches = collect_entries(CATEGORIES, repo_index)
    else:
        matches = find_matches_disk(args.name, repo_index)

    eligible = [e for e in matches
                if (e["path"] / "Dockerfile.fixed").exists()
                and (e["path"] / "patch.txt").exists()
                and list(e["path"].glob("*.test.js"))]
    print(f"Processing {len(eligible)} entr"
          f"{'y' if len(eligible) == 1 else 'ies'}.\n")

    tally = {}
    metrics_by_cat = {}     # category -> [metrics dict, ...] for the CSVs
    for entry in eligible:
        target = entry["path"] / REPORT_OUT
        if target.exists() and not args.force:
            print(f"  - exists, skipping (use --force): "
                  f"{entry['category']}/{entry['folder']}/{REPORT_OUT}")
            continue
        report, status, _, metrics = process(entry, args)
        target.write_text(report, encoding="utf-8")
        tally[status] = tally.get(status, 0) + 1
        metrics_by_cat.setdefault(entry["category"], []).append(metrics)
        print(f"  => {entry['folder']}: {status}\n")
    print("Summary:", ", ".join(f"{k}={v}" for k, v in sorted(tally.items())) or "(nothing)")
    if tally:
        print("\nWhat each result means (where the problem is):")
        for status, n in sorted(tally.items()):
            base = re.sub(r" \(ci:[^)]*\)$", "", status)
            if base.endswith("-EXPLOIT-BROKEN"):
                base = base[:-len("-EXPLOIT-BROKEN")]
            print(f"  {n:>2}  {status:<46} {FAULT_CLASS.get(base, '?')}")
        print("\n  ci: preserved = patch keeps repo tests green (stealthy) | "
              "broken = patch fails repo CI | none = no test script | "
              "baseline-not-green = can't compare | skipped")

    write_csvs(metrics_by_cat)


# CSV columns: repository + the per-stage detection labels. evade_* booleans are
# the headline numbers ("how many evade semgrep at each stage"); codeql_* are the
# parallel detection-only verdicts (blank when CodeQL was skipped / could not run).
#
# Two families of detector columns, and they answer different questions:
#   semgrep_*/codeql_*          TOTAL findings on the scanned files at that stage
#   *_new_*                     findings that stage introduced over the CLEAN
#                               FIXED tree -- what the detector caught *because
#                               of* the patch. Use these for detection rates;
#                               the totals include pre-existing noise.
# The *_new_in_patched / *_top_rules / *_messages / detected_by columns describe
# the FINAL (evasive) variant -- the patch actually written to
# exploit-evasive.patch -- and are the "why did it get caught" evidence, matching
# the columns of the same name in <category>-semgrep-codeql-analysis.csv.
CSV_FIELDS = [
    "category", "repository", "package", "version",
    "outcome",
    "baseline_test", "baseline_ci",
    "semgrep_fixed", "codeql_fixed",
    "semgrep_full", "evade_full",
    "semgrep_minimal", "evade_minimal",
    "semgrep_final", "evade_final",
    "semgrep_new_full", "semgrep_new_minimal", "semgrep_new_final", "evade_new_final",
    "codeql_full", "codeql_minimal", "codeql_final",
    "codeql_new_full", "codeql_new_minimal", "codeql_new_final", "codeql_evade_final",
    "detected_by", "evaded_both",
    "semgrep_new_in_patched", "codeql_new_in_patched",
    "semgrep_top_rules", "codeql_top_rules",
    "semgrep_messages", "codeql_messages",
    "winning_transform", "transform_layers",
    "granularity", "units_total", "units_kept", "ci_strategy",
    "ci_verdict", "audit_new", "status",
]


def _csv_cell(v):
    if v is None:
        return ""
    if isinstance(v, bool):
        return "yes" if v else "no"
    if isinstance(v, int) and v < 0:
        return "n/a"      # codeql could not build/extract
    return str(v)


def write_csvs(metrics_by_cat):
    """Write one evasion-results-<category>.csv per category, plus print the
    per-stage evasion totals (the headline 'how many evade semgrep' numbers)."""
    import csv as _csv
    if not metrics_by_cat:
        return
    print()
    for cat, rows in sorted(metrics_by_cat.items()):
        out = ROOT / f"{CSV_PREFIX}-{cat}.csv"
        with out.open("w", newline="", encoding="utf-8") as fh:
            w = _csv.DictWriter(fh, fieldnames=CSV_FIELDS)
            w.writeheader()
            for r in rows:
                row = dict(r)
                row.setdefault("outcome", outcome_of(r.get("status")))
                w.writerow({k: _csv_cell(row.get(k)) for k in CSV_FIELDS})
        # per-stage evasion tally over entries that actually reached each stage
        def tally(key):
            seen = [r for r in rows if r.get(key) is not None]
            return sum(1 for r in seen if r.get(key)), len(seen)
        ff, fn = tally("evade_full")
        mm, mn = tally("evade_minimal")
        cc, cn = tally("evade_final")
        print(f"  wrote {out.name}  ({len(rows)} entr"
              f"{'y' if len(rows) == 1 else 'ies'})")
        print(f"    evade semgrep -- no changes (full revert): {ff}/{fn}")
        print(f"    evade semgrep -- after chunking (minimal): {mm}/{mn}")
        print(f"    evade semgrep -- after syntax rewrite     : {cc}/{cn}")

        # Same three stages scored on NEW findings only (pre-existing alerts in
        # the scanned files subtracted), plus the CodeQL column and the
        # both-detectors verdict on the final evasive patch.
        def tally_zero(key):
            seen = [r for r in rows if r.get(key) is not None]
            return sum(1 for r in seen if r.get(key) == 0), len(seen)
        for label, key in (("no changes (full revert)", "semgrep_new_full"),
                           ("after chunking (minimal)", "semgrep_new_minimal"),
                           ("after syntax rewrite     ", "semgrep_new_final")):
            a, b = tally_zero(key)
            print(f"    0 NEW semgrep findings -- {label}: {a}/{b}")
        a, b = tally_zero("codeql_new_final")
        print(f"    0 NEW codeql  findings -- final (evasive) variant: {a}/{b}")
        seen = [r for r in rows if r.get("detected_by")]
        if seen:
            by = Counter(r["detected_by"] for r in seen)
            print(f"    final variant detected by: "
                  + ", ".join(f"{k}={by[k]}" for k in
                              ("neither", "semgrep", "codeql", "both") if by[k]))
        # The headline the whole pipeline exists to produce.
        judged = [r for r in rows if r.get("evaded_both") in ("yes", "no")]
        if judged:
            won = sum(1 for r in judged if r["evaded_both"] == "yes")
            print(f"    EXPLOIT PASSES *and* BOTH detectors evaded: "
                  f"{won}/{len(judged)} entries judged by both detectors "
                  f"({len(rows) - len(judged)} not judged: codeql unavailable "
                  f"or entry never reached the evasion stage)")
            xf = Counter(r.get("winning_transform") or "(none needed)"
                         for r in judged if r["evaded_both"] == "yes")
            for name, n in xf.most_common():
                print(f"      via {name}: {n}")


if __name__ == "__main__":
    main()
