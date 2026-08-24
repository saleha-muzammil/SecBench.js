#!/usr/bin/env python3
"""
Migrate the ReDoS exploit tests onto the ratio-based oracle in redos/utils.js.

The old shape measures one wall-clock sample against an absolute threshold:

    let t = measureTime(function () { vulnerable(attack_str); });
    let time = t[0] + t[1] / 1000000000;
    expect(time).toBeGreaterThan(1);

which includes lazy module init in the measured region (browserslist takes
1161 ms on the FIXED version and so passes) and has no notion of what "slow"
means for the package. The new shape measures only the vulnerable call, after
warmup, against a same-process benign baseline of the same shape:

    expectRedos({
      run: (input) => { vulnerable(input); },
      build: (n) => "a" + " ".repeat(n) + "a",
      n: 33000,
    });

Only tests whose payload is a single variable built from ONE numeric size
literal are converted -- that literal is what becomes `n`. Everything else is
reported for manual conversion and left untouched, because silently reshaping a
payload would change what the benchmark exploits.

Every rewrite is VERIFIED before it is kept: the generated `build(n)` is
executed with node and its output compared byte-for-byte with the original
payload expression. A mismatch means the file is skipped, not written.

Usage:
    python3 migrate_redos_tests.py            # dry run, prints the plan
    python3 migrate_redos_tests.py --write    # apply
    python3 migrate_redos_tests.py --only ramda_0.27.1
"""

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
REDOS = ROOT / "redos"

# let/const/var NAME = EXPR;   (single line, not a require)
ASSIGN_RE = re.compile(r"^[ \t]*(?:let|const|var)[ \t]+(\w+)[ \t]*=[ \t]*(.+?);[ \t]*$",
                       re.M)
# let t = measureTime(function () { ...body... });
# The closing brace must sit at the SAME indentation as the opening statement
# (backreference \1). Matching any `\n[ \t]*}\);` instead stops at the first
# nested `});` -- forwarded's payload is passed inside a `fresh({...})` call, and
# a non-greedy match swallowed only half the closure.
MEASURE_RE = re.compile(
    r"^([ \t]*)(?:let|const|var)[ \t]+(\w+)[ \t]*=[ \t]*measureTime\([ \t]*"
    r"function[ \t]*\([ \t]*\)[ \t]*\{(.*?)\n\1\}[ \t]*\);[ \t]*$",
    re.M | re.S)
# let time = t[0] + t[1] / 1000000000;
TIME_RE = re.compile(
    r"^[ \t]*(?:let|const|var)[ \t]+(\w+)[ \t]*=[ \t]*\w+\[0\][^\n]*?;[ \t]*$", re.M)
ASSERT_RE = re.compile(
    r"^[ \t]*expect\([ \t]*\w+[ \t]*\)\.toBeGreaterThan\([ \t]*[\d.]+[ \t]*\);[ \t]*$",
    re.M)
# The size knob: a bare integer of 3+ digits (payload lengths), not an index.
SIZE_RE = re.compile(r"(?<![\w.])(\d{3,})(?![\w.])")
UTILS_REQUIRE_RE = re.compile(
    r"^[ \t]*(?:const|let|var)[ \t]+\w+[ \t]*=[ \t]*require\(\s*[\"']\.\./utils[\"']\s*\)"
    r"(?:\.\w+)?;[ \t]*\n", re.M)


def payload_is_pure(expr):
    """True when the payload expression can be evaluated without the package.

    Verification runs the expression standalone, so it may only use string
    literals, arithmetic, .repeat/.padStart and the shared genstr helper.
    """
    stripped = re.sub(r"\"[^\"]*\"|'[^']*'|`[^`]*`", "", expr)
    allowed = {"genstr", "repeat", "padStart", "padEnd", "String", "Array",
               "join", "fill", "concat", "toString"}
    idents = set(re.findall(r"[A-Za-z_$][\w$]*", stripped))
    return idents <= allowed


def eval_payload(expr):
    """Evaluate a payload expression with node; return its string value or None."""
    script = (
        "const {genstr} = require(process.argv[1]);"
        "try { const v = (" + expr + "); "
        "process.stdout.write(JSON.stringify(String(v))); } "
        "catch (e) { process.exit(3); }"
    )
    r = subprocess.run(["node", "-e", script, str(REDOS / "utils.js")],
                       capture_output=True, text=True)
    if r.returncode != 0 or not r.stdout:
        return None
    try:
        return json.loads(r.stdout)
    except json.JSONDecodeError:
        return None


def plan(path):
    """Return (new_text, note) for a test file; new_text is None when skipped."""
    text = path.read_text(encoding="utf-8", errors="replace")
    meas = MEASURE_RE.search(text)
    if not meas:
        return None, "no measureTime(function(){...}) closure"
    if not ASSERT_RE.search(text):
        return None, "no `expect(time).toBeGreaterThan(...)` assertion"

    indent, _tvar, body = meas.group(1), meas.group(2), meas.group(3)
    payloads = [(v, e) for v, e in ASSIGN_RE.findall(text)
                if "require(" not in e and re.search(rf"\b{v}\b", body)]
    if len(payloads) != 1:
        return None, (f"{len(payloads)} candidate payload variables "
                      f"({[v for v, _ in payloads] or 'payload inlined in the closure'})")

    name, expr = payloads[0]
    sizes = SIZE_RE.findall(expr)
    if len(set(sizes)) != 1:
        return None, f"payload expression has {len(set(sizes))} size literals, need 1"
    size = sizes[0]
    if not payload_is_pure(expr):
        return None, "payload expression depends on the package; cannot verify"

    # Verify: build(n) with the original n must reproduce the original payload.
    build_expr = SIZE_RE.sub(lambda m: "n" if m.group(1) == size else m.group(1), expr)
    original = eval_payload(expr)
    rebuilt = eval_payload(f"((n) => ({build_expr}))({size})")
    if original is None or rebuilt is None:
        return None, "payload expression could not be evaluated for verification"
    if original != rebuilt:
        return None, "VERIFY FAILED: parameterised payload differs from the original"

    # The payload may be declared INSIDE the closure (printf, sshpk). Its
    # declaration has to be dropped from the body, or the rewrite emits
    # `run: (input) => { let input = ...; }` and shadows its own parameter.
    body_wo_decl = re.sub(
        rf"^[ \t]*(?:let|const|var)[ \t]+{re.escape(name)}[ \t]*=[^\n]*\n", "",
        body, count=1, flags=re.M)

    # Re-indent the closure body under its new home (two extra levels), keeping
    # the relative shape of multi-line bodies intact.
    raw_lines = [ln for ln in
                 re.sub(rf"\b{name}\b", "input", body_wo_decl).strip("\n").split("\n")
                 if ln.strip()]
    base = min((len(ln) - len(ln.lstrip()) for ln in raw_lines), default=0)
    run_body = "\n".join(f"{indent}    {ln[base:]}" for ln in raw_lines)
    new_call = (
        f"{indent}expectRedos({{\n"
        f"{indent}  run: (input) => {{\n"
        f"{run_body}\n"
        f"{indent}  }},\n"
        f"{indent}  build: (n) => {build_expr},\n"
        f"{indent}  n: {size},\n"
        f"{indent}}});"
    )

    out = text
    # Drop the payload assignment, the measureTime block, the time arithmetic
    # and the absolute assertion; the helper subsumes all four.
    out = out[:meas.start()] + new_call + out[meas.end():]
    out = re.sub(rf"^[ \t]*(?:let|const|var)[ \t]+{name}[ \t]*=[^\n]*\n", "", out,
                 count=1, flags=re.M)
    out = TIME_RE.sub("", out, count=1)
    out = ASSERT_RE.sub("", out, count=1)
    # Swap the old utils imports for the new helper. genstr has to survive when
    # the parameterised payload still builds its input with it -- dropping it
    # would leave a file that throws ReferenceError instead of testing anything.
    out = UTILS_REQUIRE_RE.sub("", out)
    helpers = ["expectRedos"]
    if re.search(r"\bgenstr\b", build_expr):
        helpers.append("genstr")
    out = (f'const {{ {", ".join(helpers)} }} = require("../utils");\n'
           + out.lstrip("\n"))
    out = re.sub(r"\n{3,}", "\n\n", out)
    return out, f"payload {name!r}, n={size}"


def main():
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--write", action="store_true", help="apply (default: dry run)")
    ap.add_argument("--only", help="restrict to one folder name")
    args = ap.parse_args()

    if not REDOS.is_dir():
        sys.exit(f"error: {REDOS} not found")

    converted, skipped = [], []
    for path in sorted(REDOS.glob("*/*.test.js")):
        if args.only and args.only not in str(path.parent.name):
            continue
        new_text, note = plan(path)
        rel = path.relative_to(ROOT)
        if new_text is None:
            skipped.append((rel, note))
            continue
        converted.append((rel, note))
        if args.write:
            path.write_text(new_text, encoding="utf-8")

    print(f"=== converted to the ratio oracle ({len(converted)}) ===")
    for rel, note in converted:
        print(f"  + {rel}  ({note})")
    print(f"\n=== left for manual conversion ({len(skipped)}) ===")
    for rel, note in skipped:
        print(f"  ~ {rel}\n      {note}")

    if not args.write:
        print(f"\nDry run. Re-run with --write to rewrite {len(converted)} file(s).")
    else:
        print(f"\nRewrote {len(converted)} test file(s). The remaining "
              f"{len(skipped)} still use the old absolute-threshold oracle; "
              f"convert them by hand with expectRedos/expectRedosPair.")


if __name__ == "__main__":
    main()
