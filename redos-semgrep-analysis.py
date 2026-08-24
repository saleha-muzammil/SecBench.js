#!/usr/bin/env python3
"""ReDoS twin of code-injection-semgrep-analysis.py: how much does semgrep notice when a ReDoS
patch is reverted?

Same pipeline, same CSV columns, same semgrep configuration (mini-swe-agent's) -- only the
category and the output paths differ. Rather than fork the implementation, this loads it from
`code-injection-semgrep-analysis.py` and supplies redos defaults, so a fix to the pipeline lands
in both analyses at once.

    python3 redos-semgrep-analysis.py                  # -> redos-semgrep-analysis.csv
    python3 redos-semgrep-analysis.py --skip-build
    python3 redos-semgrep-analysis.py --only ajv_5.2.2

Any flag the underlying script accepts works here and overrides the defaults below.

A note on what to expect: a ReDoS fix usually rewrites a nested quantifier inside a regex LITERAL
(`(a+)+` -> a linear form). That changes no construct the mini rules match -- the only regex rule,
mini-regexp-from-variable, targets dynamically CONSTRUCTED regexes -- so a 0 delta here is the
likely outcome and reflects rule coverage, not a subtle patch. Catastrophic backtracking is a
property of the regex language, which pattern matching cannot decide; that needs a dedicated
analyzer (recheck, safe-regex).
"""

import importlib.util
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
IMPL = HERE / "semgrep-codeql-analysis.py"

DEFAULTS = {
    "--category": "redos",
    "--csv": str(HERE / "redos-semgrep-analysis.csv"),
    "--out": str(HERE / ".redos-semgrep-analysis"),
}


def load_impl():
    if not IMPL.exists():
        sys.exit(f"missing sibling script: {IMPL}")
    spec = importlib.util.spec_from_file_location("ci_semgrep_analysis", IMPL)
    module = importlib.util.module_from_spec(spec)
    # Registered before exec: @dataclass resolves annotations via sys.modules[cls.__module__],
    # which is None for a module that is not yet registered.
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def main() -> int:
    argv = sys.argv[1:]
    for flag, value in DEFAULTS.items():
        if flag not in argv:            # an explicit flag on the command line always wins
            argv += [flag, value]
    sys.argv = [sys.argv[0], *argv]
    return load_impl().main()


if __name__ == "__main__":
    sys.exit(main())
