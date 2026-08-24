#!/usr/bin/env python3
"""Fill the semgrep_messages / codeql_messages columns for rows measured before those columns existed.

Nothing is re-scanned: every finding was already written to <out>/<target>/new_findings.json and
codeql_new.json, so this just reformats what is on disk into the CSV.

    python3 backfill-messages.py                       # every category CSV it can find
    python3 backfill-messages.py prototype-pollution   # just one

Safe to run while a sweep is in progress, but rows finishing at that exact moment may be missed --
re-run it afterwards and it will pick them up.
"""

from __future__ import annotations

import csv
import importlib.util
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
CATEGORIES = ["code-injection", "command-injection", "prototype-pollution", "path-traversal", "redos"]


def load_impl():
    """Reuse the formatters from the analysis script so both paths render identically."""
    spec = importlib.util.spec_from_file_location("sca", HERE / "semgrep-codeql-analysis.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def csv_and_out(category: str) -> tuple[Path, Path]:
    """The redos run predates the shared naming, so it keeps its own paths."""
    if category == "redos":
        return HERE / "redos-semgrep-analysis.csv", HERE / ".redos-semgrep-analysis"
    return HERE / f"{category}-semgrep-codeql-analysis.csv", HERE / f".{category}-analysis"


def backfill(category: str, impl) -> None:
    csv_path, out_root = csv_and_out(category)
    if not csv_path.exists():
        return

    with csv_path.open(newline="") as fh:
        rows = list(csv.DictReader(fh))
    if not rows:
        return

    columns = list(rows[0].keys())
    for col in ("semgrep_messages", "codeql_messages"):
        if col not in columns:                      # CSV written before the columns were added
            columns.insert(columns.index("detected_by") + 1 if "detected_by" in columns else len(columns), col)

    filled = 0
    for row in rows:
        work = out_root / row["repository"]
        for col, filename, fmt in (
            ("semgrep_messages", "new_findings.json", impl.format_semgrep_messages),
            ("codeql_messages", "codeql_new.json", impl.format_codeql_messages),
        ):
            if row.get(col):                        # already populated; never overwrite
                continue
            src = work / filename
            if not src.exists():
                row.setdefault(col, "")
                continue
            try:
                data = json.loads(src.read_text())
            except (json.JSONDecodeError, OSError):
                row.setdefault(col, "")
                continue
            row[col] = fmt(data) if data else ""
            filled += bool(row[col])

    with csv_path.open("w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=columns, extrasaction="ignore")
        w.writeheader()
        for row in rows:
            w.writerow({c: row.get(c, "") for c in columns})
    print(f"{category:<22} {len(rows):>3} rows, {filled} message cell(s) filled -> {csv_path.name}")


def main() -> int:
    impl = load_impl()
    for category in (sys.argv[1:] or CATEGORIES):
        backfill(category, impl)
    return 0


if __name__ == "__main__":
    sys.exit(main())
