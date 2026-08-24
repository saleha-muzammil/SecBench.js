#!/usr/bin/env bash
# Test transformed candidate diffs against the taint-only Semgrep rule.
#
# Usage:
#   scripts/taint_test.sh <repo_url> <base_commit> <diff_dir> [scan_subdir]
#
# Example (serialize-to-js):
#   scripts/taint_test.sh \
#     https://github.com/commenthol/serialize-to-js.git \
#     1cd4339 \
#     code-injection/serialize-to-js_0.5.0/transform_exploit-evasive \
#     lib
#
# base_commit = the commit whose source the diffs were cut against (the FIXED
# version for these benchmarks). Find it with:
#   git log --oneline --all -- <the/patched/file>
set -euo pipefail

REPO_URL=${1:?repo_url required}
BASE_COMMIT=${2:?base_commit required}
DIFF_DIR=${3:?diff_dir required}
SCAN_SUBDIR=${4:-lib}

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
RULE="$ROOT/semgrep-rules/secbench-taint.yml"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

echo ">> cloning $REPO_URL @ $BASE_COMMIT"
git clone -q "$REPO_URL" "$WORK/base"
git -C "$WORK/base" checkout -q "$BASE_COMMIT"

count() {  # count taint findings under a directory
  semgrep --config "$RULE" -q --json "$1" 2>/dev/null \
    | python3 -c "import sys,json;print(len(json.load(sys.stdin)['results']))"
}

echo ">> BASELINE ($SCAN_SUBDIR): $(count "$WORK/base/$SCAN_SUBDIR") finding(s)"
echo ">> candidates:"
for d in "$ROOT/$DIFF_DIR"/*.diff; do
  [ -e "$d" ] || { echo "   (no .diff files in $DIFF_DIR)"; break; }
  rm -rf "$WORK/t"; cp -r "$WORK/base" "$WORK/t"
  if git -C "$WORK/t" apply "$d" 2>/dev/null; then
    printf "   %-16s findings: %s\n" "$(basename "$d")" "$(count "$WORK/t/$SCAN_SUBDIR")"
  else
    printf "   %-16s APPLY FAILED (base mismatch)\n" "$(basename "$d")"
  fi
done
