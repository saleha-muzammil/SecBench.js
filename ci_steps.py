#!/usr/bin/env python3
"""
Extract runnable shell steps from a tests_and_ci.txt file.

Emits a ready-to-source shell script on stdout for one of two kinds:

  --kind test   the repo's own test commands (from "how to run the tests")
  --kind ci     the shell `run:`/`script:` steps embedded from the CI files

Standalone dependency-install commands (npm install / npm ci / yarn / ...) are
dropped: the benchmark image has already installed the repo's dependencies, and
re-installing inside the container would hit the network or wipe node_modules.

If there is nothing to run, nothing is printed (exit 0), so callers can simply
check whether the output is empty.

Usage:
    python3 ci_steps.py <tests_and_ci.txt> --kind {test|ci}
"""

import argparse
import re
import sys
from pathlib import Path

# Commands that are pure dependency installs -> skipped (deps already present).
INSTALL_RE = re.compile(
    r"^(npm (ci|install|i)|yarn|yarn install|pnpm (install|i)|bower install)"
    r"(\s+--?\S+|\s+\S+)*\s*$",
    re.IGNORECASE,
)

# Which YAML key holds the shell command differs per CI system, so pick the key
# set by file type to avoid emitting structural YAML (CircleCI wraps shell in
# `command:` under a `run:` step; GitHub Actions uses `run:` directly).
def keys_for(fname):
    f = fname.lower()
    if ".github/workflows" in f:
        return {"run"}
    if ".circleci" in f:
        return {"command"}
    if f.endswith(".travis.yml") or f.endswith("travis.yml"):
        return {"script", "before_script", "before_install", "after_success"}
    if "gitlab-ci" in f:
        return {"script", "before_script", "after_script"}
    return {"run", "script", "command"}


def read_section(lines, header):
    """Return the indented body lines of a '== header ==' section."""
    out, collecting = [], False
    for line in lines:
        if line.strip().startswith("==") and line.strip().endswith("=="):
            if collecting:
                break
            collecting = line.strip().strip("= ").strip() == header
            continue
        if collecting:
            out.append(line)
    return out


def read_ci_blocks(lines):
    """Yield (filename, [content lines]) for each embedded '--- file ---' block."""
    blocks, name, buf = [], None, []
    for line in lines:
        m = re.match(r"^\s*---\s+(.*?)\s+---\s*$", line)
        if m:
            if name is not None:
                blocks.append((name, buf))
            name, buf = m.group(1), []
            continue
        if name is not None:
            cm = re.match(r"^\s*\| ?(.*)$", line)
            if cm:
                buf.append(cm.group(1))
            elif line.strip() == "":
                buf.append("")
            else:
                blocks.append((name, buf))
                name, buf = None, []
    if name is not None:
        blocks.append((name, buf))
    return blocks


def extract_yaml_commands(yaml_lines, keys):
    """Pull shell commands out of CI YAML for the given key set (scalars & lists)."""
    cmds, i, n = [], 0, len(yaml_lines)
    while i < n:
        line = yaml_lines[i]
        m = re.match(r"^(\s*)-?\s*([A-Za-z_]+):\s*(.*)$", line)
        if not m or m.group(2) not in keys:
            i += 1
            continue
        indent, val = len(m.group(1)), m.group(3).strip()
        if val and val not in ("|", ">", "|-", ">-", "|+", ">+"):
            cmds.append(val.strip("\"'"))
            i += 1
            continue
        # Block scalar or list follows on more-indented lines.
        block, j = [], i + 1
        while j < n:
            l = yaml_lines[j]
            if l.strip() == "":
                block.append("")
                j += 1
                continue
            if len(l) - len(l.lstrip()) <= indent:
                break
            block.append(l)
            j += 1
        items = [b for b in block if b.lstrip().startswith("- ")]
        if items and not val:
            for b in items:
                c = b.lstrip()[2:].strip().strip("\"'")
                if c:
                    cmds.append(c)
        else:
            nonempty = [b for b in block if b.strip()]
            if nonempty:
                pad = min(len(b) - len(b.lstrip()) for b in nonempty)
                text = "\n".join(b[pad:] if len(b) >= pad else b for b in block).strip("\n")
                if text.strip():
                    cmds.append(text)
        i = j
    return cmds


def is_install(cmd):
    first = cmd.strip().splitlines()[0].strip() if cmd.strip() else ""
    return bool(INSTALL_RE.match(first))


def emit(steps):
    """Print a shell script that runs each step, stopping on the first failure."""
    if not steps:
        return
    print("set -e")
    for label, cmd in steps:
        safe = label.replace("'", "'\\''")
        print(f"echo '>>> {safe}'")
        print(cmd)


def main():
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("path", help="path to a tests_and_ci.txt file")
    ap.add_argument("--kind", choices=["test", "ci"], required=True)
    args = ap.parse_args()

    p = Path(args.path)
    if not p.exists():
        sys.exit(f"error: no such file: {p}")
    lines = p.read_text(encoding="utf-8", errors="replace").splitlines()

    steps = []
    if args.kind == "test":
        for raw in read_section(lines, "how to run the tests"):
            cmd = raw.strip()
            if not cmd or cmd.startswith("#") or is_install(cmd):
                continue
            steps.append((cmd, cmd))
    else:  # ci
        for fname, body in read_ci_blocks(lines):
            for cmd in extract_yaml_commands(body, keys_for(fname)):
                first = cmd.strip().splitlines()[0].strip() if cmd.strip() else ""
                # Skip installs and YAML noise (anchors/aliases/empty).
                if not first or first[0] in "&*" or is_install(cmd):
                    continue
                label = f"[{fname}] {first}"
                steps.append((label, cmd))

    emit(steps)


if __name__ == "__main__":
    main()
