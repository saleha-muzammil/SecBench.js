#!/usr/bin/env python3
"""
Fetch the fix-commit patch for SecBench.js benchmark entries.

For each benchmark folder ``<category>/<package>_<version>/`` whose package.json
carries a ``fixCommit`` GitHub URL, this downloads that commit's diff and writes
it to ``patch.txt`` next to the package.json. GitHub serves the raw diff of any
commit at ``<commit-url>.patch``, so that is all this does: append ``.patch`` to
the commit URL and save the response.

Entries with no usable ``fixCommit`` (missing / n/a / non-GitHub) are skipped.

This reuses the entry-walking helpers from generate_dockerfile.py so the set of
folders and the package.json parsing stay consistent with the other tooling.

Usage:
    python3 fetch_patch.py <owner/repo | package>   # one entry
    python3 fetch_patch.py --category code-injection # a whole class
    python3 fetch_patch.py --all                     # everything
    # options: [--csv repositories.csv] [--force] [--print]
"""

import argparse
import json
import re
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

from generate_dockerfile import (
    ROOT, CATEGORIES,
    csv_repo_index, collect_entries, find_matches_disk,
    parse_github_repo,
)

OUTPUT_NAME = "patch.txt"
USER_AGENT = "SecBench.js-fetch-patch"


# A single GitHub commit, in either the plain or the pull-request form:
#   .../commit/<sha>            .../pull/<n>/commits/<sha>
# Multi-commit ranges (.../compare/A...B) are intentionally NOT matched: their
# .patch is the whole range, which is not a single revertable fix.
SINGLE_COMMIT_RE = re.compile(r"/commits?/[0-9a-f]{7,40}\b", re.IGNORECASE)


def fix_commit_url(entry):
    """Return the GitHub single-commit URL from package.json, or ''.

    Accepts both .../commit/<sha> and .../pull/<n>/commits/<sha>; rejects
    advisory pages (via parse_github_repo) and multi-commit /compare/ ranges.
    """
    meta_path = entry["path"] / "package.json"
    try:
        meta = json.loads(meta_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return ""
    url = (meta.get("fixCommit") or "").strip()
    if not url or url.lower() in {"n/a", "na", "none"}:
        return ""
    if not parse_github_repo(url) or not SINGLE_COMMIT_RE.search(url):
        return ""
    return url


# --------------------------------------------------------------------------- #
# Which advisory does the PoC actually exploit?
# --------------------------------------------------------------------------- #
# package.json records the NEWEST advisory for a package; the *.test.js PoC
# exploits whichever one its author wrote it against, and for older packages
# those are routinely different vulnerabilities with different fixes:
#
#   set-value@3.0.0   test cites SNYK-JS-SETVALUE-450213  (CVE-2019-10747)
#                     package.json records CVE-2021-23440 -> a LATER fix
#   mpath@0.4.1       test cites HackerOne #390860 (2018)
#                     package.json records CVE-2021-23438
#
# Reverting the recorded (later) fix leaves the earlier fix in place, so the
# exploit never reproduces and the entry is misfiled as "needs more than the
# patch". The PoC is the ground truth for what the benchmark actually tests, so
# its citation wins.

# Advisory identifiers, in the forms the PoC comments use.
ADVISORY_IDS = (
    ("GHSA", re.compile(r"\b(GHSA(?:-[0-9a-z]{4}){3})\b", re.IGNORECASE)),
    ("CVE", re.compile(r"\b(CVE-\d{4}-\d{4,7})\b", re.IGNORECASE)),
    ("SNYK", re.compile(r"\b(SNYK-[A-Z0-9-]+)\b", re.IGNORECASE)),
    ("SNYK", re.compile(r"(npm:[a-z0-9@/._-]+:\d{8})", re.IGNORECASE)),
    ("H1", re.compile(r"hackerone\.com/reports/(\d+)", re.IGNORECASE)),
)

# Only comments: a URL in live code is a payload, not a citation.
_COMMENT_RE = re.compile(r"/\*.*?\*/|//[^\n]*", re.S)


def advisories_in(text):
    """Set of advisory identifiers cited anywhere in `text`, upper-cased."""
    found = set()
    for kind, rx in ADVISORY_IDS:
        for m in rx.finditer(text):
            found.add(f"{kind}:{m.group(1).upper()}")
    return found


def test_citations(entry):
    """(advisory ids, GitHub commit URLs) cited in the PoC's comments."""
    tests = list(entry["path"].glob("*.test.js"))
    if not tests:
        return set(), []
    comments = "\n".join(_COMMENT_RE.findall(
        tests[0].read_text(encoding="utf-8", errors="replace")))
    commits = [u for u in re.findall(r"https?://[^\s'\"()]+", comments)
               if parse_github_repo(u) and SINGLE_COMMIT_RE.search(u)]
    return advisories_in(comments), commits


def metadata_advisories(entry):
    """Advisory identifiers recorded in the folder's package.json."""
    try:
        meta = json.loads((entry["path"] / "package.json")
                          .read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return set()
    links = meta.get("links") or {}
    values = list(links.values()) if isinstance(links, dict) else list(links)
    return advisories_in(" ".join([str(meta.get("id") or "")] +
                                  [str(v) for v in values]))


def _by_namespace(ids):
    """Group 'NS:ID' identifiers into {namespace: {ids}}."""
    out = {}
    for ident in ids:
        ns, _, rest = ident.partition(":")
        out.setdefault(ns, set()).add(rest)
    return out


def resolve_commit(entry):
    """Pick the fix commit to fetch, preferring what the PoC cites.

    Returns (url, source, note). `source` is one of:

      test-commit  the PoC cites a commit URL outright -- unambiguous, use it.
      mismatch     the PoC and package.json cite DIFFERENT advisories WITHIN THE
                   SAME identifier namespace, which is real evidence of two
                   different vulnerabilities (immer's PoC cites
                   SNYK-JS-IMMER-1019369, package.json records
                   SNYK-JS-IMMER-1540542 -- a later, unrelated fix). No URL is
                   returned: fetching package.json's commit here is precisely
                   the bug this function exists to prevent.
      unverified   the PoC only cites namespaces package.json does not use (a
                   HackerOne report against a CVE, say), so the two cannot be
                   compared. Falls back to package.json but says so, because a
                   HackerOne report and the CVE it became are usually -- not
                   always -- the same bug.
      metadata     the citations agree, or the PoC cites nothing.
    """
    cited, commits = test_citations(entry)
    if commits:
        return commits[0], "test-commit", f"PoC cites {commits[0]}"

    fallback = fix_commit_url(entry)
    meta_adv = metadata_advisories(entry)
    if not cited or (cited & meta_adv):
        return fallback, "metadata", ""

    cited_ns, meta_ns = _by_namespace(cited), _by_namespace(meta_adv)
    shared = set(cited_ns) & set(meta_ns)
    conflicting = {ns for ns in shared if cited_ns[ns] != meta_ns[ns]}
    if conflicting:
        detail = "; ".join(
            f"{ns}: PoC {sorted(cited_ns[ns])} vs package.json {sorted(meta_ns[ns])}"
            for ns in sorted(conflicting))
        return "", "mismatch", detail
    return fallback, "unverified", (
        f"PoC cites {sorted(cited)}, package.json records "
        f"{sorted(meta_adv) or '(nothing)'} -- no shared namespace to compare")


def patch_url(commit_url):
    """Turn a GitHub commit URL into its raw-diff URL (append .patch)."""
    base = commit_url.split("#", 1)[0].split("?", 1)[0].rstrip("/")
    return base if base.endswith(".patch") else base + ".patch"


def fetch(url, retries=3):
    """GET a URL and return its text body, retrying transient failures."""
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    last = None
    for attempt in range(retries):
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                return resp.read().decode("utf-8", errors="replace")
        except urllib.error.HTTPError as exc:
            # 404 etc. won't fix themselves; don't waste retries on them.
            if exc.code in (403, 429, 500, 502, 503):
                last = exc
                time.sleep(2 * (attempt + 1))
                continue
            raise
        except urllib.error.URLError as exc:
            last = exc
            time.sleep(2 * (attempt + 1))
    raise last


def main():
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("name", nargs="?",
                    help="repository (owner/repo) or npm package name "
                         "(omit when using --category or --all)")
    ap.add_argument("--category", "-c",
                    help="fetch for EVERY entry in this category")
    ap.add_argument("--all", action="store_true",
                    help="fetch for every entry in every category")
    ap.add_argument("--csv", default="repositories.csv",
                    help="CSV used to enrich repositories (default: repositories.csv)")
    ap.add_argument("--force", action="store_true",
                    help=f"overwrite an existing {OUTPUT_NAME}")
    ap.add_argument("--ignore-test-citation", action="store_true",
                    help="always use package.json's fixCommit, even when the "
                         "*.test.js PoC cites a different advisory (the old, "
                         "wrong-patch behaviour; kept for comparison runs)")
    ap.add_argument("--print", dest="print_only", action="store_true",
                    help="print the patch URL(s) instead of downloading")
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
        print(f"Fetching patches for {len(matches)} entries in '{cat}'.")
    elif args.all:
        matches = collect_entries(CATEGORIES, repo_index)
        print(f"Fetching patches for all {len(matches)} entries.")
    else:
        matches = find_matches_disk(args.name, repo_index)
        if not matches:
            sys.exit(f"error: no benchmark entry matches '{args.name}'.")
        print(f"Matched {len(matches)} entr{'y' if len(matches) == 1 else 'ies'} "
              f"for '{args.name}'.")

    written = skipped_exists = skipped_nofix = failed = 0
    mismatches, unverified = [], []
    for entry in matches:
        build_path = f"{entry['category']}/{entry['folder']}"
        if args.ignore_test_citation:
            commit, source, note = fix_commit_url(entry), "metadata", ""
        else:
            commit, source, note = resolve_commit(entry)

        if source == "mismatch":
            print(f"  ! MISMATCH {build_path}: {note}")
            mismatches.append((build_path, note))
            skipped_nofix += 1
            continue
        if not commit:
            print(f"  ~ skip {build_path}: no usable fixCommit in package.json")
            skipped_nofix += 1
            continue
        if source == "test-commit":
            print(f"  * {build_path}: using the commit the PoC cites ({note})")
        elif source == "unverified":
            unverified.append((build_path, note))

        url = patch_url(commit)

        if args.print_only:
            print(f"  {build_path}: {url}")
            continue

        target = entry["path"] / OUTPUT_NAME
        if target.exists() and not args.force:
            print(f"  - exists, skipping (use --force): {build_path}/{OUTPUT_NAME}")
            skipped_exists += 1
            continue

        try:
            body = fetch(url)
        except (urllib.error.HTTPError, urllib.error.URLError) as exc:
            print(f"  ! FAIL {build_path}: {url} ({exc})", file=sys.stderr)
            failed += 1
            continue

        target.write_text(body, encoding="utf-8")
        written += 1
        print(f"  + wrote {build_path}/{OUTPUT_NAME}  "
              f"({len(body)} bytes from {url})")

    if not args.print_only:
        print(f"\nDone. {written} written, {skipped_exists} already existed, "
              f"{skipped_nofix} had no usable fixCommit, {failed} failed.")
    if mismatches:
        print(f"\n{len(mismatches)} entr{'y' if len(mismatches)==1 else 'ies'} "
              f"where the PoC and package.json name DIFFERENT vulnerabilities. "
              f"No patch was fetched for these: the recorded commit fixes a "
              f"different bug than the one the PoC exploits, so reverting it "
              f"could never reproduce. Point package.json's fixCommit at the "
              f"advisory the PoC cites (or rewrite the PoC), then re-run:")
        for build_path, note in mismatches:
            print(f"    {build_path}\n        {note}")
    if unverified:
        print(f"\n{len(unverified)} entr{'y' if len(unverified)==1 else 'ies'} "
              f"whose PoC cites an advisory in a namespace package.json does not "
              f"use, so the two could not be cross-checked. package.json's commit "
              f"was used; if one of these still fails to reproduce, the citation "
              f"is the first thing to check:")
        for build_path, note in unverified:
            print(f"    {build_path}\n        {note}")


if __name__ == "__main__":
    main()
