#!/usr/bin/env python3
"""
Extract the list of repositories referenced in the SecBench.js benchmark.

Each vulnerable package lives in a folder `<category>/<name>_<version>/` with a
`package.json` metadata file holding the CVE id, the npm package, advisory links
and (when available) the upstream fix commit.

This script walks those folders, derives the GitHub repository for each package
and writes one CSV row per package:

    category, package, version, cve_id, repository, repository_url, source

The repository is resolved from, in order of preference:
  1. the `fixCommit` URL (github.com/<owner>/<repo>/...)
  2. any github.com link in `links` (ignoring github.com/advisories/...)
  3. the npm registry (only with --npm), via the package's `repository` field

Usage:
    python3 extract_repositories.py [-o repositories.csv] [--npm] [--incubator]
"""

import argparse
import csv
import json
import re
import sys
from pathlib import Path
from urllib.request import urlopen, Request
from urllib.error import URLError, HTTPError

ROOT = Path(__file__).resolve().parent

# Default benchmark categories (the labelled 600 exploits).
CATEGORIES = [
    "prototype-pollution",
    "redos",
    "command-injection",
    "path-traversal",
    "code-injection",
]

# Matches github.com/<owner>/<repo>, tolerating .git suffixes and trailing paths.
GITHUB_RE = re.compile(
    r"github\.com[/:]+([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+?)(?:\.git)?(?:[/#?].*)?$",
    re.IGNORECASE,
)

# Pulls the bare commit SHA out of a /commit/<sha> or /pull/N/commits/<sha> URL.
COMMIT_SHA_RE = re.compile(r"/commit(?:s)?/([0-9a-f]{7,40})", re.IGNORECASE)


def clean_field(value):
    """Normalise a metadata string; treat 'n/a'/empty as missing."""
    if not isinstance(value, str):
        return ""
    value = value.strip()
    return "" if value.lower() in {"", "n/a", "na", "none"} else value


def parse_github_repo(url):
    """Return 'owner/repo' from a GitHub URL, or None. Skips advisory pages."""
    if not url or not isinstance(url, str):
        return None
    url = url.strip()
    # github.com/advisories/... and github.com/<org>/security/advisories are not
    # the source repository, so ignore them.
    if "github.com/advisories" in url.lower():
        return None
    m = GITHUB_RE.search(url)
    if not m:
        return None
    owner, repo = m.group(1), m.group(2)
    if owner.lower() in {"advisories", "sponsors"}:
        return None
    return f"{owner}/{repo}"


def iter_link_values(links):
    """Yield every string value from the `links` object (source1, source2, ...)."""
    if isinstance(links, dict):
        for value in links.values():
            if isinstance(value, str):
                yield value
    elif isinstance(links, list):
        for value in links:
            if isinstance(value, str):
                yield value


_npm_cache = {}


def resolve_repo_from_npm(package):
    """Look up a package's repository URL on the npm registry. Cached, best-effort."""
    if package in _npm_cache:
        return _npm_cache[package]
    repo = None
    try:
        req = Request(
            f"https://registry.npmjs.org/{package}",
            headers={"User-Agent": "secbench-repo-extractor"},
        )
        with urlopen(req, timeout=15) as resp:
            data = json.load(resp)
        repository = data.get("repository")
        if isinstance(repository, dict):
            repo = parse_github_repo(repository.get("url", ""))
        elif isinstance(repository, str):
            repo = parse_github_repo(repository)
    except (URLError, HTTPError, json.JSONDecodeError, ValueError):
        repo = None
    _npm_cache[package] = repo
    return repo


def load_metadata(pkg_json_path):
    try:
        with open(pkg_json_path, encoding="utf-8") as fh:
            return json.load(fh)
    except (json.JSONDecodeError, OSError) as exc:
        print(f"  ! skipping {pkg_json_path}: {exc}", file=sys.stderr)
        return None


def extract(categories, use_npm):
    rows = []
    for category in categories:
        cat_dir = ROOT / category
        if not cat_dir.is_dir():
            print(f"  (no such category folder: {category})", file=sys.stderr)
            continue
        for pkg_dir in sorted(p for p in cat_dir.iterdir() if p.is_dir()):
            meta_path = pkg_dir / "package.json"
            if not meta_path.exists():
                continue
            meta = load_metadata(meta_path)
            if meta is None:
                continue

            cve = (meta.get("id") or "").strip()
            fixed_version = clean_field(meta.get("fixedVersion"))
            fix_commit_url = clean_field(meta.get("fixCommit"))
            sha_match = COMMIT_SHA_RE.search(fix_commit_url)
            fix_commit_sha = sha_match.group(1) if sha_match else ""

            # package name + version come from `dependencies`; fall back to folder name.
            deps = meta.get("dependencies") or {}
            if isinstance(deps, dict) and deps:
                package, version = next(iter(deps.items()))
            else:
                name, _, ver = pkg_dir.name.rpartition("_")
                package, version = (name or pkg_dir.name), ver

            # Resolve the repository.
            repo = parse_github_repo(meta.get("fixCommit", ""))
            source = "fixCommit" if repo else ""
            if not repo:
                for link in iter_link_values(meta.get("links")):
                    repo = parse_github_repo(link)
                    if repo:
                        source = "links"
                        break
            if not repo and use_npm:
                repo = resolve_repo_from_npm(package)
                if repo:
                    source = "npm"

            rows.append(
                {
                    "category": category,
                    "package": package,
                    "version": version,
                    "cve_id": cve,
                    "repository": repo or "",
                    "repository_url": f"https://github.com/{repo}" if repo else "",
                    "fixed_version": fixed_version,
                    "fix_commit_url": fix_commit_url,
                    "fix_commit_sha": fix_commit_sha,
                    "source": source,
                }
            )
    return rows


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("-o", "--output", default="repositories.csv",
                    help="output CSV path (default: repositories.csv)")
    ap.add_argument("--npm", action="store_true",
                    help="resolve missing repos via the npm registry (network)")
    ap.add_argument("--incubator", action="store_true",
                    help="also include the incubator/ folder")
    args = ap.parse_args()

    categories = list(CATEGORIES)
    if args.incubator:
        categories.append("incubator")

    rows = extract(categories, args.npm)

    fields = ["category", "package", "version", "cve_id",
              "repository", "repository_url",
              "fixed_version", "fix_commit_url", "fix_commit_sha", "source"]
    out_path = ROOT / args.output if not Path(args.output).is_absolute() else Path(args.output)
    with open(out_path, "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)

    with_repo = sum(1 for r in rows if r["repository"])
    with_cve = sum(1 for r in rows if r["cve_id"] and r["cve_id"].lower() != "n/a")
    unique_repos = len({r["repository"] for r in rows if r["repository"]})
    print(f"Wrote {len(rows)} packages to {out_path}")
    print(f"  with repository: {with_repo}  (unique: {unique_repos})")
    print(f"  with CVE id:     {with_cve}")
    if not args.npm and with_repo < len(rows):
        print("  tip: re-run with --npm to resolve the remaining repositories.")


if __name__ == "__main__":
    main()
