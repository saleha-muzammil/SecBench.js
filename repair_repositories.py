#!/usr/bin/env python3
"""
Repair repositories.csv: resolve each repo by PACKAGE NAME, not by CVE.

repositories.csv was built by walking advisories, so rows whose CVE covers more
than one package inherited the wrong repository. Three command-injection entries
were cloning a completely unrelated project into ``node_modules/<package>``:

    command-exists@1.2.2   -> kellyselden/git-diff-apply   (CVE-2019-10776)
    scp@0.0.3              -> kellyselden/git-diff-apply   (CVE-2019-10776)
    samsung-remote@1.2.5   -> ronomon/opened               (CVE-2021-29300)

``require("command-exists")`` then resolved to git-diff-apply, so the exploit
could not possibly reproduce -- and the pipeline blamed patch scope for it.

This script asks the npm registry what repository each package ACTUALLY
publishes from and reconciles the CSV against that, and additionally asserts
that every ``fixed_version`` is strictly newer than the vulnerable version
(lodash@4.17.15 records a "fix" of 4.17.5, which is older).

Repairs applied with --write:
  * repository / repository_url  replaced when npm disagrees with the CSV. The
    fix_commit_url and fix_commit_sha are CLEARED at the same time: a commit
    from the wrong repository is meaningless, and leaving it would send
    fetch_patch.py after a patch that cannot apply.
  * fixed_version  cleared when it is not newer than the vulnerable version, so
    generate_dockerfile_fixed.py skips the entry loudly instead of building a
    baseline out of older code.

Nothing is guessed: if npm has no repository for a package, the row is reported
and left exactly as it is.

Usage:
    python3 repair_repositories.py                 # dry run, prints the report
    python3 repair_repositories.py --write         # apply repairs in place
    python3 repair_repositories.py --only lodash   # one package
    python3 repair_repositories.py --offline       # version checks only
"""

import argparse
import csv
import json
import shutil
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

from generate_dockerfile import ROOT, GITHUB_RE, parse_version, version_gt

CSV_NAME = "repositories.csv"
REGISTRY = "https://registry.npmjs.org/"
USER_AGENT = "SecBench.js-repair-repositories"


def resolve_fixed_version(spec, vulnerable):
    """Reduce an advisory range to the single version that fixes `vulnerable`.

    Advisory exports record "vulnerable ranges", not fix points, so some rows
    hold a whole expression:

        ansi-regex: ">=2.1.1 <3.0.1 >=4.0.0 <4.1.1 >=5.0.0 <5.0.1"

    Each `<X` is the first release of that line WITH the fix, so the answer for
    a given vulnerable version is the upper bound of the clause containing it --
    4.1.0 sits in [4.0.0, 4.1.1), so the fix is 4.1.1. Returns "" when the spec
    is a plain version (nothing to resolve) or cannot be reduced.
    """
    tokens = str(spec or "").replace(",", " ").split()
    if len(tokens) < 2:
        return ""
    lower, best = None, ""
    for tok in tokens:
        if tok.startswith(">"):
            lower = parse_version(tok)
        elif tok.startswith("<"):
            upper = parse_version(tok)
            if not upper:
                continue
            v = parse_version(vulnerable)
            # vulnerable must sit inside [lower, upper) for this clause to apply
            if v and v < upper and (lower is None or v >= lower):
                best = tok.lstrip("<=").strip()
                break
    return best



def npm_metadata(package, retries=3):
    """Registry document for `package`, or None when it cannot be fetched."""
    # Scoped names (@scope/name) must keep their slash percent-encoded.
    url = REGISTRY + urllib.parse.quote(package, safe="@")
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT,
                                               "Accept": "application/json"})
    for attempt in range(retries):
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                return json.loads(resp.read().decode("utf-8", "replace"))
        except urllib.error.HTTPError as exc:
            if exc.code == 404:
                return None            # unpublished/renamed: not retryable
        except Exception:
            pass
        time.sleep(1.5 * (attempt + 1))
    return None


def repo_from_metadata(meta, version):
    """'owner/repo' npm publishes this package from, preferring `version`.

    The version-specific document is authoritative: a package that moved orgs
    between the vulnerable release and today would otherwise be "corrected" to
    its NEW home, which is not where the vulnerable code lives.
    """
    if not meta:
        return ""
    candidates = []
    ver_doc = (meta.get("versions") or {}).get(version)
    if ver_doc:
        candidates.append(ver_doc.get("repository"))
    latest = (meta.get("dist-tags") or {}).get("latest")
    if latest:
        candidates.append(((meta.get("versions") or {}).get(latest) or {})
                          .get("repository"))
    candidates.append(meta.get("repository"))
    for repo in candidates:
        url = repo.get("url") if isinstance(repo, dict) else repo
        if not isinstance(url, str):
            continue
        m = GITHUB_RE.search(url)
        if m:
            return f"{m.group(1)}/{m.group(2)}"
    return ""


def commit_exists(repo, sha, retries=2):
    """True when `sha` resolves in github.com/`repo`.

    Used to decide whether a recorded fix commit survives a repository
    correction. Fetches the commit's .patch (not the REST API, whose
    unauthenticated budget of 60/hour would run out mid-CSV).
    """
    if not repo or not sha:
        return False
    url = f"https://github.com/{repo}/commit/{sha}.patch"
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT},
                                 method="HEAD")
    for _ in range(retries):
        try:
            with urllib.request.urlopen(req, timeout=20) as resp:
                return resp.status == 200
        except urllib.error.HTTPError:
            return False               # 404: not in this repo
        except Exception:
            time.sleep(1.0)
    return False


def main():
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--csv", default=CSV_NAME, help=f"CSV to repair (default: {CSV_NAME})")
    ap.add_argument("--write", action="store_true",
                    help="apply the repairs (default: dry run)")
    ap.add_argument("--only", help="restrict to one package name")
    ap.add_argument("--offline", action="store_true",
                    help="skip npm lookups; run only the version assertions")
    args = ap.parse_args()

    path = Path(args.csv)
    if not path.is_absolute():
        path = ROOT / path
    if not path.exists():
        sys.exit(f"error: {path} not found")

    with open(path, newline="", encoding="utf-8") as fh:
        reader = csv.DictReader(fh)
        fields, rows = reader.fieldnames, list(reader)

    repo_fixes, version_fixes, phantom_fixes, unresolved = [], [], [], []
    # One lookup per package, not per row: packages repeat across categories.
    cache = {}

    for row in rows:
        pkg = (row.get("package") or "").strip()
        ver = (row.get("version") or "").strip()
        if not pkg or (args.only and pkg != args.only):
            continue

        # --- repository, resolved by package name -------------------------- #
        if not args.offline:
            if pkg not in cache:
                cache[pkg] = npm_metadata(pkg)
                print(f"  . looked up {pkg}", file=sys.stderr)
            npm_repo = repo_from_metadata(cache[pkg], ver)
            csv_repo = (row.get("repository") or "").strip()
            if not npm_repo:
                if csv_repo:
                    unresolved.append((pkg, csv_repo))
            elif npm_repo.lower() != csv_repo.lower():
                sha = (row.get("fix_commit_sha") or "").strip()
                # Same project name under a different owner is almost always a
                # GitHub rename or org move (npm/ini -> isaacs/ini), and GitHub
                # redirects those, so the recorded fix commit is still good.
                # A DIFFERENT project name (git-diff-apply vs command-exists) is
                # the CVE-collision bug, and its commit is worthless here.
                renamed = (csv_repo.split("/")[-1].lower()
                           == npm_repo.split("/")[-1].lower())
                keep_sha = bool(sha) and (renamed or commit_exists(npm_repo, sha))
                repo_fixes.append((pkg, ver, csv_repo, npm_repo, sha[:10],
                                   "renamed" if renamed else "different project",
                                   keep_sha))
                row["repository"] = npm_repo
                row["repository_url"] = f"https://github.com/{npm_repo}"
                if sha and not keep_sha:
                    row["fix_commit_url"] = ""
                    row["fix_commit_sha"] = ""

        # --- fixed_version: normalize, then assert, in that order ----------- #
        # Range expressions have to be reduced to a point release BEFORE any
        # assertion runs, or a perfectly recoverable row (ansi-regex's
        # ">=4.0.0 <4.1.1" -> 4.1.1) gets thrown away for failing a check it was
        # never in a shape to pass.
        fixed = (row.get("fixed_version") or "").strip()
        if fixed and not version_gt(fixed, ver):
            resolved = resolve_fixed_version(fixed, ver)
            if resolved and version_gt(resolved, ver):
                version_fixes.append((pkg, ver, fixed, resolved))
                row["fixed_version"] = fixed = resolved
            else:
                version_fixes.append((pkg, ver, fixed, ""))
                row["fixed_version"] = fixed = ""

        # Being newer is not sufficient on its own: scp@0.0.3 inherited
        # git-diff-apply's fixed version 0.22.2, which is numerically newer than
        # 0.0.3 and so sails through the ordering check while naming a release
        # scp never published.
        if fixed and not args.offline and cache.get(pkg):
            published = (cache[pkg].get("versions") or {})
            if published and fixed not in published:
                phantom_fixes.append((pkg, ver, fixed))
                row["fixed_version"] = ""

    print(f"\n=== repository resolved by package name, not CVE "
          f"({len(repo_fixes)} rows) ===")
    for pkg, ver, old, new, sha, kind, keep in sorted(repo_fixes,
                                                      key=lambda r: r[5]):
        note = ("kept fix_commit " + sha if sha and keep else
                "CLEARED fix_commit " + sha if sha else "no fix_commit recorded")
        print(f"  [{kind:17s}] {pkg}@{ver}\n"
              f"      was: {old or '(empty)'}\n      now: {new}\n      {note}")

    print(f"\n=== fixed_version not newer than the vulnerable version "
          f"({len(version_fixes)} rows) ===")
    for pkg, ver, fixed, resolved in version_fixes:
        outcome = (f"resolved from range -> {resolved}" if resolved
                   else "cleared (needs a correct fix version)")
        print(f"  {pkg}: vulnerable {ver}, recorded fix {fixed!r} -> {outcome}")

    print(f"\n=== fixed_version names a release the package never published "
          f"({len(phantom_fixes)} rows) ===")
    for pkg, ver, fixed in phantom_fixes:
        print(f"  {pkg}: vulnerable {ver}, recorded fix {fixed} is not in npm's "
              f"version list for {pkg} -> cleared")

    if unresolved:
        print(f"\n=== npm has no repository; left untouched ({len(unresolved)}) ===")
        for pkg, csv_repo in unresolved[:40]:
            print(f"  {pkg} (CSV says {csv_repo})")
        if len(unresolved) > 40:
            print(f"  ... and {len(unresolved) - 40} more")

    if not args.write:
        print(f"\nDry run. Re-run with --write to apply "
              f"{len(repo_fixes) + len(version_fixes) + len(phantom_fixes)} "
              f"repair(s) to {path.name}.")
        return

    backup = path.with_suffix(path.suffix + ".bak")
    shutil.copy2(path, backup)
    with open(path, "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)
    print(f"\nWrote {path.name} ({len(repo_fixes)} repository, "
          f"{len(version_fixes)} version, {len(phantom_fixes)} phantom-version "
          f"repairs). Backup: {backup.name}")
    print("Next: re-run fetch_patch.py for the repaired rows (their fix commits "
          "were cleared), then regenerate the Dockerfiles.")


if __name__ == "__main__":
    main()
