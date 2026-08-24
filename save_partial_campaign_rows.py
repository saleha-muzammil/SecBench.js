"""Rebuild campaign CSV rows for entries the RUNNING campaign has already
finished, so the results are on disk before the whole run completes.

The campaign only writes its CSV at the very end (rows live in memory until
then). This reconstructs each finished row from the artefacts the entry itself
wrote -- evasion-report.txt and evasion-findings.json -- plus the `=> folder:
status [.. evaded_both=..]` line the campaign prints per entry, which is the
authoritative source for status/evaded_both.

Merge semantics deliberately match run_evasion_campaign.py: keyed by package,
newest row wins, untouched rows preserved. The campaign's own final write will
merge over this file, so running this mid-flight costs nothing.
"""
import csv, json, re, sys
from pathlib import Path

ROOT = Path("/Users/saleha/Desktop/cispa/SecBench.js")
sys.path.insert(0, str(ROOT))
import minimize_and_evade as ME
from run_evasion_campaign import COLUMNS, suspect_repo, collect_entries, csv_repo_index

CAT = "redos"
# The run was paused at entry 36 and reaped overnight, so it continued into a
# second log. Read every log this campaign wrote, newest last -- a later `=>`
# line for the same folder overwrites the earlier one.
LOGS = [ROOT / ".evasion-redos-full.log", ROOT / ".evasion-redos-cont.log",
        ROOT / ".evasion-redos-cont2.log"]
OUT = ROOT / "evasion-campaign-redos-rerun.csv"

# folder -> (status, evaded_both) for every entry this run has finished
done = {}
for log in LOGS:
    if not log.exists():
        continue
    for line in log.read_text(errors="replace").splitlines():
        m = re.match(r"\s*=> (\S+): (.+?)\s+\[[\d.]+ min, evaded_both=(.*)\]\s*$", line)
        if m:
            done[m.group(1)] = (m.group(2).strip(), m.group(3).strip())

entries = {e["folder"]: e for e in collect_entries([CAT], csv_repo_index(ROOT / "repositories.csv"))}

def num(pat, text, cast=int, default=None):
    m = re.search(pat, text)
    return cast(m.group(1)) if m else default

rows = []
for folder, (status, evaded) in done.items():
    e = entries.get(folder)
    if not e:
        continue
    rep = e["path"] / ME.REPORT_OUT
    txt = rep.read_text(errors="replace") if rep.exists() else ""
    fj = e["path"] / ME.FINDINGS_OUT
    f = json.loads(fj.read_text()) if fj.exists() else {}
    sg, cq = f.get("semgrep") or {}, f.get("codeql") or {}

    outcome = ME.outcome_of(status)
    r = {c: "" for c in COLUMNS}
    r.update(
        category=CAT, repository=e.get("repository") or "", package=e["package"],
        version=e.get("version") or "", outcome=outcome,
        evaded_both="" if evaded == "n/a" else evaded, status=status,
        baseline_test=("pass" if "exploit test = PASS" in txt
                       else "fail" if "exploit test = FAIL" in txt else ""),
        exploit_reproduces=("no" if "EXPLOIT-BROKEN" in status
                            else "yes" if outcome == "ok" else ""),
        granularity=num(r"patch splits into \d+ (\w+)-level", txt, str, ""),
        units_total=num(r"patch splits into (\d+) ", txt),
        units_kept=num(r"minimal revert \(exploit-only\): (\d+)/", txt),
        semgrep_fixed=sg.get("fixed_total"), semgrep_new_full=sg.get("new_full"),
        semgrep_new_minimal=sg.get("new_minimal"),
        semgrep_new_final=len(sg["new_final"]) if "new_final" in sg else None,
        codeql_fixed=cq.get("fixed_total"), codeql_new_full=cq.get("new_full"),
        codeql_new_minimal=cq.get("new_minimal"),
        codeql_new_final=len(cq["new_final"]) if "new_final" in cq else None,
        detected_by=f.get("detected_by", ""),
        semgrep_top_rules=ME.top_rules(sg.get("new_final") or [],
                                       lambda x: x.get("check_id", "?").split(".")[-1]),
        codeql_top_rules=ME.top_rules(cq.get("new_final") or [],
                                      lambda x: x.get("rule", "?")),
        semgrep_messages=ME.format_semgrep_messages(sg.get("new_final") or []),
        codeql_messages=ME.format_codeql_messages(cq.get("new_final") or []),
        ci_verdict=(re.search(r"\(ci:([^)]+)\)", status) or [None, ""])[1]
                   if "(ci:" in status else "",
        audit_new=num(r"(\d+) advisory\(ies\) introduced", txt),
        repo_suspect=suspect_repo(e),
    )
    wt = re.search(r"^winning rewrite\(s\): (.+)$", txt, re.M)
    if wt:
        r["winning_transform"] = wt.group(1).strip()
    rows.append(r)

# merge onto whatever is on disk, this run's rows winning (campaign semantics)
merged = {}
if OUT.exists():
    with OUT.open(encoding="utf-8") as fh:
        for old in csv.DictReader(fh):
            merged[old.get("package") or old.get("repository")] = old
for r in rows:
    merged[r["package"]] = r
with OUT.open("w", newline="", encoding="utf-8") as fh:
    w = csv.DictWriter(fh, fieldnames=COLUMNS)
    w.writeheader()
    for k in sorted(merged):
        row = merged[k]
        w.writerow({c: ("" if row.get(c) is None else row.get(c, "")) for c in COLUMNS})

print(f"reconstructed {len(rows)} finished row(s) from this run; "
      f"{len(merged)} total rows in {OUT.name}")
for r in sorted(rows, key=lambda x: x["package"]):
    print(f"  {r['package']:<28} {r['status']:<45} evaded_both={r['evaded_both'] or 'n/a'}")
