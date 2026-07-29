#!/usr/bin/env python3
"""
aggregate_audits.py -- turn many gpu_audit.py records into one table.

Reads every audit_*.json in a directory and produces the providers-down-the-
side, checks-across-the-top table that is the actual pitch: one row per
instance audited, one column per check, plus a summary line.

Every cell reports exactly what the record said -- NOT_RUN stays "not run",
PARTIAL stays "verify", nothing is hidden or upgraded. A claim you can't
defend when someone re-runs the audit is worse than a smaller true one.

Runs anywhere; no GPU needed.

Usage:
  python3 aggregate_audits.py                 # scan current dir
  python3 aggregate_audits.py --dir results   # scan a folder
  python3 aggregate_audits.py --out table.md  # where to write the markdown
"""
import argparse, glob, json, os


def _contention(c):
    if not c or c.get("status") == "NOT_RUN":
        return "not run"
    if c.get("status") != "OK":
        return c.get("status", "?").lower()
    m, s = c.get("mean_degradation_pct"), c.get("stdev_pct", 0)
    return f"-{m}% (+/-{s})" if m is not None else "inconclusive"


def _tenant(c):
    if not c or c.get("status") == "NOT_RUN":
        return "not run"
    n = c.get("leftover_count", 0)
    if n:
        return f"{n} file(s), oldest {c.get('oldest_age_days', '?')}d"
    return "clean"


def _cve(c):
    if not c or c.get("status") == "NOT_RUN":
        return "not run"
    if c.get("status") == "PARTIAL":
        k = c.get("kernel", "?")
        return f"{k} (verify)"
    hits = c.get("matches", [])
    return ("MATCH: " + ", ".join(h["id"] for h in hits)) if hits else "clean"


def load(dir_):
    recs = []
    for path in sorted(glob.glob(os.path.join(dir_, "audit_*.json"))):
        try:
            with open(path) as f:
                r = json.load(f)
            r["_file"] = os.path.basename(path)
            recs.append(r)
        except Exception as e:
            print(f"  skipped {path}: {e}")
    return recs


def build_rows(recs):
    rows = []
    for r in recs:
        ch = r.get("checks", {})
        rows.append({
            "provider": r.get("provider", "?"),
            "gpu": r.get("gpu", "?"),
            "region": r.get("region", "?"),
            "date": (r.get("timestamp_utc", "")[:10] or "?"),
            "contention": _contention(ch.get("contention")),
            "tenant_files": _tenant(ch.get("tenant_files")),
            "stale_cve": _cve(ch.get("stale_cve")),
        })
    return rows


def to_markdown(rows):
    cols = [("provider", "Provider"), ("gpu", "GPU"), ("region", "Region"),
            ("date", "Date"), ("contention", "Contention"),
            ("tenant_files", "Tenant files"), ("stale_cve", "Stale CVE")]
    head = "| " + " | ".join(h for _, h in cols) + " |"
    sep = "| " + " | ".join("---" for _ in cols) + " |"
    body = ["| " + " | ".join(str(row[k]) for k, _ in cols) + " |" for row in rows]
    return "\n".join([head, sep] + body)


def summary(rows):
    n = len(rows)
    leftover = sum(1 for r in rows if r["tenant_files"] not in ("clean", "not run"))
    cve = sum(1 for r in rows if r["stale_cve"].startswith("MATCH"))
    contended = sum(1 for r in rows if r["contention"] not in ("not run", "inconclusive"))
    providers = sorted({r["provider"] for r in rows})
    lines = [
        f"{n} instance(s) across {len(providers)} provider(s): {', '.join(providers)}",
        f"{leftover}/{n} left another tenant's files behind",
        f"{cve}/{n} ran an unpatched host matching a known CVE",
        f"{contended}/{n} had contention measured",
    ]
    return "\n".join(lines)


def main():
    ap = argparse.ArgumentParser(description="Aggregate Watchdog audit records into one table")
    ap.add_argument("--dir", default=".", help="folder containing audit_*.json")
    ap.add_argument("--out", default="audit_table.md")
    args = ap.parse_args()

    recs = load(args.dir)
    if not recs:
        print(f"no audit_*.json files found in {os.path.abspath(args.dir)}")
        print("run gpu_audit.py on some instances first.")
        return

    rows = build_rows(recs)
    md = to_markdown(rows)
    summ = summary(rows)

    with open(args.out, "w") as f:
        f.write("# Watchdog multi-provider audit\n\n")
        f.write(summ + "\n\n")
        f.write(md + "\n")

    print("\n" + summ + "\n")
    print(md + "\n")
    print(f"written: {args.out}")


if __name__ == "__main__":
    main()
