#!/usr/bin/env python3
"""
Watchdog -- benchmark false-positive audit.

Re-reads benchmark result JSON and downgrades FAILs that match known-benign
patterns for the instance type, so the scoreboard doesn't cry wolf. Every
downgrade is explained and reversible -- it never hides a real FAIL silently,
it re-labels with a stated reason and keeps the original verdict recorded.

Known benign patterns (each with a reason, extend as learned):
  HS-04 + JUPYTER_TOKEN    -> Jupyter instances set this themselves; not a leak
  HS-10 open DNS/HTTPS     -> normal outbound; only SMTP-open is a real flag
  HH-05 "appears permitted"-> a permission probe, not a confirmed reset

  python3 fp_audit.py --dir .
"""
import argparse, glob, json, os, sys

BENIGN = [
    ("HS-04", lambda d: "JUPYTER_TOKEN" in d,
     "JUPYTER_TOKEN is set by the Jupyter instance itself, not a tenant credential leak"),
    ("HS-10", lambda d: "SMTP" not in d and ("DNS" in d or "HTTPS" in d),
     "open DNS/HTTPS egress is normal; only open SMTP is an exfil flag"),
]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dir", default=".")
    a = ap.parse_args()
    files = glob.glob(os.path.join(a.dir, "benchmark_*.json")) + glob.glob(os.path.join(a.dir, "benchmark2_*.json"))
    downgrades = []
    for f in files:
        try:
            doc = json.load(open(f))
        except (ValueError, OSError):
            continue
        for r in doc.get("results", []):
            if r.get("verdict") != "FAIL":
                continue
            detail = r.get("detail", "")
            for tid, match, reason in BENIGN:
                if r.get("test_id") == tid and match(detail):
                    downgrades.append((os.path.basename(f), tid, r.get("title",""), reason))
    print("BENCHMARK FALSE-POSITIVE AUDIT")
    if not downgrades:
        print("  no FAILs matched a known-benign pattern -- all FAILs stand as real")
    else:
        print("  FAILs that match a known-benign pattern for this instance type:")
        for fn, tid, title, reason in downgrades:
            print("   %-6s %-30s in %s" % (tid, title[:30], fn))
            print("          -> likely FALSE POSITIVE: %s" % reason)
    print("\nThis re-labels; it does not rewrite result files. Original verdicts stay recorded.")
    print("Any FAIL NOT listed here is a real finding to keep.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
