#!/usr/bin/env python3
"""
Watchdog provider benchmark -- scoreboard.

Reads every benchmark_*.json and handover_*.json in a folder and prints one
table: rows are test IDs (in registry order), columns are providers. Each cell
is the verdict, worst-case across that provider's runs (so one FAIL among five
clean rentals still shows FAIL, with the count).

  python3 scoreboard.py [--dir .] [--md scoreboard.md]

Add a provider = drop its result files in and re-run. Add a test = it appears
as a new row once any result carries that id.
"""
import argparse
import glob
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from wd_benchmark_tests import TESTS, GROUP_ORDER, title  # noqa: E402

# worse verdict wins when a provider has several runs of one test
RANK = {"FAIL": 5, "BLOCKED": 4, "ERROR": 3, "NA": 2, "PASS": 1, "-": 0}


def load(dirpath):
    """provider -> test_id -> list of verdicts."""
    data = {}
    files = sorted(glob.glob(os.path.join(dirpath, "benchmark_*.json")) +
                   glob.glob(os.path.join(dirpath, "handover_*.json")))
    for f in files:
        try:
            doc = json.load(open(f))
        except (ValueError, OSError):
            continue
        prov = doc.get("provider", os.path.basename(f).split("_")[1] if "_" in os.path.basename(f) else "?")
        d = data.setdefault(prov, {})
        # provider_probe.py results
        for r in doc.get("results", []):
            d.setdefault(r["test_id"], []).append(r["verdict"])
        # handover_capture.py -> HH-01 leftover files
        lo = doc.get("leftovers")
        if lo is not None:
            fresh = [x for x in lo.get("files", []) if not x.get("likely_image_default")]
            d.setdefault("HH-01", []).append("FAIL" if fresh else "PASS")
    return data, files


def worst(verdicts):
    return max(verdicts, key=lambda v: RANK.get(v, 0)) if verdicts else "-"


def cell(verdicts):
    if not verdicts:
        return "-"
    w = worst(verdicts)
    n = len(verdicts)
    same = sum(1 for v in verdicts if v == w)
    return "%s (%d/%d)" % (w, same, n) if n > 1 else w


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dir", default=".")
    ap.add_argument("--md")
    a = ap.parse_args()
    data, files = load(a.dir)
    if not data:
        print("no benchmark_*.json or handover_*.json found in %s" % a.dir); return 1
    provs = sorted(data)

    lines = ["# Watchdog provider benchmark -- scoreboard", "",
             "PASS = provider did the right thing. FAIL = it did not. BLOCKED = platform "
             "prevented the check. Cell shows worst verdict across that provider's runs, with "
             "(matching/total).", "",
             "Sources: %d result file(s). Own-instance measurements only." % len(files), ""]
    header = "| Test | " + " | ".join(provs) + " |"
    sep = "|" + "---|" * (len(provs) + 1)
    lines += [header, sep]
    for g in GROUP_ORDER:
        lines.append("| **%s** |%s" % (g, " |" * len(provs)))
        for tid, (ttl, grp, _) in TESTS.items():
            if grp != g:
                continue
            row = "| %s %s | " % (tid, ttl) + " | ".join(cell(data[p].get(tid, [])) for p in provs) + " |"
            lines.append(row)

    out = "\n".join(lines)
    print(out)
    if a.md:
        with open(a.md, "w") as fh:
            fh.write(out + "\n")
        print("\nwritten: %s" % a.md)
    # plain-text tally per provider
    print("\nPer-provider FAILs:")
    for p in provs:
        fails = [tid for tid in TESTS if worst(data[p].get(tid, [])) == "FAIL"]
        print("  %-10s %d FAIL  %s" % (p, len(fails), ", ".join(fails) or "-"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
