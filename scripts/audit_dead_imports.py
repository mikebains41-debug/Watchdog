#!/usr/bin/env python3
# Author: Manmohan (Mike) Bains -- Watchdog
"""
scripts/audit_dead_imports.py -- Dead-code audit for a security product

Watchdog's README documents two modules as "dead imports -- present, loaded,
doing nothing": alerting/email_alerter.py and intelligence/threat_intel.py.
Dead code in a security product is a due-diligence flag: a reviewer asks
"what does this do?" and "nothing" is a bad answer.

This script does NOT delete anything. It inspects each file and reports,
honestly: does it exist, is it imported anywhere, is any function of it
CALLED anywhere, does it still contain the issues the README noted
(hardcoded recipient; fabricated IOC data), and what the recommended action
is (wire in / remove / keep-with-note). The decision stays with a human.

Run from repo root:  python3 scripts/audit_dead_imports.py
"""
import os
import re
import sys

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

TARGETS = {
    "alerting/email_alerter.py": {
        "module": "email_alerter",
        "readme_notes": ["defaults to a hardcoded personal recipient address when none is configured"],
        "smell_patterns": [r"@gmail\.com", r"@[a-z0-9.-]+\.(com|ca|net)"],
    },
    "intelligence/threat_intel.py": {
        "module": "threat_intel",
        "readme_notes": ["KNOWN_IOCS previously listed named campaigns with invented attribution; "
                         "fabricated data removed, correlation logic reports zero matches until real entries added"],
        "smell_patterns": [r"KNOWN_IOCS\s*=\s*\[\s*\]", r"KNOWN_IOCS\s*=\s*\{\s*\}"],
    },
}

SEARCH_DIRS = ["detection", "intelligence", "alerting", "remediation", "orchestration",
               "runtime", "api", "agent", "telemetry", "saas", "forensics"]
ROOT_FILES = ["watchdog.py"]


def _py_files():
    for d in SEARCH_DIRS:
        p = os.path.join(REPO, d)
        if not os.path.isdir(p):
            continue
        for root, _, files in os.walk(p):
            for f in files:
                if f.endswith(".py"):
                    yield os.path.join(root, f)
    for f in ROOT_FILES:
        p = os.path.join(REPO, f)
        if os.path.isfile(p):
            yield p


def _read(path):
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            return fh.read()
    except Exception as e:  # surfaced, not swallowed
        return f"<<READ_ERROR {type(e).__name__}: {e}>>"


def audit_one(rel, spec):
    path = os.path.join(REPO, rel)
    out = {"file": rel, "exists": os.path.isfile(path)}
    if not out["exists"]:
        out["recommendation"] = "ALREADY_REMOVED"
        return out

    src = _read(path)
    mod = spec["module"]
    # public functions/classes defined in the module
    defs = re.findall(r"^(?:def|class)\s+([A-Za-z_]\w*)", src, flags=re.M)
    out["defines"] = defs

    importers, callers = [], []
    imp_re = re.compile(rf"(from\s+\S*{mod}\s+import|import\s+\S*{mod}\b)")
    for f in _py_files():
        if os.path.abspath(f) == os.path.abspath(path):
            continue
        s = _read(f)
        if imp_re.search(s):
            importers.append(os.path.relpath(f, REPO))
        for name in defs:
            if re.search(rf"\b{re.escape(name)}\s*\(", s):
                callers.append((os.path.relpath(f, REPO), name))
                break
    out["imported_by"] = importers
    out["called_from"] = callers

    smells = [p for p in spec["smell_patterns"] if re.search(p, src)]
    out["readme_notes"] = spec["readme_notes"]
    out["smells_present"] = smells

    if callers:
        out["state"] = "LIVE"
        out["recommendation"] = "KEEP -- it is called; verify README wording is current"
    elif importers:
        out["state"] = "DEAD_IMPORT"
        out["recommendation"] = ("WIRE_OR_REMOVE -- imported but never called. Either wire it into "
                                 "alerting/manager.py behind an env-var (safe no-op without creds, "
                                 "same pattern as alerting/siem.py) or delete it. Do not leave it dead.")
    else:
        out["state"] = "ORPHAN"
        out["recommendation"] = "REMOVE -- not imported, not called; git keeps the history."
    return out


def main():
    print("=" * 64)
    print("WATCHDOG DEAD-IMPORT AUDIT (report only; deletes nothing)")
    print("=" * 64)
    results = [audit_one(rel, spec) for rel, spec in TARGETS.items()]
    for r in results:
        print(f"\n## {r['file']}")
        if not r["exists"]:
            print("  exists: NO -> ALREADY_REMOVED")
            continue
        print(f"  defines      : {r['defines']}")
        print(f"  imported by  : {r['imported_by'] or 'nothing'}")
        print(f"  called from  : {r['called_from'] or 'nothing'}")
        print(f"  state        : {r['state']}")
        print(f"  README notes : {r['readme_notes']}")
        print(f"  smells found : {r['smells_present'] or 'none'}")
        print(f"  RECOMMENDATION: {r['recommendation']}")
    print("\nNext: decide wire vs remove per file, then update README 'Alerting' section to match.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
