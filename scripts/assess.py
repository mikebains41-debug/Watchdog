#!/usr/bin/env python3
"""
Watchdog -- one-command provider assessment runner.

Runs every applicable own-instance check in sequence and writes ONE timestamped
report, so a pod session is a single command instead of five pasted by hand
while the meter runs. Wires together tools that already exist; adds no new
claims. Safe to run as the first thing on a rented machine.

  python3 scripts/assess.py --provider vastai --advertised H200

Order: handover capture (must be first) -> probe round 1 -> probe round 2 ->
facility-power estimate -> PUE audit -> scoreboard. Each step is best-effort;
one failing does not stop the rest. Everything is own-instance, metadata-only.
"""
import argparse, subprocess, sys, os, json, glob
from datetime import datetime, timezone

HERE = os.path.dirname(os.path.abspath(__file__))


def run(desc, cmd):
    print("\n=== %s ===" % desc)
    try:
        r = subprocess.run(cmd, cwd=os.path.dirname(HERE) or ".", capture_output=True, text=True, timeout=900)
        out = (r.stdout or "") + (r.stderr or "")
        print(out[-4000:])
        return desc, r.returncode, out
    except Exception as e:
        print("step failed: %s" % e)
        return desc, 1, str(e)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--provider", required=True)
    ap.add_argument("--advertised", default="")
    ap.add_argument("--it-power-kw", type=float, help="measured IT power for PUE audit (optional)")
    ap.add_argument("--stated-pue", type=float, help="operator-claimed PUE (optional)")
    ap.add_argument("--facility-class", default="", help="for facility-power estimate / PUE audit")
    a = ap.parse_args()
    py = sys.executable
    s = HERE
    stamp = datetime.now(timezone.utc).isoformat()
    results = []

    results.append(run("handover capture (first, before any workload)",
                       [py, os.path.join(s, "handover_capture.py")]))
    results.append(run("provider probe round 1",
                       [py, os.path.join(s, "provider_probe.py"), "--provider", a.provider,
                        "--advertised", a.advertised]))
    results.append(run("provider probe round 2",
                       [py, os.path.join(s, "provider_probe2.py"), "--provider", a.provider]))

    # facility-power estimate -> PUE audit, only if we have inputs
    if a.it_power_kw and a.facility_class:
        results.append(run("facility power estimate",
                           [py, os.path.join(s, "facility_power_estimate.py"),
                            "--it-power-kw", str(a.it_power_kw), "--class", a.facility_class, "--json"]))
    if a.it_power_kw:
        pue_cmd = [py, os.path.join(s, "pue_auditor.py"), "--it-power-kw", str(a.it_power_kw)]
        if a.stated_pue: pue_cmd += ["--stated-pue", str(a.stated_pue)]
        if a.facility_class: pue_cmd += ["--class", a.facility_class]
        results.append(run("PUE / cooling-overhead audit", pue_cmd))

    results.append(run("scoreboard",
                       [py, os.path.join(s, "scoreboard.py"), "--dir", ".", "--md", "scoreboard.md"]))

    # one report
    rep = os.path.join(os.path.dirname(s) or ".", "ASSESSMENT_%s_%s.md" % (a.provider,
                       datetime.now().strftime("%Y%m%d_%H%M%S")))
    with open(rep, "w") as fh:
        fh.write("# Watchdog assessment -- %s\n\n%s UTC. Own-instance only, metadata only.\n\n" % (a.provider, stamp))
        for desc, rc, out in results:
            fh.write("## %s  [%s]\n\n```\n%s\n```\n\n" % (desc, "ok" if rc == 0 else "nonzero/blocked", out[-3000:]))
    print("\n================ SUMMARY ================")
    for desc, rc, _ in results:
        print("  %-40s %s" % (desc, "ok" if rc == 0 else "check output"))
    print("report: %s" % rep)
    print("Copy the report + all *.json + scoreboard.md OFF the pod before releasing it.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
