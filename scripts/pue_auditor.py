#!/usr/bin/env python3
"""
Watchdog -- PUE / cooling-overhead auditor.

Turns the published data-centre efficiency figures (Chin/Zhang/Venkateshkumar,
"Computing at Sea", arXiv:2609.12511v1, Table II) into a live audit check that
runs on GPU power telemetry Watchdog already collects.

WHAT IT DOES
  From measured GPU power (idle floor + active draw) and an operator-stated PUE,
  it computes the implied facility overhead and checks it against the published
  band for the claimed facility class. If a facility claims a PUE its own power
  telemetry cannot support, that is a discrepancy -- the same "telemetry vs
  claim" pattern as Watchdog's other integrity checks (PStateHonesty, billing).

WHAT IT IS / ISN'T
  - Runs on real GPU power data (the kind already captured on the pods).
  - Does NOT measure facility cooling power directly -- GPU telemetry can't see
    chillers. It checks the *claimed* PUE for internal consistency against
    published class ranges and flags implausible claims. An honest auditor of a
    number, not a replacement for facility metering.
  - PUE = total facility power / IT power. Cooling fraction = (PUE-1) roughly
    maps to non-IT overhead; we compare against the paper's per-class bands.

VERDICTS (provider/operator viewpoint, same convention as the benchmark):
  PASS    stated PUE is within the published band for its class and consistent
  FAIL    stated PUE is better than the physical floor for its class (implausible)
  WARN    stated PUE is worse than its class band (inefficient, not dishonest)
  INFO    no class given; reports computed figures only

Usage:
  python3 pue_auditor.py --it-power-kw 700 --stated-pue 1.15 --class subsea_passive
  python3 pue_auditor.py --it-power-kw 700 --total-power-kw 770   # compute PUE from measured
"""
import argparse
import json
import sys

# Published bands (Table II, arXiv:2609.12511v1). (pue_low, pue_high, cooling_low%, cooling_high%)
CLASSES = {
    "land_legacy":      (1.8, 2.5, 35, 40),
    "land_hyperscale":  (1.1, 1.4, 15, 25),
    "land_bestinclass": (1.03, 1.12, 8, 15),
    "offshore_surface": (1.05, 1.15, 5, 10),
    "subsea_passive":   (1.03, 1.10, 2, 7),    # Natick class ~1.07
    "subsea_deep":      (1.03, 1.07, 3, 5),
}
CITATION = "Chin, Zhang, Venkateshkumar, 'Computing at Sea', arXiv:2609.12511v1, Table II"


def audit(it_kw, stated_pue=None, total_kw=None, cls=None):
    out = {"citation": CITATION, "it_power_kw": it_kw}
    # derive PUE if measured total supplied
    if total_kw is not None and it_kw:
        measured_pue = total_kw / it_kw
        out["measured_pue"] = round(measured_pue, 4)
        out["measured_total_kw"] = total_kw
        pue = measured_pue if stated_pue is None else stated_pue
    else:
        pue = stated_pue
    if pue is None:
        out["verdict"] = "INFO"; out["detail"] = "no PUE stated or derivable"; return out
    out["pue_used"] = round(pue, 4)
    out["implied_overhead_kw"] = round(it_kw * (pue - 1), 2)
    out["implied_cooling_plus_overhead_pct"] = round((pue - 1) / pue * 100, 1)

    # if measured AND stated both present, check they agree
    if total_kw is not None and stated_pue is not None:
        if abs(measured_pue - stated_pue) / stated_pue > 0.05:
            out["verdict"] = "FAIL"
            out["detail"] = ("stated PUE %.3f but measured power implies %.3f (>5%% apart) -- "
                             "the claim does not match the facility's own power draw"
                             % (stated_pue, measured_pue))
            return out

    if cls is None:
        out["verdict"] = "INFO"
        out["detail"] = "PUE %.3f; no facility class given to check against published bands" % pue
        return out
    if cls not in CLASSES:
        out["verdict"] = "INFO"; out["detail"] = "unknown class %r" % cls; return out
    lo, hi, clo, chi = CLASSES[cls]
    out["class"] = cls; out["published_band"] = [lo, hi]
    if pue < lo:
        out["verdict"] = "FAIL"
        out["detail"] = ("PUE %.3f is BELOW the published floor %.3f for '%s' -- physically "
                         "implausible for this class; claim likely overstated" % (pue, lo, cls))
    elif pue > hi:
        out["verdict"] = "WARN"
        out["detail"] = ("PUE %.3f is ABOVE the published range top %.3f for '%s' -- inefficient "
                         "for its class (not dishonest, just poor)" % (pue, hi, cls))
    else:
        out["verdict"] = "PASS"
        out["detail"] = ("PUE %.3f within published band %.2f-%.2f for '%s'" % (pue, lo, hi, cls))
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--it-power-kw", type=float, required=True, help="measured IT (GPU/server) power, kW")
    ap.add_argument("--stated-pue", type=float, help="PUE the operator/listing claims")
    ap.add_argument("--total-power-kw", type=float, help="measured total facility power, kW (to derive PUE)")
    ap.add_argument("--class", dest="cls", help="facility class: " + ", ".join(CLASSES))
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args()
    r = audit(a.it_power_kw, a.stated_pue, a.total_power_kw, a.cls)
    if a.json:
        print(json.dumps(r, indent=2))
    else:
        print("WATCHDOG PUE / COOLING-OVERHEAD AUDIT")
        for k in ("it_power_kw","measured_pue","pue_used","implied_overhead_kw",
                  "implied_cooling_plus_overhead_pct","class","published_band"):
            if k in r: print("  %-32s %s" % (k, r[k]))
        print("  %-32s %s" % ("VERDICT", r["verdict"]))
        print("  %s" % r["detail"])
        print("  source: %s" % r["citation"])
    return 0 if r["verdict"] in ("PASS","INFO") else 1


if __name__ == "__main__":
    sys.exit(main())
