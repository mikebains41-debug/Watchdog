#!/usr/bin/env python3
"""
Watchdog -- facility power estimator.

Closes the loop for the PUE auditor: Watchdog measures GPU/IT power, but the PUE
auditor needs FACILITY total power (which includes cooling + overhead that GPU
telemetry cannot see). This estimates facility total from measured IT power using
the published per-class overhead ranges (arXiv:2609.12511v1, Table II), so the
audit can run on the number you actually have.

HONEST: this is an ESTIMATE from published class ranges, not a measurement of the
facility. It outputs a range (low/high) plus midpoint, and says so. Use it to
sanity-check a claim, never as metered truth.

  python3 facility_power_estimate.py --it-power-kw 700 --class subsea_passive
"""
import argparse, json, sys

# class -> (pue_low, pue_high) from Table II
PUE_BANDS = {
    "land_legacy": (1.8, 2.5), "land_hyperscale": (1.1, 1.4),
    "land_bestinclass": (1.03, 1.12), "offshore_surface": (1.05, 1.15),
    "subsea_passive": (1.03, 1.10), "subsea_deep": (1.03, 1.07),
}
CITATION = "Chin et al., 'Computing at Sea', arXiv:2609.12511v1, Table II"


def estimate(it_kw, cls):
    if cls not in PUE_BANDS:
        return {"error": "unknown class %r; known: %s" % (cls, ", ".join(PUE_BANDS))}
    lo, hi = PUE_BANDS[cls]
    return {
        "citation": CITATION, "class": cls, "it_power_kw": it_kw,
        "pue_band": [lo, hi],
        "facility_power_kw_low": round(it_kw * lo, 1),
        "facility_power_kw_high": round(it_kw * hi, 1),
        "facility_power_kw_midpoint": round(it_kw * (lo + hi) / 2, 1),
        "overhead_kw_low": round(it_kw * (lo - 1), 1),
        "overhead_kw_high": round(it_kw * (hi - 1), 1),
        "note": "ESTIMATE from published class band, not a facility measurement.",
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--it-power-kw", type=float, required=True)
    ap.add_argument("--class", dest="cls", required=True, help=", ".join(PUE_BANDS))
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args()
    r = estimate(a.it_power_kw, a.cls)
    if "error" in r:
        print(r["error"]); return 1
    if a.json:
        print(json.dumps(r, indent=2))
    else:
        print("WATCHDOG FACILITY POWER ESTIMATE (from published band, not measured)")
        print("  class            : %s  (PUE %.2f-%.2f)" % (r["class"], r["pue_band"][0], r["pue_band"][1]))
        print("  IT power          : %s kW" % r["it_power_kw"])
        print("  facility total    : %.1f - %.1f kW (mid %.1f)" % (r["facility_power_kw_low"],
              r["facility_power_kw_high"], r["facility_power_kw_midpoint"]))
        print("  cooling+overhead  : %.1f - %.1f kW" % (r["overhead_kw_low"], r["overhead_kw_high"]))
        print("  %s" % r["note"]); print("  source: %s" % r["citation"])
    return 0


if __name__ == "__main__":
    sys.exit(main())
