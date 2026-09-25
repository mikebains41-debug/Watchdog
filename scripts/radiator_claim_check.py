#!/usr/bin/env python3
"""
Watchdog -- orbital radiator / thermal claim checker.

Checks whether a claimed orbital data-centre spec is thermally possible, using
the Stefan-Boltzmann law. In vacuum there is no conduction or convection: 100%
of heat must be radiated. That puts a hard physical floor on radiator area for a
given compute load, and lets Watchdog flag claims that cannot be true.

  P_rad = emissivity * sigma * A * (T_rad^4 - T_space^4),  T_space~=3K so ~0

Implements Watchdog Space Category M, modules 206 (RadiatorClaimVerifier) and
212 (ThroughputPerSatelliteClaimVerifier): take a vendor's stated numbers, check
the physics closes.

HONEST SCOPE: this is a first-order steady-state check -- total heat vs total
radiator area at a stated radiator temperature, one-sided radiation, T_space~=0.
It does NOT model view factors, solar loading on the panel, duty cycle, or
internal thermal transport. So a FAIL ("claimed area is below the physical
floor") is a hard result; a PASS means "not ruled out by first-order physics,"
not "verified feasible." Real designs need margin above this floor.

  python3 radiator_claim_check.py --chips 50 --watts-per-chip 700 \
      --radiator-area-m2 300 --radiator-temp-k 350
"""
import argparse, json, sys

SIGMA = 5.670374419e-8  # Stefan-Boltzmann, W/m^2/K^4
T_SPACE = 2.7           # cosmic microwave background, K


def required_area(total_watts, t_rad_k, emissivity):
    """m^2 of one-sided radiator needed to shed total_watts at t_rad_k."""
    flux = emissivity * SIGMA * (t_rad_k**4 - T_SPACE**4)  # W/m^2 radiated
    if flux <= 0:
        return None, flux
    return total_watts / flux, flux


def check(chips, watts_per_chip, area_m2, t_rad_k, emissivity=0.9, margin=1.0):
    total_w = chips * watts_per_chip
    req, flux = required_area(total_w, t_rad_k, emissivity)
    out = {
        "law": "Stefan-Boltzmann P=e*sigma*A*(T_rad^4 - T_space^4)",
        "chips": chips, "watts_per_chip": watts_per_chip, "total_heat_w": total_w,
        "radiator_temp_k": t_rad_k, "emissivity": emissivity,
        "radiated_flux_w_per_m2": round(flux, 2) if flux else flux,
        "required_area_m2": round(req, 2) if req else None,
        "required_area_per_chip_m2": round(req / chips, 3) if req and chips else None,
    }
    if req is None:
        out["verdict"] = "ERROR"; out["detail"] = "radiator temp <= space temp; no radiation"
        return out
    if area_m2 is None:
        out["verdict"] = "INFO"
        out["detail"] = ("needs >= %.1f m2 of radiator (%.3f m2/chip) to shed %.0f W at %.0fK. "
                         "No claimed area given to check." % (req, req/chips, total_w, t_rad_k))
        return out
    out["claimed_area_m2"] = area_m2
    out["ratio_claimed_to_required"] = round(area_m2 / req, 3)
    if area_m2 < req:
        out["verdict"] = "FAIL"
        out["detail"] = ("claimed %.1f m2 is BELOW the physical floor of %.1f m2 needed to shed "
                         "%.0f W at %.0fK -- thermally impossible as stated (short by %.1f m2)"
                         % (area_m2, req, total_w, t_rad_k, req - area_m2))
    elif area_m2 < req * (1.0 + max(0.0, margin - 1.0)) or area_m2 < req * 1.2:
        out["verdict"] = "WARN"
        out["detail"] = ("claimed %.1f m2 exceeds the %.1f m2 floor but with little margin "
                         "(<20%%); real designs need headroom for solar load, view factor, "
                         "duty cycle. Not ruled out, but tight." % (area_m2, req))
    else:
        out["verdict"] = "PASS"
        out["detail"] = ("claimed %.1f m2 is above the %.1f m2 first-order floor with margin. "
                         "Not ruled out by basic physics (not a full feasibility proof)."
                         % (area_m2, req))
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--chips", type=int, required=True)
    ap.add_argument("--watts-per-chip", type=float, required=True)
    ap.add_argument("--radiator-area-m2", type=float, help="claimed radiator area to check")
    ap.add_argument("--radiator-temp-k", type=float, default=350.0, help="radiator surface temp (K), default 350")
    ap.add_argument("--emissivity", type=float, default=0.9)
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args()
    r = check(a.chips, a.watts_per_chip, a.radiator_area_m2, a.radiator_temp_k, a.emissivity)
    if a.json:
        print(json.dumps(r, indent=2))
    else:
        print("WATCHDOG ORBITAL RADIATOR / THERMAL CLAIM CHECK")
        for k in ("chips","watts_per_chip","total_heat_w","radiator_temp_k","emissivity",
                  "radiated_flux_w_per_m2","required_area_m2","required_area_per_chip_m2",
                  "claimed_area_m2","ratio_claimed_to_required"):
            if k in r: print("  %-28s %s" % (k, r[k]))
        print("  %-28s %s" % ("VERDICT", r["verdict"]))
        print("  %s" % r["detail"])
        print("  law: %s" % r["law"])
    return 0 if r["verdict"] in ("PASS","INFO") else 1


if __name__ == "__main__":
    sys.exit(main())
