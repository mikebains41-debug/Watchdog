#!/usr/bin/env python3
# Author: Manmohan (Mike) Bains -- Watchdog
"""
tests/test_solar_storm.py

Tests the space-weather layer: NOAA S-scale classification, NOAA JSON
parsing, storm onset detection (the 28 Oct 2003 profile), hard-proton
alert, early-warning ingest, gated hardening posture, and the storm swarm
correlator (cause -> effect).

Run standalone: python3 tests/test_solar_storm.py
Or via suite:   python3 tests/run_all.py (once registered in TEST_FILES).
"""
import os
import sys

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

from detection.solar_storm_detectors import (
    SolarParticleEventDetector, SpaceWeatherWarningIngest, StormHardeningPosture,
    classify_s_level, parse_noaa_integral_protons, GATED_ACTIONS,
)
from intelligence.swarm.solar_storm_swarm_correlator import SolarStormSwarmCorrelator

PASSED = []
FAILED = []


def check(name, condition, detail=""):
    if condition:
        PASSED.append(name)
        print(f"[PASS] {name}")
    else:
        FAILED.append(name)
        print(f"[FAIL] {name} {detail}")


# --------------------------------------------------------------------------
# S-scale (NOAA published thresholds)
# --------------------------------------------------------------------------
def test_s_scale_thresholds():
    cases = [(2, "S0"), (10, "S1"), (99, "S1"), (100, "S2"), (1000, "S3"),
             (10000, "S4"), (100000, "S5"), (43500, "S4")]  # 43,500 = March 1991 max
    ok = all(classify_s_level(f)[0] == lvl for f, lvl in cases)
    check("s-scale: NOAA thresholds classify correctly (incl. 1991 max = S4)", ok,
          f"got {[classify_s_level(f)[0] for f, _ in cases]}")


# --------------------------------------------------------------------------
# NOAA JSON parsing
# --------------------------------------------------------------------------
def test_parse_noaa_records():
    recs = [
        {"time_tag": "2026-09-02T12:00:00Z", "flux": 2.1, "energy": ">=10 MeV"},
        {"time_tag": "2026-09-02T12:00:00Z", "flux": 0.3, "energy": ">=100 MeV"},
        {"time_tag": "2026-09-02T12:05:00Z", "flux": 2.4, "energy": ">=10 MeV"},
        {"time_tag": "2026-09-02T12:05:00Z", "flux": None, "energy": ">=10 MeV"},  # bad
        {"time_tag": "2026-09-02T12:10:00Z", "flux": 2.2, "energy": ">=1 MeV"},   # other channel
    ]
    f10 = parse_noaa_integral_protons(recs, ">=10 MeV")
    check("noaa: parses only the >=10 MeV channel, skips None",
          len(f10) == 2 and f10[0][1] == 2.1, f"got {f10}")
    f100 = parse_noaa_integral_protons(recs, ">=100 MeV")
    check("noaa: parses the >=100 MeV channel", len(f100) == 1 and f100[0][1] == 0.3, f"got {f100}")


# --------------------------------------------------------------------------
# SPE detector
# --------------------------------------------------------------------------
def _quiet(det, n=50, flux=2.0):
    for _ in range(n):
        det.update(flux)


def test_quiet_background_stays_quiet():
    det = SolarParticleEventDetector()
    _quiet(det)
    r = det.update(2.3)
    check("spe: steady ~2 pfu background -> SPACE_WEATHER_QUIET (negative control)",
          r["type"] == "SPACE_WEATHER_QUIET", f"got {r['type']}")


def test_onset_detected_oct2003_profile():
    det = SolarParticleEventDetector()
    _quiet(det)
    r = None
    for f in (5, 30, 200, 900, 2500, 5200):
        r = det.update(f)
        if r["type"] == "SOLAR_PARTICLE_EVENT":
            break
    check("spe: 2 -> 5000 pfu ramp fires SOLAR_PARTICLE_EVENT (onset)",
          r["type"] == "SOLAR_PARTICLE_EVENT" and r["onset_detected"], f"got {r}")
    check("spe: onset carries orders-of-magnitude rise",
          r["onset_decades"] is not None and r["onset_decades"] >= 1.0, f"got {r['onset_decades']}")


def test_escalation_to_s4_is_critical():
    det = SolarParticleEventDetector()
    _quiet(det)
    r = None
    for f in (50, 500, 5000, 12000):
        r = det.update(f)
    check("spe: reaching S4 (10,000 pfu) -> CRITICAL",
          r["s_level"] == "S4" and r["severity"] == "CRITICAL", f"got {r}")


def test_hard_proton_alert():
    det = SolarParticleEventDetector()
    _quiet(det)
    r = det.update(3.0, flux_100mev_pfu=1.5)   # >=100 MeV crosses 1 pfu
    check("spe: >=100 MeV >= 1 pfu -> hard-proton alert, CRITICAL",
          r["hard_proton_alert"] and r["type"] == "SOLAR_PARTICLE_EVENT"
          and r["severity"] == "CRITICAL", f"got {r}")


def test_ingest_noaa_payload_end_to_end():
    det = SolarParticleEventDetector()
    recs = []
    for i in range(50):
        recs.append({"time_tag": f"2026-09-02T{i:02d}:00:00Z", "flux": 2.0, "energy": ">=10 MeV"})
    # then a storm
    for j, f in enumerate((50, 500, 5000)):
        recs.append({"time_tag": f"2026-09-03T0{j}:00:00Z", "flux": f, "energy": ">=10 MeV"})
    r = det.ingest_noaa(recs)
    check("spe: ingest_noaa on a NOAA-format payload detects the storm",
          r["type"] == "SOLAR_PARTICLE_EVENT", f"got {r['type']}")


# --------------------------------------------------------------------------
# Warning ingest
# --------------------------------------------------------------------------
def test_warning_gives_lead_time():
    w = SpaceWeatherWarningIngest()
    r = w.ingest({"product": "WARNING", "threshold_pfu": 100, "energy": ">=10 MeV",
                  "issue_time": "t0", "valid_to": "t1"})
    check("warning: NOAA WARNING -> SOLAR_STORM_WARNING with lead-time note",
          r["type"] == "SOLAR_STORM_WARNING" and "lead_time_note" in r
          and r["expected_level"] == "S2", f"got {r}")


def test_alert_and_summary_lifecycle():
    w = SpaceWeatherWarningIngest()
    w.ingest({"product": "ALERT", "threshold_pfu": 1000, "energy": ">=10 MeV"})
    check("warning: ALERT tracked as active", w.get_stats()["active_warnings"] == 1)
    r = w.ingest({"product": "SUMMARY", "threshold_pfu": 1000, "energy": ">=10 MeV"})
    check("warning: SUMMARY ends the event and clears it",
          r["type"] == "SOLAR_STORM_ENDED" and w.get_stats()["active_warnings"] == 0, f"got {r}")


# --------------------------------------------------------------------------
# Posture
# --------------------------------------------------------------------------
def test_posture_escalates_with_level():
    p = StormHardeningPosture()
    s1 = p.recommend("S1")
    s5 = p.recommend("S5")
    check("posture: S1 is ELEVATED_MONITORING, S5 is SURVIVAL",
          s1["posture"] == "ELEVATED_MONITORING" and s5["posture"] == "SURVIVAL",
          f"got {s1['posture']}, {s5['posture']}")


def test_posture_disruptive_actions_are_gated():
    p = StormHardeningPosture()
    r = p.recommend("S4")
    gated = [a for a in r["actions"] if a["mode"] == "gated_approval_request"]
    auto = [a for a in r["actions"] if a["mode"] == "auto_safe"]
    check("posture: pausing/holding work is gated, monitoring/checkpoint is auto-safe",
          any(a["action"] in GATED_ACTIONS for a in gated)
          and any(a["action"] == "checkpoint_critical_state" for a in auto), f"got {r['actions']}")


def test_posture_never_autoshutdown_note():
    p = StormHardeningPosture()
    r = p.recommend("S5")
    check("posture: states it never auto-shuts-down a workload",
          "never auto-shuts-down" in r["gating_note"], f"got {r['gating_note']}")


# --------------------------------------------------------------------------
# Storm swarm correlator (cause -> effect)
# --------------------------------------------------------------------------
def test_storm_induced_degradation():
    clock = {"t": 1000.0}
    c = SolarStormSwarmCorrelator(time_fn=lambda: clock["t"])
    check("storm-swarm: storm alone -> no incident",
          c.observe({"swarm_signal": "SOLAR_PARTICLE_EVENT"}) == [])
    clock["t"] += 600
    out = c.observe({"type": "SDC_CORRUPTION_DETECTED"})
    check("storm-swarm: storm + SDC -> STORM_INDUCED_DEGRADATION",
          any(i["incident"] == "STORM_INDUCED_DEGRADATION" for i in out), f"got {out}")


def test_storm_latchup_event():
    clock = {"t": 2000.0}
    c = SolarStormSwarmCorrelator(time_fn=lambda: clock["t"])
    c.observe({"swarm_signal": "SOLAR_STORM_ALERT"})
    clock["t"] += 60
    out = c.observe({"swarm_signal": "SEL_LATCHUP_SUSPECTED"})
    check("storm-swarm: storm + latch-up -> STORM_LATCHUP_EVENT",
          any(i["incident"] == "STORM_LATCHUP_EVENT" for i in out), f"got {out}")


def test_missed_warning_operational_finding():
    clock = {"t": 3000.0}
    c = SolarStormSwarmCorrelator(time_fn=lambda: clock["t"])
    out = c.observe({"swarm_signal": "SOLAR_STORM_ALERT"})  # no WARNING first
    check("storm-swarm: ALERT with no prior WARNING -> PRE_STORM_HARDENING_MISSED",
          any(i["incident"] == "PRE_STORM_HARDENING_MISSED" for i in out), f"got {out}")


def test_warning_then_alert_no_missed_finding():
    clock = {"t": 4000.0}
    c = SolarStormSwarmCorrelator(time_fn=lambda: clock["t"])
    c.observe({"swarm_signal": "SOLAR_STORM_WARNING"})
    clock["t"] += 1200
    out = c.observe({"swarm_signal": "SOLAR_STORM_ALERT"})
    check("storm-swarm: WARNING then ALERT -> window used, no missed finding",
          not any(i["incident"] == "PRE_STORM_HARDENING_MISSED" for i in out), f"got {out}")


def test_storm_window_is_hours():
    clock = {"t": 5000.0}
    c = SolarStormSwarmCorrelator(time_fn=lambda: clock["t"])
    c.observe({"swarm_signal": "SOLAR_PARTICLE_EVENT"})
    clock["t"] += 4 * 3600   # 4h later, still within a 6h storm window
    out = c.observe({"type": "SDC_CORRUPTION_DETECTED"})
    check("storm-swarm: SDC 4h into a storm still correlates (hours-long window)",
          any(i["incident"] == "STORM_INDUCED_DEGRADATION" for i in out), f"got {out}")


if __name__ == "__main__":
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for t in tests:
        try:
            t()
        except Exception as e:
            check(t.__name__, False, f"EXCEPTION {e!r}")
    print("\n" + "=" * 60)
    print(f"PASSED: {len(PASSED)}   FAILED: {len(FAILED)}")
    if FAILED:
        print("\nFailures:")
        for f in FAILED:
            print(f"  - {f}")
    print("=" * 60)
    sys.exit(1 if FAILED else 0)
