#!/usr/bin/env python3
# Author: Manmohan (Mike) Bains -- Watchdog
"""
tests/test_security_swarm.py

Tests the security prediction agents (6, 7, 8) and the SecurityCorrelator.
Verifies: agents stay SILENT on clean telemetry (negative controls) and
FIRE on the documented attack precursor (positive controls); the
correlator escalates only when required alert types co-occur in-window,
and de-dupes.

Run standalone: python3 tests/test_security_swarm.py
Or via suite:   python3 tests/run_all.py (once registered in TEST_FILES).
Imports use intelligence.swarm.* package paths (run_all.py runs with
cwd=REPO_ROOT).
"""
import os
import sys
from datetime import datetime, timezone

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

from intelligence.swarm.agent6_rowhammer_precursor_predictor import RowhammerPrecursorPredictor
from intelligence.swarm.agent7_cryptojacking_onset_predictor import CryptojackingOnsetPredictor
from intelligence.swarm.agent8_model_extraction_precursor_predictor import ModelExtractionPrecursorPredictor
from intelligence.swarm.security_correlator import SecurityCorrelator

PASSED = []
FAILED = []


def check(name, condition, detail=""):
    if condition:
        PASSED.append(name)
        print(f"[PASS] {name}")
    else:
        FAILED.append(name)
        print(f"[FAIL] {name} {detail}")


def _ts():
    return datetime.now(timezone.utc).isoformat()


# --------------------------------------------------------------------------
# Agent 6 -- Rowhammer / ECC-break precursor
# --------------------------------------------------------------------------
def test_agent6_negative_control_clean_ecc():
    """A trickle of environmental SEUs must NOT fire the predictor."""
    a = RowhammerPrecursorPredictor(gpu_id=0)
    corrected = 0
    fired = False
    for i in range(40):
        corrected += (1 if i % 10 == 0 else 0)  # rare, uniform, non-accelerating
        if a.update({'ecc_corrected_total': corrected,
                     'ecc_uncorrectable_total': 0, 'timestamp': _ts()}):
            fired = True
    check("agent6: clean environmental ECC trickle does NOT fire", not fired)


def test_agent6_positive_control_accelerating_hammer():
    a = RowhammerPrecursorPredictor(gpu_id=0)
    corrected = 0
    # warm up
    for i in range(10):
        a.update({'ecc_corrected_total': corrected, 'ecc_uncorrectable_total': 0,
                  'timestamp': _ts()})
    fired = None
    for i in range(15):
        corrected += (i * 3 + 2)  # accelerating + bursty
        r = a.update({'ecc_corrected_total': corrected,
                      'ecc_uncorrectable_total': 0, 'timestamp': _ts()})
        if r:
            fired = r
            break
    check("agent6: accelerating hammer FIRES GPUTHOR_PRECURSOR_PREDICTED",
          fired is not None and fired['type'] == 'GPUTHOR_PRECURSOR_PREDICTED',
          f"got {fired}")
    check("agent6: alert carries CVE context and gated forensics action",
          fired is not None and 'GPUHammer (USENIX Sec 2025)' in fired['cve_context']
          and 'forensics' in fired['recommended_action'].lower(), f"got {fired}")


# --------------------------------------------------------------------------
# Agent 7 -- Cryptojacking onset
# --------------------------------------------------------------------------
def test_agent7_negative_control_idle():
    a = CryptojackingOnsetPredictor(gpu_id=0)
    fired = False
    for i in range(30):
        if a.update({'gpu_util': 8 + (i % 3), 'sm_clock_mhz': 1400 + (i % 5) * 40,
                     'power_watts': 90, 'mem_bw_util_pct': 12, 'timestamp': _ts()}):
            fired = True
    check("agent7: idle/light load does NOT fire", not fired)


def test_agent7_negative_control_legit_training():
    """Memory-heavy, bursty-clock training should NOT look like mining."""
    a = CryptojackingOnsetPredictor(gpu_id=0)
    fired = False
    for i in range(30):
        # high util but VARIED clock and HIGH mem-bandwidth = training
        clock = 1700 + (i * 37 % 300)  # varying
        if a.update({'gpu_util': 92 + (i % 5), 'sm_clock_mhz': clock,
                     'power_watts': 400, 'mem_bw_util_pct': 75, 'timestamp': _ts()}):
            fired = True
    check("agent7: memory-heavy varied-clock training does NOT fire (not mining)",
          not fired)


def test_agent7_positive_control_miner_spinup():
    a = CryptojackingOnsetPredictor(gpu_id=0)
    for i in range(15):  # warm up idle
        a.update({'gpu_util': 5, 'sm_clock_mhz': 1400, 'power_watts': 90,
                  'mem_bw_util_pct': 10, 'timestamp': _ts()})
    fired = None
    for i in range(20):
        r = a.update({'gpu_util': min(99, 50 + i * 4), 'sm_clock_mhz': 1980,  # uniform
                      'power_watts': 160 + i * 12, 'mem_bw_util_pct': 6,  # compute-bound
                      'timestamp': _ts()})
        if r:
            fired = r
            break
    check("agent7: miner spin-up FIRES COVERT_COMPUTE_ONSET_PREDICTED",
          fired is not None and fired['type'] == 'COVERT_COMPUTE_ONSET_PREDICTED',
          f"got {fired}")
    check("agent7: does not recommend auto-kill on onset",
          fired is not None and 'not auto-kill' in fired['recommended_action'].lower(),
          f"got {fired}")


# --------------------------------------------------------------------------
# Agent 8 -- Model-extraction precursor
# --------------------------------------------------------------------------
def test_agent8_negative_control_organic():
    a = ModelExtractionPrecursorPredictor(gpu_id=0)
    import random
    random.seed(11)
    fired = False
    for i in range(30):
        if a.update({'inference_req_per_s': random.uniform(2, 8),
                     'avg_req_compute_ms': random.uniform(10, 60),  # varied
                     'power_watts': 200 + random.uniform(-30, 30),
                     'vram_used_mb': 8000 + random.uniform(-500, 500),
                     'timestamp': _ts()}):
            fired = True
    check("agent8: organic mixed traffic does NOT fire", not fired)


def test_agent8_positive_control_sweep():
    a = ModelExtractionPrecursorPredictor(gpu_id=0)
    for i in range(15):  # warm up organic
        a.update({'inference_req_per_s': 5, 'avg_req_compute_ms': 30,
                  'power_watts': 200, 'vram_used_mb': 8000, 'timestamp': _ts()})
    fired = None
    for i in range(20):
        r = a.update({'inference_req_per_s': min(80, 25 + i * 4),
                      'avg_req_compute_ms': 25,  # uniform
                      'power_watts': 260 + i * 6,
                      'vram_used_mb': 8200,  # steady footprint
                      'timestamp': _ts()})
        if r:
            fired = r
            break
    check("agent8: systematic sweep FIRES MODEL_EXTRACTION_PRECURSOR_PREDICTED",
          fired is not None and fired['type'] == 'MODEL_EXTRACTION_PRECURSOR_PREDICTED',
          f"got {fired}")


# --------------------------------------------------------------------------
# SecurityCorrelator
# --------------------------------------------------------------------------
def test_correlator_single_alert_no_incident():
    clock = {'t': 1000.0}
    c = SecurityCorrelator(window_seconds=30.0, time_fn=lambda: clock['t'])
    out = c.observe({'type': 'GPUTHOR_PRECURSOR_PREDICTED', 'severity': 'WARNING'})
    check("correlator: single alert does not create an incident", out == [])


def test_correlator_pair_in_window_fires_incident():
    clock = {'t': 1000.0}
    c = SecurityCorrelator(window_seconds=30.0, time_fn=lambda: clock['t'])
    c.observe({'type': 'GPUTHOR_PRECURSOR_PREDICTED', 'severity': 'WARNING'})
    clock['t'] += 5
    out = c.observe({'type': 'MICRO_BURST_PATTERN', 'severity': 'WARNING'})
    check("correlator: ECC-precursor + micro-burst in-window -> COORDINATED_WEIGHT_TAMPER",
          len(out) == 1 and out[0]['incident'] == 'COORDINATED_WEIGHT_TAMPER',
          f"got {out}")
    check("correlator: escalated incident is CRITICAL",
          len(out) == 1 and out[0]['severity'] == 'CRITICAL', f"got {out}")


def test_correlator_pair_outside_window_no_incident():
    clock = {'t': 1000.0}
    c = SecurityCorrelator(window_seconds=30.0, time_fn=lambda: clock['t'])
    c.observe({'type': 'COVERT_COMPUTE_ONSET_PREDICTED', 'severity': 'WARNING'})
    clock['t'] += 100  # well outside the 30s window
    out = c.observe({'type': 'GHOST_POWER_PREDICTED', 'severity': 'WARNING'})
    check("correlator: alerts outside the window do NOT correlate", out == [])


def test_correlator_dedupes_repeat_in_window():
    clock = {'t': 1000.0}
    c = SecurityCorrelator(window_seconds=30.0, time_fn=lambda: clock['t'])
    c.observe({'type': 'MODEL_EXTRACTION_PRECURSOR_PREDICTED', 'severity': 'WARNING'})
    clock['t'] += 2
    first = c.observe({'type': 'TENANT_ISOLATION_RISK', 'severity': 'WARNING'})
    clock['t'] += 2
    second = c.observe({'type': 'MODEL_EXTRACTION_PRECURSOR_PREDICTED', 'severity': 'WARNING'})
    check("correlator: IP_EXFILTRATION_CAMPAIGN fires once",
          len(first) == 1 and first[0]['incident'] == 'IP_EXFILTRATION_CAMPAIGN',
          f"got {first}")
    check("correlator: same rule does not re-fire within window (de-duped)",
          second == [], f"got {second}")


if __name__ == '__main__':
    tests = [v for k, v in sorted(globals().items()) if k.startswith('test_')]
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
