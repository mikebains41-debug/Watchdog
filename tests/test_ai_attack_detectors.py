#!/usr/bin/env python3
"""
test_ai_attack_detectors.py -- self-contained tests for the Pile 1
AI-attack detectors: FPNA determinism, micro-burst, model weight integrity.
Run standalone: python3 tests/test_ai_attack_detectors.py
Or via the suite: python3 tests/run_all.py (registered in TEST_FILES).
Imports use detection.* package paths because run_all.py runs with
cwd=REPO_ROOT.
Follows the tests/README.md pattern: check(name, condition, detail),
PASSED/FAILED counts, and a final summary line run_all.py can parse.
"""

import os
import sys
import shutil
import tempfile
import pickle
import zipfile
import io
from pathlib import Path

# Ensure the repo root is importable whether this file is run standalone
# (python3 tests/test_ai_attack_detectors.py) or via tests/run_all.py.
# sys.path[0] is the tests/ dir in both cases, so add its parent (repo root).
_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

from detection.fpna_determinism_detector import evaluate_determinism, relative_variation
from detection.micro_burst_detector import detect_micro_bursts
from detection.model_weight_integrity_detector import check_model_file, scan_pickle_opcodes, sha256_file

PASSED = 0
FAILED = 0


def check(name, condition, detail=""):
    global PASSED, FAILED
    if condition:
        PASSED += 1
        print(f"[PASS] {name}")
    else:
        FAILED += 1
        print(f"[FAIL] {name} {detail}")


# --------------------------------------------------------------------------
# FPNA determinism detector
# --------------------------------------------------------------------------
def test_fpna():
    tmp = Path(tempfile.mkdtemp(prefix="fpna_"))
    try:
        bl = tmp / "fpna_baseline.json"

        # bit-identical repeats => deterministic OK
        r = evaluate_determinism([12.34, 12.34, 12.34], baseline_path=bl)
        check("FPNA: identical repeats -> FPNA_DETERMINISTIC_OK",
              r["status"] == "FPNA_DETERMINISTIC_OK", f"got {r['status']}")

        # attack-grade spread AFTER a clean baseline => attack suspected + transition
        r2 = evaluate_determinism([12.34, 12.36, 12.31, 12.40], baseline_path=bl)
        check("FPNA: large spread -> FPNA_ATTACK_SUSPECTED",
              r2["status"] == "FPNA_ATTACK_SUSPECTED", f"got {r2['status']}")
        check("FPNA: transition-from-clean flagged after clean baseline",
              r2.get("transition_from_clean_baseline") is True, f"got {r2}")
        check("FPNA: gated by default (recommended_action, not applied)",
              "recommended_action" in r2 and "remediation_dispatched" not in r2,
              f"got keys {list(r2.keys())}")

        # auto_remediate=True dispatches the (reversible) action
        r3 = evaluate_determinism([1.0, 1.02, 0.98, 1.05],
                                  baseline_path=tmp / "b2.json",
                                  auto_remediate=True)
        check("FPNA: auto_remediate dispatches force_deterministic action",
              r3.get("remediation_dispatched", {}).get("action") == "force_deterministic_algorithms",
              f"got {r3.get('remediation_dispatched')}")

        # single value can't be assessed
        r4 = evaluate_determinism([1.0])
        check("FPNA: single value -> SKIPPED",
              r4["status"] == "SKIPPED", f"got {r4['status']}")

        # mid-level instability -> informational, not attack
        r5 = evaluate_determinism([1.0, 1.0 + 1e-6, 1.0], baseline_path=tmp / "b3.json")
        check("FPNA: mild instability -> FPNA_NONDETERMINISM_DETECTED",
              r5["status"] == "FPNA_NONDETERMINISM_DETECTED", f"got {r5['status']}")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


# --------------------------------------------------------------------------
# Micro-burst detector
# --------------------------------------------------------------------------
def test_micro_burst():
    # High-rate burst-hide pattern: short 100% spikes padded by idle.
    ts, sm = [], []
    t = 0.0
    for _ in range(6):
        for _ in range(2):
            ts.append(t); sm.append(100.0); t += 0.01
        for _ in range(8):
            ts.append(t); sm.append(0.0); t += 0.01
    r = detect_micro_bursts(ts, sm, idle_floor=0.0)
    check("micro-burst: diluted repeated spikes -> MICRO_BURST_PATTERN",
          r["status"] == "MICRO_BURST_PATTERN", f"got {r['status']}")
    check("micro-burst: counts multiple bursts",
          r.get("burst_count", 0) >= 3, f"got {r.get('burst_count')}")
    check("micro-burst: does NOT auto-kill (gated action)",
          r.get("recommended_action", {}).get("risk") == "do_not_auto_kill",
          f"got {r.get('recommended_action')}")

    # Steady honest load at ~50% -> no burst-hide shape.
    ts2 = [i * 0.02 for i in range(100)]
    sm2 = [50.0 + (1.0 if i % 2 else -1.0) for i in range(100)]
    r2 = detect_micro_bursts(ts2, sm2, idle_floor=0.0)
    check("micro-burst: steady mid load -> MICRO_BURST_NONE",
          r2["status"] == "MICRO_BURST_NONE", f"got {r2['status']}")

    # Coarse sampling (like real 5Hz pod) -> honest UNDERSAMPLED, not clean.
    ts3 = [i * 0.2 for i in range(10)]   # 5 Hz
    sm3 = [100.0 if i % 2 else 0.0 for i in range(10)]
    r3 = detect_micro_bursts(ts3, sm3, idle_floor=0.0)
    check("micro-burst: coarse sample rate -> MICRO_BURST_UNDERSAMPLED (not clean)",
          r3["status"] == "MICRO_BURST_UNDERSAMPLED", f"got {r3['status']}")

    # Too few points -> SKIPPED
    r4 = detect_micro_bursts([0.0, 1.0], [0.0, 1.0], idle_floor=0.0)
    check("micro-burst: too few points -> SKIPPED",
          r4["status"] == "SKIPPED", f"got {r4['status']}")


# --------------------------------------------------------------------------
# Model weight integrity detector
# --------------------------------------------------------------------------
def _write_clean_pickle(path: Path):
    # A benign pickle: just a dict of "weights".
    with open(path, "wb") as f:
        pickle.dump({"layer.0.weight": [0.1, 0.2, 0.3]}, f)


class _EvilReduce:
    def __reduce__(self):
        import os
        return (os.system, ("echo pwned",))


def _write_malicious_pickle(path: Path):
    with open(path, "wb") as f:
        pickle.dump(_EvilReduce(), f)


def test_weight_integrity():
    tmp = Path(tempfile.mkdtemp(prefix="weights_"))
    try:
        clean = tmp / "model_clean.pth"
        evil = tmp / "model_evil.pth"
        _write_clean_pickle(clean)
        _write_malicious_pickle(evil)

        # Malicious pickle detected via opcode scan (no execution).
        r_evil = check_model_file(evil)
        check("weights: os.system pickle -> MALICIOUS_PICKLE_DETECTED",
              r_evil["status"] == "MALICIOUS_PICKLE_DETECTED", f"got {r_evil['status']}")
        check("weights: flagged global names os",
              any("os" in g for g in r_evil.get("flagged_globals", [])),
              f"got {r_evil.get('flagged_globals')}")
        check("weights: malicious file quarantine is gated by default",
              "recommended_action" in r_evil, f"got keys {list(r_evil.keys())}")

        # auto_remediate dispatches quarantine (reversible, never delete).
        r_evil2 = check_model_file(evil, auto_remediate=True)
        check("weights: auto_remediate dispatches quarantine (not delete)",
              r_evil2.get("remediation_dispatched", {}).get("action") == "quarantine_file",
              f"got {r_evil2.get('remediation_dispatched')}")

        # Clean pickle with a matching manifest -> INTEGRITY_OK.
        clean_hash = sha256_file(clean)
        manifest = tmp / "manifest.json"
        manifest.write_text('{"%s": "%s"}' % (clean.name, clean_hash))
        r_ok = check_model_file(clean, manifest_path=manifest)
        check("weights: clean file matching manifest -> INTEGRITY_OK",
              r_ok["status"] == "INTEGRITY_OK", f"got {r_ok['status']}")

        # Swap the file (rewrite different content) -> hash drift.
        import time
        with open(clean, "wb") as f:
            pickle.dump({"layer.0.weight": [9.9, 9.9]}, f)
        r_swap = check_model_file(clean, manifest_path=manifest)
        check("weights: hash drift vs manifest -> WEIGHT_SWAP_DETECTED",
              r_swap["status"] == "WEIGHT_SWAP_DETECTED", f"got {r_swap['status']}")
        check("weights: weight-swap remediation is gated (no auto-kill)",
              r_swap.get("recommended_action", {}).get("risk") == "gated_no_autokill",
              f"got {r_swap.get('recommended_action')}")

        # File not in manifest -> flagged, not silently trusted.
        stray = tmp / "stray.pth"
        _write_clean_pickle(stray)
        r_stray = check_model_file(stray, manifest_path=manifest)
        check("weights: unknown file -> UNKNOWN_FILE_NOT_IN_MANIFEST",
              r_stray["status"] == "UNKNOWN_FILE_NOT_IN_MANIFEST", f"got {r_stray['status']}")

        # safetensors (pickle-free) with no manifest -> SAFETENSORS_OK.
        st = tmp / "model.safetensors"
        st.write_bytes(b"\x00\x00\x00\x00not-a-pickle-header-safetensors")
        r_st = check_model_file(st)
        check("weights: safetensors -> SAFETENSORS_OK (pickle scan skipped)",
              r_st["status"] == "SAFETENSORS_OK", f"got {r_st['status']}")

        # ZIP-container .pth (torch save format) with malicious embedded pickle.
        ziptorch = tmp / "model_zip.pth"
        payload = pickle.dumps(_EvilReduce())
        with zipfile.ZipFile(ziptorch, "w") as z:
            z.writestr("archive/data.pkl", payload)
        r_zip = check_model_file(ziptorch)
        check("weights: malicious pickle inside ZIP .pth -> MALICIOUS_PICKLE_DETECTED",
              r_zip["status"] == "MALICIOUS_PICKLE_DETECTED", f"got {r_zip['status']}")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def main():
    test_fpna()
    test_micro_burst()
    test_weight_integrity()
    print(f"\nPASSED: {PASSED}   FAILED: {FAILED}")
    sys.exit(1 if FAILED else 0)


if __name__ == "__main__":
    main()
