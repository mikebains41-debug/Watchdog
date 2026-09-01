#!/usr/bin/env python3
# Author: Manmohan (Mike) Bains -- Watchdog
"""
tests/test_published_circuit_verifier.py

Tests the published-circuit tamper-detection ingester: QASM parsing,
bitstring parsing, consistency PASS on well-formed released-style data,
and ANOMALY flags on tampered/inconsistent data (wrong qubit count, wrong
sample count, degenerate samples, T-count mismatch). Also verifies the
honest-scope disclaimer is always present.

Run standalone: python3 tests/test_published_circuit_verifier.py
Or via suite:   python3 tests/run_all.py (once registered in TEST_FILES).
"""
import os
import sys
import random

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

from detection.published_circuit_verifier import (
    PublishedCircuitVerifier, parse_qasm_counts, parse_bitstrings,
)

PASSED = []
FAILED = []


def check(name, condition, detail=""):
    if condition:
        PASSED.append(name)
        print(f"[PASS] {name}")
    else:
        FAILED.append(name)
        print(f"[FAIL] {name} {detail}")


def _qasm(qubits=97, t_gates=468):
    lines = ['OPENQASM 2.0;', 'include "qelib1.inc";', f'qreg q[{qubits}];',
             'creg c[70];', 'h q[0];', 'cx q[0],q[1];']
    for i in range(t_gates):
        lines.append(f't q[{i % qubits}];')
    return "\n".join(lines) + "\n"


def _samples(n=2051, width=70, seed=1, degenerate=False):
    random.seed(seed)
    if degenerate:
        return ["0" * width] * n
    return ["".join(random.choice("01") for _ in range(width)) for _ in range(n)]


IBM_META = {"qubits": 70, "t_count": 468, "expected_samples": 2051,
            "fidelity_value": 0.32, "name": "ibm_boston_dcs_nq70_depth70_checks27"}


# --------------------------------------------------------------------------
# Parsers
# --------------------------------------------------------------------------
def test_qasm_parse_qubits_and_t():
    f = parse_qasm_counts(_qasm(qubits=97, t_gates=468))
    check("qat: QASM parse extracts qubit count",
          f["qubits"] == 97, f"got {f['qubits']}")
    check("qat: QASM parse counts T gates",
          f["t_count"] == 468, f"got {f['t_count']}")
    check("qat: QASM parse counts two-qubit ops",
          f["two_qubit_ops"] >= 1, f"got {f['two_qubit_ops']}")


def test_qasm_parse_openqasm3_style():
    q3 = "OPENQASM 3;\nqubit[70] q;\nbit[70] c;\nh q[0];\nt q[1];\n"
    f = parse_qasm_counts(q3)
    check("qat: parses OpenQASM 3 qubit declaration",
          f["qubits"] == 70 and f["t_count"] == 1, f"got {f}")


def test_bitstring_parse_plain():
    text = "0101\n1100\n0000\n"
    s = parse_bitstrings(text)
    check("qat: parses plain bitstrings", len(s) == 3 and s[0] == "0101", f"got {s}")


def test_bitstring_parse_with_counts():
    text = "0101 5\n1100 3\n"
    s = parse_bitstrings(text)
    check("qat: parses bitstring+count pairs (expands)",
          len(s) == 8 and s.count("0101") == 5, f"got {len(s)}")


def test_bitstring_parse_ignores_junk():
    text = "# comment\n0101\nnot_bits\n1100\n"
    s = parse_bitstrings(text)
    check("qat: parser ignores comments and non-bit lines",
          len(s) == 2, f"got {s}")


# --------------------------------------------------------------------------
# Consistency PASS on well-formed released-style data
# --------------------------------------------------------------------------
def test_consistent_on_wellformed_data():
    v = PublishedCircuitVerifier()
    facts = parse_qasm_counts(_qasm())
    samples = _samples()
    r = v.verify(facts, samples, IBM_META)
    check("qat: well-formed released-style data -> CONSISTENT",
          r["type"] == "PUBLISHED_CIRCUIT_CONSISTENT", f"got {r['type']} anomalies={r['anomalies']}")
    check("qat: fidelity claim assessed as plausible on diverse samples",
          r["fidelity_plausibility"]["plausible"] is True, f"got {r['fidelity_plausibility']}")


def test_honest_scope_always_present():
    v = PublishedCircuitVerifier()
    r = v.verify(parse_qasm_counts(_qasm()), _samples(), IBM_META)
    check("qat: honest-scope disclaimer always present",
          "NOT a reproduction" in r["honest_scope"]
          and "NOT a validation" in r["honest_scope"], "disclaimer missing/incomplete")


# --------------------------------------------------------------------------
# Anomaly flags on tampered / inconsistent data
# --------------------------------------------------------------------------
def test_anomaly_wrong_sample_count():
    v = PublishedCircuitVerifier()
    facts = parse_qasm_counts(_qasm())
    samples = _samples(n=1000)  # published claims 2051
    r = v.verify(facts, samples, IBM_META)
    check("qat: wrong sample count -> ANOMALY",
          r["type"] == "PUBLISHED_CIRCUIT_ANOMALY"
          and any(a["check"] == "sample_count" for a in r["anomalies"]), f"got {r['anomalies']}")


def test_anomaly_inconsistent_bitstring_width():
    v = PublishedCircuitVerifier()
    facts = parse_qasm_counts(_qasm())
    samples = _samples(n=2051)
    samples[0] = "010"  # wrong width
    r = v.verify(facts, samples, IBM_META)
    check("qat: inconsistent bitstring width -> ANOMALY",
          any(a["check"] == "bitstring_width" for a in r["anomalies"]), f"got {r['anomalies']}")


def test_anomaly_degenerate_samples():
    v = PublishedCircuitVerifier()
    facts = parse_qasm_counts(_qasm())
    samples = _samples(degenerate=True)  # all identical
    r = v.verify(facts, samples, IBM_META)
    check("qat: degenerate (all-identical) samples -> ANOMALY",
          any(a["check"] == "degenerate_samples" for a in r["anomalies"]), f"got {r['anomalies']}")
    check("qat: degenerate samples -> fidelity claim implausible",
          r["fidelity_plausibility"]["plausible"] is False, f"got {r['fidelity_plausibility']}")


def test_anomaly_qubit_undercount():
    v = PublishedCircuitVerifier()
    facts = parse_qasm_counts(_qasm(qubits=40))  # fewer than claimed 70
    r = v.verify(facts, _samples(), IBM_META)
    check("qat: QASM qubit count below published -> ANOMALY",
          any(a["check"] == "manifest_qubits" for a in r["anomalies"]), f"got {r['anomalies']}")


def test_anomaly_t_count_mismatch():
    v = PublishedCircuitVerifier()
    facts = parse_qasm_counts(_qasm(t_gates=100))  # published claims 468
    r = v.verify(facts, _samples(), IBM_META)
    check("qat: T-count mismatch -> ANOMALY",
          any(a["check"] == "manifest_t_count" for a in r["anomalies"]), f"got {r['anomalies']}")


def test_no_samples_flagged():
    v = PublishedCircuitVerifier()
    r = v.verify(parse_qasm_counts(_qasm()), [], IBM_META)
    check("qat: no samples -> ANOMALY",
          any(a["check"] == "no_samples" for a in r["anomalies"]), f"got {r['anomalies']}")


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
