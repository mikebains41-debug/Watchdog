#!/usr/bin/env python3
"""
Watchdog — Module 95: Circuit Fault Injection Robustness Test
Status: FUNCTIONAL — real hardware submission required

WHAT THIS TESTS: submits a known-correct circuit alongside a
deliberately corrupted variant (an injected extra gate, or a bit-flip
inserted into the QASM before submission), and compares the resulting
output distributions. This tests whether the pipeline — the SDK,
network transit, and QPU compilation — can be silently tampered with
between "circuit designed" and "circuit executed."

THE THREAT MODEL: a compromised network path, a malicious or compromised
cloud provider component, or a supply-chain attack on the SDK itself
could alter a circuit in transit. Comparing the actual measured output
against BOTH the ideal expected distribution AND a deliberately-injected
alternative gives a concrete, falsifiable signal: did the circuit that
ran match the circuit that was submitted?

METHOD:
  1. Submit the known-correct circuit (e.g. a Bell state) — this is the
     control, and its expected output is mathematically known.
  2. Separately submit the SAME circuit with one deliberate extra gate
     inserted (e.g. an extra X gate on one qubit) — the "corrupted"
     variant, whose expected output is ALSO mathematically known and
     different from the control.
  3. Compare both real results against their respective mathematical
     predictions.
  4. If the control circuit's result does NOT match its prediction, but
     instead resembles the corrupted variant's prediction (or vice
     versa), that is direct evidence something altered the circuit
     between submission and execution — the two are cleanly
     distinguishable by design.

This is not a hardware-noise test (that's what fidelity percentages
elsewhere in this suite measure) — it is a PIPELINE INTEGRITY test,
using the QPU's own real physics as the detector.
"""
import json, time, datetime, math, os
from quantum_providers import get_provider

def now_iso():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()

def build_bell_control():
    return """OPENQASM 2.0;
include "qelib1.inc";
qreg q[2];
creg c[2];
h q[0];
cx q[0],q[1];
measure q[0] -> c[0];
measure q[1] -> c[1];
"""

def build_bell_injected(injection_type="extra_x"):
    """
    A deliberately corrupted variant with a KNOWN, predictable different
    output — not random noise, a specific mathematical prediction to
    compare against.
    """
    if injection_type == "extra_x":
        # Extra X on q1 before measurement: (|00>+|11>)/sqrt(2) -> (|01>+|10>)/sqrt(2)
        # Expected: dominant 01/10, near-zero 00/11 — the OPPOSITE of the control
        qasm = """OPENQASM 2.0;
include "qelib1.inc";
qreg q[2];
creg c[2];
h q[0];
cx q[0],q[1];
x q[1];
measure q[0] -> c[0];
measure q[1] -> c[1];
"""
        expected_dominant = ["01", "10"]
    elif injection_type == "extra_h":
        # Extra H on q0 before measurement collapses entanglement structure
        qasm = """OPENQASM 2.0;
include "qelib1.inc";
qreg q[2];
creg c[2];
h q[0];
cx q[0],q[1];
h q[0];
measure q[0] -> c[0];
measure q[1] -> c[1];
"""
        expected_dominant = ["00", "01", "10", "11"]  # near-uniform
    else:
        raise ValueError(f"unknown injection_type: {injection_type}")

    return qasm, expected_dominant

def classify_result(counts: dict, dominant_states: list, total_shots: int) -> dict:
    dominant_count = sum(counts.get(s, 0) for s in dominant_states)
    fraction = dominant_count / total_shots if total_shots else 0
    return {"dominant_states": dominant_states,
             "dominant_fraction": round(fraction, 4),
             "matches_prediction": fraction > 0.7}

def run_injection_test(provider, shots=1024):
    results = {}

    print("--- Submitting CONTROL circuit (Bell state, unmodified) ---")
    control_qasm = build_bell_control()
    control_job = provider.submit_circuit(control_qasm, shots=shots,
                                           backend="iqm:garnet",
                                           name="watchdog_fault_injection_control")
    print(f"Control job ID: {control_job}")

    print("\n--- Submitting INJECTED circuit (Bell state + extra X gate) ---")
    injected_qasm, expected_dominant = build_bell_injected("extra_x")
    injected_job = provider.submit_circuit(injected_qasm, shots=shots,
                                            backend="iqm:garnet",
                                            name="watchdog_fault_injection_test")
    print(f"Injected job ID: {injected_job}")

    print("\nWaiting 40s for both jobs...")
    time.sleep(40)

    control_result = provider.get_job_results(control_job)
    control_counts = control_result.get("raw", {})
    control_total = sum(control_counts.values())
    control_check = classify_result(control_counts, ["00", "11"], control_total)

    injected_result = provider.get_job_results(injected_job)
    injected_counts = injected_result.get("raw", {})
    injected_total = sum(injected_counts.values())
    injected_check = classify_result(injected_counts, expected_dominant, injected_total)

    print(f"\nControl counts: {control_counts}")
    print(f"Control matches Bell prediction (00/11 dominant): {control_check['matches_prediction']}")
    print(f"\nInjected counts: {injected_counts}")
    print(f"Injected matches corrupted prediction (01/10 dominant): {injected_check['matches_prediction']}")

    pipeline_integrity_ok = (control_check["matches_prediction"]
                             and injected_check["matches_prediction"])

    print(f"\n{'='*50}")
    print(f"PIPELINE INTEGRITY: {'CONFIRMED' if pipeline_integrity_ok else 'FAILED — INVESTIGATE'}")
    print(f"{'='*50}")

    return {
        "control_job_id": control_job, "control_counts": control_counts,
        "control_check": control_check,
        "injected_job_id": injected_job, "injected_counts": injected_counts,
        "injected_check": injected_check,
        "pipeline_integrity_confirmed": pipeline_integrity_ok,
        "shots": shots, "timestamp": now_iso(),
        "method": ("Submits a control circuit and a deliberately-corrupted "
                    "variant with a known, distinct expected output. If both "
                    "match their respective predictions, the pipeline "
                    "faithfully executed exactly what was submitted — "
                    "confirmed by the QPU's own physics, not just SDK "
                    "metadata"),
    }

if __name__ == "__main__":
    provider = get_provider()
    print(f"Provider: {provider.provider_name}\n")

    result = run_injection_test(provider)

    OUTPUT_DIR = "/data/data/com.termux/files/home/Watchdog-quantum-collab/open_quantum_results"
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    output_path = os.path.join(OUTPUT_DIR, "module95_fault_injection_result.json")
    with open(output_path, "w") as f:
        json.dump(result, f, indent=2)
    print(f"\nSaved to {output_path}")
