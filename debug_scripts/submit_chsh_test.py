"""
Submits the numerically-verified CHSH Bell inequality test to real
OpenQuantum hardware. 4 measurement settings, each a real circuit.

Verified locally first: S = -2.8284 (theoretical Tsirelson bound) on
the ideal simulator, decisively beating the classical bound of 2.0.

If real hardware reproduces |S| > 2, that is unambiguous, quantitative
proof of genuine quantum entanglement — not a histogram that "looks"
entangled, but a rigorous physics test with a hard mathematical bound
that only quantum mechanics can cross.
"""
import time, json, math
from quantum_providers import get_provider

provider = get_provider()
print(f"Provider: {provider.provider_name}\n")

# Verified angles from grid search
a, a2 = 0.0, math.pi/2
b, b2 = math.radians(225), math.radians(315)

def make_qasm(theta_a, theta_b):
    return f"""OPENQASM 2.0;
include "qelib1.inc";
qreg q[2];
creg c[2];
h q[0];
cx q[0],q[1];
ry({-theta_a}) q[0];
ry({-theta_b}) q[1];
measure q[0] -> c[0];
measure q[1] -> c[1];
"""

settings = [
    ("chsh_ab",   a,  b),
    ("chsh_ab2",  a,  b2),
    ("chsh_a2b",  a2, b),
    ("chsh_a2b2", a2, b2),
]

SHOTS = 2048  # more shots = tighter statistical error on S

submitted = []
for name, ta, tb in settings:
    print(f"--- Submitting {name} ({SHOTS} shots) ---")
    qasm = make_qasm(ta, tb)
    try:
        job_id = provider.submit_circuit(qasm, shots=SHOTS,
                                          backend="iqm:garnet",
                                          name=f"watchdog_chsh_{name}")
        print(f"Job ID: {job_id}")
        submitted.append((name, job_id))
    except Exception as e:
        print(f"FAILED: {e}")
    time.sleep(2)

print(f"\n=== Submitted {len(submitted)} jobs — waiting 45s ===")
time.sleep(45)

print("\n=== Results ===")
E_values = {}
for name, jid in submitted:
    try:
        job = provider._scheduler.get_job(jid)
        result = provider.get_job_results(jid)
        counts = result.get("raw", {})
        total = sum(counts.values())
        p00 = counts.get("00", 0) / total if total else 0
        p11 = counts.get("11", 0) / total if total else 0
        p01 = counts.get("01", 0) / total if total else 0
        p10 = counts.get("10", 0) / total if total else 0
        E = p00 + p11 - p01 - p10
        E_values[name] = E
        print(f"\n{name} ({jid}): status={job.status}")
        print(f"  Counts: {counts}")
        print(f"  E = {E:.4f}")
    except Exception as e:
        print(f"{name}: FAILED - {e}")

print("\n" + "="*50)
print("=== REAL HARDWARE CHSH RESULT ===")
print("="*50)

if len(E_values) == 4:
    S_real = (E_values["chsh_ab"] - E_values["chsh_ab2"]
              + E_values["chsh_a2b"] + E_values["chsh_a2b2"])
    print(f"E(a,b)   = {E_values['chsh_ab']:.4f}")
    print(f"E(a,b')  = {E_values['chsh_ab2']:.4f}")
    print(f"E(a',b)  = {E_values['chsh_a2b']:.4f}")
    print(f"E(a',b') = {E_values['chsh_a2b2']:.4f}")
    print(f"\nS (real hardware) = {S_real:.4f}")
    print(f"Classical bound: 2.0")
    print(f"Quantum (Tsirelson) bound: {2*math.sqrt(2):.4f}")
    print(f"\n*** VIOLATES CLASSICAL BOUND: {abs(S_real) > 2.0} ***")

    with open("chsh_real_result.json", "w") as f:
        json.dump({
            "E_values": E_values,
            "S": S_real,
            "classical_bound": 2.0,
            "quantum_bound": 2*math.sqrt(2),
            "violates_classical": abs(S_real) > 2.0,
            "jobs": dict(submitted),
            "shots_per_setting": SHOTS,
            "verified_locally_first": True,
            "simulator_S": -2.8284,
        }, f, indent=2)
    print("\nSaved to chsh_real_result.json")
else:
    print(f"Only {len(E_values)}/4 settings completed — cannot compute S")
