"""
CHSH test, fixed. Every ry(-theta) replaced with the mathematically
identical ry(2*pi - theta) — same physics (differs only by an
unobservable global phase), but avoids the confirmed negative-angle
compiler bug.
"""
import time, json, math
from quantum_providers import get_provider

provider = get_provider()
print(f"Provider: {provider.provider_name}\n")

def positive_angle(theta):
    """RY(2pi - theta) === RY(-theta) up to global phase (unobservable)."""
    if abs(theta) < 1e-9:
        return 0.0
    return (2 * math.pi - theta) % (2 * math.pi)

# Same verified angles as before — a, a', b, b' from the grid search
a, a2 = 0.0, math.pi / 2
b, b2 = math.radians(225), math.radians(315)

def make_qasm(theta_a, theta_b):
    pos_a = positive_angle(theta_a)
    pos_b = positive_angle(theta_b)
    return f"""OPENQASM 2.0;
include "qelib1.inc";
qreg q[2];
creg c[2];
h q[0];
cx q[0],q[1];
ry({pos_a}) q[0];
ry({pos_b}) q[1];
measure q[0] -> c[0];
measure q[1] -> c[1];
"""

settings = [
    ("chsh_ab_fixed",   a,  b),
    ("chsh_ab2_fixed",  a,  b2),
    ("chsh_a2b_fixed",  a2, b),
    ("chsh_a2b2_fixed", a2, b2),
]

SHOTS = 2048

print("=== Corrected angles (all positive) ===")
for name, ta, tb in settings:
    print(f"  {name}: ry({positive_angle(ta):.4f}) q0, ry({positive_angle(tb):.4f}) q1")
print()

submitted = []
for name, ta, tb in settings:
    print(f"--- Submitting {name} ({SHOTS} shots) ---")
    qasm = make_qasm(ta, tb)
    job_id = provider.submit_circuit(qasm, shots=SHOTS,
                                      backend="iqm:garnet",
                                      name=f"watchdog_{name}")
    print(f"Job ID: {job_id}")
    submitted.append((name, job_id))
    time.sleep(2)

print(f"\n=== Submitted {len(submitted)} jobs — waiting 45s ===")
time.sleep(45)

print("\n=== Results ===")
E_values = {}
for name, jid in submitted:
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

print("\n" + "="*50)
print("=== REAL HARDWARE CHSH RESULT (FIXED) ===")
print("="*50)

S_real = (E_values["chsh_ab_fixed"] - E_values["chsh_ab2_fixed"]
          + E_values["chsh_a2b_fixed"] + E_values["chsh_a2b2_fixed"])
print(f"E(a,b)   = {E_values['chsh_ab_fixed']:.4f}")
print(f"E(a,b')  = {E_values['chsh_ab2_fixed']:.4f}")
print(f"E(a',b)  = {E_values['chsh_a2b_fixed']:.4f}")
print(f"E(a',b') = {E_values['chsh_a2b2_fixed']:.4f}")
print(f"\nS (real hardware) = {S_real:.4f}")
print(f"Classical bound: 2.0")
print(f"Quantum (Tsirelson) bound: {2*math.sqrt(2):.4f}")
print(f"\n*** VIOLATES CLASSICAL BOUND: {abs(S_real) > 2.0} ***")

with open("chsh_fixed_result.json", "w") as f:
    json.dump({
        "E_values": E_values, "S": S_real,
        "classical_bound": 2.0, "quantum_bound": 2*math.sqrt(2),
        "violates_classical": abs(S_real) > 2.0,
        "jobs": dict(submitted), "shots_per_setting": SHOTS,
        "bug_fixed": "negative ry() angles replaced with positive equivalents (2pi - theta)",
    }, f, indent=2)
print("\nSaved to chsh_fixed_result.json")
