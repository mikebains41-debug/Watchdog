"""
Local Physics Verification — Modules 95, 96, 97 (companion, not a replacement)

WHAT THIS IS: an exact, local statevector simulation of the same three
circuits used in modules 95, 96, and 97, computing the true theoretical
quantum-mechanical predictions using real linear algebra (numpy) — no
OpenQuantum API, no hardware queue, no credits.

WHAT THIS IS NOT: this is NOT a substitute for real hardware
validation. It verifies that the TEST LOGIC (classification thresholds,
entropy formulas, fidelity witness math) is mathematically correct
against known-exact ground truth. It cannot and does not tell you
anything about real IQM Garnet hardware noise, decoherence, or
gate-error behavior — that requires the actual hardware runs (95, 96,
97), which remain genuinely pending on OpenQuantum's queue as of
tonight.

Think of this the same way module90/91's test_physics_90_91.py relates
to real hardware: a literature/theory-calibrated local check, distinct
from and complementary to real device evidence.
"""
import numpy as np
import json
import datetime
import os
import math

def now_iso():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


# ---------- Exact 2-qubit statevector simulation (numpy, no dependencies) ----------

H = (1/np.sqrt(2)) * np.array([[1, 1], [1, -1]], dtype=complex)
I2 = np.eye(2, dtype=complex)
X = np.array([[0, 1], [1, 0]], dtype=complex)

def kron_n(*mats):
    out = mats[0]
    for m in mats[1:]:
        out = np.kron(out, m)
    return out

def cx_2q():
    """CNOT with qubit 0 as control, qubit 1 as target, in |q0 q1> ordering."""
    return np.array([
        [1, 0, 0, 0],
        [0, 1, 0, 0],
        [0, 0, 0, 1],
        [0, 0, 1, 0],
    ], dtype=complex)

def bell_state():
    """H on q0, then CX(0,1) — produces (|00>+|11>)/sqrt(2)."""
    psi = np.zeros(4, dtype=complex)
    psi[0] = 1.0  # |00>
    psi = kron_n(H, I2) @ psi
    psi = cx_2q() @ psi
    return psi

def apply_x_to_q1(psi):
    return kron_n(I2, X) @ psi

def apply_h_to_both(psi):
    return kron_n(H, H) @ psi

def probabilities(psi):
    """Returns dict of {'00':p, '01':p, '10':p, '11':p} — exact
    theoretical probabilities, not simulated shot noise."""
    probs = np.abs(psi) ** 2
    labels = ["00", "01", "10", "11"]
    return {labels[i]: float(probs[i]) for i in range(4)}

def sample_shots(probs_dict, shots, seed=None):
    """Draws simulated shot counts from the EXACT theoretical
    distribution — this models real shot noise on top of exact physics,
    same statistical process real hardware measurement follows (minus
    hardware noise/decoherence, which this cannot simulate)."""
    rng = np.random.default_rng(seed)
    labels = list(probs_dict.keys())
    p = list(probs_dict.values())
    draws = rng.choice(labels, size=shots, p=p)
    counts = {lbl: int(np.sum(draws == lbl)) for lbl in labels}
    return counts


# ---------- Module 95 verification: fault injection classification logic ----------

def classify_result(counts, dominant_states, total_shots):
    dominant_count = sum(counts.get(s, 0) for s in dominant_states)
    fraction = dominant_count / total_shots if total_shots else 0
    return {"dominant_states": dominant_states,
             "dominant_fraction": round(fraction, 4),
             "matches_prediction": fraction > 0.7}

def verify_module95(shots=4096, seed=42):
    print("--- Module 95 logic verification: fault injection classification ---")

    control_psi = bell_state()
    control_probs = probabilities(control_psi)
    print(f"Exact theoretical control probabilities: {control_probs}")

    injected_psi = apply_x_to_q1(bell_state())
    injected_probs = probabilities(injected_psi)
    print(f"Exact theoretical injected (X-gate) probabilities: {injected_probs}")

    control_counts = sample_shots(control_probs, shots, seed=seed)
    injected_counts = sample_shots(injected_probs, shots, seed=seed + 1)

    control_check = classify_result(control_counts, ["00", "11"], shots)
    injected_check = classify_result(injected_counts, ["01", "10"], shots)

    print(f"Simulated control counts ({shots} shots): {control_counts}")
    print(f"Control classification: {control_check}")
    print(f"Simulated injected counts ({shots} shots): {injected_counts}")
    print(f"Injected classification: {injected_check}")

    logic_correct = control_check["matches_prediction"] and injected_check["matches_prediction"]
    print(f"Pipeline integrity logic correctly distinguishes control vs "
          f"injected under IDEAL (noiseless) conditions: {logic_correct}")

    return {
        "exact_control_probabilities": control_probs,
        "exact_injected_probabilities": injected_probs,
        "simulated_control_counts": control_counts,
        "simulated_injected_counts": injected_counts,
        "control_classification": control_check,
        "injected_classification": injected_check,
        "test_logic_verified_correct": logic_correct,
        "shots": shots,
    }


# ---------- Module 96 verification: QRNG entropy formula ----------

def shannon_entropy(counts, total):
    entropy = 0.0
    for c in counts.values():
        if c <= 0:
            continue
        p = c / total
        entropy -= p * math.log2(p)
    return entropy

def verify_module96(num_qubits=8, shots=4096, seed=7):
    print("\n--- Module 96 logic verification: QRNG entropy formula ---")

    # H on each qubit independently, no entangling gates -> exact
    # uniform distribution over 2^num_qubits states
    n_states = 2 ** num_qubits
    exact_prob_per_state = 1.0 / n_states
    print(f"Exact theoretical distribution: uniform over {n_states} states, "
          f"p={exact_prob_per_state:.6f} each")
    print(f"Exact theoretical entropy: {num_qubits}.0000 bits (= num_qubits, "
          f"by definition of uniform distribution over 2^n outcomes)")

    rng = np.random.default_rng(seed)
    draws = rng.integers(0, n_states, size=shots)
    unique, counts_arr = np.unique(draws, return_counts=True)
    counts = {str(int(u)): int(c) for u, c in zip(unique, counts_arr)}

    measured_entropy = shannon_entropy(counts, shots)
    entropy_ratio = round(measured_entropy / num_qubits, 4)

    print(f"Simulated measured entropy from {shots} shots: {measured_entropy:.4f} bits")
    print(f"Entropy ratio: {entropy_ratio} (approaches 1.0 as shots -> infinity, "
          f"by the law of large numbers — finite-shot deviation from 1.0 here is "
          f"expected statistical noise, not an error)")

    formula_correct = 0.85 < entropy_ratio <= 1.0  # generous bound for finite-shot noise
    print(f"Entropy formula produces theoretically-expected result under IDEAL "
          f"(noiseless) conditions: {formula_correct}")

    return {
        "num_qubits": num_qubits,
        "exact_theoretical_entropy_bits": float(num_qubits),
        "simulated_measured_entropy_bits": round(measured_entropy, 4),
        "entropy_ratio": entropy_ratio,
        "test_logic_verified_correct": formula_correct,
        "shots": shots,
    }


# ---------- Module 97 verification: fidelity witness formula ----------

def correlation_fraction(counts, total):
    correlated = counts.get("00", 0) + counts.get("11", 0)
    return correlated / total if total else 0

def verify_module97(shots=2048, seed=99):
    print("\n--- Module 97 logic verification: entanglement witness formula ---")

    # Ideal Bell state case
    psi = bell_state()
    zz_probs = probabilities(psi)
    xx_psi = apply_h_to_both(psi)
    xx_probs = probabilities(xx_psi)
    print(f"Exact ZZ-basis probabilities (ideal Bell state): {zz_probs}")
    print(f"Exact XX-basis probabilities (ideal Bell state): {xx_probs}")

    zz_counts = sample_shots(zz_probs, shots, seed=seed)
    xx_counts = sample_shots(xx_probs, shots, seed=seed + 1)
    p_zz = correlation_fraction(zz_counts, shots)
    p_xx = correlation_fraction(xx_counts, shots)
    fidelity_lower_bound = max(0.0, p_zz + p_xx - 1.0)

    print(f"Simulated ideal-state P_ZZ={p_zz:.4f}, P_XX={p_xx:.4f}, "
          f"fidelity lower bound={fidelity_lower_bound:.4f} "
          f"(theoretical exact value: 1.0)")

    # Deliberately degraded case — depolarizing-style mixture, to verify
    # the witness actually CATCHES a bad state rather than always
    # passing regardless of input
    degrade_fraction = 0.3  # 30% ideal Bell state, 70% random noise -- majority noise, should genuinely fail the witness
    rng = np.random.default_rng(seed + 2)
    ideal_draws = rng.choice(["00", "01", "10", "11"], size=shots,
                              p=list(zz_probs.values()))
    noise_draws = rng.choice(["00", "01", "10", "11"], size=shots, p=[0.25]*4)
    mask = rng.random(shots) < degrade_fraction
    mixed_zz_draws = np.where(mask, ideal_draws, noise_draws)
    mixed_zz_counts = {lbl: int(np.sum(mixed_zz_draws == lbl))
                        for lbl in ["00", "01", "10", "11"]}

    ideal_draws_xx = rng.choice(["00", "01", "10", "11"], size=shots,
                                 p=list(xx_probs.values()))
    noise_draws_xx = rng.choice(["00", "01", "10", "11"], size=shots, p=[0.25]*4)
    mask_xx = rng.random(shots) < degrade_fraction
    mixed_xx_draws = np.where(mask_xx, ideal_draws_xx, noise_draws_xx)
    mixed_xx_counts = {lbl: int(np.sum(mixed_xx_draws == lbl))
                        for lbl in ["00", "01", "10", "11"]}

    p_zz_degraded = correlation_fraction(mixed_zz_counts, shots)
    p_xx_degraded = correlation_fraction(mixed_xx_counts, shots)
    fidelity_lower_bound_degraded = max(0.0, p_zz_degraded + p_xx_degraded - 1.0)

    print(f"\nDeliberately degraded state ({int(degrade_fraction*100)}% ideal / "
          f"{int((1-degrade_fraction)*100)}% random noise mixture):")
    print(f"  P_ZZ={p_zz_degraded:.4f}, P_XX={p_xx_degraded:.4f}, "
          f"fidelity lower bound={fidelity_lower_bound_degraded:.4f}")

    ideal_passes = fidelity_lower_bound > 0.5
    degraded_correctly_flagged = fidelity_lower_bound_degraded <= 0.5
    witness_discriminates_correctly = ideal_passes and degraded_correctly_flagged

    print(f"\nWitness correctly PASSES ideal Bell state: {ideal_passes}")
    print(f"Witness correctly FLAGS degraded/fake state as NOT genuinely "
          f"entangled: {degraded_correctly_flagged}")
    print(f"Witness formula discriminates real vs fake entanglement "
          f"correctly under these test conditions: {witness_discriminates_correctly}")

    return {
        "ideal_case": {
            "exact_zz_probabilities": zz_probs,
            "exact_xx_probabilities": xx_probs,
            "simulated_fidelity_lower_bound": round(fidelity_lower_bound, 4),
            "witness_passed": ideal_passes,
        },
        "degraded_case": {
            "degrade_fraction_random_noise": 1 - degrade_fraction,
            "simulated_fidelity_lower_bound": round(fidelity_lower_bound_degraded, 4),
            "witness_correctly_flagged_as_not_entangled": degraded_correctly_flagged,
        },
        "test_logic_verified_correct": witness_discriminates_correctly,
        "shots": shots,
    }


if __name__ == "__main__":
    print("="*70)
    print("LOCAL PHYSICS VERIFICATION — modules 95/96/97 test logic")
    print("(exact statevector simulation, NOT real hardware — see docstring)")
    print("="*70 + "\n")

    m95 = verify_module95()
    m96 = verify_module96()
    m97 = verify_module97()

    all_correct = (m95["test_logic_verified_correct"]
                   and m96["test_logic_verified_correct"]
                   and m97["test_logic_verified_correct"])

    print(f"\n{'='*70}")
    print(f"ALL THREE TEST-LOGIC VERIFICATIONS PASSED: {all_correct}")
    print(f"{'='*70}")

    result = {
        "purpose": ("Local exact-physics simulation verifying the test logic "
                     "used in modules 95/96/97 against known-correct quantum "
                     "mechanics. NOT a substitute for real hardware validation."),
        "module95_verification": m95,
        "module96_verification": m96,
        "module97_verification": m97,
        "all_logic_verified_correct": all_correct,
        "timestamp": now_iso(),
    }

    OUTPUT_DIR = "/data/data/com.termux/files/home/Watchdog/todo"
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    output_path = os.path.join(OUTPUT_DIR, "local_physics_95_96_97_result.json")
    with open(output_path, "w") as f:
        json.dump(result, f, indent=2)
    print(f"\nSaved to {output_path}")
