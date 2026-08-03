#!/usr/bin/env python3
"""
M_literature_comparison.py

Positions the Uusnakki et al. (2026) experimental Otto-cycle result within
the broader literature on quantum heat engine cycle optimization, using
real published figures from:

    Erdman, P.A. & Noe, F. "Identifying optimal cycles in quantum thermal
    machines with reinforcement-learning." npj Quantum Information 8, 1
    (2022). DOI: 10.1038/s41534-021-00512-0

KEY FINDING FROM THIS PAPER: the standard Otto cycle is NOT, in general,
optimal for power extraction. A reinforcement-learning agent applied to a
superconducting-qubit refrigerator (a closely related system to Uusnakki
et al.'s device, though a different specific setup and NOT the same
hardware) discovered a cycle that outperformed the best previously
published (trapezoidal) cycle for that same system.

STATUS: Literature context only. This module does NOT claim the Erdman &
Noe results transfer directly to the Uusnakki et al. device -- the two
papers study related but distinct superconducting-qubit thermal-machine
setups (refrigerator vs. heat engine; different Hamiltonians and bath
couplings). This module exists to document the theoretical/simulated
headroom reported in the field, not to claim it applies 1:1 to
gpu-quantum-core's Otto cycle model.
"""

# ---------------------------------------------------------------------------
# Published figures: Erdman & Noe (2022), npj Quantum Information 8, 1
# ---------------------------------------------------------------------------

# Superconducting qubit REFRIGERATOR case (closest system to Uusnakki et al,
# though not the same device or the same thermal-machine mode: refrigerator
# vs. heat engine).
SC_QUBIT_REFRIGERATOR = {
    "best_prior_trapezoidal_cooling_power": 2.3e-4,   # <P_R>, dimensionless units of ref
    "rl_discovered_cooling_power": 10.8e-4,           # <P_R>, same units
    "improvement_factor": 10.8e-4 / 2.3e-4,
    "rl_cop_fraction_of_carnot": 0.06,                # COP at max power / Carnot COP
    "coherence_rl_cycle": 0.116,                      # time-avg relative entropy of coherence
    "coherence_trapezoidal_cycle": 0.194,             # same metric, prior best cycle
}

# Two-level system heat engine (benchmark case, RL matched the KNOWN
# analytically optimal cycle exactly)
TWO_LEVEL_HEAT_ENGINE = {
    "emp_fraction_of_curzon_ahlborn": 1.00,   # 100% of eta_CA
    "emp_fraction_of_carnot": 0.59,           # 59% of eta_C
}

# Harmonic oscillator heat engine, two control-range configurations
HARMONIC_OSCILLATOR_HEAT_ENGINE = {
    "narrow_range": {
        "emp_fraction_of_curzon_ahlborn": 0.60,
        "emp_fraction_of_carnot": 0.46,
    },
    "wide_range": {
        "emp_fraction_of_curzon_ahlborn": 0.78,
        "emp_fraction_of_carnot": 0.59,
    },
}


def summary() -> dict:
    return {
        "source": "Erdman & Noe, npj Quantum Information 8, 1 (2022)",
        "doi": "10.1038/s41534-021-00512-0",
        "status": "LITERATURE_CONTEXT_ONLY_NOT_DIRECTLY_APPLIED_TO_UUSNAKKI_DEVICE",
        "key_finding": (
            "The standard Otto cycle is not, in general, optimal for power "
            "extraction. RL-discovered cycles outperformed prior best cycles "
            "in all three systems studied."
        ),
        "sc_qubit_refrigerator_improvement_factor": round(
            SC_QUBIT_REFRIGERATOR["improvement_factor"], 2
        ),
        "sc_qubit_refrigerator_coherence_reduction": round(
            1 - SC_QUBIT_REFRIGERATOR["coherence_rl_cycle"]
            / SC_QUBIT_REFRIGERATOR["coherence_trapezoidal_cycle"], 3
        ),
        "caveat": (
            "This is a DIFFERENT superconducting-qubit system (a refrigerator "
            "with a fixed two-bath coupling, simulated) than the Uusnakki et "
            "al. device (a heat engine with a single tunable QCR reservoir, "
            "experimentally realized). Figures here document field-level "
            "headroom, not a validated bound on the specific gpu-quantum-core "
            "Otto cycle model."
        ),
    }


if __name__ == "__main__":
    print("=" * 70)
    print("  LITERATURE COMPARISON — Erdman & Noe 2022 (npj Quantum Info)")
    print("=" * 70)
    for k, v in summary().items():
        print(f"  {k}: {v}")
    print()
    print(f"  RL vs. best prior trapezoidal cycle (SC qubit refrigerator):")
    print(f"    Cooling power improvement: {SC_QUBIT_REFRIGERATOR['improvement_factor']:.2f}x")
    print(f"    Coherence generated (lower is better): "
          f"RL={SC_QUBIT_REFRIGERATOR['coherence_rl_cycle']}, "
          f"trapezoidal={SC_QUBIT_REFRIGERATOR['coherence_trapezoidal_cycle']}")
