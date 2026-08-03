#!/usr/bin/env python3
"""
M_absorption_refrigerator_comparison.py

Documents a second, independent real-hardware superconducting-circuit
quantum thermal machine result for field-level context, from:

    Aamir, M.A., Suria, P.J., Marin Guzman, J.A., Castillo-Moreno, C.,
    Epstein, J.M., Yunger Halpern, N. & Gasparinetti, S.
    "Thermally driven quantum refrigerator autonomously resets a
    superconducting qubit."
    Nature Physics 21, 318-323 (2025). DOI: 10.1038/s41567-024-02708-5

This is a QUALITATIVELY DIFFERENT machine and task than Uusnakki et al.
(2026): an autonomous three-qudit ABSORPTION refrigerator used for qubit
RESET, driven purely by a thermal gradient (no external work input),
versus a two-body Otto-cycle HEAT ENGINE requiring active driving pulses.
Both are real, hardware-measured superconducting-circuit quantum thermal
machines, which is why they are documented together here as field
context -- NOT because one is an upgrade or variant of the other.

STATUS: Literature context only. Real, published, hardware-measured
results. Not independently reproduced by GPU Optimizer / gpu-quantum-core.
"""

# ---------------------------------------------------------------------------
# Published figures: Aamir et al. (2025), Nature Physics 21, 318-323
# ---------------------------------------------------------------------------

RESET_PERFORMANCE = {
    "steady_state_temp_mK": 22.0,
    "steady_state_temp_upper_err_mK": 2.0,
    "steady_state_temp_lower_err_mK": 3.0,
    "steady_state_population": 3e-4,
    "steady_state_population_err": 2e-4,
    "theoretical_prediction_temp_mK": 18.6,   # from general QAR theory
    "theoretical_prediction_population": 6.7e-5,
    "natural_relaxation_time_us": 16.8,       # Trelax without refrigeration
    "refrigerated_relaxation_time_ns": 230,   # Trelax at nH=19.38
    "relaxation_speedup_factor": 16.8e3 / 230,  # convert us to ns for ratio
    "fastest_reset_time_ns": 970,             # time to reach Pexc=0.01
}

COMPARISON_TO_PRIOR_RESET_PROTOCOLS = {
    "this_work_population_range": (8e-4, 2e-3),  # NOTE: paper's own stated
    # comparison range for STATE-OF-THE-ART prior protocols, not this work.
    # This work achieves BELOW this range (3e-4), i.e. better than prior art.
    "this_work_achieved_population": 3e-4,
    "prior_art_temp_range_mK": (40, 49),
    "this_work_temp_mK": 22.0,
}

COEFFICIENT_OF_PERFORMANCE = {
    "measured_cop": 0.7,
    "carnot_bound_cop": 0.95,
    "cop_fraction_of_carnot": 0.7 / 0.95,
    "reference_air_conditioner_cop": 0.7,  # paper's own real-world comparison
}


def summary() -> dict:
    return {
        "source": "Aamir et al., Nature Physics 21, 318-323 (2025)",
        "doi": "10.1038/s41567-024-02708-5",
        "status": "LITERATURE_CONTEXT_DIFFERENT_MACHINE_TYPE_THAN_OTTO_CYCLE_MODULE",
        "machine_type": "Autonomous three-qudit absorption refrigerator (qubit reset)",
        "key_result": (
            f"{RESET_PERFORMANCE['steady_state_temp_mK']} mK steady-state "
            f"effective temperature, beating prior state-of-the-art reset "
            f"protocols ({COMPARISON_TO_PRIOR_RESET_PROTOCOLS['prior_art_temp_range_mK']} mK range)."
        ),
        "cop_matches_air_conditioner": (
            COEFFICIENT_OF_PERFORMANCE["measured_cop"]
            == COEFFICIENT_OF_PERFORMANCE["reference_air_conditioner_cop"]
        ),
        "relaxation_speedup_factor": round(RESET_PERFORMANCE["relaxation_speedup_factor"], 1),
        "caveat": (
            "This is a different task (autonomous qubit reset via thermal "
            "gradient) and different machine class (three-qudit absorption "
            "refrigerator) than the Otto-cycle heat engine in "
            "M_quantum_otto_cycle_simulator.py. Documented for field-level "
            "context on real, hardware-measured superconducting quantum "
            "thermal machine performance, not as a direct comparison point."
        ),
    }


if __name__ == "__main__":
    print("=" * 70)
    print("  ABSORPTION REFRIGERATOR COMPARISON — Aamir et al. 2025")
    print("=" * 70)
    for k, v in summary().items():
        print(f"  {k}: {v}")
    print()
    print(f"  Reset performance: {RESET_PERFORMANCE['steady_state_temp_mK']} mK "
          f"(+{RESET_PERFORMANCE['steady_state_temp_upper_err_mK']}/"
          f"-{RESET_PERFORMANCE['steady_state_temp_lower_err_mK']} mK)")
    print(f"  vs. theoretical prediction: {RESET_PERFORMANCE['theoretical_prediction_temp_mK']} mK")
    print(f"  Relaxation time speedup: {RESET_PERFORMANCE['relaxation_speedup_factor']:.1f}x "
          f"({RESET_PERFORMANCE['natural_relaxation_time_us']} us -> "
          f"{RESET_PERFORMANCE['refrigerated_relaxation_time_ns']} ns)")
    print(f"  COP: {COEFFICIENT_OF_PERFORMANCE['measured_cop']} "
          f"({COEFFICIENT_OF_PERFORMANCE['cop_fraction_of_carnot']*100:.1f}% of Carnot bound "
          f"{COEFFICIENT_OF_PERFORMANCE['carnot_bound_cop']})")
