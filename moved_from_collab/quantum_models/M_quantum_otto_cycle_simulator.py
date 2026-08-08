#!/usr/bin/env python3
"""
M_quantum_otto_cycle_simulator.py

Quantum Otto cycle model for a flux-tunable transmon qubit coupled to a
quantum-circuit refrigerator (QCR), based on the experimentally realized
device in:

    Uusnakki, T., Morstedt, T., Teixeira, W., Rasola, M. & Mottonen, M.
    "Initial demonstration of a quantum heat engine based on
    dissipation-engineered superconducting circuits."
    Nature Communications 17, 6054 (2026).
    DOI: 10.1038/s41467-026-72651-x

This module does NOT reproduce the authors' full Lindblad master-equation
simulation (which required QuTiP and detailed QCR-induced transition-rate
modeling, see Methods of the paper). It implements the simplified IDEAL
Otto-cycle relations the paper itself defines (their Eq. 3 and the ideal
compression-ratio efficiency formula), calibrated against the paper's
Table 1 device parameters, so that GPU Optimizer's Prometheus/Grafana
stack can report a physically-grounded efficiency figure for tracking
purposes.

STATUS: Calibrated against published data. This is a simplified analytic
model, not a reproduction of the authors' open-quantum-system simulation.
Validated only against the single device/pulse configuration reported in
the paper (Table 1, Table 2, eight repetitions of the first Otto cycle).
Extrapolation to other qubit/QCR parameters is untested.
"""

import math

QUBIT_FREQ_GHZ = 4.047
ANHARMONICITY_MHZ = -279
READOUT_RES_FREQ_GHZ = 7.436
RESET_RES_FREQ_GHZ = 4.670
TUNNELING_RESISTANCE_KOHM = 25.7
SUPERCONDUCTOR_GAP_UEV = 186
DYNES_PARAMETER = 4.0e-3
BASE_TEMP_MK = 40

MEASURED = {
    "Q_abs_ueV": 4.22,
    "Q_abs_stderr_ueV": 0.14,
    "W_tot_ueV": -0.023,
    "W_tot_stderr_ueV": 0.0010,
    "P_eV_per_s": 0.039,
    "P_stderr_eV_per_s": 0.0017,
    "efficiency": 0.0055,
    "efficiency_stderr": 0.0004,
}

SIMULATED_BY_AUTHORS = {
    "Q_abs_ueV": 4.06,
    "W_tot_ueV": -0.018,
    "P_eV_per_s": 0.031,
    "efficiency": 0.0045,
}

IDEAL_OTTO_EFFICIENCY = 0.020
STEADY_STATE_EFFICIENCY = 0.022
MEASURED_FRACTION_OF_IDEAL = MEASURED["efficiency"] / IDEAL_OTTO_EFFICIENCY
CARNOT_LIMIT_EFFICIENCY = 0.83


def ideal_otto_efficiency(omega_min_ghz: float, omega_max_ghz: float) -> float:
    if omega_max_ghz <= 0:
        raise ValueError("omega_max_ghz must be positive")
    kappa = omega_min_ghz / omega_max_ghz
    return 1.0 - kappa


def detuning_to_ideal_efficiency(detuning_mhz: float, base_freq_ghz: float = QUBIT_FREQ_GHZ) -> float:
    omega_max = base_freq_ghz
    omega_min = base_freq_ghz - abs(detuning_mhz) / 1000.0
    return ideal_otto_efficiency(omega_min, omega_max)


def estimate_first_cycle_efficiency(ideal_efficiency: float,
                                     measured_fraction: float = MEASURED_FRACTION_OF_IDEAL) -> float:
    return ideal_efficiency * measured_fraction


def summary() -> dict:
    return {
        "source": "Uusnakki et al., Nature Communications 17, 6054 (2026)",
        "doi": "10.1038/s41467-026-72651-x",
        "status": "CALIBRATED_AGAINST_PUBLISHED_DATA_NOT_HARDWARE_TESTED_BY_GPU_OPTIMIZER",
        "measured_efficiency": MEASURED["efficiency"],
        "measured_efficiency_stderr": MEASURED["efficiency_stderr"],
        "ideal_otto_efficiency": IDEAL_OTTO_EFFICIENCY,
        "steady_state_efficiency_projected": STEADY_STATE_EFFICIENCY,
        "carnot_limit": CARNOT_LIMIT_EFFICIENCY,
        "measured_fraction_of_ideal": round(MEASURED_FRACTION_OF_IDEAL, 4),
        "note": (
            "This is a simplified analytic model calibrated to one published "
            "experimental configuration. It is NOT a reproduction of the "
            "authors' full open-quantum-system simulation, and has not been "
            "validated against real hardware by GPU Optimizer / gpu-quantum-core."
        ),
    }


if __name__ == "__main__":
    print("=" * 70)
    print("  QUANTUM OTTO CYCLE MODEL — calibrated vs. Uusnakki et al. 2026")
    print("=" * 70)
    for k, v in summary().items():
        print(f"  {k}: {v}")
    print()
    print("  Reproducing paper's reported ideal efficiency for their")
    print("  -82.4 MHz detuning configuration:")
    computed = detuning_to_ideal_efficiency(-82.4)
    print(f"    computed ideal eta_Otto = {computed:.4f}  (paper reports ~0.020)")
