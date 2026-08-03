#!/usr/bin/env python3
"""
M_qubit_temperature_evolution.py

Models the effective-temperature trajectory of the transmon qubit during
cyclic Otto-cycle operation, based on:

    Uusnakki et al., "Initial demonstration of a quantum heat engine
    based on dissipation-engineered superconducting circuits."
    Nature Communications 17, 6054 (2026). DOI: 10.1038/s41467-026-72651-x

Data source: main text ("We observe an increase of the effective
temperature from around 200 mK to 600 mK in three cycles") and the
arXiv preprint Extended Data Fig. 2 / Methods (saturation time constant
tau_sat = 1.0 microsecond, state saturates to a maximum temperature of
600 mK after approximately five cycles, starting effective temperature
T_int = 160 mK before any pulses are applied).

STATUS: Calibrated against published data (single device, single pulse
configuration). Not independently reproduced or hardware-tested by
GPU Optimizer / gpu-quantum-core. The exponential-saturation model below
is a simplified fit description taken directly from the paper's own
stated functional form (~ -exp(-t/tau_sat)), not an independent
re-derivation.
"""

import math

# ---------------------------------------------------------------------------
# Published temperature data (Uusnakki et al. 2026)
# ---------------------------------------------------------------------------
T_INITIAL_MK = 160.0        # T_int, thermal state before any pulses
T_AFTER_3_CYCLES_LOW_MK = 200.0   # approximate start of the reported 3-cycle rise
T_AFTER_3_CYCLES_HIGH_MK = 600.0  # approximate end of the reported 3-cycle rise
T_SATURATION_MK = 600.0     # maximum simulated saturation temperature
CYCLES_TO_SATURATE = 5      # approximate number of cycles to reach saturation
TAU_SAT_US = 1.0            # saturation time constant, microseconds

# Measurement span: the paper notes eight-repetition measurements already
# span twice the saturation time constant, i.e. ~2 microseconds, supporting
# that near-saturated temperatures are already being measured.
MEASUREMENT_SPAN_US = 2.0


def saturation_model(t_us: float, t_start_mk: float = T_INITIAL_MK,
                      t_max_mk: float = T_SATURATION_MK,
                      tau_us: float = TAU_SAT_US) -> float:
    """
    Simplified exponential-saturation model of effective temperature vs.
    time, following the functional form described in the paper
    ("fitting exponential decay functions of form ~ -exp(-t/tau_sat) to
    both the maximum and minimum points of the cycles").

    This is NOT a re-derivation from the Lindblad master equation -- it is
    a phenomenological fit shape matching the paper's own description.
    Treat as illustrative for tracking/dashboard purposes only.
    """
    if tau_us <= 0:
        raise ValueError("tau_us must be positive")
    return t_max_mk - (t_max_mk - t_start_mk) * math.exp(-t_us / tau_us)


def is_near_saturation(t_us: float, tolerance_mk: float = 10.0,
                        tau_us: float = TAU_SAT_US,
                        t_max_mk: float = T_SATURATION_MK) -> bool:
    """
    Returns True if, at time t_us, the modeled temperature is within
    tolerance_mk of the saturation temperature.
    """
    modeled = saturation_model(t_us, tau_us=tau_us, t_max_mk=t_max_mk)
    return abs(t_max_mk - modeled) <= tolerance_mk


def summary() -> dict:
    return {
        "source": "Uusnakki et al., Nature Communications 17, 6054 (2026)",
        "doi": "10.1038/s41467-026-72651-x",
        "status": "CALIBRATED_AGAINST_PUBLISHED_DATA_NOT_HARDWARE_TESTED_BY_GPU_OPTIMIZER",
        "t_initial_mK": T_INITIAL_MK,
        "t_saturation_mK": T_SATURATION_MK,
        "cycles_to_saturate_approx": CYCLES_TO_SATURATE,
        "tau_sat_us": TAU_SAT_US,
        "measurement_span_us": MEASUREMENT_SPAN_US,
        "note": (
            "Exponential saturation model follows the functional form "
            "described in the paper's Methods, calibrated to one published "
            "device configuration. Not an independent physics re-derivation."
        ),
    }


if __name__ == "__main__":
    print("=" * 70)
    print("  QUBIT TEMPERATURE EVOLUTION — Uusnakki et al. 2026")
    print("=" * 70)
    for k, v in summary().items():
        print(f"  {k}: {v}")
    print()
    print("  Modeled temperature trajectory (mK) vs. time (us):")
    for t in [0.0, 0.5, 1.0, 1.5, 2.0, 3.0, 5.0]:
        temp = saturation_model(t)
        near_sat = is_near_saturation(t)
        print(f"    t={t:4.1f} us -> T={temp:6.1f} mK  (near saturation: {near_sat})")
