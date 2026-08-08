#!/usr/bin/env python3
"""
M_device_parameter_validation.py

Physical sanity checks on the device parameters reported in Table I of:

    Uusnakki et al., "Initial demonstration of a quantum heat engine
    based on dissipation-engineered superconducting circuits."
    Nature Communications 17, 6054 (2026). DOI: 10.1038/s41467-026-72651-x

This module does NOT re-derive these parameters from first principles. It
checks that the reported values fall within known, physically reasonable
ranges for aluminum-based superconducting transmon/QCR devices, as
established by the broader field (see reference ranges and their sources
in each check function's docstring).

STATUS: Sanity-check layer only. A device parameter passing these checks
does not mean it is correct -- only that it is not obviously anomalous
for this device family. This is a plausibility filter, not a validation
of the paper's measurements.
"""

# ---------------------------------------------------------------------------
# Published device parameters (Table I, Uusnakki et al. 2026)
# ---------------------------------------------------------------------------
QUBIT_FREQ_GHZ = 4.047
ANHARMONICITY_MHZ = -279
READOUT_RES_FREQ_GHZ = 7.436
RESET_RES_FREQ_GHZ = 4.670
TUNNELING_RESISTANCE_KOHM = 25.7
SUPERCONDUCTOR_GAP_UEV = 186
DYNES_PARAMETER = 4.0e-3
BASE_TEMP_MK = 40

# ---------------------------------------------------------------------------
# Known physically reasonable reference ranges for this device family
# ---------------------------------------------------------------------------

# Typical transmon qubit frequencies in the literature span roughly
# 3-8 GHz (standard microwave-cavity-compatible design window).
TRANSMON_FREQ_RANGE_GHZ = (3.0, 8.0)

# Transmon anharmonicity is characteristically negative (a defining
# feature distinguishing it from a simple harmonic oscillator) and
# typically falls in the range of roughly -150 to -350 MHz for standard
# single-junction transmon designs.
TRANSMON_ANHARMONICITY_RANGE_MHZ = (-350, -150)

# The superconducting gap parameter for aluminum (the standard material
# for this device family, as used in the paper's fabrication) has a
# well-known BCS value of approximately 2*Delta_Al ~= 360-380 ueV,
# i.e. Delta_Al ~= 180-190 ueV, consistent with standard aluminum
# thin-film superconducting gap literature values.
ALUMINUM_GAP_RANGE_UEV = (170, 200)

# Dynes parameter (subgap density of states) for high-quality NIS
# junctions is typically in the range 1e-4 to 1e-2; values much larger
# indicate a "leaky" junction with poor subgap behavior.
DYNES_PARAMETER_RANGE = (1e-5, 1e-2)

# Typical dilution refrigerator base temperatures for this class of
# experiment are in the range 10-100 mK.
DILUTION_FRIDGE_BASE_TEMP_RANGE_MK = (10, 100)


def _in_range(value: float, bounds: tuple) -> bool:
    low, high = bounds
    return low <= value <= high


def check_qubit_frequency_reasonable() -> bool:
    return _in_range(QUBIT_FREQ_GHZ, TRANSMON_FREQ_RANGE_GHZ)


def check_anharmonicity_is_negative_and_reasonable() -> bool:
    return _in_range(ANHARMONICITY_MHZ, TRANSMON_ANHARMONICITY_RANGE_MHZ)


def check_gap_consistent_with_aluminum() -> bool:
    return _in_range(SUPERCONDUCTOR_GAP_UEV, ALUMINUM_GAP_RANGE_UEV)


def check_dynes_parameter_reasonable() -> bool:
    return _in_range(DYNES_PARAMETER, DYNES_PARAMETER_RANGE)


def check_base_temperature_reasonable() -> bool:
    return _in_range(BASE_TEMP_MK, DILUTION_FRIDGE_BASE_TEMP_RANGE_MK)


def check_readout_resonator_above_qubit_frequency() -> bool:
    """
    Standard dispersive readout design requires the readout resonator to
    be detuned from the qubit frequency (commonly, though not always,
    with the resonator above the qubit in frequency for this device
    family, as reported: 7.436 GHz resonator vs. 4.047 GHz qubit).
    """
    return READOUT_RES_FREQ_GHZ > QUBIT_FREQ_GHZ


def check_reset_resonator_between_qubit_and_readout() -> bool:
    """
    The reported reset/auxiliary resonator frequency (4.670 GHz) sits
    just above the qubit frequency (4.047 GHz) and well below the
    readout resonator (7.436 GHz), consistent with its role as an
    intermediate coupling element to the QCR.
    """
    return QUBIT_FREQ_GHZ < RESET_RES_FREQ_GHZ < READOUT_RES_FREQ_GHZ


def run_all_checks() -> dict:
    return {
        "qubit_frequency_reasonable": check_qubit_frequency_reasonable(),
        "anharmonicity_negative_and_reasonable": check_anharmonicity_is_negative_and_reasonable(),
        "gap_consistent_with_aluminum": check_gap_consistent_with_aluminum(),
        "dynes_parameter_reasonable": check_dynes_parameter_reasonable(),
        "base_temperature_reasonable": check_base_temperature_reasonable(),
        "readout_resonator_above_qubit": check_readout_resonator_above_qubit_frequency(),
        "reset_resonator_between_qubit_and_readout": check_reset_resonator_between_qubit_and_readout(),
    }


def summary() -> dict:
    checks = run_all_checks()
    return {
        "source": "Uusnakki et al., Nature Communications 17, 6054 (2026)",
        "doi": "10.1038/s41467-026-72651-x",
        "status": "PLAUSIBILITY_CHECKS_ONLY_NOT_INDEPENDENT_VALIDATION",
        "all_checks_passed": all(checks.values()),
        "checks": checks,
        "note": (
            "These checks confirm the reported device parameters are not "
            "obviously anomalous for an aluminum-based transmon/QCR device. "
            "They do not independently verify the measurements themselves."
        ),
    }


if __name__ == "__main__":
    print("=" * 70)
    print("  DEVICE PARAMETER PLAUSIBILITY CHECKS — Uusnakki et al. 2026")
    print("=" * 70)
    result = summary()
    for k, v in result.items():
        if k != "checks":
            print(f"  {k}: {v}")
    print()
    print("  Individual checks:")
    for check_name, passed in result["checks"].items():
        status = "PASS" if passed else "FAIL"
        print(f"    [{status}] {check_name}")
