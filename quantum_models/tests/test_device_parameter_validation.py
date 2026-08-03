#!/usr/bin/env python3
"""
test_device_parameter_validation.py

Validates M_device_parameter_validation.py plausibility checks against
published Table I values from Uusnakki et al., Nature Communications
17, 6054 (2026). DOI: 10.1038/s41467-026-72651-x

Run with: pytest test_device_parameter_validation.py -v
"""

import pytest
from M_device_parameter_validation import (
    run_all_checks,
    check_qubit_frequency_reasonable,
    check_anharmonicity_is_negative_and_reasonable,
    check_gap_consistent_with_aluminum,
    check_dynes_parameter_reasonable,
    check_base_temperature_reasonable,
    check_readout_resonator_above_qubit_frequency,
    check_reset_resonator_between_qubit_and_readout,
    QUBIT_FREQ_GHZ,
    ANHARMONICITY_MHZ,
    SUPERCONDUCTOR_GAP_UEV,
)


class TestIndividualChecks:
    def test_qubit_frequency_passes(self):
        assert check_qubit_frequency_reasonable() is True

    def test_anharmonicity_passes(self):
        assert check_anharmonicity_is_negative_and_reasonable() is True

    def test_gap_passes(self):
        assert check_gap_consistent_with_aluminum() is True

    def test_dynes_parameter_passes(self):
        assert check_dynes_parameter_reasonable() is True

    def test_base_temperature_passes(self):
        assert check_base_temperature_reasonable() is True

    def test_readout_above_qubit_passes(self):
        assert check_readout_resonator_above_qubit_frequency() is True

    def test_reset_resonator_ordering_passes(self):
        assert check_reset_resonator_between_qubit_and_readout() is True


class TestAllChecksAggregate:
    def test_all_checks_pass_for_published_device(self):
        results = run_all_checks()
        assert all(results.values()), f"Failed checks: {[k for k, v in results.items() if not v]}"

    def test_run_all_checks_returns_seven_checks(self):
        results = run_all_checks()
        assert len(results) == 7


class TestParameterValuesUnchanged:
    """Guard against accidental transcription drift from Table I."""

    def test_qubit_freq_matches_table_1(self):
        assert QUBIT_FREQ_GHZ == pytest.approx(4.047, abs=1e-6)

    def test_anharmonicity_matches_table_1(self):
        assert ANHARMONICITY_MHZ == pytest.approx(-279, abs=1e-6)

    def test_gap_matches_table_1(self):
        assert SUPERCONDUCTOR_GAP_UEV == pytest.approx(186, abs=1e-6)

    def test_anharmonicity_is_negative(self):
        """Fundamental transmon property -- must always be negative."""
        assert ANHARMONICITY_MHZ < 0


if __name__ == "__main__":
    import sys
    sys.exit(pytest.main([__file__, "-v"]))
