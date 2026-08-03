#!/usr/bin/env python3
"""Tests for M_quasiparticle_heating_reference.py"""
import pytest
from M_quasiparticle_heating_reference import (
    is_qubit_likely_to_heat_quasiparticles,
    DRIVEN_HEATING_THRESHOLD_POPULATION,
    GAMMA_0_HZ,
    TAU_PH_NS,
    QUBIT_FREQ_RANGE_GHZ,
    T_STAR_OVER_OMEGA0_RANGE,
)


class TestThresholdConstant:
    def test_threshold_matches_paper_formula(self):
        """Paper states n_bar > 1/(1+e) ~ 0.27"""
        import math
        expected = 1.0 / (1.0 + math.e)
        assert DRIVEN_HEATING_THRESHOLD_POPULATION == pytest.approx(expected, rel=1e-9)

    def test_threshold_approximately_0_27(self):
        assert DRIVEN_HEATING_THRESHOLD_POPULATION == pytest.approx(0.27, abs=0.01)


class TestIsQubitLikelyToHeatQuasiparticles:
    def test_below_threshold_returns_false(self):
        assert is_qubit_likely_to_heat_quasiparticles(0.1) is False

    def test_above_threshold_returns_true(self):
        assert is_qubit_likely_to_heat_quasiparticles(0.5) is True

    def test_typical_undriven_qubit_population_returns_false(self):
        """Paper: undriven qubits typically have n_bar of a few % to ~10%"""
        assert is_qubit_likely_to_heat_quasiparticles(0.05) is False
        assert is_qubit_likely_to_heat_quasiparticles(0.10) is False

    def test_negative_population_raises_value_error(self):
        with pytest.raises(ValueError):
            is_qubit_likely_to_heat_quasiparticles(-0.1)

    def test_population_above_one_raises_value_error(self):
        with pytest.raises(ValueError):
            is_qubit_likely_to_heat_quasiparticles(1.5)

    def test_zero_population_returns_false(self):
        assert is_qubit_likely_to_heat_quasiparticles(0.0) is False

    def test_full_population_returns_true(self):
        assert is_qubit_likely_to_heat_quasiparticles(1.0) is True


class TestCitedConstants:
    def test_gamma_0_matches_paper(self):
        assert GAMMA_0_HZ == pytest.approx(1e5, rel=1e-9)

    def test_tau_ph_matches_paper(self):
        assert TAU_PH_NS == pytest.approx(10.0, rel=1e-9)

    def test_qubit_freq_range_matches_paper(self):
        assert QUBIT_FREQ_RANGE_GHZ == (4.0, 8.0)

    def test_t_star_ratio_range_matches_paper(self):
        """Paper: T*/omega_0 varies between 0.8 and 1.2 for their example parameters."""
        assert T_STAR_OVER_OMEGA0_RANGE == (0.8, 1.2)

    def test_t_star_ratio_range_brackets_unity(self):
        """
        Core qualitative point: since this range brackets 1.0, quasiparticle
        heating stays on the same order as the qubit frequency itself, not
        far above it -- consistent with the paper's stated conclusion.
        """
        low, high = T_STAR_OVER_OMEGA0_RANGE
        assert low < 1.0 < high


if __name__ == "__main__":
    import sys
    sys.exit(pytest.main([__file__, "-v"]))
