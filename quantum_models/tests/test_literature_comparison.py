#!/usr/bin/env python3
"""
test_literature_comparison.py

Validates M_literature_comparison.py against published values in:
Erdman & Noe, npj Quantum Information 8, 1 (2022). DOI: 10.1038/s41534-021-00512-0

Run with: pytest test_literature_comparison.py -v
"""

import pytest
from M_literature_comparison import (
    SC_QUBIT_REFRIGERATOR,
    TWO_LEVEL_HEAT_ENGINE,
    HARMONIC_OSCILLATOR_HEAT_ENGINE,
)


class TestSuperconductingQubitRefrigerator:
    def test_prior_cooling_power_matches_paper(self):
        assert SC_QUBIT_REFRIGERATOR["best_prior_trapezoidal_cooling_power"] == pytest.approx(2.3e-4, rel=1e-6)

    def test_rl_cooling_power_matches_paper(self):
        assert SC_QUBIT_REFRIGERATOR["rl_discovered_cooling_power"] == pytest.approx(10.8e-4, rel=1e-6)

    def test_rl_outperforms_prior_cycle(self):
        assert SC_QUBIT_REFRIGERATOR["rl_discovered_cooling_power"] > SC_QUBIT_REFRIGERATOR["best_prior_trapezoidal_cooling_power"]

    def test_improvement_factor_roughly_5x(self):
        # Paper states the RL cycle extracts heat "5 times faster"
        assert SC_QUBIT_REFRIGERATOR["improvement_factor"] == pytest.approx(5.0, rel=0.1)

    def test_cop_fraction_matches_paper(self):
        # Paper states COP at max power is "6% of Carnot's upper bound"
        assert SC_QUBIT_REFRIGERATOR["rl_cop_fraction_of_carnot"] == pytest.approx(0.06, abs=1e-6)

    def test_rl_cycle_generates_less_coherence_than_trapezoidal(self):
        # Paper states trapezoidal cycle "generates almost twice as much
        # coherence" as the RL cycle at the same speed
        assert SC_QUBIT_REFRIGERATOR["coherence_trapezoidal_cycle"] > SC_QUBIT_REFRIGERATOR["coherence_rl_cycle"]

    def test_coherence_ratio_matches_almost_twice_claim(self):
        # Paper states trapezoidal cycle generates "almost twice as much
        # coherence" -- qualitative language. Actual computed ratio from
        # the paper's own numbers (0.194 / 0.116) is 1.67x. We validate
        # against the real computed ratio, not an idealized 2.0x, since
        # 1.67x is what "almost twice" actually refers to here.
        ratio = SC_QUBIT_REFRIGERATOR["coherence_trapezoidal_cycle"] / SC_QUBIT_REFRIGERATOR["coherence_rl_cycle"]
        assert ratio == pytest.approx(1.67, rel=0.05)
        assert 1.5 < ratio < 2.0  # consistent with "almost twice", not exactly 2x


class TestTwoLevelHeatEngine:
    def test_rl_matches_known_optimal_cycle_exactly(self):
        # Paper states RL finds the exact known-optimal cycle for this
        # benchmark case: 100% of Curzon-Ahlborn efficiency
        assert TWO_LEVEL_HEAT_ENGINE["emp_fraction_of_curzon_ahlborn"] == pytest.approx(1.00, abs=1e-6)

    def test_carnot_fraction_matches_paper(self):
        assert TWO_LEVEL_HEAT_ENGINE["emp_fraction_of_carnot"] == pytest.approx(0.59, abs=1e-6)


class TestHarmonicOscillatorHeatEngine:
    def test_wide_range_outperforms_narrow_range(self):
        narrow = HARMONIC_OSCILLATOR_HEAT_ENGINE["narrow_range"]["emp_fraction_of_carnot"]
        wide = HARMONIC_OSCILLATOR_HEAT_ENGINE["wide_range"]["emp_fraction_of_carnot"]
        assert wide > narrow

    def test_narrow_range_matches_paper(self):
        assert HARMONIC_OSCILLATOR_HEAT_ENGINE["narrow_range"]["emp_fraction_of_carnot"] == pytest.approx(0.46, abs=1e-6)

    def test_wide_range_matches_paper(self):
        assert HARMONIC_OSCILLATOR_HEAT_ENGINE["wide_range"]["emp_fraction_of_carnot"] == pytest.approx(0.59, abs=1e-6)


class TestCrossSystemConsistency:
    def test_all_efficiency_fractions_below_one(self):
        """No reported efficiency fraction should exceed the reference it's a fraction of."""
        assert TWO_LEVEL_HEAT_ENGINE["emp_fraction_of_curzon_ahlborn"] <= 1.0
        assert TWO_LEVEL_HEAT_ENGINE["emp_fraction_of_carnot"] <= 1.0
        assert SC_QUBIT_REFRIGERATOR["rl_cop_fraction_of_carnot"] <= 1.0
        for config in HARMONIC_OSCILLATOR_HEAT_ENGINE.values():
            assert config["emp_fraction_of_curzon_ahlborn"] <= 1.0
            assert config["emp_fraction_of_carnot"] <= 1.0


if __name__ == "__main__":
    import sys
    sys.exit(pytest.main([__file__, "-v"]))
