#!/usr/bin/env python3
"""
test_absorption_refrigerator_comparison.py

Validates M_absorption_refrigerator_comparison.py against published values
in Aamir et al., Nature Physics 21, 318-323 (2025). DOI: 10.1038/s41567-024-02708-5

Run with: pytest test_absorption_refrigerator_comparison.py -v
"""

import pytest
from M_absorption_refrigerator_comparison import (
    RESET_PERFORMANCE,
    COMPARISON_TO_PRIOR_RESET_PROTOCOLS,
    COEFFICIENT_OF_PERFORMANCE,
)


class TestResetPerformance:
    def test_steady_state_temp_matches_paper(self):
        assert RESET_PERFORMANCE["steady_state_temp_mK"] == pytest.approx(22.0, abs=1e-6)

    def test_theoretical_prediction_matches_paper(self):
        assert RESET_PERFORMANCE["theoretical_prediction_temp_mK"] == pytest.approx(18.6, abs=1e-6)

    def test_measured_temp_close_to_theoretical_prediction(self):
        # Paper states measured result is "remarkably close" to theory
        diff = abs(RESET_PERFORMANCE["steady_state_temp_mK"] - RESET_PERFORMANCE["theoretical_prediction_temp_mK"])
        assert diff < 5.0  # within 5 mK, consistent with "remarkably close"

    def test_relaxation_speedup_exceeds_70x(self):
        # Paper explicitly states "a factor of >70"
        assert RESET_PERFORMANCE["relaxation_speedup_factor"] > 70.0

    def test_relaxation_speedup_matches_paper_value(self):
        assert RESET_PERFORMANCE["relaxation_speedup_factor"] == pytest.approx(73.0, rel=0.02)

    def test_fastest_reset_time_matches_paper(self):
        assert RESET_PERFORMANCE["fastest_reset_time_ns"] == pytest.approx(970, abs=1e-6)


class TestComparisonToPriorArt:
    def test_this_work_beats_prior_art_population(self):
        # This work: 3e-4. Prior art range: 8e-4 to 2e-3. Lower is better.
        assert (
            COMPARISON_TO_PRIOR_RESET_PROTOCOLS["this_work_achieved_population"]
            < COMPARISON_TO_PRIOR_RESET_PROTOCOLS["this_work_population_range"][0]
        )

    def test_this_work_beats_prior_art_temperature(self):
        # This work: 22 mK. Prior art range: 40-49 mK. Lower is better.
        assert (
            COMPARISON_TO_PRIOR_RESET_PROTOCOLS["this_work_temp_mK"]
            < COMPARISON_TO_PRIOR_RESET_PROTOCOLS["prior_art_temp_range_mK"][0]
        )


class TestCoefficientOfPerformance:
    def test_measured_cop_matches_paper(self):
        assert COEFFICIENT_OF_PERFORMANCE["measured_cop"] == pytest.approx(0.7, abs=1e-6)

    def test_carnot_bound_matches_paper(self):
        assert COEFFICIENT_OF_PERFORMANCE["carnot_bound_cop"] == pytest.approx(0.95, abs=1e-6)

    def test_measured_cop_below_carnot_bound(self):
        # Second law of thermodynamics -- paper explicitly confirms this
        assert COEFFICIENT_OF_PERFORMANCE["measured_cop"] < COEFFICIENT_OF_PERFORMANCE["carnot_bound_cop"]

    def test_cop_matches_common_air_conditioner_per_paper(self):
        # Paper explicitly compares COP to a common air conditioner (~0.7)
        assert COEFFICIENT_OF_PERFORMANCE["measured_cop"] == pytest.approx(
            COEFFICIENT_OF_PERFORMANCE["reference_air_conditioner_cop"], abs=1e-6
        )


if __name__ == "__main__":
    import sys
    sys.exit(pytest.main([__file__, "-v"]))
