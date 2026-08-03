#!/usr/bin/env python3
"""Tests for M_quantum_fleet_score.py"""
import pytest
from M_quantum_fleet_score import unit_score, carnot_amp, PUBLISHED_W_PER_QUBIT


class TestCarnotAmp:
    def test_default_uses_mixing_chamber_temp(self):
        result = carnot_amp()
        assert result > 10000  # confirms genuinely large multiplier at 15mK


class TestUnitScore:
    def test_returns_three_values(self):
        result = unit_score(1000, 26000.0, 1.0)
        assert len(result) == 3

    def test_score_in_valid_range(self):
        _, s, _ = unit_score(1000, 26000.0, 1.0)
        assert 0 <= s <= 100

    def test_rating_matches_score_bands(self):
        _, s, rating = unit_score(1000, 26000.0, 1.0)
        if s >= 75:
            assert rating == "EFFICIENT"
        elif s >= 45:
            assert rating == "ACCEPTABLE"
        elif s >= 20:
            assert rating == "WASTEFUL"
        else:
            assert rating == "CRITICAL"

    def test_wpq_matches_manual_calc(self):
        wpq, _, _ = unit_score(1000, 26000.0, 1.0)
        assert wpq == pytest.approx(26.0, rel=1e-9)

    def test_zero_wall_power_does_not_crash(self):
        wpq, s, rating = unit_score(1000, 0, 1.0)
        assert wpq == 0

    def test_higher_wall_power_gives_lower_or_equal_score(self):
        _, s_low, _ = unit_score(1000, 6250.0, 1.0)
        _, s_high, _ = unit_score(1000, 62500.0, 1.0)
        assert s_high <= s_low


class TestFleetLevelConsistency:
    """
    This module's unit_score() logic is a near-duplicate of
    M_quantum_efficiency_score.py's score(). Confirm they agree on the
    same inputs, since fleet-level and single-unit scoring should be
    consistent with each other.
    """

    def test_matches_single_unit_efficiency_score_module(self):
        from M_quantum_efficiency_score import score as single_unit_score
        fleet_wpq, fleet_s, fleet_rating = unit_score(1000, 26000.0, 1.0)
        single_wpq, _, _, single_s, single_rating = single_unit_score(1000, 26000.0, 1.0)
        assert fleet_wpq == pytest.approx(single_wpq, rel=1e-9)
        assert fleet_s == single_s
        # Note: rating labels differ slightly ("CRITICAL" vs "CRITICAL WASTE")
        # for the lowest band -- documented here, not silently assumed equal.


if __name__ == "__main__":
    import sys
    sys.exit(pytest.main([__file__, "-v"]))
