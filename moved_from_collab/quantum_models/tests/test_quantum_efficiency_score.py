#!/usr/bin/env python3
"""Tests for M_quantum_efficiency_score.py"""
import pytest
from M_quantum_efficiency_score import score, carnot_amp, PUBLISHED_W_PER_QUBIT, ROOM_TEMP_K, MIXING_K


class TestCarnotAmp:
    def test_default_uses_mixing_chamber_temp(self):
        result = carnot_amp()
        expected = (ROOM_TEMP_K - MIXING_K) / MIXING_K
        assert result == pytest.approx(expected, rel=1e-9)

    def test_custom_temperature(self):
        result = carnot_amp(t=10.0)
        expected = (ROOM_TEMP_K - 10.0) / 10.0
        assert result == pytest.approx(expected, rel=1e-9)


class TestScoreFunction:
    def test_returns_five_values(self):
        result = score(1000, 26000.0, 1.0)
        assert len(result) == 5

    def test_score_is_integer_in_valid_range(self):
        _, _, _, s, _ = score(1000, 26000.0, 1.0)
        assert isinstance(s, int)
        assert 0 <= s <= 100

    def test_rating_matches_score_bands(self):
        _, _, _, s, rating = score(1000, 26000.0, 1.0)
        if s >= 75:
            assert rating == "EFFICIENT"
        elif s >= 45:
            assert rating == "ACCEPTABLE"
        elif s >= 20:
            assert rating == "WASTEFUL"
        else:
            assert rating == "CRITICAL WASTE"

    def test_score_ceiling_behavior_documented(self):
        """
        DOCUMENTED CHARACTERISTIC, not a bug: the wq_comp term (100/r, capped
        at 100) means any wall power AT OR BELOW the published reference
        (6.25 W/qubit) scores the maximum wq_comp of 100 -- the formula does
        not distinguish "exactly at reference" from "far better than
        reference." Both 1 W/qubit and 6.25 W/qubit score 100 here. This is
        a real ceiling in the current scoring design, documented rather than
        worked around.
        """
        _, _, _, s_well_under, _ = score(qubits=1000, wall_w=1000, cold_load_w=1.0)
        _, _, _, s_at_reference, _ = score(qubits=1000, wall_w=6250, cold_load_w=1.0)
        assert s_well_under == s_at_reference == 100

    def test_worse_than_reference_scores_lower_than_at_reference(self):
        """Above the reference wattage, score should meaningfully decrease."""
        _, _, _, s_at_reference, _ = score(qubits=1000, wall_w=6250, cold_load_w=1.0)
        _, _, _, s_worse, _ = score(qubits=1000, wall_w=12500, cold_load_w=1.0)
        assert s_worse < s_at_reference

    def test_zero_wall_power_does_not_crash(self):
        wpq, ideal, carnot_pct, s, rating = score(qubits=1000, wall_w=0, cold_load_w=1.0)
        assert carnot_pct == 0
        assert wpq == 0

    def test_wpq_matches_manual_calc(self):
        wpq, _, _, _, _ = score(qubits=1000, wall_w=26000.0, cold_load_w=1.0)
        assert wpq == pytest.approx(26.0, rel=1e-9)

    def test_score_capped_at_100(self):
        # Extremely low wall power relative to qubit count should not exceed 100
        _, _, _, s, _ = score(qubits=1000, wall_w=1.0, cold_load_w=0.0001)
        assert s <= 100

    def test_score_not_negative(self):
        # Extremely high wall power should not drive score below 0
        _, _, _, s, _ = score(qubits=1000, wall_w=10_000_000.0, cold_load_w=1.0)
        assert s >= 0


if __name__ == "__main__":
    import sys
    sys.exit(pytest.main([__file__, "-v"]))
