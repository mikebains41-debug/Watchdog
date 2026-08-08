#!/usr/bin/env python3
"""Tests for M_thermal_anchoring.py"""
import pytest
from M_thermal_anchoring import carnot, distribute, STAGES, ROOM_TEMP_K, PUBLISHED_W_PER_QUBIT


class TestCarnot:
    def test_matches_manual_formula(self):
        result = carnot(10.0)
        expected = (ROOM_TEMP_K - 10.0) / 10.0
        assert result == pytest.approx(expected, rel=1e-9)

    def test_colder_temp_gives_higher_carnot(self):
        assert carnot(0.1) > carnot(10.0)


class TestStages:
    def test_five_stages_defined(self):
        assert len(STAGES) == 5

    def test_temperatures_strictly_decreasing(self):
        temps = [t for _, t, _ in STAGES]
        for i in range(len(temps) - 1):
            assert temps[i] > temps[i + 1]

    def test_all_anchor_fractions_between_zero_and_one(self):
        for name, temp, frac in STAGES:
            assert 0.0 < frac <= 1.0

    def test_mixing_chamber_is_final_stage_with_full_anchoring(self):
        name, temp, frac = STAGES[-1]
        assert "Mixing chamber" in name
        assert frac == pytest.approx(1.0, abs=1e-9)


class TestDistribute:
    def test_total_conducted_heat_fully_allocated(self):
        """All heat should end up anchored somewhere - none should vanish."""
        rows, total_cost = distribute(30.0)
        total_anchored = sum(row[2] for row in rows)
        assert total_anchored == pytest.approx(30.0, rel=1e-6)

    def test_returns_one_row_per_stage(self):
        rows, _ = distribute(30.0)
        assert len(rows) == len(STAGES)

    def test_total_cost_is_positive(self):
        _, total_cost = distribute(30.0)
        assert total_cost > 0

    def test_zero_input_gives_zero_output(self):
        rows, total_cost = distribute(0.0)
        assert total_cost == pytest.approx(0.0, abs=1e-9)
        for row in rows:
            assert row[2] == pytest.approx(0.0, abs=1e-9)

    def test_doubling_input_doubles_total_cost(self):
        _, cost1 = distribute(30.0)
        _, cost2 = distribute(60.0)
        assert cost2 == pytest.approx(2 * cost1, rel=1e-6)

    def test_anchoring_reduces_cost_vs_unanchored_baseline(self):
        """
        The whole point of this module: anchoring most heat at warmer
        stages should cost far less than letting it all reach the mixing
        chamber unanchored. Compare against the naive unanchored cost.
        """
        _, anchored_cost = distribute(30.0)
        unanchored_cost = 30.0 * carnot(0.015)  # all heat reaches mixing chamber
        assert anchored_cost < unanchored_cost

    def test_result_lands_same_order_of_magnitude_as_published_reference(self):
        """
        Module's own stated goal: land near ~6.25 W/qubit for 1000 qubits
        (i.e. total cost near 6250W), closing the previously-identified
        96x gap. Validate this claim directly.
        """
        _, total_cost = distribute(30.0)
        qubits = 1000
        w_per_qubit = total_cost / qubits
        ratio = w_per_qubit / PUBLISHED_W_PER_QUBIT
        assert 0.1 <= ratio <= 10  # "same order of magnitude" per module's own logic


if __name__ == "__main__":
    import sys
    sys.exit(pytest.main([__file__, "-v"]))
