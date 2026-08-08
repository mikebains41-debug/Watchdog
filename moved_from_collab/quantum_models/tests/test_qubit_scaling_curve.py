#!/usr/bin/env python3
"""Tests for M_qubit_scaling_curve.py"""
import pytest
from M_qubit_scaling_curve import (
    carnot_amplification_min,
    wiring_heat_leak_watts,
    compute_scaling_curve,
    MIXING_CHAMBER_KELVIN,
    ROOM_TEMP_KELVIN,
)


class TestCarnotAmplification:
    def test_zero_cold_temp_raises_value_error(self):
        with pytest.raises(ValueError):
            carnot_amplification_min(0.0)

    def test_negative_cold_temp_raises_value_error(self):
        with pytest.raises(ValueError):
            carnot_amplification_min(-1.0)

    def test_matches_manual_formula(self):
        result = carnot_amplification_min(10.0, t_hot_kelvin=300.0)
        expected = (300.0 - 10.0) / 10.0
        assert result == pytest.approx(expected, rel=1e-9)

    def test_mixing_chamber_amplification_is_large(self):
        amp = carnot_amplification_min(MIXING_CHAMBER_KELVIN)
        assert amp > 10000  # confirms this is genuinely a huge multiplier


class TestWiringHeatLeak:
    def test_scales_linearly_with_qubit_count(self):
        leak1 = wiring_heat_leak_watts(100)
        leak2 = wiring_heat_leak_watts(200)
        assert leak2 == pytest.approx(2 * leak1, rel=1e-9)

    def test_zero_qubits_gives_zero_leak(self):
        assert wiring_heat_leak_watts(0) == pytest.approx(0.0, abs=1e-12)


class TestComputeScalingCurve:
    def test_returns_one_point_per_qubit_count(self):
        counts = [10, 50, 100]
        points = compute_scaling_curve(counts)
        assert len(points) == len(counts)

    def test_points_match_input_qubit_counts_in_order(self):
        counts = [10, 50, 100]
        points = compute_scaling_curve(counts)
        assert [p.qubit_count for p in points] == counts

    def test_room_temp_cost_increases_with_qubit_count(self):
        points = compute_scaling_curve([10, 100, 1000])
        costs = [p.room_temp_power_cost_watts for p in points]
        for i in range(len(costs) - 1):
            assert costs[i] < costs[i + 1]

    def test_total_mc_load_equals_sum_of_components(self):
        points = compute_scaling_curve([100])
        p = points[0]
        assert p.total_mc_heat_load_watts == pytest.approx(
            p.wiring_heat_leak_at_mc_watts + p.control_load_at_mc_watts, rel=1e-9
        )

    def test_room_temp_cost_equals_mc_load_times_amplification(self):
        points = compute_scaling_curve([100])
        p = points[0]
        amp = carnot_amplification_min(MIXING_CHAMBER_KELVIN)
        assert p.room_temp_power_cost_watts == pytest.approx(
            p.total_mc_heat_load_watts * amp, rel=1e-6
        )

    def test_empty_qubit_list_returns_empty_points(self):
        points = compute_scaling_curve([])
        assert points == []


if __name__ == "__main__":
    import sys
    sys.exit(pytest.main([__file__, "-v"]))
