#!/usr/bin/env python3
"""Tests for M_cryo_thermal_cascade.py"""
import pytest
from M_cryo_thermal_cascade import CascadeStage, DEFAULT_CASCADE, GhostLoadEstimate, estimate_ghost_load_cost


class TestCascadeStage:
    def test_carnot_amplification_computed_on_init(self):
        stage = CascadeStage("Test", 10.0, "test_tech")
        expected = (300.0 - 10.0) / 10.0
        assert stage.carnot_amplification_min == pytest.approx(expected, rel=1e-9)

    def test_zero_temperature_raises_value_error(self):
        with pytest.raises(ValueError):
            CascadeStage("Test", 0.0, "test_tech")

    def test_negative_temperature_raises_value_error(self):
        with pytest.raises(ValueError):
            CascadeStage("Test", -5.0, "test_tech")

    def test_colder_stage_has_higher_amplification(self):
        warm = CascadeStage("Warm", 50.0, "test")
        cold = CascadeStage("Cold", 0.015, "test")
        assert cold.carnot_amplification_min > warm.carnot_amplification_min


class TestDefaultCascade:
    def test_default_cascade_has_five_stages(self):
        assert len(DEFAULT_CASCADE) == 5

    def test_default_cascade_temperatures_strictly_decreasing(self):
        temps = [s.temp_kelvin for s in DEFAULT_CASCADE]
        for i in range(len(temps) - 1):
            assert temps[i] > temps[i + 1]

    def test_mixing_chamber_is_coldest_stage(self):
        coldest = min(DEFAULT_CASCADE, key=lambda s: s.temp_kelvin)
        assert "Mixing Chamber" in coldest.name

    def test_mixing_chamber_carnot_amplification_matches_known_value(self):
        """At 15mK, Carnot amplification should be (300-0.015)/0.015 ~= 19999x"""
        mc = DEFAULT_CASCADE[-1]
        assert mc.carnot_amplification_min == pytest.approx(19999.0, rel=0.01)


class TestGhostLoadEstimate:
    def test_none_static_leak_returns_none_cost(self):
        estimate = GhostLoadEstimate(stage=DEFAULT_CASCADE[-1], static_heat_leak_watts=None)
        assert estimate.total_room_temp_cost_watts() is None

    def test_cost_scales_with_static_leak(self):
        stage = DEFAULT_CASCADE[-1]
        est1 = GhostLoadEstimate(stage=stage, static_heat_leak_watts=1.0)
        est2 = GhostLoadEstimate(stage=stage, static_heat_leak_watts=2.0)
        assert est2.total_room_temp_cost_watts() == pytest.approx(2 * est1.total_room_temp_cost_watts(), rel=1e-9)

    def test_cost_equals_leak_times_amplification(self):
        stage = DEFAULT_CASCADE[-1]
        est = GhostLoadEstimate(stage=stage, static_heat_leak_watts=1.0)
        expected = 1.0 * stage.carnot_amplification_min
        assert est.total_room_temp_cost_watts() == pytest.approx(expected, rel=1e-9)


class TestEstimateGhostLoadCostDoesNotCrash:
    def test_runs_without_error_with_none_input(self, capsys):
        estimate_ghost_load_cost(static_heat_leak_watts=None)
        captured = capsys.readouterr()
        assert "AWAITING_HARDWARE_TEST" in captured.out

    def test_runs_without_error_with_real_input(self, capsys):
        estimate_ghost_load_cost(static_heat_leak_watts=1.0)
        captured = capsys.readouterr()
        assert "Carnot-minimum" in captured.out


if __name__ == "__main__":
    import sys
    sys.exit(pytest.main([__file__, "-v"]))
