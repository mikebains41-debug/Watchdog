#!/usr/bin/env python3
"""Tests for M_qubit_hour_economics.py"""
import pytest
from M_qubit_hour_economics import QubitHourEconomics, EU_ELECTRICITY_EUR_KWH, USD_ELECTRICITY_KWH


class TestCostPerQubitHour:
    def test_zero_qubits_raises_value_error(self):
        econ = QubitHourEconomics("TEST", qubit_count=0, wall_power_watts=1000.0)
        with pytest.raises(ValueError):
            econ.cost_per_qubit_hour_eur()

    def test_negative_qubits_raises_value_error(self):
        econ = QubitHourEconomics("TEST", qubit_count=-5, wall_power_watts=1000.0)
        with pytest.raises(ValueError):
            econ.cost_per_qubit_hour_eur()

    def test_cost_doubles_when_power_doubles(self):
        econ1 = QubitHourEconomics("TEST", qubit_count=100, wall_power_watts=1000.0)
        econ2 = QubitHourEconomics("TEST", qubit_count=100, wall_power_watts=2000.0)
        assert econ2.cost_per_qubit_hour_eur() == pytest.approx(2 * econ1.cost_per_qubit_hour_eur(), rel=1e-9)

    def test_cost_halves_when_qubit_count_doubles(self):
        econ1 = QubitHourEconomics("TEST", qubit_count=100, wall_power_watts=1000.0)
        econ2 = QubitHourEconomics("TEST", qubit_count=200, wall_power_watts=1000.0)
        assert econ2.cost_per_qubit_hour_eur() == pytest.approx(econ1.cost_per_qubit_hour_eur() / 2, rel=1e-9)

    def test_eur_calculation_matches_manual_computation(self):
        econ = QubitHourEconomics("TEST", qubit_count=100, wall_power_watts=1000.0, uptime_fraction=1.0)
        expected = (1000.0 / 1000) * EU_ELECTRICITY_EUR_KWH / 100
        assert econ.cost_per_qubit_hour_eur() == pytest.approx(expected, rel=1e-9)

    def test_usd_calculation_matches_manual_computation(self):
        econ = QubitHourEconomics("TEST", qubit_count=100, wall_power_watts=1000.0, uptime_fraction=1.0)
        expected = (1000.0 / 1000) * USD_ELECTRICITY_KWH / 100
        assert econ.cost_per_qubit_hour_usd() == pytest.approx(expected, rel=1e-9)

    def test_lower_uptime_increases_effective_cost(self):
        full_uptime = QubitHourEconomics("TEST", qubit_count=100, wall_power_watts=1000.0, uptime_fraction=1.0)
        low_uptime = QubitHourEconomics("TEST", qubit_count=100, wall_power_watts=1000.0, uptime_fraction=0.5)
        assert low_uptime.cost_per_qubit_hour_eur() > full_uptime.cost_per_qubit_hour_eur()

    def test_zero_uptime_returns_infinite_cost(self):
        econ = QubitHourEconomics("TEST", qubit_count=100, wall_power_watts=1000.0, uptime_fraction=0.0)
        assert econ.cost_per_qubit_hour_eur() == float("inf")

    def test_default_uptime_is_full(self):
        econ = QubitHourEconomics("TEST", qubit_count=100, wall_power_watts=1000.0)
        assert econ.uptime_fraction == 1.0


if __name__ == "__main__":
    import sys
    sys.exit(pytest.main([__file__, "-v"]))
