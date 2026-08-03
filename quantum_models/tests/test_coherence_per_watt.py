#!/usr/bin/env python3
"""Tests for M_coherence_per_watt.py"""
import pytest
from M_coherence_per_watt import CoherenceEfficiency, REPRESENTATIVE_T1_MICROSECONDS


class TestCoherenceEfficiency:
    def test_zero_power_raises_value_error(self):
        ce = CoherenceEfficiency(qubit_count=1000, t1_microseconds=150.0, total_power_watts=0.0)
        with pytest.raises(ValueError):
            ce.coherent_qubit_seconds_per_watt()

    def test_negative_power_raises_value_error(self):
        ce = CoherenceEfficiency(qubit_count=1000, t1_microseconds=150.0, total_power_watts=-100.0)
        with pytest.raises(ValueError):
            ce.coherent_qubit_seconds_per_watt()

    def test_metric_scales_linearly_with_qubit_count(self):
        ce1 = CoherenceEfficiency(qubit_count=100, t1_microseconds=150.0, total_power_watts=1000.0)
        ce2 = CoherenceEfficiency(qubit_count=200, t1_microseconds=150.0, total_power_watts=1000.0)
        assert ce2.coherent_qubit_seconds_per_watt() == pytest.approx(
            2 * ce1.coherent_qubit_seconds_per_watt(), rel=1e-9
        )

    def test_metric_scales_linearly_with_t1(self):
        ce1 = CoherenceEfficiency(qubit_count=1000, t1_microseconds=100.0, total_power_watts=1000.0)
        ce2 = CoherenceEfficiency(qubit_count=1000, t1_microseconds=200.0, total_power_watts=1000.0)
        assert ce2.coherent_qubit_seconds_per_watt() == pytest.approx(
            2 * ce1.coherent_qubit_seconds_per_watt(), rel=1e-9
        )

    def test_metric_scales_inversely_with_power(self):
        ce1 = CoherenceEfficiency(qubit_count=1000, t1_microseconds=150.0, total_power_watts=1000.0)
        ce2 = CoherenceEfficiency(qubit_count=1000, t1_microseconds=150.0, total_power_watts=2000.0)
        assert ce2.coherent_qubit_seconds_per_watt() == pytest.approx(
            ce1.coherent_qubit_seconds_per_watt() / 2, rel=1e-9
        )

    def test_manual_calculation_matches(self):
        ce = CoherenceEfficiency(qubit_count=1000, t1_microseconds=150.0, total_power_watts=26000.0)
        expected = (1000 * 150.0 * 1e-6) / 26000.0
        assert ce.coherent_qubit_seconds_per_watt() == pytest.approx(expected, rel=1e-9)


class TestRepresentativeT1Values:
    def test_three_generations_present(self):
        expected = {"early_generation", "current_generation", "best_published"}
        assert expected == set(REPRESENTATIVE_T1_MICROSECONDS.keys())

    def test_t1_increases_across_generations(self):
        assert (
            REPRESENTATIVE_T1_MICROSECONDS["early_generation"]
            < REPRESENTATIVE_T1_MICROSECONDS["current_generation"]
            < REPRESENTATIVE_T1_MICROSECONDS["best_published"]
        )

    def test_better_t1_yields_better_coherence_per_watt(self):
        """Same qubit count and power, higher T1 should give a higher metric."""
        results = {}
        for gen, t1 in REPRESENTATIVE_T1_MICROSECONDS.items():
            ce = CoherenceEfficiency(qubit_count=1000, t1_microseconds=t1, total_power_watts=26000.0)
            results[gen] = ce.coherent_qubit_seconds_per_watt()
        assert results["early_generation"] < results["current_generation"] < results["best_published"]


if __name__ == "__main__":
    import sys
    sys.exit(pytest.main([__file__, "-v"]))
