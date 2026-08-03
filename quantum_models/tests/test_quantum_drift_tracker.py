#!/usr/bin/env python3
"""Tests for M_quantum_drift_tracker.py"""
import pytest
from M_quantum_drift_tracker import DriftTracker, ScoreReading, DRIFT_WARNING_PCT, DRIFT_CRITICAL_PCT


class TestDriftTrackerBasics:
    def test_no_data_status_before_any_reading(self):
        tracker = DriftTracker(unit_id="TEST")
        assert tracker.status() == "NO_DATA"

    def test_first_reading_sets_baseline(self):
        tracker = DriftTracker(unit_id="TEST")
        tracker.add_reading(ScoreReading("t0", 80))
        assert tracker.baseline_score == 80

    def test_baseline_does_not_change_on_subsequent_readings(self):
        tracker = DriftTracker(unit_id="TEST")
        tracker.add_reading(ScoreReading("t0", 80))
        tracker.add_reading(ScoreReading("t1", 70))
        assert tracker.baseline_score == 80

    def test_history_accumulates_all_readings(self):
        tracker = DriftTracker(unit_id="TEST")
        tracker.add_reading(ScoreReading("t0", 80))
        tracker.add_reading(ScoreReading("t1", 70))
        assert len(tracker.history) == 2


class TestDriftPercentage:
    def test_no_drift_when_score_unchanged(self):
        tracker = DriftTracker(unit_id="TEST")
        tracker.add_reading(ScoreReading("t0", 80))
        tracker.add_reading(ScoreReading("t1", 80))
        assert tracker.current_drift_pct() == pytest.approx(0.0, abs=1e-9)

    def test_positive_drift_when_score_drops(self):
        tracker = DriftTracker(unit_id="TEST")
        tracker.add_reading(ScoreReading("t0", 100))
        tracker.add_reading(ScoreReading("t1", 80))
        assert tracker.current_drift_pct() == pytest.approx(20.0, rel=1e-9)

    def test_negative_drift_when_score_improves(self):
        tracker = DriftTracker(unit_id="TEST")
        tracker.add_reading(ScoreReading("t0", 80))
        tracker.add_reading(ScoreReading("t1", 100))
        assert tracker.current_drift_pct() == pytest.approx(-25.0, rel=1e-9)

    def test_zero_baseline_returns_none(self):
        tracker = DriftTracker(unit_id="TEST")
        tracker.add_reading(ScoreReading("t0", 0))
        assert tracker.current_drift_pct() is None


class TestStatusClassification:
    def test_stable_status_within_normal_range(self):
        tracker = DriftTracker(unit_id="TEST")
        tracker.add_reading(ScoreReading("t0", 100))
        tracker.add_reading(ScoreReading("t1", 95))
        assert tracker.status() == "STABLE"

    def test_warning_status_at_threshold(self):
        tracker = DriftTracker(unit_id="TEST")
        tracker.add_reading(ScoreReading("t0", 100))
        tracker.add_reading(ScoreReading("t1", 90))
        assert tracker.status() == "WARNING_DRIFT"

    def test_critical_status_at_threshold(self):
        tracker = DriftTracker(unit_id="TEST")
        tracker.add_reading(ScoreReading("t0", 100))
        tracker.add_reading(ScoreReading("t1", 80))
        assert tracker.status() == "CRITICAL_DRIFT"

    def test_improved_status_when_significantly_better(self):
        tracker = DriftTracker(unit_id="TEST")
        tracker.add_reading(ScoreReading("t0", 80))
        tracker.add_reading(ScoreReading("t1", 100))
        assert tracker.status() == "IMPROVED"


class TestTrendSlope:
    def test_none_with_fewer_than_two_readings(self):
        tracker = DriftTracker(unit_id="TEST")
        tracker.add_reading(ScoreReading("t0", 80))
        assert tracker.trend_slope() is None

    def test_negative_slope_for_declining_scores(self):
        tracker = DriftTracker(unit_id="TEST")
        for i, s in enumerate([100, 90, 80, 70]):
            tracker.add_reading(ScoreReading(f"t{i}", s))
        assert tracker.trend_slope() < 0

    def test_positive_slope_for_improving_scores(self):
        tracker = DriftTracker(unit_id="TEST")
        for i, s in enumerate([70, 80, 90, 100]):
            tracker.add_reading(ScoreReading(f"t{i}", s))
        assert tracker.trend_slope() > 0

    def test_zero_slope_for_constant_scores(self):
        tracker = DriftTracker(unit_id="TEST")
        for i in range(4):
            tracker.add_reading(ScoreReading(f"t{i}", 80))
        assert tracker.trend_slope() == pytest.approx(0.0, abs=1e-9)


class TestThresholdConstants:
    def test_critical_threshold_higher_than_warning(self):
        assert DRIFT_CRITICAL_PCT > DRIFT_WARNING_PCT


if __name__ == "__main__":
    import sys
    sys.exit(pytest.main([__file__, "-v"]))
