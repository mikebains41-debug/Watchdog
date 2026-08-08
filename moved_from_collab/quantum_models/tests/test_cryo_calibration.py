#!/usr/bin/env python3
"""Tests for M_cryo_calibration.py"""
import pytest
from M_cryo_calibration import verdict, PUBLISHED_W_PER_QUBIT, IBM_QUBITS, IBM_FRIDGE_KW


class TestVerdict:
    def test_same_order_within_tenth_to_ten_times(self):
        assert verdict(1.0, 1.0) == "SAME ORDER"
        assert verdict(5.0, 1.0) == "SAME ORDER"  # 5x, within 10x
        assert verdict(0.5, 1.0) == "SAME ORDER"  # 0.5x, within 0.1x

    def test_model_high_above_ten_times(self):
        result = verdict(15.0, 1.0)
        assert "MODEL HIGH" in result
        assert "15.0" in result

    def test_model_low_below_one_tenth(self):
        result = verdict(0.05, 1.0)
        assert "MODEL LOW" in result

    def test_boundary_at_exactly_ten_times_is_same_order(self):
        assert verdict(10.0, 1.0) == "SAME ORDER"

    def test_boundary_at_exactly_one_tenth_is_same_order(self):
        assert verdict(0.1, 1.0) == "SAME ORDER"


class TestPublishedConstants:
    def test_published_w_per_qubit_matches_stated_reference(self):
        assert PUBLISHED_W_PER_QUBIT == pytest.approx(6.25, abs=1e-9)

    def test_ibm_qubits_matches_stated_reference(self):
        assert IBM_QUBITS == 4158

    def test_ibm_fridge_kw_matches_stated_reference(self):
        assert IBM_FRIDGE_KW == pytest.approx(26.0, abs=1e-9)


class TestDerivedIBMFigure:
    def test_ibm_derived_w_per_qubit_matches_manual_calc(self):
        derived = IBM_FRIDGE_KW * 1000 / IBM_QUBITS
        expected = 26000.0 / 4158
        assert derived == pytest.approx(expected, rel=1e-9)

    def test_ibm_derived_figure_is_same_order_as_published(self):
        """
        This is the core claim of this calibration module: IBM's real
        published fridge power / qubit count should land in the same
        order of magnitude as the independently published 6.25 W/qubit
        reference (arXiv:2304.14344).
        """
        derived = IBM_FRIDGE_KW * 1000 / IBM_QUBITS
        result = verdict(derived, PUBLISHED_W_PER_QUBIT)
        assert result == "SAME ORDER"


if __name__ == "__main__":
    import sys
    sys.exit(pytest.main([__file__, "-v"]))
