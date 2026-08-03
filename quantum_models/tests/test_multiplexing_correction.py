#!/usr/bin/env python3
"""Tests for M_multiplexing_correction.py"""
import pytest
from M_multiplexing_correction import effective_wire_count, total_effective_wires, LINE_TYPES


class TestEffectiveWireCount:
    def test_unknown_line_type_raises_value_error(self):
        with pytest.raises(ValueError):
            effective_wire_count(100, "not_a_real_line_type")

    def test_readout_divides_by_multiplexing_ratio(self):
        result = effective_wire_count(80, "readout")
        expected = 80 / 8.0  # 8x multiplexing ratio
        assert result == pytest.approx(expected, rel=1e-9)

    def test_drive_lines_not_multiplexed(self):
        """Drive lines have multiplexing ratio of 1.0, so should equal qubit count."""
        result = effective_wire_count(100, "drive")
        assert result == pytest.approx(100.0, rel=1e-9)

    def test_flux_bias_divides_by_two(self):
        result = effective_wire_count(100, "flux_bias")
        assert result == pytest.approx(50.0, rel=1e-9)

    def test_zero_qubits_gives_zero_wires(self):
        for line_type in LINE_TYPES:
            assert effective_wire_count(0, line_type) == pytest.approx(0.0, abs=1e-9)


class TestTotalEffectiveWires:
    def test_equals_sum_of_all_line_types(self):
        q = 100
        manual_total = sum(effective_wire_count(q, key) for key in LINE_TYPES)
        assert total_effective_wires(q) == pytest.approx(manual_total, rel=1e-9)

    def test_multiplexed_total_less_than_naive_linear_assumption(self):
        """Core thesis of this module: multiplexed total should be less than
        naive 3-wires-per-qubit assumption used elsewhere in the repo."""
        q = 1000
        naive = q * 3
        multiplexed_total = total_effective_wires(q)
        assert multiplexed_total < naive

    def test_readout_dominates_less_at_scale_due_to_multiplexing(self):
        """At high qubit counts, drive lines (unmultiplexed) should exceed
        readout lines (8x multiplexed) in the total wire count."""
        q = 1000
        readout = effective_wire_count(q, "readout")
        drive = effective_wire_count(q, "drive")
        assert drive > readout


class TestLineTypesReference:
    def test_three_line_types_defined(self):
        assert set(LINE_TYPES.keys()) == {"readout", "drive", "flux_bias"}

    def test_drive_has_lowest_multiplexing_ratio(self):
        drive_ratio = LINE_TYPES["drive"].typical_multiplexing_ratio
        for key, lt in LINE_TYPES.items():
            if key != "drive":
                assert drive_ratio <= lt.typical_multiplexing_ratio

    def test_readout_has_highest_multiplexing_ratio(self):
        readout_ratio = LINE_TYPES["readout"].typical_multiplexing_ratio
        for key, lt in LINE_TYPES.items():
            if key != "readout":
                assert readout_ratio >= lt.typical_multiplexing_ratio


if __name__ == "__main__":
    import sys
    sys.exit(pytest.main([__file__, "-v"]))
