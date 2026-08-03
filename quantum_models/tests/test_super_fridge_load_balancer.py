#!/usr/bin/env python3
"""Tests for M_super_fridge_load_balancer.py"""
import pytest
from M_super_fridge_load_balancer import FridgeUnit, allocate_qubits_to_fridges


class TestFridgeUnit:
    def test_headroom_positive_when_under_capacity(self):
        f = FridgeUnit("F1", mixing_chamber_capacity_uW=400.0, qubit_capacity=100)
        f.allocated_heat_load_uW = 100.0
        assert f.headroom_uW() == pytest.approx(300.0, rel=1e-9)

    def test_is_over_capacity_false_when_under(self):
        f = FridgeUnit("F1", mixing_chamber_capacity_uW=400.0, qubit_capacity=100)
        f.allocated_heat_load_uW = 300.0
        assert f.is_over_capacity() is False

    def test_is_over_capacity_true_when_exceeded(self):
        f = FridgeUnit("F1", mixing_chamber_capacity_uW=400.0, qubit_capacity=100)
        f.allocated_heat_load_uW = 500.0
        assert f.is_over_capacity() is True

    def test_qubit_headroom(self):
        f = FridgeUnit("F1", mixing_chamber_capacity_uW=400.0, qubit_capacity=100)
        f.allocated_qubits = 40
        assert f.qubit_headroom() == 60


class TestAllocateQubitsToFridges:
    def test_allocation_within_single_fridge_capacity(self):
        fleet = [FridgeUnit("F1", 400.0, 100)]
        error = allocate_qubits_to_fridges(fleet, 50, heat_load_per_qubit_uW=2.5)
        assert error is None
        assert fleet[0].allocated_qubits == 50
        assert fleet[0].allocated_heat_load_uW == pytest.approx(125.0, rel=1e-9)

    def test_allocation_spills_to_second_fridge(self):
        fleet = [FridgeUnit("F1", 400.0, 100), FridgeUnit("F2", 400.0, 100)]
        error = allocate_qubits_to_fridges(fleet, 150, heat_load_per_qubit_uW=1.0)
        assert error is None
        assert fleet[0].allocated_qubits == 100
        assert fleet[1].allocated_qubits == 50

    def test_over_total_fleet_capacity_returns_error_message(self):
        fleet = [FridgeUnit("F1", 400.0, 100), FridgeUnit("F2", 400.0, 100)]
        error = allocate_qubits_to_fridges(fleet, 250, heat_load_per_qubit_uW=1.0)
        assert error is not None
        assert "OVER CAPACITY" in error
        assert "50" in error  # 250 requested - 200 capacity = 50 unallocated

    def test_exact_fleet_capacity_no_error(self):
        fleet = [FridgeUnit("F1", 400.0, 100), FridgeUnit("F2", 400.0, 100)]
        error = allocate_qubits_to_fridges(fleet, 200, heat_load_per_qubit_uW=1.0)
        assert error is None

    def test_zero_qubits_requested_allocates_nothing(self):
        fleet = [FridgeUnit("F1", 400.0, 100)]
        error = allocate_qubits_to_fridges(fleet, 0, heat_load_per_qubit_uW=1.0)
        assert error is None
        assert fleet[0].allocated_qubits == 0

    def test_allocation_fills_fridges_in_order(self):
        """Greedy fill-in-order behavior, explicitly documented in module."""
        fleet = [FridgeUnit("F1", 400.0, 50), FridgeUnit("F2", 400.0, 100)]
        allocate_qubits_to_fridges(fleet, 60, heat_load_per_qubit_uW=1.0)
        assert fleet[0].allocated_qubits == 50  # F1 fills first, to its cap
        assert fleet[1].allocated_qubits == 10  # remainder spills to F2


if __name__ == "__main__":
    import sys
    sys.exit(pytest.main([__file__, "-v"]))
