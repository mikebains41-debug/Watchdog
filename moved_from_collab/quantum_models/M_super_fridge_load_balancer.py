#!/usr/bin/env python3
"""
M_super_fridge_load_balancer.py

Models power/thermal load distribution across multiple dilution refrigerators
wired together into a "super fridge" system, as qubit counts scale beyond
what a single unit can cool. Direct structural port of the rack thermal
cascade logic (rack_thermal_model.py) - GPU rack positions -> fridge units.

STATUS: AWAITING_HARDWARE_TEST
Per-unit cooling capacity limits below are representative order-of-magnitude
figures from public vendor literature (Bluefors, IBM Goldeneye/Kide), not
confirmed specs for any specific deployed system. Use for illustrating the
shape of the scaling/allocation problem, not as a procurement or engineering
spec.
"""

from dataclasses import dataclass, field
from typing import List, Optional


@dataclass
class FridgeUnit:
    unit_id: str
    mixing_chamber_capacity_uW: float
    qubit_capacity: int
    allocated_qubits: int = 0
    allocated_heat_load_uW: float = 0.0

    def headroom_uW(self) -> float:
        return self.mixing_chamber_capacity_uW - self.allocated_heat_load_uW

    def is_over_capacity(self) -> bool:
        return self.allocated_heat_load_uW > self.mixing_chamber_capacity_uW

    def qubit_headroom(self) -> int:
        return self.qubit_capacity - self.allocated_qubits


def allocate_qubits_to_fridges(
    fridges: List[FridgeUnit],
    total_qubits: int,
    heat_load_per_qubit_uW: float,
) -> Optional[str]:
    remaining = total_qubits
    for fridge in fridges:
        take = min(remaining, fridge.qubit_capacity)
        fridge.allocated_qubits = take
        fridge.allocated_heat_load_uW = take * heat_load_per_qubit_uW
        remaining -= take
        if remaining <= 0:
            break

    if remaining > 0:
        return (
            "OVER CAPACITY: {} qubits could not be allocated - total fleet "
            "capacity is {} qubits across {} units. Add another fridge unit "
            "before scaling further.".format(
                remaining, sum(f.qubit_capacity for f in fridges), len(fridges)
            )
        )
    return None


def print_fleet_report(fridges: List[FridgeUnit]):
    print("=" * 88)
    print("SUPER FRIDGE FLEET - LOAD ALLOCATION REPORT")
    print("STATUS: AWAITING_HARDWARE_TEST (illustrative capacity figures)")
    print("=" * 88)
    print("{:<10}{:>14}{:>14}{:>16}{:>16}{:>14}".format(
        "Unit", "Qubit Cap", "Qubits On", "MC Cap (uW)", "MC Load (uW)", "Status"
    ))
    print("-" * 88)
    for f in fridges:
        status = "OVER LIMIT" if f.is_over_capacity() else "OK"
        print("{:<10}{:>14}{:>14}{:>16.1f}{:>16.1f}{:>14}".format(
            f.unit_id,
            f.qubit_capacity,
            f.allocated_qubits,
            f.mixing_chamber_capacity_uW,
            f.allocated_heat_load_uW,
            status,
        ))
    print("-" * 88)
    total_qubits = sum(f.allocated_qubits for f in fridges)
    total_capacity = sum(f.qubit_capacity for f in fridges)
    over_limit_units = [f.unit_id for f in fridges if f.is_over_capacity()]
    print("Total qubits allocated: {} / {} fleet capacity".format(total_qubits, total_capacity))
    if over_limit_units:
        print("WARNING: units over mixing-chamber capacity: {}".format(", ".join(over_limit_units)))
    else:
        print("All units within rated mixing-chamber cooling capacity.")
    print()


if __name__ == "__main__":
    fleet = [
        FridgeUnit(unit_id="FRIDGE-01", mixing_chamber_capacity_uW=400.0, qubit_capacity=100),
        FridgeUnit(unit_id="FRIDGE-02", mixing_chamber_capacity_uW=400.0, qubit_capacity=100),
        FridgeUnit(unit_id="FRIDGE-03", mixing_chamber_capacity_uW=600.0, qubit_capacity=150),
    ]

    HEAT_LOAD_PER_QUBIT_UW = 2.5

    scenarios = [150, 250, 400]
    for total_qubits in scenarios:
        print("SCENARIO: allocating {} qubits across {} fridge units".format(
            total_qubits, len(fleet)
        ))
        for f in fleet:
            f.allocated_qubits = 0
            f.allocated_heat_load_uW = 0.0

        error = allocate_qubits_to_fridges(fleet, total_qubits, HEAT_LOAD_PER_QUBIT_UW)
        print_fleet_report(fleet)
        if error:
            print(error)
            print()

    print("NEXT STEPS TO MOVE THIS OUT OF AWAITING_HARDWARE_TEST:")
    print("  1. Get real mixing-chamber cooling capacity from actual vendor")
    print("     spec sheets for the specific units being deployed.")
    print("  2. Measure real heat load per qubit (control + readout +")
    print("     conducted wiring heat) from a live system.")
    print("  3. Replace greedy fill-in-order allocation with a real")
    print("     optimization pass once cost-per-unit and inter-fridge")
    print("     wiring constraints are known - greedy is a placeholder.")
