#!/usr/bin/env python3
"""
M_coherence_per_watt.py

Quantum equivalent of GPU Optimizer's CEI (FLOPs per joule). Power spent
keeping decohered qubits powered is wasted energy - this metric asks not
just "how much power" but "how much USEFUL coherent qubit-time did that
power buy."

STATUS: AWAITING_HARDWARE_TEST
T1 coherence times below are representative published figures for
superconducting qubits, NOT measured on any specific target system.
Real coherence varies significantly by qubit design, materials, and
fabrication quality - treat as illustrative order of magnitude only.
"""

from dataclasses import dataclass


REPRESENTATIVE_T1_MICROSECONDS = {
    "early_generation": 20.0,
    "current_generation": 150.0,
    "best_published": 500.0,
}


@dataclass
class CoherenceEfficiency:
    qubit_count: int
    t1_microseconds: float
    total_power_watts: float

    def coherent_qubit_seconds_per_watt(self) -> float:
        t1_seconds = self.t1_microseconds * 1e-6
        total_coherent_qubit_seconds = self.qubit_count * t1_seconds
        if self.total_power_watts <= 0:
            raise ValueError("total_power_watts must be > 0")
        return total_coherent_qubit_seconds / self.total_power_watts


def print_comparison():
    print("=" * 88)
    print("COHERENCE PER WATT - QUANTUM EQUIVALENT OF GPU CEI")
    print("STATUS: AWAITING_HARDWARE_TEST (T1 values are published literature figures)")
    print("=" * 88)
    print("{:<20}{:>14}{:>16}{:>18}{:>18}".format(
        "T1 Generation", "T1 (us)", "Qubits", "Power (kW)", "Coh.qubit-s/W"
    ))
    print("-" * 88)

    QUBIT_COUNT = 1000
    POWER_KW = 26.0

    for gen, t1 in REPRESENTATIVE_T1_MICROSECONDS.items():
        ce = CoherenceEfficiency(
            qubit_count=QUBIT_COUNT,
            t1_microseconds=t1,
            total_power_watts=POWER_KW * 1000,
        )
        cpw = ce.coherent_qubit_seconds_per_watt()
        print("{:<20}{:>14.1f}{:>16}{:>18.1f}{:>18.6f}".format(gen, t1, QUBIT_COUNT, POWER_KW, cpw))
    print("-" * 88)
    print("KEY INSIGHT: a system can look power-efficient on watts-per-qubit")
    print("alone while actually being coherence-inefficient if T1 is short -")
    print("power is being spent maintaining qubits that don't stay useful long")
    print("enough to do meaningful computation. This metric exposes that gap.")
    print()
    print("This does NOT replace watts-per-qubit or the Carnot cascade cost -")
    print("it's a complementary metric, same way CEI complements raw wattage")
    print("in the GPU product: both power AND usefulness-per-power matter.")
    print()


if __name__ == "__main__":
    print_comparison()

    print("NEXT STEPS TO MOVE THIS OUT OF AWAITING_HARDWARE_TEST:")
    print("  1. Get real T1 (and ideally T2) coherence measurements from the")
    print("     target quantum system - varies significantly by qubit design.")
    print("  2. Confirm whether gate fidelity should factor in alongside raw")
    print("     T1 - a qubit can stay coherent but still execute noisy gates.")
    print("  3. Decide whether this metric should be tracked per-shot (live)")
    print("     or as a system-level snapshot figure for reporting.")
