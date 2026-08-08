#!/usr/bin/env python3
"""
M_qubit_scaling_curve.py

Combines the cascade Carnot-amplification model (M_cryo_thermal_cascade.py)
and the wiring heat leak model (M_wiring_heat_leak.py) to project how total
room-temperature input power scales as qubit count grows. This is the
"how expensive does this get as you scale" curve.

STATUS: AWAITING_HARDWARE_TEST
This is a composed model built on two other AWAITING_HARDWARE_TEST models.
Every number that comes out of this is at minimum two layers of
approximation removed from measured hardware. Treat the OUTPUT SHAPE
(power grows faster than linearly with qubit count) as the useful insight,
NOT any specific wattage figure, until both upstream models are validated
against real cryostat telemetry.
"""

from dataclasses import dataclass
from typing import List


ROOM_TEMP_KELVIN = 300.0
MIXING_CHAMBER_KELVIN = 0.015

def carnot_amplification_min(t_cold_kelvin: float, t_hot_kelvin: float = ROOM_TEMP_KELVIN) -> float:
    if t_cold_kelvin <= 0:
        raise ValueError("t_cold_kelvin must be > 0")
    return (t_hot_kelvin - t_cold_kelvin) / t_cold_kelvin


STAINLESS_INTEGRATED_K_W_PER_M = 0.30
LINES_PER_QUBIT_ESTIMATE = 3
WIRE_LENGTH_M = 1.5
WIRE_CROSS_SECTION_MM2 = 0.05

def wiring_heat_leak_watts(qubit_count: int) -> float:
    wires = qubit_count * LINES_PER_QUBIT_ESTIMATE
    per_wire_leak = (
        STAINLESS_INTEGRATED_K_W_PER_M
        * (WIRE_CROSS_SECTION_MM2 / 1.0)
        / WIRE_LENGTH_M
    )
    return per_wire_leak * wires


CONTROL_LOAD_PER_QUBIT_UW = 2.5


@dataclass
class ScalingPoint:
    qubit_count: int
    wiring_heat_leak_at_mc_watts: float
    control_load_at_mc_watts: float
    total_mc_heat_load_watts: float
    room_temp_power_cost_watts: float


def compute_scaling_curve(qubit_counts: List[int]) -> List[ScalingPoint]:
    amp = carnot_amplification_min(MIXING_CHAMBER_KELVIN)
    points = []
    for q in qubit_counts:
        wiring_leak = wiring_heat_leak_watts(q)
        control_load = (q * CONTROL_LOAD_PER_QUBIT_UW) * 1e-6
        total_mc_load = wiring_leak + control_load
        room_temp_cost = total_mc_load * amp
        points.append(ScalingPoint(
            qubit_count=q,
            wiring_heat_leak_at_mc_watts=wiring_leak,
            control_load_at_mc_watts=control_load,
            total_mc_heat_load_watts=total_mc_load,
            room_temp_power_cost_watts=room_temp_cost,
        ))
    return points


def print_scaling_report(points: List[ScalingPoint]):
    print("=" * 96)
    print("QUBIT COUNT vs PROJECTED ROOM-TEMPERATURE COOLING POWER")
    print("STATUS: AWAITING_HARDWARE_TEST - composed from two unvalidated models")
    print("=" * 96)
    print("{:<10}{:>18}{:>18}{:>18}{:>22}".format(
        "Qubits", "Wiring Leak (mW)", "Control Load (mW)", "Total @ MC (mW)", "Room-Temp Cost (W)"
    ))
    print("-" * 96)
    for p in points:
        print("{:<10}{:>18.3f}{:>18.3f}{:>18.3f}{:>22.1f}".format(
            p.qubit_count,
            p.wiring_heat_leak_at_mc_watts * 1000,
            p.control_load_at_mc_watts * 1000,
            p.total_mc_heat_load_watts * 1000,
            p.room_temp_power_cost_watts,
        ))
    print("-" * 96)
    print()
    print("KEY INSIGHT (shape, not absolute numbers): room-temperature power")
    print("cost scales roughly LINEARLY with qubit count in this simplified")
    print("model, because both wiring count and control load scale linearly")
    print("with qubits, multiplied by the FIXED Carnot penalty at the mixing")
    print("chamber. Real systems may deviate from linear due to multiplexing")
    print("(sharing control lines across qubits) or non-linear engineering")
    print("costs at scale - this model does not capture those effects.")
    print()


if __name__ == "__main__":
    qubit_counts = [10, 50, 100, 500, 1000, 5000]
    points = compute_scaling_curve(qubit_counts)
    print_scaling_report(points)

    print("NEXT STEPS TO MOVE THIS OUT OF AWAITING_HARDWARE_TEST:")
    print("  1. Validate M_cryo_thermal_cascade.py and M_wiring_heat_leak.py")
    print("     independently against real cryostat telemetry first - this")
    print("     model inherits every assumption from both.")
    print("  2. Get real control-load-per-qubit figures from an operating")
    print("     quantum system (varies significantly by architecture and")
    print("     by how much control-line multiplexing is used).")
    print("  3. Model multiplexing explicitly once real ratios are known -")
    print("     current model assumes a flat linear lines-per-qubit ratio,")
    print("     which likely overestimates wiring count at high qubit counts.")
