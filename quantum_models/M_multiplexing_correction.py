#!/usr/bin/env python3
"""
M_multiplexing_correction.py

Corrects the flat linear lines-per-qubit assumption in M_wiring_heat_leak.py
and M_qubit_scaling_curve.py. Real superconducting qubit systems share
readout lines across multiple qubits using frequency-domain multiplexing
(FDM), so wire count does NOT scale 1:1 with qubit count at large scale.

STATUS: AWAITING_HARDWARE_TEST
Multiplexing ratios below are common figures cited in superconducting qubit
literature (typically 4-10 qubits sharing one readout line via FDM), NOT
confirmed for any specific target system. Control lines (drive lines) are
generally NOT multiplexed as aggressively as readout lines - this model
treats them separately.
"""

from dataclasses import dataclass


@dataclass
class LineType:
    name: str
    lines_per_qubit_unmultiplexed: float
    typical_multiplexing_ratio: float
    notes: str


LINE_TYPES = {
    "readout": LineType(
        name="Readout lines",
        lines_per_qubit_unmultiplexed=1.0,
        typical_multiplexing_ratio=8.0,
        notes="FDM commonly shares one readout line across ~4-10 qubits.",
    ),
    "drive": LineType(
        name="Drive/control lines",
        lines_per_qubit_unmultiplexed=1.0,
        typical_multiplexing_ratio=1.0,
        notes="Drive lines are typically NOT multiplexed - each qubit needs its own.",
    ),
    "flux_bias": LineType(
        name="Flux bias lines",
        lines_per_qubit_unmultiplexed=1.0,
        typical_multiplexing_ratio=2.0,
        notes="Some architectures share flux bias lines in pairs - varies widely.",
    ),
}


def effective_wire_count(qubit_count: int, line_type_key: str) -> float:
    lt = LINE_TYPES.get(line_type_key)
    if lt is None:
        raise ValueError("Unknown line type: {}".format(line_type_key))
    return (qubit_count * lt.lines_per_qubit_unmultiplexed) / lt.typical_multiplexing_ratio


def total_effective_wires(qubit_count: int) -> float:
    return sum(effective_wire_count(qubit_count, key) for key in LINE_TYPES)


def print_comparison():
    print("=" * 90)
    print("MULTIPLEXING CORRECTION - EFFECTIVE WIRE COUNT VS NAIVE LINEAR ASSUMPTION")
    print("STATUS: AWAITING_HARDWARE_TEST (multiplexing ratios are literature estimates)")
    print("=" * 90)
    print("{:<12}{:>16}{:>16}{:>16}{:>16}".format(
        "Qubits", "Naive Wires", "Readout", "Drive", "Flux Bias"
    ))
    print("-" * 90)
    NAIVE_LINES_PER_QUBIT = 3
    for q in [10, 50, 100, 500, 1000, 5000]:
        naive = q * NAIVE_LINES_PER_QUBIT
        readout = effective_wire_count(q, "readout")
        drive = effective_wire_count(q, "drive")
        flux = effective_wire_count(q, "flux_bias")
        print("{:<12}{:>16.0f}{:>16.1f}{:>16.1f}{:>16.1f}".format(q, naive, readout, drive, flux))
    print("-" * 90)
    print("Naive model (M_wiring_heat_leak.py) assumes 3 wires per qubit with NO")
    print("sharing - likely overestimates wire count and therefore heat leak,")
    print("especially at high qubit counts where readout multiplexing matters most.")
    print("Drive lines dominate the corrected total since they are NOT multiplexed")
    print("in this model - confirm this against the real target architecture.")
    print()


if __name__ == "__main__":
    print_comparison()

    print("NEXT STEPS TO MOVE THIS OUT OF AWAITING_HARDWARE_TEST:")
    print("  1. Confirm actual multiplexing ratios for the target quantum")
    print("     architecture (varies significantly: superconducting vs")
    print("     trapped-ion vs neutral atom have very different wiring needs).")
    print("  2. Feed effective_wire_count() output into M_wiring_heat_leak.py")
    print("     in place of the flat wire_count = qubits * 3 assumption.")
    print("  3. Re-run M_qubit_scaling_curve.py with corrected wire counts to")
    print("     see how much the room-temp power projection changes.")
