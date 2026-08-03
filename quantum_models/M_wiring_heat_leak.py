#!/usr/bin/env python3
"""
M_wiring_heat_leak.py

Models parasitic heat leak conducted down signal wiring from room temperature
to the coldest stage of a dilution refrigerator. As qubit counts scale up,
wire count scales with them (each qubit needs control/readout lines), and
each wire is a physical heat-conduction path into the coldest, most
expensive-to-cool stage.

STATUS: AWAITING_HARDWARE_TEST
Thermal conductivity integral values below are simplified single-value
approximations pulled from published cryogenics engineering literature for
common wiring materials (stainless steel coax, phosphor bronze, NbTi
superconducting). Real designs use temperature-dependent integrals
(integral of k(T) dT from T_cold to T_hot) and real wire gauge/geometry
from the specific fridge wiring loom - treat these numbers as order-of-
magnitude estimates, not measured or vendor-confirmed values.
"""

from dataclasses import dataclass
from typing import Optional
import math


@dataclass
class WireMaterial:
    name: str
    integrated_k_4K_to_300K_W_per_m: float
    notes: str


MATERIALS = {
    "stainless_steel": WireMaterial(
        name="Stainless Steel (coax outer/inner conductor)",
        integrated_k_4K_to_300K_W_per_m=0.30,
        notes="Common choice for low heat leak; higher electrical loss than copper.",
    ),
    "phosphor_bronze": WireMaterial(
        name="Phosphor Bronze (twisted pair)",
        integrated_k_4K_to_300K_W_per_m=0.60,
        notes="Better conductivity than stainless, more heat leak; common compromise wire.",
    ),
    "copper": WireMaterial(
        name="Copper (high-conductivity, NOT typical for cold wiring)",
        integrated_k_4K_to_300K_W_per_m=4.50,
        notes="Excellent electrical conductor but conducts far too much heat for long cold runs.",
    ),
    "nbti_superconducting": WireMaterial(
        name="NbTi Superconducting Wire",
        integrated_k_4K_to_300K_W_per_m=0.05,
        notes="Near-zero resistive heating below Tc, but still has phonon-conduction heat leak.",
    ),
}


@dataclass
class WiringRun:
    material_key: str
    length_m: float
    cross_section_mm2: float
    wire_count: int

    def heat_leak_watts(self, t_hot_kelvin=300.0, t_cold_kelvin=0.015) -> Optional[float]:
        material = MATERIALS.get(self.material_key)
        if material is None:
            return None
        if self.length_m <= 0:
            raise ValueError("length_m must be > 0")
        if t_hot_kelvin <= t_cold_kelvin:
            raise ValueError("t_hot_kelvin must be > t_cold_kelvin")

        # The stored integrated_k value is calibrated for the standard
        # 4K-to-300K reference span (296K). Scale it linearly by the
        # actual requested temperature span as a first-order correction.
        # NOTE: this is a linear approximation of what is physically a
        # temperature-dependent integral of k(T) dT -- flagged here
        # explicitly rather than presented as exact.
        reference_span_kelvin = 300.0 - 4.0
        actual_span_kelvin = t_hot_kelvin - t_cold_kelvin
        span_scaling = actual_span_kelvin / reference_span_kelvin

        reference_cross_section_mm2 = 1.0
        per_wire_leak = (
            material.integrated_k_4K_to_300K_W_per_m
            * span_scaling
            * (self.cross_section_mm2 / reference_cross_section_mm2)
            / self.length_m
        )
        return per_wire_leak * self.wire_count


def print_material_reference():
    print("=" * 78)
    print("WIRING HEAT LEAK - MATERIAL REFERENCE (approximate, AWAITING_HARDWARE_TEST)")
    print("=" * 78)
    print("{:<45}{:>20}".format("Material", "Integrated k (W/m)"))
    print("-" * 78)
    for key, m in MATERIALS.items():
        print("{:<45}{:>20.3f}".format(m.name, m.integrated_k_4K_to_300K_W_per_m))
    print("-" * 78)
    print("Note: values approximate integral of k(T) dT from ~4K to 300K per")
    print("1 sq mm cross-section conductor. Real cryostat designs use staged")
    print("thermal anchoring at each cascade stage to intercept most of this")
    print("heat before it reaches the mixing chamber - this model does NOT")
    print("account for that anchoring and will overestimate raw heat leak")
    print("if used to model an anchored, real-world wiring loom.")
    print()


def print_scaling_example():
    print("=" * 78)
    print("EXAMPLE: HEAT LEAK VS QUBIT COUNT (illustrative wire counts only)")
    print("STATUS: AWAITING_HARDWARE_TEST - qubit-to-wire ratios below are")
    print("common industry rules of thumb (multiple lines per qubit for")
    print("control + readout), NOT confirmed against a specific real system.")
    print("=" * 78)

    LINES_PER_QUBIT_ESTIMATE = 3

    qubit_counts = [5, 50, 100, 500, 1000]
    length_m = 1.5
    cross_section_mm2 = 0.05

    print("{:<12}{:<12}{:>25}".format("Qubits", "Est. Wires", "Est. Heat Leak (mW, stainless)"))
    print("-" * 78)
    for q in qubit_counts:
        wires = q * LINES_PER_QUBIT_ESTIMATE
        run = WiringRun(
            material_key="stainless_steel",
            length_m=length_m,
            cross_section_mm2=cross_section_mm2,
            wire_count=wires,
        )
        leak_w = run.heat_leak_watts()
        print("{:<12}{:<12}{:>25.2f}".format(q, wires, leak_w * 1000))
    print("-" * 78)
    print("This is a ROUGH illustrative scaling shape, not a validated")
    print("prediction. Real heat leak per wire depends heavily on thermal")
    print("anchoring quality at intermediate stages, which is not modeled")
    print("here. Use this to see the SHAPE of the scaling problem, not to")
    print("quote an absolute number to anyone.")
    print()


if __name__ == "__main__":
    print_material_reference()
    print_scaling_example()

    print("NEXT STEPS TO MOVE THIS OUT OF AWAITING_HARDWARE_TEST:")
    print("  1. Get real integrated k(T) values from wire manufacturer specs")
    print("     or measured cryogenics literature for the exact wire gauge")
    print("     and material actually used in the target fridge.")
    print("  2. Confirm real lines-per-qubit ratio for the target quantum")
    print("     hardware architecture (varies significantly by platform).")
    print("  3. Add thermal anchoring effects - real designs intercept most")
    print("     conducted heat at intermediate stages (50K, 4K) before it")
    print("     reaches the mixing chamber; this model currently does not.")
