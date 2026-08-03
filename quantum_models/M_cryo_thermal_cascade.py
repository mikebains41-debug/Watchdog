#!/usr/bin/env python3
"""
M_cryo_thermal_cascade.py

Models power amplification through a dilution refrigerator's cooling cascade,
for GPU Optimizer's expansion into quantum computing infrastructure monitoring.

STATUS: AWAITING_HARDWARE_TEST
No live dilution refrigerator telemetry has been used to validate this model.
Stage temps and Carnot-limit math are derived from published physics and
public vendor specs (Bluefors, IBM Goldeneye). Treat outputs as theoretical
bounds, not measured values, until real cryostat sensor data is ingested.
"""

from dataclasses import dataclass, field
from typing import Optional


@dataclass
class CascadeStage:
    name: str
    temp_kelvin: float
    cooling_tech: str
    carnot_amplification_min: float = field(init=False)
    room_temp_kelvin: float = 300.0

    def __post_init__(self):
        if self.temp_kelvin <= 0:
            raise ValueError("Stage {}: temperature must be > 0K".format(self.name))
        self.carnot_amplification_min = (
            (self.room_temp_kelvin - self.temp_kelvin) / self.temp_kelvin
        )


DEFAULT_CASCADE = [
    CascadeStage("50K Stage (pulse tube 1st stage)", 50.0, "pulse_tube"),
    CascadeStage("4K Stage (pulse tube 2nd stage)", 4.0, "pulse_tube"),
    CascadeStage("Still (~0.7-1K)", 0.8, "dilution_still"),
    CascadeStage("Cold Plate (~100mK)", 0.1, "dilution_cold_plate"),
    CascadeStage("Mixing Chamber (~10-20mK)", 0.015, "dilution_mixing_chamber"),
]


@dataclass
class GhostLoadEstimate:
    stage: CascadeStage
    static_heat_leak_watts: Optional[float] = None
    active_control_load_watts: Optional[float] = None

    def total_room_temp_cost_watts(self):
        if self.static_heat_leak_watts is None:
            return None
        return self.static_heat_leak_watts * self.stage.carnot_amplification_min


def print_cascade_report(cascade=DEFAULT_CASCADE):
    print("=" * 78)
    print("CRYOGENIC THERMAL CASCADE - CARNOT-LIMITED POWER AMPLIFICATION")
    print("STATUS: AWAITING_HARDWARE_TEST (theoretical bounds only)")
    print("=" * 78)
    print("{:<40}{:>10}{:>28}".format("Stage", "Temp (K)", "Min W @300K per 1W removed"))
    print("-" * 78)
    for stage in cascade:
        print("{:<40}{:>10.4f}{:>28.1f}".format(
            stage.name, stage.temp_kelvin, stage.carnot_amplification_min
        ))
    print("-" * 78)
    last = cascade[-1]
    print(
        "Interpretation: removing 1W of heat at the mixing chamber (~{:.0f}mK) "
        "costs a THEORETICAL MINIMUM of {:.0f}W at room temperature - real "
        "systems draw substantially more due to non-ideal efficiency. This is "
        "the physical floor, not a measured value.".format(
            last.temp_kelvin * 1000, last.carnot_amplification_min
        )
    )
    print()
    print("NOTE: This mirrors the GPU 'ghost power' finding (146.66W at 0%")
    print("utilization) but the amplification here is orders of magnitude")
    print("larger because of the Carnot penalty at millikelvin temperatures.")
    print("A cryostat's static heat leak - present whether or not the")
    print("quantum processor is doing useful work - is the direct analog")
    print("to GPU idle floor power, just far more expensive to remove.")
    print()


def estimate_ghost_load_cost(static_heat_leak_watts=None, stage=None):
    if stage is None:
        stage = DEFAULT_CASCADE[-1]
    estimate = GhostLoadEstimate(stage=stage, static_heat_leak_watts=static_heat_leak_watts)
    cost = estimate.total_room_temp_cost_watts()

    print("-" * 78)
    print("Ghost load cost estimate - {}".format(stage.name))
    if cost is None:
        print("STATUS: AWAITING_HARDWARE_TEST")
        print("No static_heat_leak_watts value provided. Cannot estimate cost")
        print("without real cryostat telemetry - refusing to guess a number.")
    else:
        print("Static heat leak at stage: {:.4f} W".format(static_heat_leak_watts))
        print("Carnot-minimum room-temp cost to remove it: {:.1f} W".format(cost))
        print("(Real cost will be higher - this is the theoretical floor only.)")
    print("-" * 78)


if __name__ == "__main__":
    print_cascade_report()
    estimate_ghost_load_cost(static_heat_leak_watts=None)

    print()
    print("NEXT STEPS TO MOVE THIS OUT OF AWAITING_HARDWARE_TEST:")
    print("  1. Get real static heat leak measurements per stage from a")
    print("     live dilution refrigerator (vendor spec sheets often list")
    print("     total cooling power budget per stage - not the same as")
    print("     static leak, but a useful cross-check).")
    print("  2. Confirm actual stage temperatures for the specific unit")
    print("     being modeled (Bluefors, IBM Kide, etc. vary).")
    print("  3. Replace carnot_amplification_min-only outputs with measured")
    print("     wall-plug power draw per stage once available, same as the")
    print("     GPU work moved from theoretical curve to validated FP8 data.")
