#!/usr/bin/env python3
"""
M_qubit_hour_economics.py

Cost-per-qubit-hour economics for quantum infrastructure, mirroring the
orbital LCOC ($/hr/GPU) figure already used elsewhere in GPU Optimizer.
Converts electricity + cooling overhead into a single dollar figure a
CFO can compare against alternative compute.

STATUS: AWAITING_HARDWARE_TEST
Electricity rates and facility overhead assumptions are illustrative -
same category as the orbital LCOC figures already flagged as "modeled,
not measured" in ORBITAL_README.md. This model inherits assumptions from
M_quantum_fleet_score.py and M_cryo_thermal_cascade.py.
"""

from dataclasses import dataclass


EU_ELECTRICITY_EUR_KWH = 0.25
USD_ELECTRICITY_KWH = 0.12


@dataclass
class QubitHourEconomics:
    unit_id: str
    qubit_count: int
    wall_power_watts: float
    uptime_fraction: float = 1.0

    def cost_per_qubit_hour_eur(self) -> float:
        if self.qubit_count <= 0:
            raise ValueError("qubit_count must be > 0")
        kwh_per_hour = self.wall_power_watts / 1000
        cost_per_hour_total = kwh_per_hour * EU_ELECTRICITY_EUR_KWH
        cost_per_qubit_hour = cost_per_hour_total / self.qubit_count
        return cost_per_qubit_hour / self.uptime_fraction if self.uptime_fraction > 0 else float("inf")

    def cost_per_qubit_hour_usd(self) -> float:
        if self.qubit_count <= 0:
            raise ValueError("qubit_count must be > 0")
        kwh_per_hour = self.wall_power_watts / 1000
        cost_per_hour_total = kwh_per_hour * USD_ELECTRICITY_KWH
        cost_per_qubit_hour = cost_per_hour_total / self.qubit_count
        return cost_per_qubit_hour / self.uptime_fraction if self.uptime_fraction > 0 else float("inf")


def print_fleet_economics():
    print("=" * 90)
    print("COST PER QUBIT-HOUR - QUANTUM INFRASTRUCTURE ECONOMICS")
    print("STATUS: AWAITING_HARDWARE_TEST (electricity rates real, wall power modeled)")
    print("=" * 90)

    fleet = [
        QubitHourEconomics("FRIDGE-01", 4158, 26000.0, uptime_fraction=0.95),
        QubitHourEconomics("FRIDGE-02", 4158, 28000.0, uptime_fraction=0.95),
        QubitHourEconomics("FRIDGE-03", 4158, 45000.0, uptime_fraction=0.90),
    ]

    print("{:<12}{:>10}{:>14}{:>14}{:>16}{:>16}".format(
        "Unit", "Qubits", "Wall (kW)", "Uptime", "EUR/qubit-hr", "USD/qubit-hr"
    ))
    print("-" * 90)
    total_qubits = 0
    total_cost_eur_per_hr = 0.0
    for unit in fleet:
        eur = unit.cost_per_qubit_hour_eur()
        usd = unit.cost_per_qubit_hour_usd()
        total_qubits += unit.qubit_count
        total_cost_eur_per_hr += eur * unit.qubit_count
        print("{:<12}{:>10}{:>14.1f}{:>14.0%}{:>16.5f}{:>16.5f}".format(
            unit.unit_id, unit.qubit_count, unit.wall_power_watts / 1000,
            unit.uptime_fraction, eur, usd
        ))
    print("-" * 90)
    fleet_avg_eur = total_cost_eur_per_hr / total_qubits
    print("Fleet-average cost: EUR {:.5f} per qubit-hour across {} qubits".format(
        fleet_avg_eur, total_qubits
    ))
    print()
    print("Annualized (24/7, no additional downtime beyond uptime_fraction):")
    annual_hours = 8760
    print("  Per qubit per year: EUR {:.2f}".format(fleet_avg_eur * annual_hours))
    print("  Fleet total per year: EUR {:,.0f}".format(fleet_avg_eur * annual_hours * total_qubits))
    print()


if __name__ == "__main__":
    print_fleet_economics()

    print("NEXT STEPS TO MOVE THIS OUT OF AWAITING_HARDWARE_TEST:")
    print("  1. Get real facility wall power per unit (not just cryostat power -")
    print("     control electronics, room cooling, and overhead all count).")
    print("  2. Get real uptime figures - calibration/maintenance downtime is")
    print("     significant for early quantum systems and directly inflates")
    print("     effective cost per qubit-hour.")
    print("  3. Compare against classical GPU $/hr figures already tracked in")
    print("     GPU Optimizer to give customers an apples-to-apples reference.")
