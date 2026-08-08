#!/usr/bin/env python3
"""
Watchdog — Physics Bridge
Safe importer for quantum_models with deterministic fallbacks.
"""
import importlib
from typing import Any, Callable

def safe_import(attr_path: str, fallback: Any = None) -> Any:
    try:
        mod_path, attr = attr_path.rsplit(".", 1)
        mod = importlib.import_module(mod_path)
        return getattr(mod, attr)
    except Exception:
        return fallback

# Economics
cost_per_shot = safe_import(
    "quantum_models.M_qubit_hour_economics.cost_per_shot",
    lambda shots, qubits=1: shots * 0.001
)

# Thermal / cooling
cooling_power_per_qubit = safe_import(
    "quantum_models.M_cryo_thermal_cascade.cooling_power_per_qubit",
    0.05
)

# Fleet scoring
fleet_score = safe_import(
    "quantum_models.M_quantum_fleet_score.fleet_score",
    lambda *a, **k: 0.0
)

# Efficiency
quantum_efficiency = safe_import(
    "quantum_models.M_quantum_efficiency_score.efficiency_score",
    lambda *a, **k: 0.0
)
