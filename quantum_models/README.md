# Watchdog — Quantum Models Layer

Physics and economics models for quantum computing infrastructure.
Originally from: github.com/mikebains41-debug/Gpu-quantum-Optimizer-

## Status
AWAITING_HARDWARE_TEST — all models calibrated against published,
peer-reviewed research. None validated against dedicated hardware
by this project yet.

## 204 tests, all passing
```
cd quantum_models && pip install pytest --break-system-packages
python3 -m pytest tests/ -v
```

## Layer architecture
```
Watchdog/
  todo/              ← Security modules 01-47 (detection + prevention + quantum security)
  quantum_models/    ← Physics models (this directory)
  b200_watchdog/     ← Real B200 hardware test data
  detection/         ← 32 automatic detection engines
```

## Integration point
M_quantum_prometheus_exporter.py feeds live metrics.
module21 (supervisor) correlates security events with physics anomalies.

## Models
| File | What it models | Calibration |
|------|---------------|-------------|
| M_coherence_per_watt.py | Coherence-normalized efficiency | Internal, AWAITING_HARDWARE_TEST |
| M_cryo_calibration.py | Cross-check vs IBM System Two | IBM specs + arXiv:2304.14344 |
| M_cryo_thermal_cascade.py | Carnot-limited power per cooling stage | Internal |
| M_quantum_drift_tracker.py | Efficiency degradation over time | Internal |
| M_quantum_efficiency_score.py | Composite 0-100 efficiency score | Internal |
| M_quantum_fleet_score.py | Fleet-level aggregated efficiency | Internal |
| M_quantum_otto_cycle_simulator.py | Otto-cycle heat engine efficiency | Uusnäkki et al., Nature Comms 17, 6054 (2026) |
| M_quantum_prometheus_exporter.py | Live Prometheus/Grafana metrics | — |
| M_qubit_hour_economics.py | Cost per qubit-hour | Internal |
| M_qubit_scaling_curve.py | Power cost vs qubit count | Internal |
| M_qubit_temperature_evolution.py | Temperature saturation trajectory | Uusnäkki et al., Nature Comms 17, 6054 (2026) |
| M_super_fridge_load_balancer.py | Multi-fridge qubit allocation | Internal |
| M_thermal_anchoring.py | Heat interception effectiveness | Internal (fixed 96x gap) |
| M_wiring_heat_leak.py | Parasitic wiring heat conduction | Internal (bug fixed) |
| M_multiplexing_correction.py | Readout-line sharing overhead | Internal |
| M_literature_comparison.py | Field headroom vs Otto cycle | Erdman & Noé, npj QI 8, 1 (2022) |
| M_absorption_refrigerator_comparison.py | Autonomous refrigeration vs Carnot | Aamir et al., Nature Physics 21, 318-323 (2025) |
| M_quasiparticle_heating_reference.py | Quasiparticle heating thresholds | Catelani & Basko, SciPost Phys. 6, 013 (2019) |
| M_device_parameter_validation.py | Device parameter plausibility | Uusnäkki et al. + aluminum-transmon literature |
