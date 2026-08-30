# T-28 Timing Attack — H200 NVL

**Date:** 2026-06-10
**Author:** Manmohan Mike Bains, GPU Optimizer Inc, Duncan BC Canada
**CVE:** 2048350
**Hardware:** NVIDIA H200 NVL 141GB
**Platform:** Phala Cloud Intel TDX CVM

## What This Test Proves

Three workload sizes run sequentially. Each leaves a unique VRAM residual fingerprint after graceful exit. An attacker sharing the same physical server can determine the previous tenant's workload size from VRAM residual alone — no privileged access required.

## Phases

| Phase | VRAM Loaded | Power Spike | VRAM Residual | GPU Util |
|---|---|---|---|---|
| Baseline | 0MB | 77W | 0MB | 0% |
| Workload 1 (small) | 721MB | 124W | 625MB | 0% |
| Workload 2 (medium) | 1009MB | 182W | 1009MB | 0% |
| Workload 3 (large) | 2161MB | 524W | 2161MB | 0% |

## Key Findings

- Ghost power delta: **+47W permanent** above baseline
- NVML reports **0% utilization** throughout all phases
- Each workload size produces **unique VRAM residual fingerprint**
- Attacker can build a workload size lookup table
- SIGKILL would prevent residual — graceful exit is the vulnerability

## Files

- `t28_raw.csv` — 273 rows 1Hz summary
- `t28_raw_20min_100hz.csv` — 215,232 rows 100Hz full dataset
- `t28_20min_100hz.py` — test script
- `t28_summary_20260610.txt` — human readable summary
- `t28_metrics_20260610.txt` — machine readable metrics
- `t28_evidence_20260610.txt` — evidence for CVE submission
