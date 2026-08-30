# GPU Security Layer v2.0
PRIVATE - DO NOT DISTRIBUTE

Author: Manmohan (Mike) Bains
Contact: mikebains41@gmail.com
Project: GPU Energy Optimizer v2.0

## What This Does
Real-time GPU security monitoring.
Four detection layers:
1. Covert Channel Detection
2. VRAM Introspection
3. Unauthorized Compute Detection
4. Abnormal Draw Alerting

## Why This Matters
Proven: 146W ghost power at 0% util on A100.
P0 state locks, VRAM retention, covert compute.
This catches all of it in real time.

## Usage
Run via SSH on real NVIDIA GPU hardware only.
No pynvml required. Uses nvidia-smi.
python3 security_layer.py

## Output
security_scan_YYYYMMDD_HHMMSS.json

## Status
Security Layer v2.0: COMPLETE
Infrastructure Layer: COMPLETE

## License
Proprietary. All rights reserved.
2026 Manmohan Bains
