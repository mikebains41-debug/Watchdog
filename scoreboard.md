# Watchdog provider benchmark -- scoreboard

PASS = provider did the right thing. FAIL = it did not. BLOCKED = platform prevented the check. Cell shows worst verdict across that provider's runs, with (matching/total).

Sources: 4 result file(s). Own-instance measurements only.

| Test | 7ff12d1760d2 | dfa5e32169cd | vastai |
|---|---|---|---|
| **Handover Hygiene** | | | |
| HH-01 Leftover Tenant Files | FAIL | FAIL | - |
| HH-02 VRAM Zeroed at Handover | - | - | PASS |
| HH-03 GPU Counter Reset | - | - | ERROR |
| HH-04 Live Context at Handover | - | - | FAIL |
| HH-05 GPU Reset Available | - | - | PASS |
| HH-06 Host RAM Scrubbed | - | - | PASS |
| HH-07 Shared Memory / IPC Residue | - | - | PASS |
| HH-08 GPU State at Handover | - | - | FAIL |
| HH-09 Disk & Log Residue | - | - | FAIL |
| HH-10 Network Trace Residue | - | - | PASS |
| HH-11 GPU Local-Memory Residue (LeftoverLocals class) | - | - | BLOCKED |
| **Host Security** | | | |
| HS-01 Kernel vs KEV | - | - | BLOCKED |
| HS-02 Container Escape Surface | - | - | FAIL |
| HS-03 Namespace Isolation | - | - | PASS |
| HS-04 Baked-in Credentials | - | - | FAIL |
| HS-05 Cloud Metadata Reachable | - | - | PASS |
| HS-06 Container Toolkit Version (NVIDIAScape) | - | - | BLOCKED |
| HS-07 Metadata IMDS Version | - | - | PASS |
| HS-08 Provider Agent Reachable | - | - | FAIL |
| HS-09 VBIOS / Firmware Integrity | - | - | BLOCKED |
| HS-10 Network Egress Openness | - | - | BLOCKED |
| **Billing Honesty** | | | |
| BH-01 VRAM Accounting Gap | - | - | - |
| BH-02 Ghost Power at Idle | - | - | - |
| BH-03 GPU Generation as Advertised | - | - | PASS |
| BH-04 Noisy-Neighbour Throughput Loss | - | - | - |
| **Side-Channel Exposure** | | | |
| SC-01 Co-Tenant Side-Channel Exposure (config only) | - | - | BLOCKED |
