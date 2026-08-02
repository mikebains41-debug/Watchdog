# Watchdog Module List (1–16)

Detector IDs below match `DETECTOR_REGISTRY.md` — the single source of truth.
Do not add a new detector without registering its ID there first.

**Module 1 — NVML / nvidia-smi**
D1 ghost power · D3 pstate transitions · D4 zero-syscall mining · D8 thermal stress · D71 GPU memory attribution.

**Module 2 — /proc + cgroup**
D10 host-memory sprawl · D11 process-lineage anomalies · D12 container resource limits · D13 cgroup I/O burst · D14 cron persistence · D15 credential-store access.

**Module 3 — dmesg + PCIe**
D70 XID errors · D32 PCIe resets · D37 degraded PCIe link speed.

**Module 4 — Network**
D74 outbound C2/miner domains · D75 suspicious mining ports · D50 registry pull events.

**Module 5a — Correlation**
D26 GPU power vs CPU load correlation (hidden kernel / telemetry tampering).

**Module 5b — Active Probes**
D51 VRAM residual scan (on-demand only).

**Module 6 — sysfs Integrity**
D48 RAPL disabled · D45 library hash capture (informational) · D38 ASLR disabled.

**Module 7 — Physical Attacks**
D72 clock glitch · D73 power brake transient.

**Module 8 — Thermal & IOMMU**
D64 CPU thermal throttle · D59 IOMMU/DMA error.

**Module 9 — Model Exfil & Compiler**
D80 model exfiltration (high mem bandwidth + outbound) · D81 unauthorized compiler injection.

**Module 10 — PCIe MMIO Channel**
D82 MMIO anomaly (PCIe link speed drop).

**Module 11 — ECC Stress Patterns**
D83 ECC error acceleration · D84 memory clock desync vs ECC surge.

**Module 12 — CPU Cache & Bus Stress**
D85 L3 cache thrashing · D86 RAPL spike with no compute. Also logs isolcpus configuration state as context (see module docstring for the known coverage gap on per-process isolation violations).

**Module 13 — NVLink Fabric**
D87 unexpected NVLink state change · D88 NVLink bandwidth spike (possible cross-GPU exfil).

**Module 14 — Memory Covert Channel**
D89 synchronized CPU/GPU memory usage spike.

**Module 15 — GPU Driver & Kernel**
D90 GPU driver unloaded · D91 GPU kernel error/fault.

**Module 16 — CPU Cache Monitoring**
D92 cache miss / TLB flush rate deviation from baseline.

---

**Note:** All modules are detection-only and safe to run in a containerized environment. They do not modify hardware or perform remediation.

**Run duration:** standardized to 120s across all timed-loop modules (previously ranged 120s–600s inconsistently, and Module 16 was double-sleeping — see CHANGELOG.md). Module 5b and Module 9 are single-pass, not loops.
