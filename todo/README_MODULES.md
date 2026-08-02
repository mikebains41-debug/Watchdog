# Watchdog Module List (1–16)

This file explains what each module does and what it detects.

---

**Module 1 — NVML / nvidia-smi**
Detects ghost power, pstate transitions, zero-syscall mining, thermal stress, and VRAM attribution issues.

**Module 2 — /proc + cgroup**
Detects host-memory sprawl, process lineage anomalies, cgroup limit violations, cron persistence, credential stores, and cgroup mismatches.

**Module 3 — dmesg + PCIe**
Detects XID errors, PCIe resets, degraded PCIe link speeds, and IOMMU/DMA errors.

**Module 4 — Network**
Detects outbound connections to known miner/C2 domains, suspicious ports, and registry pull rates.

**Module 5a — Correlation**
Correlates GPU power draw with CPU load to catch hidden kernels or telemetry tampering.

**Module 5b — Active Probes**
Allocates VRAM on-demand to scan for residual cross-tenant memory patterns.

**Module 6 — sysfs Integrity**
Monitors RAPL powercap state, CUDA library hashes, and ASLR configuration.

**Module 7 — Physical Attacks**
Detects rapid clock glitches and extreme power transients.

**Module 8 — Thermal & IOMMU**
Scans dmesg for CPU thermal throttle events and IOMMU/DMA remapping errors.

**Module 9 — Model Exfil & Compiler**
Detects high memory bandwidth + outbound traffic (possible model theft) and unauthorized compiler injection events.

**Module 10 — PCIe MMIO Channel**
Logs PCIe link state and flags drops that may indicate MMIO exfiltration.

**Module 11 — ECC Stress Patterns**
Tracks ECC error acceleration and memory clock desyncs to spot silicon-level stress.

**Module 12 — CPU Cache & Bus Stress**
Detects L3 cache thrashing, RAPL energy spikes with no compute, and core isolation violations.

**Module 13 — NVLink Fabric**
Detects unexpected NVLink state changes and extreme bandwidth spikes (possible cross-GPU exfil).

**Module 14 — Memory Covert Channel**
Detects synchronized CPU/GPU memory usage spikes that may indicate a cache-timing side-channel.

**Module 15 — GPU Driver & Kernel**
Monitors loaded kernel modules for GPU drivers and scans dmesg for GPU/kernel errors.

**Module 16 — CPU Cache Monitoring**
Uses perf to monitor LLC cache misses and TLB flushes; flags deviations >50% from baseline.

---

**Note:** All modules are detection-only and safe to run in a containerized environment. They do not modify hardware or perform remediation.
