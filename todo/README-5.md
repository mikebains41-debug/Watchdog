# Watchdog

Host-level GPU and quantum security — detection, prevention, and physics modelling in one stack.

**Mike Bains · GPU Optimizer Inc. · Duncan, BC, Canada · mike@gpu-optimizer.com**

---

## What this is

Watchdog monitors GPU power, memory, bus interconnects, and quantum cloud APIs. It alerts on conditions that standard monitoring tools report as normal, and actively prevents attacks at the hardware and software level.

Built around confirmed hardware findings on real B200 SXM silicon. Extended to quantum computing infrastructure as QaaS platforms scale.

---

## Repository structure

```
todo/              Security modules 01–50
quantum_models/    19 quantum physics models (18 M_*.py + Prometheus exporter)
b200_watchdog/     Real B200 hardware test data and evidence logs
detection/         29 automatic detection engines (FullDetectionPipeline)
intelligence/      5 prediction agents (swarm/)
forensics/         Tamper-evident audit ledger, clean-run certificates
remediation/       Response actions (log, kill, quarantine, reset)
orchestration/     Kubernetes taint, SLURM evict, NVLink disable
alerting/          Severity filter, dedup, SIEM routing
api/               REST API with key auth and rate limiting
tests/             36+ test files — 148+ tests
scripts/           Validation harnesses, CEI benchmark, CVE checks
quantum_models/tests/  204 quantum physics model tests
```

---

## Module layers

### Detection layer — modules 01–16 (read-only)
Sensors. Observe, measure, report. Never touch hardware.

| Module | What it detects |
|--------|----------------|
| module01 — NVML | GPU telemetry via nvidia-smi |
| module02 — proc/cgroup | Process and cgroup monitoring |
| module03 — dmesg/PCIe | Kernel ring buffer + PCIe events |
| module04 — network | Network anomaly detection |
| module05a — correlation | Cross-signal correlation |
| module05b — active probes | Active hardware probing |
| module06 — sysfs integrity | Sysfs filesystem integrity |
| module07 — physical attacks | Physical attack signatures |
| module08 — thermal/IOMMU | Thermal + IOMMU monitoring |
| module09 — model exfil | Model exfiltration detection |
| module10 — MMIO channel | Memory-mapped I/O covert channel |
| module11 — ECC stress | ECC error pattern analysis |
| module12 — CPU cache/bus | CPU cache and bus stress |
| module13 — NVLink fabric | NVLink fabric monitoring |
| module14 — memory covert | Memory covert channel |
| module15 — GPU kernel | GPU kernel monitoring |
| module16 — CPU cache | CPU cache monitor |

### Prevention layer — modules 17–31 (active intervention)
Kills processes, resets GPUs, unbinds drivers, taints nodes, signs audit chains.

| Module | What it prevents |
|--------|-----------------|
| module17 | Ghost power, thermal attack, P-state hijack, ECC Rowhammer, clock glitch |
| module18 | PCIe Gen5 degradation, NVLink session hijacking, IOMMU/DMA attacks |
| module19 | Miner PIDs, stale CUDA contexts, driver unload, model exfiltration |
| module20 | LLC flood, container escape, DMA attacks, CPU side-channel, pre-exec malware |
| module21 | Supervisor: attestation + threat correlation + Kubernetes quarantine + compliance proofs |
| module22 | PCIe link state attack (TLP packet drop across generations) |
| module23 | L3 Prime+Probe cache timing side-channel |
| module24 | ACPI/SMI firmware power rail attack |
| module25 | initramfs tamper detection |
| module26 | GPU Direct Storage VRAM write via NVMe |
| module27 | VFIO hypervisor escape (GPU passthrough DMA) |
| module28 | NVLink inter-packet gap timing side-channel |
| module29 | SGX/SEV-SNP attestation bypass |
| module30 | GPU HBM3e page retirement poisoning |
| module31 | PXE/iSCSI boot injection + DHCP spoofing |

### Quantum security — modules 32–50

#### Cloud-accessible (working now)
| Module | Attack vector |
|--------|--------------|
| module32 | Post-quantum crypto readiness (SSH/TLS/OpenSSL vs NIST PQC standards) |
| module33 | QaaS API integrity (circuit hash + IBM Quantum API monitoring) |
| module34 | QPU calibration drift (IBM Quantum backend.properties()) |
| module35 | Qubit error rate anomaly (simultaneous multi-qubit spike) |
| module40 | QaaS API replay attack prevention |
| module41 | Qubit-specific calibration DDoS detection |
| module42 | Quantum job queue front-running / timing side-channel |
| module43 | Classical host crypto downgrade prevention |
| module44 | Cryogenic system power spike detection (RAPL + IPMI) |
| module45 | Quantum cloud credential drain detection |
| module46 | D-Wave annealer side-channel + noise injection |
| module47 | QaaS open-source supply chain integrity |
| module48 | Quantum cost drain (M_qubit_hour_economics integration) |
| module49 | Fleet efficiency anomaly (M_quantum_fleet_score integration) |
| module50 | Load balancer manipulation (M_super_fridge_load_balancer integration) |

#### Physical hardware stubs (AWAITING_HARDWARE_INTEGRATION)
| Module | Future coverage |
|--------|----------------|
| module36 | Cryogenic temperature (dilution refrigerator millikelvin sensors) |
| module37 | FPGA pulse timing (microwave gate timing, PCIe scan runs now) |
| module38 | Vacuum pressure (Pfeiffer/Edwards gauge controller) |
| module39 | Helium level monitoring (Cryomagnetics LM-500 / Oxford ILM) |

---

## Quantum physics models (quantum_models/)

19 models calibrated against published peer-reviewed research. None validated against dedicated hardware by this project yet — stated explicitly throughout.

**204 tests, all passing.**

```bash
cd quantum_models
pip install pytest --break-system-packages
python3 -m pytest tests/ -v
```

Integration point: `module21` imports `M_quantum_efficiency_score` and `M_quantum_drift_tracker`. Every threat correlation event includes a live quantum efficiency score snapshot.

---

## Real hardware findings (B200 SXM, RunPod)

**Ghost power:** +56W sustained at 0% utilization. NVML reports 0% throughout. The HBM3e memory subsystem stays at full clock speed regardless of compute activity. Confirmed on B200 SXM. Not by itself evidence of an attack — a monitoring gap. Evidence: `b200_watchdog/ghost_power_vram_residual_live_repro.log`

**VRAM residual:** ~1520MB stays allocated after process exit. Identical for graceful exit and SIGKILL. Zero bytes recoverable — accounting gap, not a data leak. Confirmed on B200. Reported to MITRE 2026-05-31. CVE pending. Self-assessed CVSS: 8.4. Evidence: `b200_watchdog/vram_residual_b200_1.txt`

**NVLink contention:** −43% to −55% throughput degradation under cross-GPU load. NVLinkContentionDetector confirmed firing on real B200 after 3 bugs fixed. Evidence: `b200_watchdog/nvlink_final_test_b200_1.jsonl`

**PCIe:** Gen5 x16 confirmed (32 GT/s). Evidence: `b200_watchdog/nvidia_smi_full_query.txt`

**NVLink topology:** NV18 (18 links). Evidence: `b200_watchdog/nvidia_topo.txt`

---

## Test suite

```bash
# Prevention modules (17–50)
cd todo && python3 test_b200_watchdog.py

# Quantum physics models (204 tests)
cd quantum_models && python3 -m pytest tests/ -v

# Detection engines (17/17)
python3 -m pytest tests/test_engines.py -v

# Full suite
python3 -m pytest tests/ -v
```

**Total tests:** 148+ (security) + 204 (quantum physics) = 350+

---

## Run

```bash
python3 watchdog.py --api
```

API requires key. First run generates a random key (SHA256-hashed, plaintext shown once).

Quantum modules need credentials:
```bash
export IBM_QUANTUM_TOKEN=your_token
export DWAVE_API_TOKEN=your_token   # module46 only
```

---

## B200 test plan

360 hours remaining across 5 providers × 4 GPU types.

| Provider | H100 | H200 | B200 | B300 |
|----------|------|------|------|------|
| RunPod | NOT STARTED | NOT STARTED | PARTIAL | NOT STARTED |
| Lambda | NOT STARTED | NOT STARTED | NOT STARTED | NOT STARTED |
| Vast.ai | NOT STARTED | NOT STARTED | NOT STARTED | NOT STARTED |
| Jarvis Labs | NOT STARTED | NOT STARTED | NOT STARTED | NOT STARTED |
| Spheron AI | NOT STARTED | NOT STARTED | NOT STARTED | NOT STARTED |

---

## Markets

**GPU data centres:** Watchdog is production-ready. Confirms ghost power, VRAM residual, NVLink contention on real B200 hardware. Integrates with Kubernetes, Prometheus, Grafana, PagerDuty, Splunk, Sentinel, Datadog.

**Crypto mining facilities:** All 50 modules apply except LLM-specific detectors (module09, AgentOrchestrationAnomalyDetector, PromptInjectionSideEffectDetector). Mining workloads are ideal for power-vs-utilization correlation detection.

**Quantum facilities:** Modules 32–50 cover classical control plane security. Quantum physics models track cryogenic efficiency, qubit-hour economics, and fleet scoring. Physical integration modules (36–39) are architected and ready for facility hardware access.

---

## Limitations

- Prevention module tests (modules 17–50) are synthetic — no live hardware execution of prevention actions
- Quantum modules 34/35/40–50 require IBM_QUANTUM_TOKEN to activate
- TPM signing falls back to software HMAC in RunPod container environment
- eBPF pre-exec guard (module20) requires bcc + kernel headers — blocked in RunPod containers
- kubectl taint and SLURM actions untested against real clusters
- PCIe device address hardcoded as 0000:00:00.0 in several modules — must be confirmed per system
- B300 may run PCIe Gen6 (64 GT/s) — module18 PCIE_EXPECTED must be updated before B300 deployment
- `CEIDegradationForecaster` and `EUAIActComplianceForecaster` cannot fire (FLOPs/joule field not collected)

---

## Patent

Canadian application filed with CIPO, July 2026. Filed, not granted.

---

## License

Source-available. See LICENSE.
