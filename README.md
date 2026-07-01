# Watchdog AIDR v2.0
**AI Infrastructure Detection and Response**

Mike Bains · CVE-2048350 · Duncan BC Canada
Run: python3 watchdog.py --api --hz 100
Test: python3 watchdog.py --test

---

## What Watchdog Does

Watchdog is a host and OS-level GPU security platform. It detects threat classes completely invisible to GPU-level telemetry tools including NVML and nvidia-smi.

In June 2026, Watchdog identified on a Vast.ai H200 instance:
- CVE-2026-31431 CVSS 7.8 — unpatched kernel, container escape via shared page cache — confirmed unpatched, responsible disclosure sent to security@vast.ai
- Container overlay sanitization gap — previous tenant files 17 days old still present — 5 independent confirmations, contents not inspected
- Noisy-neighbor performance degradation — baseline 372.32 iter/sec to 336.96 under contention, -9.5%

Neither finding was visible to GPU-level telemetry. Both required Watchdog host and OS-level detection.

---

## Detection Engines (24 active · 26/26 tests passing)

### Base Engines (7)
- GhostPowerDetector — detects sustained power draw at 0% reported utilization. Dynamic idle+8W threshold. Validated at 147.96W on H200, cert sa-b2f092. CVSS 6.8
- VRAMResidualDetector — detects VRAM retention after process exit. Detection basis for CVE-2048350 CVSS 8.4
- PowerSideChannelDetector — detects periodic power oscillation indicating workload fingerprinting by adjacent tenant. CVSS 5.9
- ThermalEmanationDetector — detects temperature oscillation at 0% utilization indicating thermal covert channel. CVSS 4.7
- CrossTenantBleedingDetector — detects power bleed patterns consistent with neighboring tenant workload inference. CVSS 7.5
- TimingCovertChannelDetector — detects regular timing patterns in power draw indicating deliberate covert signaling. CVSS 5.9
- CrossWorkloadClusteringDetector — correlates alerts across multiple GPUs to detect coordinated multi-GPU attacks. CVSS 9.3 CRITICAL

### Hardware Attack Engines (4)
- ClockGlitchDetector — detects sudden SM clock drops under active load indicating clock injection. CVSS 7.8
- VoltageGlitchDetector — detects rapid power drop from sustained high load indicating voltage fault injection. CVSS 8.2
- DMAAttackDetector — detects memory spike at 0% utilization indicating DMA bus attack. CVSS 9.6 CRITICAL
- LaserInjectionDetector — detects sudden thermal spike indicating physical laser fault injection. CVSS 7.1

### Memory Attack Engines (3)
- CacheSideChannelDetector — detects high memory utilization at low GPU utilization indicating L2 cache side-channel. CVSS 5.9
- MIGPartitionDesyncDetector — detects memory activity at 0% GPU utilization indicating MIG partition boundary violation. CVSS 7.5
- SequentialVRAMReadDetector — detects sequential memory read pattern at low utilization indicating bulk VRAM scraping. CVSS 9.0 CRITICAL

### LLM / Agentic AI Engines (5)
- InferencePowerFingerprintDetector — detects model substitution or adversarial input via power deviation from calibrated baseline during active inference. CVSS 7.7
- AgentOrchestrationAnomalyDetector — detects covert mining or model extraction when agent claims idle but GPU draws sustained high power. CVSS 8.8
- PromptInjectionSideEffectDetector — detects adversarial prompts or jailbreak attempts via abnormal power spikes during inference. CVSS 6.5
- AgentSessionVRAMRetentionDetector — detects proprietary data exposure after agentic AI session ends. Directly applies CVE-2048350 to drug discovery platforms where molecular data sits in VRAM post-session while NVML reports 0% utilization. CVSS 8.4
- InterAgentHandoffAnomalyDetector — detects compromised upstream agent passing malicious payload to downstream agent via power side-channel. CVSS 8.1

### Infrastructure Engines (4)
- PCIeHealthDetector — PCIe bus health anomaly detection
- FanWearDetector — predictive fan failure detection
- CapacitorAgingDetector — predictive capacitor failure detection
- PackageCrackingDetector — predictive physical package degradation detection

### Attestation (1)
- BootAttestation — verifies GPU firmware integrity at session start

---

## Response and Containment

### EBPFQuarantine
Container kill and cgroup freeze when critical engines fire. Requires root and Linux kernel >= 5.4.0.
- KILL_CONTAINER: DMA_ATTACK, SEQUENTIAL_VRAM_READ, MODEL_MUTATION
- FREEZE_CGROUP: CROSS_WORKLOAD_CLUSTER, MIG_PARTITION_DESYNC, CLOCK_GLITCH, VOLTAGE_GLITCH, SUPPLY_CHAIN_ANOMALY
- Safe fallback to SIGSTOP when unprivileged. auto_quarantine=False by default.
- Pre-deployment check: python3 detection/verify_ebpf_compat.py

### PrecisionAdvisor
Recommends FP32 to FP16 to BF16 to FP8 precision switches based on energy state.
- GHOST_POWER_DETECTED: high power at low utilization
- THERMAL_WARNING: temperature approaching limit
- HIGH_POWER_UNDER_LOAD: sustained >500W at >50% utilization
- CEI_DEGRADATION: compute energy intensity below baseline
- Integration point for external precision controllers. Power reduction estimates from Serial Alice cert sa-e6628d, marked as estimated.

### CUDA and NCCL Interception Hooks
LD_PRELOAD libraries for pre-execution kernel sandboxing.
- detection/cuda_hook/watchdog_hook.c: intercepts cudaLaunchKernel before hardware execution
- detection/cuda_hook/watchdog_nccl_hook.c: intercepts ncclAllReduce for gradient poisoning detection during distributed training. Detects NaN/Inf and variance anomalies.
- Compile: gcc -shared -fPIC -o libwatchdog_interceptor.so watchdog_hook.c -ldl
- Requires CUDA runtime. Test on GPU rental.

---

## Memory Security

- WatchdogWeightPinner: continuously hashes model weight VRAM regions and verifies against signed registry. Detects runtime model substitution or extraction. Uses process_vm_readv when privileged, file-based SHA256 fallback otherwise.
- WatchdogSHMProtector: locks POSIX /dev/shm model weight segments to read-only after loading via chmod 0o444 and chattr +i.
- WatchdogSysVProtector: attaches to System V IPC memory segments read-only and marks for deletion via IPC_RMID to prevent re-attachment.
- SharedMemoryOrphanCleaner: detects and unlinks dead /dev/shm segments from terminated container workloads via /proc/*/fd cross-reference. Runs every 10 minutes via Kubernetes CronJob.

---

## Alert Pipeline

Every alert passes through five stages:

1. CVSS enrichment: all 28 alert types mapped to CVSS v3.1 base scores (4.0 to 9.6), vectors, and rationale
2. Alert state management: OPEN/ACKNOWLEDGED/RESOLVED lifecycle, deduplication by type+GPU, auto-resolve after 300s
3. SIEM routing: PagerDuty Events API v2, Splunk HEC, Microsoft Sentinel Data Collector, Datadog Events API. Credential-gated via env vars.
4. Threat intelligence correlation: 7 IOC signatures over 300s sliding window. CVE-2048350 cross-referenced. Air-gapped bundle support.
5. Compliance evidence mapping: SOC2 Type II controls, EU AI Act articles, NIST AI RMF, NIST CSF 2.0 per alert type.

---

## Forensics and Compliance Evidence

- AuditLedger: SHA256-chained append-only tamper-evident log. Air-gapped. Supports SOC2 CC7.2 and ISO 27001 A.5.33 evidence requirements.
- AISafeHarborLedger: HMAC-SHA256 chained compliance event ledger with auditor proof bundle export.
- SafeHarborS3Exporter: automated export of proof bundles to AWS S3 or sovereign MinIO/Ceph. KMS encryption at rest.
- ComplianceReportGenerator: structured evidence reports mapping alerts to SOC2, EU AI Act, NIST AI RMF, NIST CSF 2.0 controls.
- AttackTimelineBuilder: chronological multi-GPU attack timeline with MITRE ATLAS kill chain mapping and propagation analysis.
- IOC Bundle System: signed offline IOC bundles for air-gapped deployments. SHA256 verified before loading.

All compliance outputs are evidence reports, not certifications. Formal SOC2 Type II or ISO 27001 certification requires an accredited third-party auditor.

---

## Cross-Cluster Swarm Intelligence

- Gossip Daemon (intelligence/gossip/src/lib.rs): Rust daemon broadcasting signed swarm vaccines across cluster nodes. Hybrid UDP/TCP. Ed25519 signed payloads. 50KB/s rate limiting. Byzantine fault tolerance with trust scoring. WD magic byte validation (0x5744). Kademlia P2P topology.
- SwarmVaccine Schema (intelligence/gossip/vaccine.capnp): Cap'n Proto zero-copy binary serialization. Maps all 24 engines, EBPFQuarantine actions, PrecisionAdvisor steps.
- AirGappedThreatIntel: extends ThreatIntelEngine with signed offline bundle loading. Falls back to 7 built-in IOC signatures.

---

## Deployment

### Kubernetes
    kubectl apply -f kubernetes/watchdog-cleanup-cronjob.yaml
    kubectl apply -f helm/watchdog-aidr/templates/namespace.yaml
    helm install watchdog-aidr ./helm/watchdog-aidr

### LD_PRELOAD injection into GPU workloads
    gcc -shared -fPIC -o libwatchdog_interceptor.so detection/cuda_hook/watchdog_hook.c -ldl
    export LD_PRELOAD=./libwatchdog_interceptor.so
    python3 your_inference_script.py

### Fleet deployment via Ansible
    ansible-playbook -i ansible/inventory.ini ansible/deploy_watchdog_fleet.yml

### eBPF compatibility check
    python3 detection/verify_ebpf_compat.py
    python3 detection/verify_ebpf_quarantine_core.py

---

## Architecture

    agent/telemetry.py
    detection/engines.py
    detection/hardware_attacks.py
    detection/memory_attacks.py
    detection/llm_attacks.py
    detection/advanced.py
    detection/pcie_health.py
    detection/predictive_failure.py
    detection/attestation.py
    detection/precision_advisor.py
    detection/ebpf_quarantine.py
    detection/weight_pinner.py
    detection/watchdog_shm_protector.py
    detection/watchdog_shm_cleaner.py
    detection/watchdog_sysv_protector.py
    detection/verify_ebpf_compat.py
    detection/verify_ebpf_quarantine_core.py
    detection/cuda_hook/watchdog_hook.c
    detection/cuda_hook/watchdog_nccl_hook.c
    alerting/manager.py
    alerting/state.py
    alerting/siem.py
    alerting/email_alerter.py
    api/server.py
    api/auth.py
    forensics/audit_ledger.py
    forensics/safe_harbor_ledger.py
    forensics/harbor_s3_exporter.py
    forensics/compliance_report.py
    forensics/compliance.py
    forensics/timeline.py
    forensics/ioc_bundle.py
    forensics/chain_of_custody.py
    forensics/spectral.py
    intelligence/threat_intel.py
    intelligence/threat_intel_airgap.py
    intelligence/gossip/src/lib.rs
    intelligence/gossip/vaccine.capnp
    intelligence/swarm/swarm_orchestrator.py
    remediation/response.py
    orchestration/cluster_actions.py
    kubernetes/watchdog-cleanup-cronjob.yaml
    kubernetes/watchdog-seccomp-profile.json
    helm/watchdog-aidr/
    ansible/deploy_watchdog_fleet.yml
    ci/verify_kubeconfig.sh
    ci/run_local_test_suite.sh

---

## CVE

CVE-2048350 — submitted to MITRE 2026-05-31, pending assignment.

PyTorch CUDA caching allocator retains VRAM contents after graceful process exit. NVML reports 0% memory utilization throughout. Data from one tenant is readable by the next tenant on shared GPU infrastructure.

- Affected: A100 SXM, H100 SXM, H200 SXM, B200 SXM, B300 SXM
- Unaffected: T4, A100 PCIe, RTX 4090
- SIGKILL confirmed to clear VRAM to 0MB on A100 SXM
- Cross-GPU isolation failure confirmed: GPU1 picked up 528MB residual data from GPU0 at 0% utilization on 2x H200. NVML blind throughout.
- CVSS: 8.4

Independent validation: 15 blockchain-anchored Serial Alice certificates, all overall_valid, on NVIDIA H200 inside Intel TDX confidential compute enclave. Verifiable at api.serialalice.pt with no account required.

---

## Serial Alice Independent Validation

Hardware: NVIDIA H200 · Intel TDX · Phala Cloud
Date: 2026-06-27 · 24h+ testing · 11,052 samples · 0 crashes · ±1.6% CEI reproducibility
Certificates: 15/15 overall_valid · Ed25519 + ML-DSA-65 + Merkle + Polygon

| Test | Certificate ID |
|------|---------------|
| M2 ghost detection | sa-29820cec7f404fcfb9b56ed15e1757ca |
| M3 DESYNC detection | sa-1270c86eacd64db6bf5f26a34fe1381f |
| M4 CEI FP32 | sa-8858266ebbda45ceb240db0fa122a554 |
| M6 sustained run | sa-b2f092b30e3c4196a8afbceffda266ee |
| M7 CEI FP16 | sa-b6d99f8d118543fdb136bf36872a9ad3 |
| M19 ghost accuracy | sa-6d9f9abf7bb64b9d9894b19338cf57d7 |
| M20 CEI accuracy | sa-9c90bff0f6ce4e4898ff5cc32407bfd2 |
| M20 H200 calibrated | sa-51e01f583e4b4505834f98df32448ae6 |
| SEC-AB isolation | sa-f47d9425a06b443ab3bb93d033276da0 |
| SEC-VRAM isolation | sa-2346aeedc75a464b974f5fc052ad2b56 |
| SEC-KILL isolation | sa-83c49247b7b94b5dbe77d2075031d37d |
| AGT-M4 TDX attested | sa-482d90ff89cd415e9b32ac68ef5759e5 |
| AGT-M7 TDX attested | sa-208f23496b324f22b8f1327028b612bf |
| FP8 precision ladder | sa-e6628d5cff38402da74d5343a0b17c03 |
| SA self-proof | sa-cb4f69809b524f1faaac37d5b51a20f4 |

Shared Polygon anchor (11 bridge certs): 0x28327b
Verify: https://api.serialalice.pt/v2/certificates/<id>/verify

---

## Watchdog Findings — Vast.ai H200 Instance 41986069 (June 2026)

| Finding | Severity | Status |
|---------|----------|--------|
| CVE-2026-31431 unpatched kernel — container escape via shared page cache | CRITICAL CVSS 7.8 | Responsible disclosure sent to security@vast.ai |
| Container overlay sanitization gap — previous tenant files 17 days old | MEDIUM | 5 independent confirmations, contents not inspected |
| Noisy-neighbor performance degradation -9.5% | LOW/MEDIUM | Documented |

Neither finding was visible to GPU-level telemetry. Both required Watchdog host and OS-level detection.

---

Manmohan Mike Bains · Independent GPU Security Researcher · Duncan BC Canada
mikebains41@gmail.com · CVE-2048350 CVSS 8.4
https://github.com/mikebains41-debug/ai-gpu-energy-optimizer-
