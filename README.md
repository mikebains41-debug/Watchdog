# Watchdog AIDR v2.0
AI Infrastructure Detection and Response - Pure Security
Mike Bains | CVE-2048350 | Duncan BC Canada

Run: python3 watchdog.py --api --hz 100
Test: python3 watchdog.py --test

## Detection Engines (24 active)

### Base Engines (7)
Ghost power, VRAM residual, power side-channel, thermal emanation,
cross-tenant bleeding, timing covert channel, cross-workload clustering.

### Hardware Attack Engines (4)
Clock glitch, voltage glitch, DMA attack, laser injection.

### Memory Attack Engines (3)
Cache side-channel, MIG partition desync, sequential VRAM read.

### LLM / Agentic AI Engines (5)
- Inference power fingerprint — detects model substitution or adversarial
  input via power deviation from calibrated baseline during active inference.
- Agent orchestration anomaly — detects covert mining or model extraction
  when agent claims idle but GPU draws sustained high power.
- Prompt injection side-effects — detects adversarial prompts or jailbreak
  attempts via abnormal power spikes during inference.
- Agent session VRAM retention — detects proprietary data exposure after
  agentic AI session ends. Directly applies CVE-2048350 to drug discovery
  platforms (Aevom, Benchling, FutureHouse) where molecular data sits in
  VRAM post-session while NVML reports 0% utilization.
- Inter-agent handoff anomaly — detects compromised upstream agent passing
  malicious payload to downstream agent via power side-channel. Baselines
  normal handoff power transitions and fires CRITICAL on abnormal resume.

### Infrastructure Engines (3)
PCIe health, predictive failure (fan wear, capacitor aging, package cracking).

### Attestation (1)
Boot attestation — verifies GPU firmware integrity at session start.

## Architecture
agent/telemetry.py, detection/engines.py, detection/hardware_attacks.py,
detection/memory_attacks.py, detection/llm_attacks.py, detection/advanced.py,
detection/pcie_health.py, detection/predictive_failure.py, detection/attestation.py,
alerting/manager.py, api/server.py, forensics/timeline.py, forensics/compliance.py,
forensics/spectral.py, forensics/chain_of_custody.py, remediation/response.py

## CVE
CVE-2048350 filed 2026-05-31, MITRE, pending assignment.
PyTorch CUDA caching allocator retains VRAM after graceful process exit.
Affected: A100 SXM, H100 SXM, H200 SXM, B200 SXM.
Unaffected: T4, A100 PCIe, RTX 4090.
SIGKILL confirmed to clear VRAM to 0MB on A100 SXM.
