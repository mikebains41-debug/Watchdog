# Watchdog AIDR v1.5
AI Infrastructure Detection and Response - Pure Security
Mike Bains | CVE 2048350 | Duncan BC Canada

Run: python3 watchdog.py --api --hz 100
Test: python3 watchdog.py --test

16 detection engines covering ghost power, VRAM residual, power side-channel,
thermal emanation, cross-tenant bleeding, timing covert channel, cross-workload
clustering, clock glitch, voltage glitch, DMA attack, laser injection, cache
side-channel, MIG partition desync, sequential VRAM read, inference power
fingerprint, agent orchestration anomaly, and prompt injection side-effects.

Architecture: agent/telemetry.py, detection/engines.py, detection/hardware_attacks.py,
detection/memory_attacks.py, detection/llm_attacks.py, detection/advanced.py,
alerting/manager.py, api/server.py, forensics/timeline.py, forensics/compliance.py,
forensics/spectral.py, forensics/chain_of_custody.py, remediation/response.py

CVE 2048350 filed 2026-05-31, MITRE, pending assignment.
