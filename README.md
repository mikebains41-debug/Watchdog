# Watchdog

Host-level detection for GPU telemetry blind spots.

Mike Bains · GPU Optimizer Inc. · Duncan, BC, Canada
Contact: mike@gpu-optimizer.com

Run:   python3 watchdog.py --api
Test:  python3 tests/test_engines.py

---

## What this is

Watchdog monitors GPU power, memory, and per-process state, and alerts on
conditions that NVML and nvidia-smi report as normal.

It is built around two findings from our own hardware testing, both
reproduced across multiple architectures:

Ghost power — GPUs draw substantial power while NVML reports 0%
utilization. Observed across A100 SXM, H100, H200, and B200. The magnitude
tracks memory clock: the HBM subsystem stays at full speed regardless of
compute activity.

VRAM residual — 382MB to 1.6GB of GPU memory remains allocated and readable
after a process exits gracefully. SIGKILL reclaims it; a clean exit does
not. NVML reports 0% memory utilization throughout.

The VRAM residual finding was reported to MITRE on 2026-05-31.
No CVE has been assigned yet. Status: submitted, pending assignment.
Our self-assessed CVSS is 8.4; that score has not been reviewed by anyone else.

---

## Detection engines (4)

Each engine has a paired positive and negative control in
tests/test_engines.py. Current status: 17/17 passing.

- GhostPowerDetector: power over 15W above a learned idle floor at 0%
  utilization. Requires power.draw, utilization.gpu, memory.used.
  Severity WARNING, or CRITICAL above 50W delta.

- VRAMResidualDetector: memory still allocated after the owning PID exits.
  Requires per-process data via --query-compute-apps. Severity CRITICAL.

- PowerPeriodicityDetector: periodic structure in power draw, detected via
  autocorrelation. Requires power.draw. Severity WARNING.

- MultiGPUCorrelation: anomalies co-occurring across GPUs. Severity INFO
  only, not an attack signal.

Notes on what these engines deliberately do not claim:

PowerPeriodicityDetector reports that a periodic signal exists. It does
not attribute a cause. Periodicity is consistent with a covert channel
and equally consistent with a batched inference loop.

MultiGPUCorrelation is INFO, not an attack signal. Coordinated bursts
across GPUs are architectural behavior documented on A100 SXM and B200.

No CVSS score is attached to any engine. CVSS scores vulnerabilities, not
detectors: a detector has no attack vector, no privileges required, and no
scope. Scoring one is a category error.

---

## Testing methodology

Every engine has both controls:

Positive control — a synthetic pattern the engine must fire on.
Negative control — a state our research documents as normal, which the
engine must stay silent on.

The negative controls matter more. A positive control alone proves nothing:
feed a detector the exact pattern it is coded to trigger on and it will pass
whether or not the detector is correct. The negative controls here are drawn
from measured behavior:

Idle floor, normal jitter — 80.36W H200 (cert sa-29820c), 67W A100.
Cooldown tail after workload — 147.96W decaying (cert sa-b2f092).
Resident model, process alive — commonest state in inference serving.
Coordinated multi-GPU burst — architectural on A100 SXM / B200.

The headline number is the pipeline negative control: 3600 consecutive
clean idle samples produce 0 alerts. An always-firing detector is
indistinguishable from no detector.

Not yet run on live GPU hardware. Synthetic controls only. See Limitations.

---

## Field observations

On a Vast.ai H200 instance, June 2026:

Unpatched host kernel. The instance was running a kernel vulnerable to
CVE-2026-31431 ("Copy Fail"), a Linux kernel local privilege escalation
disclosed 2026-04-29 and listed in CISA KEV. This vulnerability is not our
finding — it is a widely known industry CVE. What we observed is that a
commercially rented GPU instance was still unpatched against it roughly two
months after public disclosure and vendor patches. We notified
security@vast.ai. The finding is the unpatched host, not the vulnerability.

Container overlay sanitization gap. Files belonging to a previous tenant,
17 days old, still present in the container filesystem. 5 independent
confirmations across separate instances. Contents were not inspected.

Noisy-neighbor degradation. Throughput dropped from 372.32 to 336.96
iter/sec under contention, -9.5%. Single measurement; not yet repeated.

None of these were visible to GPU-level telemetry.

---

## Independent validation

Serial Alice (Sirius GreenTech, Portugal) produced 15 blockchain-anchored
certificates on 2026-06-27 across NVIDIA H200, Intel TDX, and Phala Cloud.

The certificates are real and the anchoring is verifiable. They come with
caveats we state rather than let a reviewer discover:

Actual sampling in Test 4 was approximately 2Hz against a 100ms target.
average_power_w equals peak_power_w in two certificates, indicating idle
power was captured rather than workload power.
trust_score is 0.4: TEE attestation passed, signed_exporter failed.
One H200 hardware certificate carries a "Blackwell telemetry" warning.
The CVM has since been destroyed; those logs are unrecoverable.

---

## Limitations

Stated plainly, because a reviewer will find these anyway.

Absolute CEI is not reproducible. Across 30 runs, coefficient of variation
on absolute Compute Efficiency Index is approximately 20%. Point values from
any single run, including those in our certificates, should not be treated
as constants. Ratios between precisions appear more stable than absolutes
because same-session comparisons cancel common-mode noise, but this has not
been quantified. Do not rely on absolute CEI figures until this is fixed.

Sampling rate is not what it claims. The requested interval and the
achieved interval differ substantially under nvidia-smi subprocess polling.
The collector must log measured inter-sample deltas, not the requested rate.
Any figure not derived from measured deltas is unreliable.

No live-hardware validation of the engines. The 17 passing tests use
synthetic data. The engines have not been run against a real GPU. The
negative control in particular needs an hour on a clean idle H200 before
it means anything.

Container-only. RunPod and Vast.ai instances are Linux containers with GPU
passthrough, not bare metal. Persistence mode and power caps are blocked by
the hypervisor. Firmware attestation is not possible from this position.

Single operator, pre-revenue. No third-party security audit. No SOC2 or
ISO 27001 certification (in progress, not complete, see SECURITY.md).

Patent. Canadian application filed with CIPO, July 2026. Filed, not granted.

---

## Related

Public repo: https://github.com/mikebains41-debug/ai-gpu-energy-optimizer-

---

## License

Source-available. See LICENSE.
