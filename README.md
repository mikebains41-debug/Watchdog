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

## Detection engines (22 automatic + 1 separate)

Four foundational engines, detailed below. Eighteen more were added since,
covering hardware attacks, memory attacks, LLM/agent attacks, PCIe health,
predictive failure, and boot attestation — listed by category further
down. All 22 run automatically on every telemetry sample via
FullDetectionPipeline. A 23rd, ThroughputContentionDetector, is wired
separately: it needs externally-reported workload throughput
(iterations/sec), which GPU telemetry alone cannot provide, so it is
reached via a dedicated /throughput API endpoint (calibrate then process
mode) rather than the per-sample loop. These are three separate code
paths — automatic pipeline, throughput endpoint, and the prediction layer
described further down — and conflating their counts would misstate what
runs automatically today.

Each of the original four has a paired positive and negative control in
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

### The eighteen additional engines

Hardware attacks (5) — ClockGlitchDetector, VoltageGlitchDetector,
DMAAttackDetector, LaserInjectionDetector, NVLinkContentionDetector. The
last is new: NVLink covert-channel and side-channel attacks are documented
in three papers (2023–2026), one demonstrating a real cross-VM attack on
GCP. No standard monitoring tool tracks NVLink at all. Stated in the
detector itself: the same signature also arises from legitimate
distributed-training synchronization traffic (all-reduce, all-gather), and
telemetry alone cannot tell the two apart. NVLink data is sampled via a
separate nvidia-smi subcommand (nvidia-smi nvlink -g <index> -gt d), not
the combined --query-gpu call the other fields use, and is deliberately
NOT called on every sample — the per-GPU subprocess cost at 100Hz has not
been measured on real hardware, so it is rate-limited by design pending
that measurement.

Memory attacks (3) — CacheSideChannelDetector, MIGPartitionDesyncDetector,
SequentialVRAMReadDetector.

LLM/agent attacks (5) — InferencePowerFingerprintDetector,
AgentOrchestrationAnomalyDetector, PromptInjectionSideEffectDetector,
AgentSessionVRAMRetentionDetector, InterAgentHandoffAnomalyDetector.

Predictive hardware failure (3) — FanWearDetector, CapacitorAgingDetector,
PackageCrackingDetector. Sustained-load heuristics (temperature, power
ripple, thermal delta thresholds), not physics models. Unvalidated on real
hardware, same as everything else in this list.

Infrastructure (2) — PCIeHealthDetector (checked every sample, link
generation/width downgrade vs. a learned baseline) and BootAttestation
(checked once, at the first sample after startup, not continuously —
hardware fingerprint hash mismatch since baseline, e.g. a firmware or
driver change).

None of the eighteen have live-hardware validation beyond the same
synthetic-control methodology described below for the original four.

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

Across the full repository: at least 36 test files, covering everything
described above plus the prediction layer and the remediation/alerting
fixes, all passing as of the last full run. All synthetic, all subject to
the same "positive control alone proves nothing" caveat above as
test_engines.py's own 17/17. Two files (test_metrics_alert_firing.py,
test_webhook_pipeline_delivery.py) require a running API server and skip
cleanly when one is not present, rather than reporting a false pass.

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
The check we use for this (matching the running kernel version string
against known-vulnerable ranges) is fragile by design: distributions
routinely backport security fixes without changing the version string, so
a host can show a vulnerable-looking version and already be patched, or
vice versa. A separate script checks live-patch tooling
(canonical-livepatch / kpatch) for exactly this reason, but the two are
not yet connected.

Container overlay sanitization gap. Files belonging to a previous tenant,
17 days old, still present in the container filesystem. 5 independent
confirmations across separate instances. Contents were not inspected.

Noisy-neighbor degradation. Throughput dropped from 372.32 to 336.96
iter/sec under contention, -9.5%. Single measurement; not yet repeated.
ThroughputContentionDetector (see above) was subsequently built to catch
this class of event; it has not been checked against a repeat of the
original measurement.

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

This validates the underlying findings — that ghost power and VRAM
residual are real, and measured at the figures above. It does not validate
Watchdog's own detection code: Serial Alice measured the phenomena
independently, using their own methodology on their own infrastructure,
and has not run any Watchdog detector directly.

---

## Prediction layer (not wired into the pipeline)

Every engine above is reactive — it reports a condition once underway.
Five additional agents (intelligence/swarm/) attempt prediction:
identifying leading indicators 30–60 seconds before an event, from
power/thermal/VRAM/compliance-metric trends rather than a single reading.
None are imported or instantiated anywhere in watchdog.py. They contribute
zero capability to a running Watchdog instance today.

Each was validated with randomized synthetic trials — fresh random noise
per trial, severity varied randomly per trial, not hand-scripted
demonstrations built to fire. Results (false positive rate on clean
trials / overall true positive rate / weakest severity tier):

GhostPowerPredictor — 0% / 96.5% / 89.4%
CEIDegradationForecaster — 0% / 68.0% / 9.1%
ThermalEventPredictor — 0.5% / 63.0% / 0%
TenantIsolationRiskScorer — 0% / 24.5% / 0%
EUAIActComplianceForecaster — 0% / 54.0% / 1.5%

TenantIsolationRiskScorer cannot function even if wired in: its risk score
depends on row['memory_access_timing_ms'], a field nothing in
agent/telemetry.py collects. It is also the weakest agent by a wide
margin.

This proves the scoring logic generalizes across randomized severity. It
does not prove any of these precursor patterns actually precede real
events on real hardware — that requires real, timestamped hardware data,
which does not exist for this project yet.

---

## Remediation

remediation/response.py maps certain alert types to response actions (log
only, kill a specific targeted process, quarantine a MIG partition, reset
GPU memory). Two real bugs were found and fixed here: a kill-process
action that killed every process on the GPU indiscriminately (no detector
supplies a specific PID, so it now refuses rather than guesses), and a
"clear VRAM" action that called torch.cuda.empty_cache() in Watchdog's own
process — which cannot affect memory held by a different, already-exited
process — and returned success regardless of whether anything happened.
Both are fixed: kill_process now requires and verifies a named PID or
refuses; VRAM_RESIDUAL's action is gpu_memory_reset, gated behind human
approval by default, since no automated path to reclaim orphaned VRAM
exists.

orchestration/cluster_actions.py adds three infrastructure actions —
kubernetes_taint, slurm_evict_job, nvlink_disable — wired in with the same
discipline: all three are gated behind human approval by default, and all
three refuse cleanly unless the alert supplies a specific target (node
name, job ID, link index respectively). No current alert type supplies any
of the three, so none of them fire yet even with human approval granted;
mapping alert types to these actions is a deliberate, separate decision
not yet made.

---

## Alerting

alerting/manager.py handles severity filtering and audit logging for every
alert; this is wired in and runs on every alert. Four additional modules
are imported in watchdog.py but never instantiated or called anywhere:
alerting/state.py (alert lifecycle and deduplication), alerting/siem.py
(PagerDuty/Splunk/Sentinel/Datadog routing — safe by design, each
integration no-ops without its own credential env var),
alerting/email_alerter.py, and intelligence/threat_intel.py. All four are
dead imports as of this writing — present, loaded, doing nothing.
email_alerter.py has one known bug independent of being wired in: it
hardcodes a reference to CVE-2048350 into every alert email regardless of
the alert's actual type.

intelligence/threat_intel.py additionally has a known problem in its own
data, not just its wiring: KNOWN_IOCS lists named attack campaigns with
invented attribution, dates, and CVSS scores, several referencing detector
alert types that do not exist anywhere in this codebase (e.g.
BOOT_ATTESTATION_FAIL, when the real type is ATTESTATION_FAILURE). Not
wired in, not shipped as-is, flagged here rather than fixed silently.

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
synthetic data, same as the rest of the repository's 36+ test files. The
engines have not been run against a real GPU. The negative control in
particular needs an hour on a clean idle H200 before it means anything.

Container-only. RunPod and Vast.ai instances are Linux containers with GPU
passthrough, not bare metal. Persistence mode and power caps are blocked by
the hypervisor. Firmware attestation is not possible from this position.

Single operator, pre-revenue. No third-party security audit. No SOC2 or
ISO 27001 certification (in progress, not complete, see SECURITY.md).

Patent. Canadian application filed with CIPO, July 2026. Filed, not granted.
A CMU-affiliated paper measuring the same broad ghost-power phenomenon was
published shortly before this filing, creating real prior-art exposure for
the patent's general claims. It does not affect the more specific
memory-clock mechanistic finding, or Watchdog's own detection capability,
which stand independently of the patent's outcome.

Prediction layer not wired in. See above. Contributes zero capability to a
running instance today, regardless of the per-agent numbers reported.

Alerting mostly not wired in. See above. Only alerting/manager.py runs
today; SIEM routing, alert deduplication, email alerts, and threat-intel
correlation are all present in the codebase and all inert.

---

## Related

Public repo: https://github.com/mikebains41-debug/ai-gpu-energy-optimizer-

---

## License

Source-available. See LICENSE.
