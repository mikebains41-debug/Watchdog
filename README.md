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
utilization. Confirmed on A100 SXM (146.66W), H200 SXM (598.41W peak,
99.9% of cooldown samples), B200 SXM (233W, from cold boot with no
workload), and B300 SXM6 (244W, never recovers). H100 SXM is the negative
control: none detected, which is what confirms the detector does not
false-positive. See EVIDENCE.md. The magnitude
tracks memory clock: the HBM subsystem stays at full speed regardless of
compute activity. This is normal HBM power behavior, surfaced here as a monitoring gap -- not, by itself, evidence of an attack. See Limitations for what has and has not been validated on real hardware.

VRAM residual — GPU memory remains reported as allocated after a process
exits. Measured on H200: memory.used ran at 773MB during an FP32 workload,
dropped to 527MB after exit, and stayed there. NVML reports 0% memory
utilization throughout.

It is an accounting residual, not a data leak. Two tests wrote a known
pattern into 256MB, ended the owning process (gracefully in one, by
SIGKILL in the other), then allocated a fresh buffer and read it for 240
seconds. Both returned zero pattern matches and zero nonzero bytes,
sustained. Nothing recoverable by either path.

Whether SIGKILL clears the accounting is now established. The two tests above
each allocate a 256MB buffer to perform their read, so their own memory figures
include the instrument and could not answer it. scripts/sigkill_residual_measure.py
was written to answer it directly -- it allocates nothing on the GPU and reads
only memory.used. On 4x H200 (RunPod, driver 570.124.06, 2026-09-19): a child
process allocated 2048MB, was killed, and the residual measured 0.0MB
immediately and throughout a 90-second watch. SIGTERM produced the identical
result over 60 seconds. On this platform the accounting clears completely on
process exit by either path.

Related and distinct: while a process remains alive, the CUDA caching allocator
holds its pool indefinitely. 620MB stayed flat across a full 30-minute watch
(0s / 60s / 300s / 900s / 1800s), with power settled at ~126W. The behaviour is
binary rather than decaying -- held while the process lives, released completely
on exit, with no time-based middle state.

The VRAM residual finding was reported to MITRE on 2026-05-31.
No CVE has been assigned yet. Status: submitted, pending assignment.
No CVSS score is attached to this finding. An earlier self-assessed 8.4 was
published before the data-recovery tests were run; it has been withdrawn, for
the same reason no CVSS score is attached to any engine below -- CVSS scores
vulnerabilities, and an accounting gap with no demonstrated confidentiality
impact is not one.

---

## Detection engines (41 automatic + 2 separate)

Four foundational engines, detailed below. Twenty-five more were added
since, covering hardware attacks, memory attacks, LLM/agent attacks, PCIe
health, predictive failure, boot attestation, business/fleet signals, and
hardware/firmware integrity — listed by category further down. They run
automatically on every telemetry sample via FullDetectionPipeline (30 engines
total; `total_engine_count` returns 30). Two more
are wired separately, because each needs data GPU telemetry alone cannot
provide: ThroughputContentionDetector needs externally-reported workload
throughput (iterations/sec), reached via a dedicated /throughput API
endpoint (calibrate then process mode); HashrateCorrelationDetector needs
externally-supplied pool hashrate and the power reading it should be
correlated against, reached via its own /hashrate endpoint, same
calibrate/process pattern. These are separate code paths from the
automatic pipeline and from the prediction layer described further down —
conflating their counts would misstate what runs automatically today.

Each of the original four has a paired positive and negative control in
tests/test_engines.py. Current status: 17/17 passing.

- GhostPowerDetector: power over 15W above a learned idle floor at 0%
  utilization. Requires power.draw, utilization.gpu, memory.used.
  Severity WARNING, or CRITICAL above 50W delta.

- VRAMResidualDetector: memory still allocated after the owning PID exits.
  Requires per-process data via --query-compute-apps. Severity CRITICAL.

- PowerPeriodicityDetector: periodic structure in power draw, detected via
  autocorrelation. Requires power.draw. Severity WARNING.

- ResidentGhostPowerDetector: ghost power on a GPU with a model loaded --
  learns each GPU's own loaded-idle floor and flags sustained power far
  above it at 0% utilization. Added 2026-09-21 to catch ghost power in
  inference serving, where a resident model means the cold-idle floor never
  applies. Severity WARNING, CRITICAL above 150W delta.

- MultiGPUCorrelation: anomalies co-occurring across GPUs. Severity INFO
  only, not an attack signal. Counted among the additional engines, not the
  four foundational.

Notes on what these engines deliberately do not claim:

PowerPeriodicityDetector reports that a periodic signal exists. It does
not attribute a cause. Periodicity is consistent with a covert channel
and equally consistent with a batched inference loop.

MultiGPUCorrelation is INFO, not an attack signal. Coordinated bursts
across GPUs are architectural behavior documented on A100 SXM and B200.

No CVSS score is attached to any engine. CVSS scores vulnerabilities, not
detectors: a detector has no attack vector, no privileges required, and no
scope. Scoring one is a category error.

### The twenty-five additional engines

Hardware attacks (5) — ClockGlitchDetector, VoltageGlitchDetector,
DMAAttackDetector, LaserInjectionDetector, NVLinkContentionDetector. The
last: NVLink covert-channel and side-channel attacks are documented in
three papers (2023–2026), one demonstrating a real cross-VM attack on
GCP. No standard monitoring tool tracks NVLink at all. Stated in the
detector itself: the same signature also arises from legitimate
distributed-training synchronization traffic (all-reduce, all-gather), and
telemetry alone cannot tell the two apart. NVLink data collection (agent/telemetry.py's sample_nvlink()) now
includes a per-link breakdown, not just combined totals, and is wired
into TelemetryCollector's live loop on a deliberately separate, slower
cadence than the main sample rate -- sample_nvlink() spawns a subprocess
per GPU, so calling it every sample would add exactly the cost its own
docstring warns about and would degrade the achieved rate
DeltaTimedSampler exists to honestly measure. It refreshes at most once
per nvlink_interval_s (default 5s), with cached values merged into every
row in between; measured at 2 subprocess calls per 1000 samples at 100Hz
rather than 1000. It is OFF by default (nvlink_enabled=False) so no
existing deployment silently changes behavior. When disabled, rows carry
no NVLink keys at all, keeping "no NVLink hardware" and "NVLink not
sampled" distinguishable rather than conflating them into a fabricated
zero. NVLinkContentionDetector therefore has a real path to firing when
sampling is enabled, and now attributes a best-effort link_index on its
alerts; both the parsing and the detector remain unvalidated against
real NVLink hardware.

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

Business/fleet signals (5) — CovertMiningDetector (sustained flat
near-TDP utilization consistent with unattended mining; explicitly cannot
determine authorization), BillingIntegrityDetector (power draw during
NVML-reported idle that would be billed as zero-utilization time; never
invents a dollar figure without an operator-supplied rate),
PowerLimitTamperDetector (power.limit changes against a learned baseline,
optional operator allowlist), PStateHonestyDetector and
PCIeBandwidthMismatchDetector (both check whether NVML's own reported
fields are internally consistent — the same "telemetry lies to itself"
pattern the ghost-power and VRAM-residual findings are built around,
applied to two more fields).

Hardware/firmware integrity (2) — ECCErrorTrendDetector (watches this
GPU's own real ECC error counters; the correct, non-exploit way to gain
visibility into GPU-driven Rowhammer-class memory disturbance research —
GPUHammer, USENIX Security 2025 — replacing an earlier detector that
claimed Rowhammer detection but could not structurally deliver it, see
Engineering notes below) and VBIOSIntegrityDetector (tracks this GPU's
VBIOS version string for changes; no external known-good baseline exists,
so this detects change from whatever was first observed, not confirmation
that a change was malicious).

None of the twenty-five have live-hardware validation beyond the same
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

The prediction layer (below) has its own, separate non-circular validation
harnesses — scripts/validate_swarm_prediction.py (Ghost Power Predictor)
and scripts/validate_swarm_prediction_agents2to5.py (the remaining four) —
which generate randomized trials at runtime rather than replaying a fixed
dataset, specifically so a detector cannot pass by matching a known input.
Both harnesses have their own tests (tests/test_validate_swarm_prediction.py)
proving the scoring math itself is correct, independent of whether any real
agent performs well, using injectable fake agents with known behavior.

Across the full repository: at least 36 test files, covering everything
described above plus the prediction layer and the remediation/alerting
fixes, all passing as of the last full run (confirmed via
tests/attack_injection_suite.py running all real positive-control modules
together: 36/36). All synthetic, all subject to the same "positive control
alone proves nothing" caveat above as test_engines.py's own 17/17. Two
files (test_metrics_alert_firing.py, test_webhook_pipeline_delivery.py)
require a running API server and skip cleanly when one is not present,
rather than reporting a false pass.

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
vice versa. scripts/check_copyfail_afalg.py adds a second, independent
check for this same CVE — it directly tests whether the AF_ALG
socket-creation attack path is reachable right now, per Microsoft's own
published mitigation guidance, regardless of what the kernel version
string claims. Neither check alone is complete; both include a runtime
warning when run on an unsuitable environment (e.g. a phone rather than a
rented server), after an early version returned a technically-true but
practically meaningless result on exactly that mismatch.

A second, independent kernel vulnerability was separately identified:
CVE-2026-64600 ("RefluXFS"), an XFS filesystem race condition disclosed
by Qualys, affecting kernels with reflink-enabled XFS.
scripts/check_refluxfs_exposure.sh checks exposure to this CVE, with the
same environment-mismatch warning.

Container overlay sanitization gap. Files belonging to a previous tenant,
16 days old, still present in the container filesystem. 5 independent
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

## Prediction layer

Every reactive engine above reports a condition once underway. Five
additional agents (intelligence/swarm/) attempt prediction: identifying
leading indicators 30–60 seconds before an event, from power/thermal/
VRAM/compliance-metric trends rather than a single reading.

As of this writing, the prediction layer is wired into the live pipeline —
previously tested code that contributed nothing to a running instance. A
telemetry adapter (intelligence/swarm/telemetry_adapter.py) translates real
nvidia-smi fields to what each agent expects. Real, per-agent status,
discovered by building that translation rather than assumed:

Fully functional — GhostPowerPredictor and ThermalEventPredictor. Every
field either needs (power draw, utilization, memory clock, SM clock,
temperature) is real, already-collected telemetry. Confirmed by forcing a
genuine precursor pattern through the full live pipeline and observing a
correct prediction fire.

Wired but permanently degraded — TenantIsolationRiskScorer. One of its
four weighted signals depends on row['memory_access_timing_ms'], a field
nothing in agent/telemetry.py collects. It does not crash — the missing
signal safely computes to zero — but real-world performance is likely
below its already-modest validated 24.5%. It remains the weakest agent by
a wide margin.

Wired but structurally, permanently silent — CEIDegradationForecaster and
EUAIActComplianceForecaster. Both require a measure of FLOPs actually
delivered (cei_flops_per_joule), which nvidia-smi cannot report under any
field name. Both agents' own code already refuses to proceed without this
value; confirmed via their internal sample counts remaining at zero rather
than crashing or guessing. intelligence/cei_benchmark.py adds a real,
separate path to closing this gap for CEIDegradationForecaster — a timed
matmul workload with a known FLOP count, real power sampling, CEI = FLOPs
/ (mean watts × elapsed seconds) — deliberately a separate, explicitly
called entry point (run_cei_benchmark), not part of the per-sample loop,
same reasoning as ThroughputContentionDetector needing its own path. Its
arithmetic is tested against hand-calculated expected values; it has not
been run against real GPU hardware, and cannot produce a real CEI number
until it is. This closes the gap for CEIDegradationForecaster only;
EUAIActComplianceForecaster needs three further fields
(ghost_power_pct, crash_count, isolation_score) not yet addressed.

A related, advisory-only capability: detection/migration_recommendation.py
generates a human-readable recommendation when ThermalEventPredictor or
TenantIsolationRiskScorer fires, suggesting a workload migration. It does
not execute any migration and has no real fleet-topology awareness — it
names the source GPU and reason, and says directly in its own output that
it cannot identify an actual target, leaving that to a human or a real
orchestration system.

Each agent's underlying performance numbers were validated with
randomized, non-circular synthetic trials — fresh random noise per trial,
severity varied randomly per trial, not hand-scripted demonstrations built
to fire, and not the same as the wiring status above, which concerns
whether real telemetry can even reach each agent. Results (false positive
rate on clean trials / overall true positive rate / weakest severity tier),
each independently reproducible via the scripts named above:

GhostPowerPredictor — 0% / 96.5% / 89.4%
  (python3 scripts/validate_swarm_prediction.py --n-clean 200 --n-event 200 --seed 42)
CEIDegradationForecaster — 0% / 68.0% / 9.1%
ThermalEventPredictor — 0.5% / 63.0% / 0%
TenantIsolationRiskScorer — 0% / 24.5% / 0%
EUAIActComplianceForecaster — 0% / 54.0% / 1.5%
  (last four: python3 scripts/validate_swarm_prediction_agents2to5.py, own stated defaults)

This proves the scoring logic generalizes across randomized severity. It
does not prove any of these precursor patterns actually precede real
events on real hardware — that requires real, timestamped hardware data,
which does not exist for this project yet.

---

## Tamper-evident audit trail

forensics/audit_ledger.py hash-chains every alert the live pipeline
produces (SHA256, append-only): each entry's hash incorporates the
previous entry's hash, so any retroactive edit or deletion breaks the
chain in a way that is immediately, mechanically detectable. Tested under
real concurrent load: 100 simultaneous append operations across 5 threads
produced a perfectly valid, unforked, sequentially-numbered chain, zero
corruption — this required an fcntl-based exclusive lock around the
entire read-tail-state-plus-write sequence, not just the write itself, and
re-reading the actual last entry from disk inside the lock rather than
trusting an in-memory cache.

Two limitations stated rather than hidden: the file lock only protects
against other writers that also respect it, not a process that ignores
locking entirely; and the ledger's trust root is the local file itself —
an attacker with root on the machine could delete it and start a fresh,
internally-"valid" fake chain. An optional anchor() method emails the
current chain hash to an external inbox, explicitly documented in the code
as a materially weaker guarantee than Serial Alice's blockchain anchoring
elsewhere in this project, not a replacement for it.

forensics/clean_run_certificate.py issues a hash-chained "clean run"
record after a sustained alert-free window across all active engines.
Deliberately, repeatedly labeled in its own code as NOT hardware TEE
attestation — nothing in Watchdog's current infrastructure runs inside a
TEE, and this cannot prove anything against an already-compromised host.
What it provides is real: a tamper-evident record of exactly which
engines were active and that they produced no alerts. A genuine precursor
to hardware attestation, not a substitute for it.

detection/fleet_aggregation.py rolls up alerts across any number of nodes
into a single view ("N of M nodes currently affected by alert type X"),
covering all 30 automatic engines including the foundational ones — which
initially bypassed both the ledger and the fleet rollup, since
DetectionPipeline.process()'s return value was being computed and
silently discarded; both now consume it directly. alerting/state.py
provides real OPEN/ACKNOWLEDGED/RESOLVED alert deduplication: the ledger
and fleet rollup log every individual detection unconditionally, for a
complete record, while repeat notifications to the external callback and
console are suppressed so a flapping condition produces one notification,
not one per sample.

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
exists. The five prediction-layer alert types, now that that layer is
live, are explicitly mapped to log_only in this same table — not new
behavior, since every prediction alert already reached this code and
already fell through to that default; making it explicit turns an
accidental safe default into an auditable one.

orchestration/cluster_actions.py adds three infrastructure actions —
kubernetes_taint, slurm_evict_job, nvlink_disable — wired in with the same
discipline: all three are gated behind human approval by default, and all
three refuse cleanly unless the alert supplies a specific target (node
name, job ID, link index respectively). detection/cluster_metadata.py now
attaches node_name (when a deployment sets it via Kubernetes' Downward
API) and job_id (available automatically inside any SLURM job) to every
alert, giving kubernetes_taint and slurm_evict_job a real path to firing
for the first time, given both human approval and the right deployment
environment — neither has been tested against a real Kubernetes or SLURM
cluster. nvlink_disable now also has a path: NVLinkContentionDetector
attributes a best-effort link_index on its alerts (the single link
deviating most from its own learned baseline), so the action is
reachable when NVLink sampling is enabled and human approval is
granted. That attribution is explicitly best-effort, not the confirmed
pairwise/topology-aware analysis the detector discloses it does not
perform, and is None until per-link baselines are established -- in
which case the action still refuses rather than guessing. Untested
against real NVLink hardware.

---

## Alerting

alerting/manager.py handles severity filtering and audit logging for
every alert, fully wired in. Two further modules are now also live:
alerting/state.py (deduplication, described above under audit trail) and
alerting/siem.py (PagerDuty/Splunk/Sentinel/Datadog routing — safe by
design, each integration no-ops without its own credential env var).
The two modules that were previously dead imports have been resolved:
alerting/email_alerter.py has been REMOVED (it was imported by watchdog.py
but never called, and defaulted to a hardcoded personal recipient
address); alert delivery goes through alerting/siem.py. intelligence/
threat_intel.py is KEPT and is live -- it is the base class for
intelligence/threat_intel_airgap.py (AirGappedThreatIntel). Its KNOWN_IOCS
list previously carried named attack campaigns with invented attribution,
dates, and CVSS scores; that fabricated data has been removed entirely
rather than corrected with more guessing, so the correlation logic is
intact and honestly reports zero matches until real, sourced entries are
added. scripts/audit_dead_imports.py verifies this state (it detects both
calls and inheritance).

---

## API security

The API is off unless --api is passed. When enabled, every endpoint
except /health requires an API key.

Keys are generated with secrets.token_urlsafe(32) and only their SHA256
hash is stored; the plaintext key is shown once at generation and never
again. There is no default or fallback key -- a first run with none
configured generates a fresh random one rather than falling back to
anything predictable.

Brute-force protection (api/rate_limit.py): 5 failed attempts from one
client within 5 minutes blocks that client for 15 minutes, returning
429 with a Retry-After header. A successful auth clears that client's
failure count. Before this existed, an attacker could attempt unlimited
keys as fast as the network allowed. Both the audit log and any active
blocks persist to watchdog_data/auth_log.json, so neither is lost on
restart; expired blocks are dropped on load rather than restored.

Three limits stated rather than left to be found. Client identity is
the peer address, so a deployment behind a proxy or load balancer must
forward the real client address -- otherwise every request appears to
come from one client and blocking one blocks everyone. Blocks are
per-process: multiple API processes do not share state, so this is not
a distributed rate limiter. And it raises the cost of guessing from one
source without defending against a distributed attempt from many.

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

Two prediction agents cannot fire under any real-world condition today.
CEIDegradationForecaster and EUAIActComplianceForecaster both require a
real FLOPs/joule measurement no passive telemetry field provides; a real
CEI benchmark now exists (see Prediction layer) but has not been run on
real hardware, and EUAIActComplianceForecaster needs three further fields
beyond CEI that remain unaddressed. TenantIsolationRiskScorer's timing
signal is permanently silent for the same class of reason. The migration
recommendation capability has no real fleet-topology awareness.

Kubernetes and SLURM remediation actions are untested against real
infrastructure. Both now have a real path to firing (see Remediation)
but neither has been confirmed against an actual cluster of either kind.
nvlink_disable now has a path via NVLinkContentionDetector's best-effort link_index attribution, but is equally untested against a real cluster or real NVLink hardware.

Audit ledger has no protection against a writer that ignores its file
lock, and no external anchoring beyond an optional, explicitly weaker
email-based fallback. The clean-run certificate is not hardware TEE
attestation and should not be represented as such.

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


---

## Related

Public repo: https://github.com/mikebains41-debug/ai-gpu-energy-optimizer-
Both repositories describe the same VRAM residual finding and use the same
characterization: an accounting and capacity-integrity gap, with no data
recoverable. Earlier revisions of the other repository described it as data
leakage with a self-assessed CVSS of 8.4. That wording predated the recovery
tests and has been corrected there.

---

## License

Source-available. See LICENSE.

---

## B200 real-hardware validation (2026-07-30)

A second real-hardware campaign, this time on 2x NVIDIA B200 SXM (RunPod). Full
detail in B200_FINDINGS_REPORT.md, B200_VRAM_RESIDUAL_REPORT.md, and B200_METRICS.md.
Raw data in b200_watchdog/.

Contention: measured -43% to -55% across four independent runs, two different
methods, two different pods. Consistent with the original -9.5% single-measurement
finding from the earlier Vast.ai/H200 session, though notably larger -- worth
further investigation into why, not yet explained.

VRAM residual: reproduced on a second architecture. Same result as H200 -- zero
bytes recoverable, both graceful exit and SIGKILL. Also newly answers a question
the H200 tests left open: SIGKILL and graceful exit produce the identical
accounting residual (~1520MB), so the residual is exit-path independent.

NVLinkContentionDetector: previously never fired on any real hardware. This
session found and fixed three separate bugs preventing it from ever receiving
real data (a stale enable flag, silently dropped CSV columns, and a deprecated
CLI flag causing silent sampling failure). 

CORRECTION (2026-09-21): this paragraph previously said the detector was then
"confirmed firing correctly on a real, deliberately induced cross-GPU transfer"
and called it "the strongest confirmation in the project to date". That is not
supported. The one NVLINK_CONTENTION alert on record (nvlink_final_test_b200_1,
61,542,977,904 KB/s) came from code that compared cumulative NVLink counters
instead of computing a rate; commit 8ba9c69 (30 July) identified it as counter
drift, not throughput, and fixed the rate calculation. In the four retests run
after that fix the detector did not fire. It is NOT confirmed firing correctly
on real hardware. See B200_FINDINGS_REPORT.md section 1.

Five more detectors were tested against genuine induced workloads rather than
synthetic test harnesses this session: three fired correctly on real events, one
correctly stayed silent on a clean VRAM release, and one produced an inconclusive
but valuable finding -- short bursty (agentic-style) workloads are largely
invisible at the current achieved sample rate (3.7-7.1Hz against a requested
100Hz), confirmed on two separate pods.

Tenant-files-left-on-disk scan: run twice on RunPod, both clean, in contrast to
5/5 dirty on the original Vast.ai/H200 instances. Sample size is too small to
call this a settled provider comparison.

As with the H200 findings, stated plainly: VRAM residual is an accounting gap,
not evidence that a previous tenant's actual data can be recovered by the next
renter -- this was tested directly and repeatedly, and the result was zero
recovery every time.
