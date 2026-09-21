# Operational Checklist

What is still required for Watchdog to run at full capability.
Complements TODO.md, which covers the separate multi-provider field
audit. This file covers the software itself.

Status as of the latest commit. Anything marked done was verified by
running it, not by assuming a patch applied.

---

## A. Blocked on rented GPU hardware

Nothing in this section can be closed without a real GPU. Every item
is code that exists and is tested, waiting on hardware to exercise it.

- [ ] Run the 360-hour campaign (5 providers x 4 architectures x 18h)
- [ ] Validate all 41 automatic engines' thresholds against real telemetry
- [ ] Run the pipeline negative control for 1 hour on a clean idle H200
- [ ] Measure real achieved sample rate vs requested (DeltaTimedSampler)
- [ ] Run `run_cei_benchmark()` -> unblocks CEIDegradationForecaster
- [ ] Run `run_residency_probe()` -> unblocks TenantIsolationRiskScorer's
      memory_access_timing_ms signal
- [ ] Verify `parse_nvlink_output()` against real `nvidia-smi nvlink` output
      (format is NVIDIA-documented but unconfirmed against a real device)
- [ ] Verify per-link `link_index` attribution on real NVLink hardware
- [ ] Verify ECCErrorTrendDetector against real ECC counters
      (2026-09-21: given a deterministic multi-GPU test and a cross-GPU
      contamination fix, commit 1c07da7; real-counter validation still
      needs hardware)
- [ ] Verify VBIOSIntegrityDetector against a real VBIOS version string
- [ ] Repeat the throughput contention measurement 3x for a real number
      (currently one unrepeated data point: 372.32 -> 336.96 iter/sec)

## B. Blocked on cluster infrastructure

CPU only. No GPU required. Cheapest section on this list.

- [ ] Minimal k3s cluster -> confirm `kubernetes_taint` actually fires
- [ ] Set NODE_NAME via the Downward API in the pod spec
- [ ] Minimal SLURM setup -> confirm `slurm_evict_job` actually fires
- [ ] Confirm `nvlink_disable` fires given a real link_index

## C. Code

Done:

- [x] Active memory-timing probe wired into TenantIsolationRiskScorer
      (`run_residency_probe()`, discards readings that fail checksum)
- [x] `update_state()` wired into main() -- /status, /alerts and /metrics
      previously returned empty data in every real run
- [x] API brute-force protection (`api/rate_limit.py`) -- 5 failures in
      5 minutes blocks a client for 15 minutes
- [x] Persistent API audit log and blocks across restart

Open:

- [x] Email alerting resolved: `alerting/email_alerter.py` was REMOVED
      (kept only as a local, gitignored .bak). Alert delivery goes through
      `alerting/siem.py`. No wiring outstanding.
- [x] `intelligence/threat_intel.py` is live as the base class of
      `intelligence/threat_intel_airgap.py` (AirGappedThreatIntel). Its
      correlation logic is intact and honestly reports zero matches.
      KNOWN_IOCS stays empty until real sourced entries with citations
      exist; the previous fabricated set was removed and MUST NOT be
      regenerated from memory.
- [ ] Wire the six forensics modules, each with its own guard condition
      rather than a blanket wire-in:
      - `safe_harbor_ledger.py` refuses without WATCHDOG_HARBOR_KEY, so
        unconditional wiring would crash startup where it is unset
      - `harbor_s3_exporter.py` needs AWS/MinIO credentials
      - `spectral.py` analyzes CSV after the fact, not live telemetry
      - `ioc_bundle.py`, `attested_report.py`, `compliance.py` reviewed
        clean, still standalone
- [ ] Decide which alert types should trigger the three cluster actions.
      This is a policy decision with real consequences on a production
      cluster, not a code question. All three remain gated behind human
      approval by default.

## D. Configuration and credentials

No code required. Nothing here is a bug.

- [ ] SIEM credentials, per integration -- each no-ops silently without
      its own: PD_ROUTING_KEY, SPLUNK_HEC_TOKEN, SENTINEL_WORKSPACE_ID
      plus SENTINEL_SHARED_KEY, DD_API_KEY
- [ ] SMTP configuration for email alerting
- [ ] WATCHDOG_HARBOR_KEY -- the safe-harbor ledger refuses to construct
      without it, by design
- [ ] AWS or MinIO credentials if using S3 evidence export
- [ ] Set `nvlink_enabled=True` on TelemetryCollector where NVLink
      monitoring is wanted (off by default; it spawns a subprocess per GPU)
- [ ] Generate and distribute an API key on first run (auto-generated,
      shown once, never displayed again)

---

---

## Fixed 2026-09-21 (multi-GPU + timing bugs, found by testing the way
## production runs -- every GPU through one pipeline, not one at a time)

These were not on any list above because they had not been found yet.
Each was reproduced before and after on the real code, with a repro
script committed alongside. None required hardware.

- [x] GhostPowerDetector kept one baseline + one consecutive-hit counter
      for all GPUs, so a real ghost on one GPU was MISSED when a clean
      GPU's rows interleaved. PerGPU wrapper. commit bfc9bbb
      (scripts/repro_ghost_multi_gpu.py)
- [x] ECCErrorTrendDetector + LaserInjectionDetector false-alarmed on a
      healthy card because they compared it against a different card
      (steady ECC 12 next to 0 read as a trend; a temperature gap between
      cards read as a jump). PerGPU. commit 1c07da7
      (scripts/audit_multi_gpu_contamination.py)
- [x] LaserInjectionDetector timed its window with the host wall clock and
      needed 3 samples in 0.5s -- blind at real ~1Hz sampling, false alarm
      when processed fast. Now uses each sample's own timestamp, 3s window.
      commit 84f378b (scripts/repro_laser_timing.py)
- [x] The prediction swarm was built once for GPU0 and fed every GPU, so a
      busy card interleaved with an idle one was predicted to be ghosting.
      One swarm per GPU. commit aae8e2a (scripts/repro_swarm_multi_gpu.py)
- [x] run_negative_control.py discarded the alerts pipeline.process()
      returned, so an alert could not be checked against its own sample
      (the 2026-09-19 unexplained alerts). It now records each alert WITH
      its triggering row. commit 613d865
- [x] Cluster actions (kubernetes_taint/slurm_evict_job/nvlink_disable)
      shelled out with NO target validation, so slurm_evict_job(None) ran
      `scancel None`. Now refused before any subprocess. commit 27eed7f
      (scripts/repro_cluster_target_validation.py). Note: this is the
      target-safety fix; whether these ACTIONS fire end-to-end is still
      Section B (needs a cluster), and the automation POLICY is unchanged
      (see Recorded decision below).

Withdrawn same day: an earlier claim that the qualification harness had
reproduced the 2026-09-19 GhostPowerDetector false positive. That result
came from a stand-in stub, not the real agent (100% TPR / 0% FPR on both
idle states). The real 2026-09-19 false positive remains unexplained --
most likely our own test activity on GPU0 during that run -- and is not a
demonstrated detector false positive. commit 669f1fb

---

## Known gaps that are not on this list

Stated so their absence is not mistaken for an oversight:

- Absolute CEI is not reproducible across runs (~20% coefficient of
  variation). Point values should not be treated as constants. This is a
  measurement-methodology problem, not a task.
- The clean-run certificate is not hardware TEE attestation and cannot
  become one without a TEE.
- The audit ledger's file lock does not protect against a writer that
  ignores POSIX advisory locking, and its trust root is the local file.
- API rate limiting is per-process and keyed on peer address. Behind a
  proxy that does not forward the real client address, every request
  appears to come from one client.

---

## Recorded decision: cluster action automation

Status: deliberately manual. Not an open task.

All three cluster actions (kubernetes_taint, slurm_evict_job,
nvlink_disable) remain gated behind human approval. This is a decision,
not an omission.

Reasoning, recorded so it does not have to be rediscovered: no current
alert type can distinguish an attack from normal operation with enough
confidence to justify killing running work automatically. The detectors
themselves say so. CovertMiningDetector cannot determine authorization.
PowerPeriodicityDetector reports that a periodic signal exists without
attributing a cause. MultiGPUCorrelation is INFO-only and explicitly
not an attack signal. NVLinkContentionDetector notes the same signature
arises from legitimate distributed-training synchronization. Ghost power
is normal on healthy idle GPUs. That hedging is honest design, and it is
exactly why none of these should trigger destructive action unattended.

One distinction to preserve if this is ever revisited: a Kubernetes
taint stops new work from scheduling onto a node while running jobs
continue. A SLURM eviction kills a job in progress. These are not
equivalent risks and should not be automated together.

The one candidate worth reconsidering after real hardware data exists:
ECC_UNCORRECTABLE_ERROR -> kubernetes_taint only. An uncorrectable ECC
error means memory corruption has already occurred -- unambiguous
hardware failure rather than an inference, and the only alert in the
catalog whose meaning is not hedged. Draining a node from new work on
that signal is standard HPC practice and kills nothing already running.

Revisit only once the hardware campaign has produced real false-positive
rates. Deciding this from synthetic data would be guessing.
