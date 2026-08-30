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
- [ ] Validate all 32 automatic engines' thresholds against real telemetry
- [ ] Run the pipeline negative control for 1 hour on a clean idle H200
- [ ] Measure real achieved sample rate vs requested (DeltaTimedSampler)
- [ ] Run `run_cei_benchmark()` -> unblocks CEIDegradationForecaster
- [ ] Run `run_residency_probe()` -> unblocks TenantIsolationRiskScorer's
      memory_access_timing_ms signal
- [ ] Verify `parse_nvlink_output()` against real `nvidia-smi nvlink` output
      (format is NVIDIA-documented but unconfirmed against a real device)
- [ ] Verify per-link `link_index` attribution on real NVLink hardware
- [ ] Verify ECCErrorTrendDetector against real ECC counters
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

- [ ] Wire `alerting/email_alerter.py` into the live pipeline. Its
      previously-documented hardcoded-CVE bug is already gone; what
      remains is a hardcoded default recipient address any real
      deployment must override.
- [ ] Wire `intelligence/threat_intel.py` in. Its correlation logic is
      intact and honestly reports zero matches. Populating KNOWN_IOCS
      needs real sourced entries with citations -- the previous
      fabricated set was removed and must not be regenerated from memory.
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
