# Evidence Register

Every factual claim Watchdog makes, and the exact thing that produced it.

## Why this file exists

Claims were written into the README, the investor document, and code
comments without a pointer back to the measurement that produced them.
Over two days of review, four separate claims turned out to be wrong or
unsourced, each one found by chasing it individually:

- VRAM residual per-architecture figures (382/625/629/728MB) traced to a
  hardcoded dictionary in one agent's source, present in no log
- A 1,417MB residual figure turned out to be a test's own 256MB
  measurement buffer, not residue
- "SIGKILL reclaims it; a clean exit does not" was contradicted by the
  logs, which show no recoverable data by either path
- "No component has been run against real GPU hardware" was false;
  detectors had been run and found nothing, which is a stronger fact

None of those were caught by a test. They were caught by someone reading
a log. This file exists so the next one is caught by looking here.

## Rules

1. No number goes in the README, the investor document, or a docstring
   unless it appears below with a source.
2. A claim with no source is listed as UNSOURCED, not omitted. Silence
   about a missing source is how the previous four survived.
3. The verification column is a command that can be run now. If it
   cannot be run, the claim is not verified.
4. When a claim changes, update here first, then the documents.

---

## VERIFIED — traceable to a specific measurement

### VRAM residual: 527MB on H200 after graceful exit
Source: `validation_results/h200_vram_reproduction_log.txt`
Evidence: memory column reads 773 during FP32 workload, 897 during FP16,
then drops to 527 at the EXIT phase (line 6570) and holds through SETTLE.
Method reads telemetry only and allocates nothing, so the figure is not
contaminated by a measuring buffer.
Verify: `grep -n "EXIT\|SETTLE" validation_results/h200_vram_reproduction_log.txt | head`

### No recoverable data after process exit, either exit path
Source: `validation_results/cross_tenant_vram_full_methodology.py` (graceful),
`validation_results/cross_tenant_vram_sigkill_full_methodology.py` (SIGKILL),
logs `test1_full_rigor_log.txt` and `test2_sigkill_full_rigor_log.txt`
Evidence: both write a known pattern into 256MB, end the owning process,
allocate a fresh buffer and read it every 0.1s for 240s. Both report
`matches=0 nonzero=0` sustained throughout.
Verify: `grep -c "matches=0 nonzero=0" validation_results/test2_sigkill_full_rigor_log.txt`

### Contention cost: 372.32 -> 336.96 iter/sec, -9.5%
Source: `validation_results/SUMMARY.md` section 4
Note: single measurement, not repeated. TODO.md calls for 3 repeats.

### Detectors silent through a real event
Source: `validation_results/SUMMARY.md` section 3
Evidence: cache-timing probe and memory-attack detectors produced 0 alerts
across 35,099 baseline samples and 0 across 35,068 contention samples.
This is the central product gap.

### Prediction layer figures
Source: the validation scripts themselves, re-run and confirmed.
Verify (Ghost Power): `python3 scripts/validate_swarm_prediction.py --n-clean 200 --n-event 200 --seed 42`
Verify (other four): `python3 scripts/validate_swarm_prediction_agents2to5.py`
Figures: Ghost Power 0% FPR / 96.5% / 89.4% weakest tier; CEI Degradation
0% / 68.0% / 9.1%; Thermal 0.5% / 63.0% / 0%; Tenant Isolation 0% / 24.5%
/ 0%; EU AI Act 0% / 54.0% / 1.5%. All synthetic.

### Negative control: 3,600 clean samples, 0 alerts
Source: `tests/test_engines.py` line 277
Note: synthetic samples, not an idle GPU. Real-hardware equivalent is in
TODO.md as a one-hour idle run.
Verify: `python3 tests/test_engines.py`

### Engine count: 41 automatic, 2 endpoint-driven
Verify: `python3 -c "from watchdog import FullDetectionPipeline; print(FullDetectionPipeline(fleet_size=10).total_engine_count)"`
Caveat: PCIeBandwidthMismatchDetector reads `pcie.bandwidth.util_pct`,
which nothing collects. It is counted among the 29 and cannot currently
fire. Its own docstring says so.

### Test suite: 40 tests across 9 modules
Verify: `python3 tests/attack_injection_suite.py`
Caveat: 41 test files exist; only 9 are wired into the suite.

### Serial Alice certificates
Source: partner-issued, 2026-06-27, H200 under Intel TDX via Phala Cloud.
Figures: idle floor 80.36W, ghost-power peak 147.96W, FP32 CEI
3.178e11 FLOPs/J (+/-1.6% over five passes), FP16 2.846e12, FP8 9.59e11,
zero crashes across 11,052 samples, overall trust_score 0.4 (TEE passed,
signed-exporter check failed).
Caveat: these certificates carry no VRAM residual figure. Partner-measured
phenomena, not validation of Watchdog's detection code.

### CVE-2026-31431 ("Copy Fail") and CVE-2026-64600 ("RefluXFS")
Both are real, externally documented industry CVEs. Copy Fail is in CISA
KEV. RefluXFS: https://nvd.nist.gov/vuln/detail/CVE-2026-64600
The finding is that a rented instance was unpatched, not the CVEs.

---

## UNSOURCED — asserted, no measurement located in this repo

### Ghost power — SOURCE LOCATED, figures corrected
Source: `gpu-optimizer-nelson-tests-/h200wed.june24.2026/GHOST_POWER_REPORT.md`
plus per-test summaries under the same directory (M2_ghost_detection,
M6_sustained_run). Measured at 10Hz via nvidia-smi on real rented cloud
hardware, timestamped, raw CSV preserved per test. Idle floor is measured
fresh during a 15s baseline at the start of every run, so the detector is
self-calibrating per GPU, driver version, and thermal state.

Measured per architecture:

| GPU | Cold boot | Post-load | HBM | Provider / date |
|---|---|---|---|---|
| A100 SXM | 61W | 146.66W (idle floor 67.1W, +79.56W) | HBM2e | RunPod 2026-05-29 |
| H100 SXM | Clean | Clean — NONE DETECTED | HBM3 | RunPod, negative control |
| H200 SXM | Clean | 598.41W peak (idle floor 74.59W) | HBM3e | Vast.ai 2026-06-24 |
| B200 SXM | 184.46W | 233-234W | HBM3e | RunPod 2026-06-03 |
| B300 SXM6 | 188.35W | 244-246W | HBM3e | RunPod 2026-06-03 |

H200 strongest finding: 1,376 ghost samples out of 1,377 taken during the
cooldown window — 99.9%. A separate 600s sustained run on H200 recorded
917 ghost events in cooldown with a 146.12W peak and zero crashes.

B200 and B300 show ghost power from COLD BOOT, before any workload runs,
and B300 never recovers.

Pattern claimed in the report: HBM clock speed predicts ghost power
magnitude; higher bandwidth means a higher ghost floor, so it grows
across generations rather than shrinking.

TWO CORRECTIONS THIS SOURCE FORCED:

1. The range "67-146W" was wrong. 67.1W is A100's IDLE FLOOR and 146.66W
   is A100's GHOST FIGURE — a floor from one line paired with a ceiling
   from the next, presented as a range, and excluding every other
   architecture. Real peak is 598.41W on H200, roughly four times the
   documented figure. The finding was being understated, not overstated.

2. H100 was listed as an architecture where ghost power was observed. It
   is the NEGATIVE CONTROL. The report states: "Ghost power: None
   detected... confirms detector does not false-positive on clean
   architectures." Claiming it as a positive finding inverts its purpose
   and would be caught immediately by anyone holding the report.

### VRAM residual per-architecture: 382 / 625 / 629 / 728 MB
Traced to a hardcoded dict in
`intelligence/swarm/agent4_tenant_isolation_risk_scorer.py`, inside a
constant named SERIAL_ALICE_ISOLATION_VALIDATED, with the comment "From
VRAM residual research" and no file or log reference. Serial Alice's
certificates contain no VRAM figures. These numbers appear in no
validation log.
REMOVED from the README and the investor document. The code retains them
as scoring baselines and now warns when substituting for an unlisted
architecture.

### CVSS 8.4 for CVE-2048350
Self-assessed. Never externally reviewed. Assigned before the
cross-tenant testing that found isolation holding. Not defended in any
current document.

### Whether SIGKILL clears the 527MB accounting
Not measured. Both existing tests allocate a 256MB read buffer, which
contaminates their memory figures for this specific question — one shows
863MB before the kill and 1417MB after, an increase that is the
instrument. Correct method is in TODO.md.

---

## KNOWN DISCREPANCY

Leftover tenant file age: `validation_results/SUMMARY.md` says 16 days.
Some document text has said 17. SUMMARY.md is the source; 16 is correct.

---

## CORRECTED — recorded so the error is not reintroduced

| Claim as written | Status | Actual |
|---|---|---|
| "382MB to 1.6GB remains allocated and readable" | WRONG | Not readable. Zero recovery, both exit paths. 527MB on H200. |
| "SIGKILL reclaims it; a clean exit does not" | WRONG | No data survives either. Accounting effect of SIGKILL unmeasured. |
| "1,417MB residual" | WRONG | Test's own 256MB buffer plus CUDA context, not residue. |
| "No component run against real GPU hardware" | WRONG | Detectors were run; they found nothing across 35k+ samples. |
| "seven architectures" for ghost power | WRONG | Five claimed: A100, H100, H200, B200, B300. Source still unlocated. |

---

## B200 REAL HARDWARE EVIDENCE (2026-07-30)

All entries below are sourced from b200_watchdog/ in this repo, with commit hashes.
Full detail in B200_FINDINGS_REPORT.md and B200_VRAM_RESIDUAL_REPORT.md.
Every number here has a source file -- see B200_METRICS.md for the complete list.

### VERIFIED

Contention: -43% to -55% across 4 independent measurements, 2 methods, 2 pods.
Verify: cat b200_watchdog/audit_b200_1.json b200_watchdog/audit_b200_2.json

VRAM residual on B200: zero bytes recovered, both graceful exit and SIGKILL,
identical ~1520MB accounting figure either way. Answers the open SIGKILL question
from the earlier TODO.md entry -- residual is exit-path independent.
Verify: cat b200_watchdog/vram_residual_b200_1.txt b200_watchdog/vram_residual_sigkill_b200_1.txt

Cross-GPU isolation held: 4MB delta (noise-level) on a 976MB allocation.
Verify: cat b200_watchdog/cross_gpu_b200_1.txt

Clean 1-hour negative control: 13,710 samples, 1 alert, ~0.007% rate.
Verify: tail -5 b200_watchdog/watchdog_idle_1hr_b200_2_gpu1.log

NVLINK_CONTENTION fired correctly on a real, deliberately induced cross-GPU
transfer. This required finding and fixing three separate bugs first (stale
enable flag, dropped CSV columns, deprecated CLI flag) -- see agent/telemetry.py
and watchdog.py commit history from this session.
Verify: grep -A6 "WATCHDOG ALERT" b200_watchdog/nvlink_final_test_b200_1.log

Four more detectors tested against real induced workloads: AGENT_ORCHESTRATION_ANOMALY
(fired 2x), PROMPT_INJECTION_SIDEEFFECT (fired), AgentSessionVRAMRetentionDetector
(correctly silent), InterAgentHandoffAnomalyDetector (inconclusive -- real sampling-
rate limitation found, not a detector bug).

### UNSOURCED / NOT YET SETTLED

Tenant files on B200/RunPod: 2 scans, both clean. Compare against 5/5 dirty on
H200/Vast.ai. Sample size too small to call this a settled provider comparison.

CovertMiningDetector: real workload measured ~89.7% of TDP, just under the 90%
threshold. Boundary case, not a pass or fail -- worth retesting with a heavier
or longer workload.

SequentialVRAMReadDetector: never actually triggered under correct conditions.
Both attempts used the wrong operation (a compute-heavy reduction/copy, not a
pure memory read) -- utilization.gpu stayed 90%+ both times against a <=5%
requirement. Still untested under the right conditions.

### CORRECTION

Do not describe the VRAM residual finding (on B200 or H200) as evidence that a
prior tenant's data is recoverable. It is the opposite: zero bytes recovered in
every test, on both exit paths, on both architectures. The real "data left behind"
evidence is the separate tenant-files-on-disk finding, not VRAM.
