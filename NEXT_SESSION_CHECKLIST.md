# Next Hardware Session — Full Test Checklist

Every real, testable vector left after the B200 campaign and the NVLinkContentionDetector
fix. Grouped by priority. Each item states what to run, why, and what a pass/fail looks
like. Nothing here should be reported as done until it has a real output file and a
commit hash, same discipline as EVIDENCE.md.

---

## GROUP A — Must confirm first (this is why you're renting)

### A1. NVLinkContentionDetector retest against the fixed code
The old detector compared raw cumulative counters and produced 61.5 billion "KB/s" --
counter drift, not throughput. Fixed in commit 8ba9c69 (rate calc) + follow-up
(iso_timestamp-based clock). Never confirmed on real hardware.

- [ ] `git pull` on the fresh pod to get the fix
- [ ] Run the same test as before: 45s clean idle baseline, then a real GPU0->GPU1
      transfer for 90s (`.to('cuda:1')` loop)
- [ ] Check the alert's `nvlink_total_kbs` -- must be a sane number (tens to low
      thousands of KB/s), NOT trillions
- [ ] If it fires correctly: replace `nvlink_final_test_b200_1.log` and rebuild
      B200_Crucial_Findings.pptx with the real number
- [ ] If it does NOT fire, or fires during the idle baseline alone: `delta_threshold_kbs`
      (currently 1000.0, unvalidated default) needs real tuning -- record whatever
      the real idle-vs-active gap actually is

---

## GROUP B — Detectors tested wrong or inconclusively, need a real retry

### B1. SequentialVRAMReadDetector
Both prior attempts (`.sum()`, `.copy_()`) dispatch a CUDA kernel and register as
compute, not a pure memory read. Needs genuine util.gpu <= 5% while memory bandwidth
is high.
- [ ] Try a pinned-memory host<->device transfer (`tensor.pin_memory()` +
      `.to('cuda', non_blocking=True)`) or a raw `cudaMemcpy`-style operation that
      does not dispatch a compute kernel
- [ ] Confirm via telemetry CSV that utilization.gpu actually stayed <=5% during
      the operation before concluding pass or fail

### B2. CovertMiningDetector
Real workload measured ~89.7% of TDP -- just under the 90% `tdp_ceiling_fraction`
threshold. Boundary case, not resolved either way.
- [ ] Rerun with a heavier/longer matmul (bigger matrix, or FP64 if available) to
      clearly clear 90%, OR
- [ ] Note the real achieved TDP fraction and consider whether the threshold itself
      needs adjusting for real saturated compute

### B3. InterAgentHandoffAnomalyDetector
Inconclusive: bursts (3.2s) were shorter than gaps between achieved samples (~3-7Hz
= up to ~1.5s between samples), so most bursts were invisible to the sampler.
- [ ] Rerun with bursts sized to the REAL achieved rate on this pod (check first
      with a quick sample-rate probe), not assumed 100Hz
- [ ] Confirm via CSV that utilization.gpu actually shows non-zero values during
      the burst windows this time

### B4. PowerLimitTamperDetector -- never tested
- [ ] `nvidia-smi -pl <value below default>` to lower the power limit, watch if
      it fires
- [ ] Restore the original power limit afterward: `nvidia-smi -pl <original>`

### B5. PStateHonestyDetector -- never tested
- [ ] Check what field/condition it actually reads (`grep -n "class PStateHonestyDetector" -A 30 detection/*.py`)
      before attempting -- don't guess at the trigger condition

### B6. MultiGPUCorrelation -- never tested
- [ ] Run correlated bursts on both GPU0 and GPU1 simultaneously (two background
      processes)
- [ ] Confirm it correctly reports INFO-only, not an attack signal -- this detector
      explicitly should not treat synchronized activity as inherently malicious

---

## GROUP C — Reproducibility (single readings need repeats)

### C1. CEI benchmark
Only ever run once (7.03e10 FLOPs/joule). EVIDENCE.md already flags ~20%
coefficient-of-variation as unresolved.
- [ ] Run `CEIBenchmarkRunner(gpu_index=0).run(duration_s=10)` 3-5 times back to back
- [ ] Record the real spread, not just one point value

### C2. Residency probe
Only one reading (23.4ms). 
- [ ] Run `run_challenge(challenge_mb=512)` 3-5 times, record the spread

### C3. Contention, sustained
Every measurement so far is a short burst (10-60s).
- [ ] Run a genuine 10+ minute sustained contention test -- does the ~43-55% loss
      hold steady, worsen, or self-correct over time?

---

## GROUP D — Multi-provider comparison (the biggest open pitch item)

### D1. A second real provider
Right now: RunPod-only rigorous data + one older, less-rigorous Vast.ai result.
TODO.md's "N of 5 providers" claim is unproven.
- [ ] Rent Lambda or Jarvis Labs
- [ ] Run the identical script suite: `gpu_audit.py`, `capture_contention.py`,
      tenant-files scan, VRAM residual (both exit paths)
- [ ] Add the result to `aggregate_audits.py`'s table

### D2. More tenant-file scans on RunPod
Currently 2-for-2 clean vs. Vast.ai's 5-for-5 dirty -- sample size too small to
compare fairly.
- [ ] Run `gpu_audit.py`'s tenant-file check on 3+ more fresh RunPod instances

---

## GROUP E — H200-specific (if renting that architecture again)

### E1. NVLink on H200
H200 SXM has NVLink. Never tested there at all -- everything NVLink so far is B200 only.
- [ ] Same test as A1, on H200 hardware
- [ ] Compare real per-link topology/link count against B200's 18 links

### E2. Throttle fields under real stress
All 6 flags (`sw_power_cap`, `hw_slowdown`, etc.) have only ever been observed
reading "Not Active" on an idle GPU -- a real negative control, but never a real
positive one.
- [ ] Run a sustained heavy workload that's likely to actually hit a thermal or
      power limit, and check whether any flag flips to "Active"

---

## Explicitly excluded -- not on this list, and why

These are real attack vectors this project has knowingly NOT attempted, because
testing them honestly would require faking a result:
- ECC uncorrectable errors -- unsafe/unreliable to induce deliberately
- DMAAttackDetector / physical fault injection -- requires hardware access no
  cloud GPU rental provides
- VBIOS integrity / boot attestation -- no clean pre-rental baseline exists to
  compare against

If any of these come up again, the answer is still: cannot test honestly on rented
cloud hardware, not "untested, get to it eventually."

---

## Recording discipline (same as always)

Nothing from this checklist goes into a report, deck, or pitch until it has:
1. A real output file in b200_watchdog/ or a new h200_watchdog/ folder
2. A commit hash
3. Either a pass, a fail, or an honestly stated inconclusive result -- never silently
   dropped if it didn't go the way you wanted

## GROUP F — New detectors needing real-hardware validation

### F1. ECCAnomalyDetector — GPUHammer/Rowhammer signal
Built and unit-tested (18/18 passing). Never run against real hardware.
- [ ] Rent a GPU pod, induce ECC correctable errors (sustained matmul stress)
- [ ] Confirm detector fires with a sane per-second rate, not a raw counter
- [ ] Confirm it stays silent on a healthy GPU with a flat ECC counter

### F2. ThermalSideChannelDetector — Hot Pixels thermal channel
Built and unit-tested. Never run against real hardware.
- [ ] Run with a co-located heavy workload and watch whether idle-GPU temperature
      rises above its own learned baseline
- [ ] Confirm INFO severity only, no overclaiming

### F3. PCIeAnomalyDetector — Invisible Probe / LockedDown PCIe channel
Built and unit-tested. PCIe throughput fields not present in every telemetry
configuration -- confirm they are available on B200 pods before testing.
- [ ] Check which PCIe field names the B200 pod actually exports
- [ ] Run a large model load at low compute and confirm it fires
- [ ] Confirm it stays silent during heavy compute with heavy PCIe

## GROUP G — Highest-priority open research items (unchanged)

### G1. Same-GPU cross-tenant exploit PoC
The hardest open item. Only the memory-management accounting gap is confirmed,
not a working exploit where Process B reads Process A's residual data.
- [ ] Attempt same-GPU cross-tenant data recovery on a real multi-tenant pod
- [ ] This is the finding that would change the whole story -- currently the
      most important unresolved item in the entire project

### G2. Remediation end-to-end test
kubernetes_taint, slurm_evict_job, nvlink_disable all exist in
orchestration/cluster_actions.py but have never been tested end-to-end.
- [ ] Set up a controlled test where a detector fires and a remediation action
      executes correctly, with human-approval gate confirmed working
- [ ] Needs a real Kubernetes cluster or SLURM scheduler, not a plain GPU pod
