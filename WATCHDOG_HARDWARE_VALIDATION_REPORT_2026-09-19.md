# Watchdog — Real-Hardware Validation Report

**Session:** 19–20 September 2026, 22:44–02:35 UTC (3:44–7:35 PM PDT)
**Hardware:** 4× NVIDIA H200 SXM, RunPod, container `32ba978711ee`
**Driver:** 570.124.06 · **VBIOS:** 96.00.CF.00.02 · **Kernel:** 6.8.0-83-generic
**Host:** 192 usable cores, 1960 GB RAM · **Torch:** 2.8.0+cu128
**Topology:** all four GPU pairs NV18 (18 bonded NVLinks); GPU0/1 on NUMA node 0, GPU2/3 on NUMA node 1; container maps physical `/dev/nvidia0,3,4,6` to CUDA indices 0–3
**Duration:** ~5 hours · **Cost:** ~$80 · **Commits:** 30 to `main`, 1 branch to gpu-core-private

Every figure below was read from a committed artifact under `evidence/`, `daemon_evidence/`, or `cpu_results/`. Nothing is paraphrased from memory.

---

## PART 1 — WHAT RAN AND WHAT IT FOUND

### 1.1 Preflight

`scripts/hardware_preflight_check.py` — run first, deliberately.

| Check | Result |
|---|---|
| nvidia-smi present | PASS, 4× H200 |
| All 24 `QUERY_FIELDS` returned in one combined query | **PASS** — `sample_gpu()` will not silently drop rows on this driver |
| `--query-compute-apps` with a live workload | **FAIL — returned empty** |
| torch + CUDA | PASS; FP8 and INT8 matmul available; FP4 unsupported (expected) |

**The compute_apps result is the most consequential preflight finding.** GPU0 showed 2054 MiB used and 122 W draw with a workload running, yet the process table was empty and `--query-compute-apps` returned nothing. The container cannot see process PIDs; the driver reports them in the host's PID namespace. Confirmed a second time during remediation testing.

Consequences, all measured downstream:
- `VRAMResidualDetector` cannot evaluate on this platform (it watches a PID leave compute_apps)
- No detector can supply a PID to `kill_process`, so that action always refuses
- `run_negative_control.py` runs with `vram_strict=False`

### 1.2 Validation harness — four runs

`runtime/pod_runner.py --live` (built this session; the original `validation_harness.py` had no CLI and ran a FakeBackend demo that printed 6/6 regardless of hardware — `FakeBackend.scan_vram_for_pattern()` hardcodes `pattern_found=True`). Every run confirmed `backend: real` and `is_evidence: True`.

| Run | Victim / workers | Tier-1 pass | Notes |
|---|---|---|---|
| pod1 | 0 / 1,2 | 2/6 | GPU0 still held a context from preflight |
| pod2 | 1 / 2,0 | 3/6 | sdc_drdna passes on a clean victim |
| pod3 | 3 / 1,2 | 3/6 | reproducible |
| pod4 | 3 / 1,2, inducer 16384²×60s | 3/6 | still fails — root cause found |

**Consistently passing:** `nvlink_livefire` (real 256 MB cross-GPU copy over NV18, detector fired), `cross_gpu_residual`, `sdc_drdna` (real forward pass, injected deviation, Dr. DNA fired), `rowhammer_capability` (Tier 2 — ECC fields readable, silent on clean; the true positive is deliberately never induced on rented hardware).

**Consistently failing, each for a known reason:**

`covert_compute` — pod4 hit 100% utilisation, 706.53 W (against a 700 W limit), 5119 iterations, 255 samples. The detector still did not fire. Root cause: the hook requires `util > 90 AND sm_clock_uniform`; `sm_clocks_seen` is a deduplicated set; the SM clock held at exactly 1455 MHz across all 255 samples; the set has one element; `(max-min < 50) if len > 1 else None` returns None; None fails the AND. **The stage fails because the clock was perfectly uniform — the exact condition it is testing for.** Inverted logic in my pod_runner.py. The inducer was never the problem.

`vram_cross_process_read` — a separate child process (`_vram_writer.py`) wrote 0xA5 into VRAM and exited without freeing; a fresh process scanned 512 MB and found `pattern_byte_matches: 0, nonzero_bytes: 0`. **Zero bytes recoverable**, consistent with every prior H200 and B200 test. The stage is coded to pass only if the pattern IS found, so a correct negative result is labelled FAIL.

`ghost_power` — the probe samples "true idle" after earlier stages have already created a CUDA context on the victim, so it measures ghost-state to ghost-state (pod2: 127.27 W → 124.90 W, delta −2.37 W). My bug. The clean measurement was done by hand (§1.3).

### 1.3 Ghost power — direct measurement

GPU3, never touched all session before this test.

| | Power | SM clock |
|---|---|---|
| Cold baseline | 78.61 W | 345 MHz |
| After 60 s bf16 GEMM, process exit, 15 s settle | 79.14 W | 345 MHz |
| **Delta** | **+0.53 W** | 0 |

**No post-exit ghost power on H200/RunPod/570.124.06.** 0.53 W is inside NVML's ±5 W accuracy. The card returned fully to its cold floor.

Separately and consistently measured five ways: **a live CUDA context costs ~47 W** — GPUs holding a context read 122–128 W at 1980 MHz SM clock versus 77–79 W at 345 MHz cold. This releases completely on process exit.

### 1.4 Negative control — one hour, and it found a bug

`scripts/run_negative_control.py --seconds 3600 --interval 1.0` on GPU0.

First attempt was contaminated by our own harness activity (I'd said "run it on GPU3" but the script monitors GPU0, and it fired correctly on real load — accidentally a true positive). Second attempt, GPUs genuinely idle:

```
samples 3523   alerts 2   false-positive rate 0.057%
ghost_power_baseline_w 78.4
achieved 0.979 Hz against 1.0 Hz requested (mean interval 1021.8 ms)
```

Both alerts, at ~36 minutes:
```
[WARNING] GHOST_POWER — 44.5W above 78.4W idle floor at 0% utilization
[WARNING] GHOST_POWER — 48.1W above 78.4W idle floor at 0% utilization
```

Ground truth, five consecutive `nvidia-smi` reads over ten seconds at the moment of checking: **78.98 / 78.98 / 78.99 / 78.95 / 78.94 W**, 0% util, 1 MiB, 345 MHz. Three python processes on the box (the control itself plus grep). Nothing ran.

**The GPU was never at 123 W. These are false positives on idle hardware.** The values (~122.9 W and ~126.5 W implied) match the context-alive figures from pod1/pod2 almost exactly — suspected stale or wrong-GPU telemetry sourcing. Intermittent: none in the final 24 minutes.

Coverage gap stated in the script's own docstring: compute_apps is not queried, so VRAMResidualDetector never evaluates; `throughput_samples: 0` because ThroughputContentionDetector needs its own API endpoint.

### 1.5 Daemon — two runs

`runtime/watchdog_daemon.py --live --duration 300`

| Run | Samples | Alerts | Incidents |
|---|---|---|---|
| 00:31:31Z | 1120 | 0 | 0 |
| 00:36:31Z | 1116 | 0 | 0 |

Detectors loaded: `rowhammer_precursor`, `cryptojacking_onset`, `ghost_power` — three, not 41; `detectors_skipped: []`. Correlator: unified. 1120 samples ÷ 4 GPUs ÷ 300.9 s ≈ 0.93 Hz per GPU. The metrics file self-labels: *"Real-hardware run. Detector logic was simulation-tested; this run is the first live-telemetry execution — results are evidence, not a pass/fail of the detectors themselves."*

While the API daemon was running separately it produced one alert on its own, worded exactly as it should be:
> `[INFO] LASER_INJECTION — Temperature changed 5.0C within 0.5s — consistent with a normal workload start/stop transient. Not evidence of physical fault injection, which cannot be detected from software telemetry alone.`

### 1.6 Master correlator

`intelligence/swarm/master_correlator.py` on 20 seconds of live telemetry, first execution on hardware:

- **Loaded 7/7:** SecurityCorrelator, CrossLayerCorrelator, SDCSwarmCorrelator, SandboxSwarmCorrelator, EgressSwarmCorrelator, ExtremeEnvSwarmCorrelator, SolarStormSwarmCorrelator
- `not_loaded: []`
- 80 samples observed, `master_incidents: 0`, `sub_incidents: 0`
- Rules armed: COORDINATED_MULTI_VECTOR_ATTACK, ENVIRONMENT_INDUCED_INTEGRITY_FAILURE, LOW_CONFIDENCE_WINDOW, FULL_SPECTRUM_INCIDENT

### 1.7 Remediation — nine checks, every action

`scripts/remediation_live_test.py` (built this session). The harness reported 3/9 because it parsed `str(handle())` and `handle()` returns None and prints. **The engine's own printed output shows correct behaviour on 7 of 8:**

| Check | Engine said | Correct? |
|---|---|---|
| Human gate blocks | `SKIPPED_HUMAN_REQUIRED` | ✅ |
| Auto-disabled blocks | `SKIPPED_AUTO_DISABLED` | ✅ |
| log_only changes nothing | `LOGGED`, memory.used 1.0 → 1.0 | ✅ |
| kill_process, no PID | `NO_PROCESSES` | ✅ refused |
| kill_process, named PID | `TARGET_PID_20594_NOT_FOUND_ON_GPU_2` | ✅ refused after verifying against the GPU process list — which compute_apps makes empty |
| Report matches reality | claims_success=False, killed=False | ✅ |
| **gpu_memory_reset, `--allow-reset`** — first live execution ever | `GPU_MEMORY_RESET_REQUIRES_HUMAN_APPROVAL — orphaned VRAM from an already-exited process cannot be reclaimed from a third-party process; only a privileged GPU reset can, and that disrupts every other tenant on the GPU` · memory.used 1132 → 1.0 · **claims_success=False** | ✅ refused with the correct technical reason, no false success |
| MIG quarantine | `MIG_QUARANTINE_REQUIRES_HUMAN_APPROVAL` | ✅ |
| Cluster actions | ImportError | my bug — class is `ClusterOrchestration` |

**Cluster actions, tested directly:**

| Call | Result |
|---|---|
| `kubernetes_taint(None)` | `KUBECTL_NOT_AVAILABLE: expected str, bytes or os.PathLike object, not NoneType` |
| `kubernetes_taint('fakenode')` | `KUBECTL_NOT_AVAILABLE: No such file or directory: 'kubectl'` |
| `slurm_evict_job(None)` | `EVICT_FAILED: scancel: res_nsearch error: Unknown host` |
| `slurm_evict_job(99999)` | same |
| `nvlink_disable(0, None)` | `NVLINK_DISABLE_FAILED:` (empty stderr) |
| `nvlink_disable(0, 3)` | `NVLINK_DISABLE_FAILED:` (empty stderr) |

**None of the three validates its target.** They refuse by accident. `kubernetes_taint(None)` fails on a TypeError inside subprocess and mislabels it as a missing binary. **`scancel` exists on this host and ran** — it failed only on DNS resolution of a SLURM controller. With a reachable controller, `scancel None` would have been sent for real. `nvlink_disable` returns empty stderr for both null and valid link, so refusal and failure are indistinguishable. The README states these "refuse cleanly unless the alert supplies a specific target." They do not check.

### 1.8 VRAM residual — the accounting question answered

`scripts/sigkill_residual_measure.py` (built this session — allocates nothing on the GPU, reads only `memory.used`, which is why it can answer what the 256 MB-buffer tests structurally cannot).

| Signal | Alloc | Residual immediately | at end of watch | Verdict |
|---|---|---|---|---|
| SIGKILL | 2048 MB | 0.0 MB | 0.0 MB (90 s) | clears |
| SIGTERM | 2048 MB | 0.0 MB | 0.0 MB (60 s) | clears |

**Exit-path independent, and the residual is zero.** B200 had found ~1520 MB either way; H200/RunPod finds 0.

Residual decay, 30 minutes, process kept alive after `del` + `empty_cache()`:
```
t=0s 620 MB 86.92 W · 60s 620 MB 121.65 W · 300s 620 MB 121.87 W
t=900s 620 MB 126.13 W · 1800s 620 MB 126.00 W
```
Confirmed a second time when GPU0 settled at 628 MB after the cross-GPU test with its process still alive. **The behaviour is binary:** the CUDA caching allocator holds ~620 MB indefinitely while the process lives and releases completely on exit. No decay, no middle state.

### 1.9 Cross-GPU isolation — three pairs at once

`scripts/cross_gpu_isolation_check.py` initially reported GPU1 1.0 → 4.0 MB after a GPU0 workload, verdict "possible isolation bleed." Isolated the mechanism:

- `torch.cuda.device_count()` alone → all four GPUs stay at 1 MiB
- single context + allocation on GPU0 alone → GPU0 640 MiB, **GPU1/2/3 all 4 MiB simultaneously**

That is CUDA context peer-mapping on an NV18-connected box, not data crossing a boundary. **False positive** — the script flags any nonzero delta.

Then all pairs measured together, workload on GPU0 only:
```
BEFORE  GPU0 4.0     GPU1 4.0  GPU2 620.0*  GPU3 4.0
DURING  GPU0 1140.0  GPU1 4.0  GPU2 620.0*  GPU3 4.0
AFTER   GPU0 628.0   GPU1 4.0  GPU2 620.0*  GPU3 4.0
* concurrent decay test's allocator pool
```
**GPU1, GPU2, GPU3 did not move by a single MB.** Zero cross-GPU residual on 0→1, 0→2 and 0→3. The 528 MB GPU0→GPU1 figure from the Serial Alice Intel TDX CVM does not reproduce on bare RunPod — two orders of magnitude apart. It is likely a CVM artifact.

### 1.10 Collective communication — real NCCL

Real `all_reduce` across all four H200s over NVLink, each rank starting with (rank+1):

| Rank | pre-digest | post-digest | value |
|---|---|---|---|
| 0 | e678838a4ec435fc | 14d254a39cbd9b86 | 10.0 |
| 1 | a2593333ae6a852e | 14d254a39cbd9b86 | 10.0 |
| 2 | eb8a846ab9226b38 | 14d254a39cbd9b86 | 10.0 |
| 3 | 9805f10af9e2eb26 | 14d254a39cbd9b86 | 10.0 |

4 distinct → 1 identical, sum exact. **CONSISTENT.**

Fed through `CollectiveCommSDCTracer.check()` with the correct op_record schema:
- Real data → `COLLECTIVE_CONSISTENT`, INFO
- Rank 2 digest replaced → `COLLECTIVE_SDC_DETECTED`, **CRITICAL**, `distinct_results 2, majority_rank_count 3, divergent_ranks [2]`, detail: *"the corruption is in the communication path, not the per-GPU compute"* — **it localised the offending rank**
- Malformed ranks → `COLLECTIVE_CHECK_ERROR`, WARNING, "failed loud, NOT reported clean"
- Missing digest → `COLLECTIVE_CHECK_INCOMPLETE`, WARNING
- Stats: 4 checks, 1 flag

`FaultAttributionEngine.attribute()`:
- Fabric signals (COLLECTIVE_SDC_DETECTED, NVLINK_CONTENTION, PCIE_ANOMALY) → `interconnect` score 2.2 share 0.71, `fabric_switch` 0.6
- **Environmental carve-out, confirmed on execution:** SOLAR_PARTICLE_EVENT + ECC_BREAK_SUSPECTED + TID_THRESHOLD_CROSSED → ranked `hbm` 0.591 / `gpu_die` 0.409, verdict ATTRIBUTED, WARNING, and `environmental_note: "an environmental cause is present — the component may be HEALTHY and merely exposed; do not retire hardware on this evidence alone"`
- Unknown signal names → `NO_COMPONENT_IMPLICATED`, refuses to guess
- Every response: *"a ranking over evidence, not proof — 'most consistent with', never 'caused by'"*

### 1.11 Precision ghost power

`scripts/precision_ghost_power_benchmark.py`, first execution anywhere:

| Precision | Ctx idle W | Active W | CEI (FLOPs/J) | Ghost W | Ghost share |
|---|---|---|---|---|---|
| fp32 | 122.5 | 660.2 | 7.76e10 | 43.7 | 6.6% |
| tf32 | 128.2 | 692.2 | 5.08e11 | 49.4 | 7.1% |
| bf16 | 127.7 | 692.2 | 9.70e11 | 48.9 | 7.1% |
| fp16 | 128.1 | 691.9 | 9.38e11 | 49.3 | 7.1% |
| int8 | 124.8 | **355.7** | **3.62e11** | 46.0 | **12.9%** |
| fp8, fp4 | UNSUPPORTED in this torch build | | | | |

Script verdict: **NOT CONFIRMED** — no gradient among tf32/bf16/fp16, which all draw ~692 W. What the data does show: the ghost term is constant (43.7–49.4 W) regardless of precision — a memory/context property; the share doubles at int8 precisely because active power halves; and **int8's CEI is worse than bf16's despite half the power** — the precision paradox, measured on hardware.

### 1.12 VRAM residency challenge

`scripts/vram_residency_challenge.py` (Monfared et al., arXiv 2602.09369), 512 MB, 20 rounds:
- hot_threshold 0.3405 ms, cold_threshold 50.34 ms
- 19/20 hot; round 3 "ambiguous" at 0.3665 ms
- All 20 rounds in 0.30–0.37 ms. The ambiguous round is 0.026 ms over the hot bound and **50 ms below** the cold bound. Not an eviction — the hot threshold sits inside the natural jitter band.

### 1.13 Contention and audits

`gpu_audit.py`, 1 competing process, 3 runs:

| Run | Baseline | Contended | Loss |
|---|---|---|---|
| 1 | 366.47 it/s | 175.59 | 52.09% |
| 2 | 371.16 | 175.91 | 52.60% |
| 3 | 371.41 | 176.35 | 52.52% |

**Mean 52.4%, stdev 0.22%.** Inside the B200 band (−43% to −55%), not the original −9.5% Vast.ai single measurement.

`capture_contention.py`: power.draw **Cohen's d = 5.50** (659.7 → 603.2 W, clear separation); temperature d=0.64; utilization.memory, clocks.sm, clocks.mem all d=0.00. Verdict: SIGNAL PRESENT, detector viable. clocks.mem flat at 3201 MHz — third independent confirmation tonight that the memory clock does not move.

Tenant files: /tmp, /var/tmp, /dev/shm scanned, **0 foreign-owned files**. /dev/shm 469 GB, 0% used. Third clean RunPod scan.

`aggregate_audits.py`: 1 instance / 1 provider, 0/1 tenant files, 0/1 unpatched host, 1/1 contention.

Full module run: 23 modules, 46 events, 4 alerts. `MODULE_ERROR` ×2 (module146 and modules_146_150_combined, both `qiskit` missing — quantum on a GPU pod, expected). `SUSPICIOUSLY_NOISELESS` CRITICAL from module51, noise_fraction 0.00024, "Too clean — likely simulation" — **second false positive of the session**, on real idle telemetry that genuinely has 0.05 W spread across five reads.

### 1.14 Capability checks

| Field | Result |
|---|---|
| PCIe static link info | YES (Gen 5 on all four) |
| PCIe real-time throughput | idle: MAYBE. **Under a forced 300× host↔device transfer: rx 7746 / 8605 / 4184 MB/s, tx 2927 / 2125 / 2122 / 2068 MB/s on GPU0, peers at 0–5.** A PCIe bandwidth detector is buildable. |
| ECC corrected / uncorrected | readable, 0/0 on all four, start and end |
| `/proc/net/tcp` | readable — `EgressCollector.collect()` executed, mode `proc`, real rows with proto/ip/port/state/inode |
| `utilization.memory`, `encoder.stats.averageFps`, `clocks_throttle_reasons.active` | readable |
| `retired_pages.pending` | [N/A] — H200 uses row-remapping |
| **TLB miss counters, cache-eviction perf counters, GPU.zip compression channel, Baddour micro-arch channel** | **NOT PRESENT** in nvidia-smi PERFORMANCE/UTILIZATION. Do not build those four detectors for H200. |
| Confidential computing | `CC State: OFF · CPU CC Capabilities: None · GPU CC Capabilities: CC Capable · CC GPUs Ready State: Not Ready` |
| `/dev/nvidia*` | 0, 3, 4, 6 — non-contiguous, mapped to CUDA 0–3 |

### 1.15 CVE checks — three methods, three answers

CVE-2026-31431 "Copy Fail", Linux kernel LPE, CISA KEV, disclosed 2026-04-29. Kernel here 6.8.0-83-generic.

| Check | Method | Result |
|---|---|---|
| `check_copyfail_afalg.py` | AF_ALG socket reachability | **`[NOT MITIGATED VIA THIS PATH] AF_ALG socket creation SUCCEEDED`** |
| `container_escape_test.py` | kernel version match | "CVE-2026-31431: not detected on this host" |
| `gpu_audit.py` stale_cve | version range | PARTIAL — declines automated matching without an authoritative DB; lists this CVE for manual verification |

The AF_ALG script's own caveat: *"does not confirm the host is vulnerable — only that this specific mitigation is absent."* The disagreement is the finding; none is conclusive alone.

CVE-2026-64600 "RefluXFS": XFS present but `xfs_info` unavailable in the container; script reported it could not determine reflink status rather than claiming clean. Verdict: exposure conditions not met.

Container escape: 2/3 — `/proc visible, possible container escape vector`.

### 1.16 Test suites on hardware

| Suite | Result |
|---|---|
| Every `test_*.py` in `tests/` (74 files, excl. test_pod_runner) | **1154 passed, 3 failed** — all three assert no-GPU fallback behaviour and can only pass on a machine *without* a GPU (inverted) |
| `attack_injection_suite.py` | **40/40 across 9 modules.** Identified `GPU0 Arch: H200 | Idle floor: 80.36W`, 8 agents + correlator, attestation baseline `d88931ae2f876562`. Memory 5/5, LLM 7/7 — every positive control paired with a silent negative control, every alert names what it cannot distinguish |
| `test_engines.py` | **17/17** including `PIPELINE NEGATIVE CONTROL: 3600 clean idle samples, 0 alerts` |
| `run_all_tests.py` | Container Escape FAIL (/proc), Compliance PASS |
| `compliance_evidence_test.py` | 2/2, AuditLedger chain VALID, 10 entries |
| `resource_benchmark.py` | 10,000 rows in 6.18 s = 1618 rows/s (rerun 1632); memory 12.0 MB min and max, **variance 0.0 MB** — no leak |
| `competitor_benchmark.py` | 3 confirmed structural advantages, 1 pending; own note: no live side-by-side performed |
| `cpu_advanced_tests.py` | numactl absent; 100 threads × 10k ops 2.54 s; **memory latency ratio 11.86×** (seq 0.0422 s, random 0.5011 s) |
| `burnin_stability.py` | configured for 24 h; 5 samples captured before kill: memory **1960.29–1960.83 GB, variance 0.54 GB** on a 1960 GB host, load 2.6–2.8% of 192 cores, ctxt/s settled 63k → 18.9k |
| `swarm_test.py` (needs API) | 1/1 reachable, **ThroughputContentionDetector triggered: True** — first live confirmation; it never evaluated in any daemon run |
| `test_metrics_alert_firing.py` (needs API) | 7 distinct metric names, PASS |
| `test_webhook_pipeline_delivery.py` (needs API) | FIRING processed, RESOLVED processed |
| `verify_patched_daemons.py` | 10/11 OK, module56 TIMEOUT |
| `check_indent_mismatch.py` | 8 files flagged in validation_results/ |
| `repo_hygiene_audit.py` | 701+ bare-excepts, concentrated in dormant todo/module19–20 |
| `audit_dead_imports.py` | correctly classified threat_intel.py LIVE (imported and called by threat_intel_airgap.py) |

**Never executable:** `false_positive_benchmark.py`, `latency_test.py`, `stability_test.py` all call `TelemetryCollector(hz=…)` and `.collect()`. The real API is `sample_hz=` and the class exposes only `start` and `stop`. These three have never run. `run_all_tests.py` excludes them citing "require real GPU hardware" — on 4× H200 they still fail; the stated reason is wrong.

**Environment-bound, not skipped:** torture/endurance (72 h), quantum modules (no QPU), neutral_current_harmonic (no PDU), module56 FPGA/JTAG verifier (hangs on absent hardware, rc=143, zero output).

**The API server** required fastapi + uvicorn, which were absent; `watchdog.py --api` ran silently as a daemon with no HTTP listener and the log said so in one line. After installing, python3 listens on 0.0.0.0:8080 and `/health` returns `{"status":"ok"}`.

### 1.17 GPU Optimizer — clock sweep (branch `h200-clock-sweep`)

`energy/clock_correlation_sweep.py` on H200 for the first time (Nelson's bare-metal work was H100 only):

| | H100 (Nelson) | **H200 (tonight)** |
|---|---|---|
| r² power vs SM clock | 0.935 | **0.974** |
| r² power vs memory clock | 0.000 | **0.000** |
| Memory clock | pinned 2619 MHz | **pinned 3201 MHz** |
| Switch cost 0→0.5% util | 280 W | **255 W** |
| Explained by memory | 0 | **0.0** |

Verdict `SM_CLOCK_DRIVEN`. 10 steps, 353 rows, power range 432.3 W, memory clock never moved. Combined with Nelson's bare-metal `-lmc` force test on H100 (119.28 vs 119.06 W baseline, no recovery), the memory-clock recovery path is closed from both directions on two architectures.

---

## PART 2 — BUGS FOUND

### In Watchdog (nine)

| # | Bug | Severity | Evidence |
|---|---|---|---|
| 1 | **Cluster actions do not validate targets** — `slurm_evict_job(None)` reached `scancel`, failed only on DNS | **High** — on a live cluster, a null-target evict would be sent | §1.7 |
| 2 | GhostPowerDetector false positive — reported 44.5/48.1 W above floor while GPU read 78.9 W ×5 | High for credibility | §1.4 |
| 3 | module51 SuspiciouslyNoiseless fires CRITICAL "likely simulation" on real idle telemetry | Medium | §1.13 |
| 4 | Three test files call a nonexistent API (`TelemetryCollector(hz=)`, `.collect()`) — never runnable | Medium — the FP-rate and latency numbers have never been produced | §1.16 |
| 5 | `cross_gpu_isolation_check.py` flags 3 MB peer-mapping overhead as "isolation bleed" | Medium | §1.9 |
| 6 | `vram_residency_challenge.py` hot threshold sits inside the jitter band | Low | §1.12 |
| 7 | `watchdog.py --api` runs silently with no listener when fastapi/uvicorn are absent | Medium | §1.16 |
| 8 | `run_all_tests.py` cites "require real GPU hardware" for tests that fail on real GPU hardware | Low | §1.16 |
| 9 | module56 hangs on absent FPGA hardware — no probe timeout | Low | §1.16 |

### In my tooling (six)

`remediation_live_test.py` imports `ClusterActions` (real: `ClusterOrchestration`) and parses return values that are None · `sigkill_residual_measure.py:197` hardcodes the verdict string regardless of `--signal` · `test_pod_runner.py` exceeds `run_all.py`'s 120 s timeout on a real-GPU host · `pod_runner.py` `sm_clock_uniform` returns None for a perfectly uniform clock · `ghost_power_probe` samples "true idle" on a GPU that already holds a context · I told you to run the negative control "on GPU3" when the script monitors GPU0.

---

## PART 3 — IS WATCHDOG BLUE CHIP?

**Short answer: no. Not yet. And the gap is specific, not vague.**

"Blue chip" here means: a Fortune-500 infrastructure team or a hyperscaler would deploy it in production, rely on its alerts, and let it act. Measured against that bar, honestly:

### What is genuinely at that level

**The alert discipline.** Every detector that fired tonight named what it could not distinguish. `SequentialVRAMReadDetector` fired CVSS 9.0 and said *"possible exfiltration OR bulk data load (cannot be distinguished from telemetry alone)."* `LASER_INJECTION` fired INFO and said *"cannot be detected from software telemetry alone."* `FaultAttributionEngine` ranked components and then said *"the component may be HEALTHY — do not retire hardware on this evidence alone."* I have not seen a commercial GPU monitoring tool do this. Blue-chip buyers pay for exactly this property, because it is what stops a 3 a.m. page from decommissioning a healthy card.

**The negative-control discipline.** 3600 synthetic samples with 0 alerts, 3523 real samples with 2, two daemon runs with 0, a master correlator with 0. The false-positive rate is *measured*, not asserted — and when it was nonzero, the ground truth was captured alongside and the bug was recorded rather than the run being rerun until it looked clean.

**The measurement rigour.** 52.4% ± 0.22% over three runs. r² 0.974 vs 0.000. Zero cross-GPU bleed on three pairs measured simultaneously. Every number sits next to a committed artifact.

**The self-labelling.** `is_evidence: True|False`. "Tier 1 / 2 / 3." "Real-hardware run — results are evidence, not a pass/fail of the detectors." A buyer's security team can audit what was claimed against what was measured without asking.

### What is not at that level

**Remediation has never executed.** Every action tonight refused — correctly, but that means there is no evidence any remediation *works*. `gpu_memory_reset` refused. `kill_process` refused. MIG quarantine refused. The three cluster actions refused by accident. Watchdog is, on tonight's evidence, a detection product with a remediation layer that has been proven safe and never proven effective. Blue chip means both.

**The one remediation defect is disqualifying until fixed.** `slurm_evict_job(None)` reaching `scancel` is the kind of bug that, in production, evicts the wrong job or a null job and gets the tool removed. It contradicts the README.

**False positives on idle hardware.** 0.057% sounds small. At 1 Hz across 1,000 GPUs it is roughly one false GhostPower alert every two seconds. And module51 raised CRITICAL on genuinely idle telemetry. A blue-chip SOC turns off any source that does that within a week.

**The container gap.** compute_apps is empty in a RunPod container, so `VRAMResidualDetector` — one of the four foundational engines — cannot evaluate where most GPU rental actually happens. That is a platform limitation, correctly documented, but it means a headline detector is silent on the deployment target.

**Coverage is narrower than the count.** 41 engines are documented. The daemon loads 3. Two prediction agents are structurally silent (they need FLOPs/joule no passive field provides). Three test files that would produce FP-rate and latency numbers have never run. The distance between "41 engines" and "what runs on hardware tonight" is large and a buyer's engineer will find it.

**Operational maturity.** Single operator. No third-party security audit. No SOC 2, no ISO 27001 (both in progress per SECURITY.md). API server silently failed to start because two packages were missing. 701 bare-excepts in the dormant module tree. A hang in module56 with no timeout. Two CVE checks that disagree with each other on the same host.

### What would close the gap, in order

1. **Fix the cluster-action target validation.** Null check before every subprocess call, explicit `NO_TARGET` refusal, narrow the except. This is a day's work and it is the one item that would embarrass you in diligence.
2. **Fix the two idle false positives** — GhostPowerDetector's telemetry sourcing and module51's noise-floor calibration. Then re-run the hour and get the 0 the README promises.
3. **Prove one remediation actually executes.** On a real Kubernetes or SLURM cluster, with a real target, watch `kubernetes_taint` apply and log. One working action changes the product's category.
4. **Make the three broken tests run**, so the false-positive rate and detection latency are numbers rather than test files.
5. **Reconcile the engine count** — state plainly which of the 41 run in the daemon, which are separate paths, and which cannot evaluate in containers.
6. **A second hostile provider.** Vast.ai gave you 5/5 dirty and an unpatched KEV host. RunPod is clean. The findings that sell a security product live on the badly-run platforms, and you have sampled one of each.
7. Then the paperwork — the audit, SOC 2 — which cannot start until 1–5 are done anyway.

### Where it actually stands

Watchdog tonight is a **research-grade validation platform with an unusually honest measurement discipline, and a remediation layer that is safe but unproven.** That is a real and defensible thing to be. The evidence artifacts from this session are stronger than most vendors' marketing claims, precisely because half of them are negatives.

It is not blue chip. It is roughly two focused engineering weeks and one real cluster away from being able to make that claim without an engineer on the other side of the table finding the gap in ten minutes. The bugs found tonight are the map to those two weeks.
