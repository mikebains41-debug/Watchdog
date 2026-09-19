# Bare-Metal H200 Test Battery — What Each Script Does

Fifteen scripts. Ten are tests. Five are shared components the tests import —
they are not run directly but must be present.

Read `README.md` for the run order and the reasoning. This file is the
reference for what each individual script does and what it proves.

---

## THE TESTS

### 1. `max_recovery_ladder.py` — 45 min — **needs root** — MOST IMPORTANT

**What it does.** Establishes one ghost state, then runs eleven separate arms
against it, rebuilding the same ghost state between each so every arm is
measured against an identical baseline.

| arm | lever |
|---|---|
| A0 | ghost baseline, no intervention |
| A1 | `cuDevicePrimaryCtxReset` alone |
| A2 | SIGKILL (control — should match A1) |
| A3 | `-lgc` SM clock locked to minimum |
| A4 | `-ac` application clocks minimum |
| A5 | `-pl` power limit floor |
| A6 | `-lmc` memory clock minimum |
| **B1** | **reset THEN `-lgc`** |
| **B2** | **reset THEN `-ac`** |
| **B3** | **`-lgc` THEN `-pl`** |
| **C1** | **everything permitted, stacked** |

**What it proves.** Whether any privileged lever recovers power *on top of* the
context reset. The individual levers A3–A6 have published or expected values.
The combination arms B1, B2, B3 and C1 have never been measured by anyone —
that is the new ground.

**Why it matters.** The context reset already lands at the cold idle floor, so
on that lever alone there is nothing underneath. If more power is reachable, it
comes from a second lever stacked on top, and this is the test that finds out.

**Safety.** Restores `-rgc`, `-rac`, `-rmc` and the original power limit in a
`finally` block. Flags `COMBINATION_WINS` only when a combination beats the
best single lever by more than a 3 W noise band. Refused arms are recorded as
refused, never as zero recovery.

---

### 2. `sm_clock_lock_test.py` — 20 min — **needs root**

**What it does.** Two arms against the same ghost baseline. Arm one uses
`-lgc` to lock the SM clock down. Arm two uses `-ac` application clocks. Both
run **with the CUDA context still alive** — the context is never destroyed.
Reads back the achieved SM clock on every sample rather than assuming the
request took effect.

**What it proves.** Whether the watts can be recovered *without* destroying the
context. If they can, the switch gains a non-destructive mode — no 0.9–1.4 s
rebuild cost, no process boundary constraint.

It also verifies the Erlangen result (arXiv:2605.11999) on our own hardware.
They measured 47–90 W saved on H200 by locking the SM clock to 780 MHz during
inference decode, at under 1% throughput loss. That has never been reproduced
in-house because no rented provider permits the command.

**Known trap it handles.** `--lock-gpu-clocks` silently clamps requests at or
above 1830 MHz down to ~1830 on driver 590.48. The script detects the clamp
instead of recording the requested value.

---

### 3. `memory_clock_arm.py` — 15 min — **needs root** — THE >50% QUESTION

**What it does.** Enumerates supported memory clocks, forces the memory clock
to each, and reads memory power at every step.

**What it proves.** Whether memory power can be moved at all.

**Why it is the only path past 50% on H200.** Memory is 31.52 W of H200's
76.12 W idle floor — 41% of it. The reset cannot touch the floor. If memory
power can be reduced, the floor drops and the ceiling rises:

| | recovery |
|---|---|
| now, reset only | 38.9% |
| if memory power halved | **51.5%** |
| if memory power zeroed | **64.2%** |

**What the existing evidence says.** Against it. A clock-correlation sweep on
H100 returned r² = 0.000 against memory clock, pinned at 2619 MHz across the
entire range. On B200 and B300 memory power *falls* entering the ghost state.
Five architectures now point to SM clock as the mechanism and memory as inert.

But nobody has forced the memory clock with real root and watched what happens.
That is the open question, and this test closes it either way.

---

### 4. `fullsuite.py` — 6 h — no root needed, but phase 8 needs root to be useful

**What it does.** Nine phases, sequential, one GPU, with a second GPU left
untouched as a cold reference if available.

| phase | duration | what it establishes |
|---|---|---|
| P1 | 10 min | cold idle floor and memory power, on a GPU where no context has ever existed |
| P2 | 10 min | what an empty CUDA context costs, zero work performed |
| P3+P4 | 130 min | ghost state after real work, 60 min decay curve, then `cuDevicePrimaryCtxReset` and 60 min watch |
| P5 | 5 min | context rebuild latency, 20 trials — this is what sets the dwell timer |
| P6 | 15 min | SIGKILL versus reset — should land within 1 W, flags if not |
| P7 | 60 min | power floor map at 7 calibrated duty levels |
| P8 | 2 min | which privileged levers this host permits |
| P9 | 130 min | consolidation model |

**What it proves.** The complete per-architecture picture. This is the protocol
that produced the measured figures for A100, H100, H200, B200 and B300.

**Why run it again on bare metal.** Phase 8 on a root host establishes which
levers are actually available, which has never been possible on rented
hardware. Everything else serves as an independent reproduction on a different
host and driver.

---

### 5. `torture.py` and 6. `endurance.py` — 72 h — no root needed

**What they do.** Sustained maximum load, thermal cycling, and recovery
behaviour after prolonged stress. Continuous sampling throughout.

**What they prove.** Six things that a six-hour run cannot:

**Thermal drift.** Every ghost figure measured so far came from a card running
minutes to hours. Whether ghost power holds, grows or decays under sustained
thermal load over days is completely unmeasured.

**Long-horizon decay.** H100 shed roughly 11 W over a 60-minute ghost window
and then plateaued. What happens at 12, 24 or 48 hours is unknown. If ghost
power decays on its own over a long enough window, the switch is worth less
than currently claimed. If it holds flat, it is worth exactly what was
measured.

**Reproducibility.** The same measurement repeated across thermal states, so
figures carry error bars rather than being single values.

**Endurance under load.** The conditions a production datacentre actually runs
in, rather than a clean short test.

**Repeated reset durability.** Does `cuDevicePrimaryCtxReset` still recover the
same watts on the thousandth firing as on the first? Does anything leak or
degrade across thousands of teardown and rebuild cycles? This is the single
most important durability question for the product.

**Lever persistence.** If `-lgc` or `-pl` do recover additional power, do they
hold that recovery over 72 hours, or does the driver quietly drift back? A
lever that releases after ten minutes is worse than no lever.

---

### 7. `clock_correlation_sweep.py` — 6 min — no root needed

**What it does.** Ramps utilisation across ten steps from 0% to 25%, sampling
power, SM clock and memory clock at 1 Hz. Fits power against each clock
independently.

**What it proves.** Which clock actually drives the power switch.

**Result on H100:** r² = 0.935 against SM clock, **r² = 0.000 against memory
clock**, with memory pinned at 2619 MHz across the entire sweep. The switch
between 0% and 0.5% utilisation cost 280 W, of which memory clock explained
exactly none.

**Why run it on H200.** It has never been run there. If H200 shows the same
signature, the mechanism is confirmed on a second Hopper card — and it makes
the memory clock test above more predictive.

---

### 8. `fleet_consolidation.py` — 45–90 min — no root, **needs 2 GPUs**

**What it does.** A real N=2 consolidation measurement, not a model.

- **Spread arm:** GPU0 at u% duty and GPU1 at u% duty, both measured
- **Packed arm:** GPU0 at 2u% duty and GPU1 idled after a context reset, both
  measured

Counts matmuls completed in both arms. If the packed arm does less than 95% of
the spread arm's work, the level is marked `INVALID_WORK_NOT_CONSERVED` and no
saving is reported — because a power saving achieved by doing less work is not
a saving.

**What it proves.** The real fleet-level number.

**Why it matters.** The nine-phase suite's P9 runs one GPU and multiplies by N.
On A100 that model said 25.7% at 5% utilisation. The real two-card measurement
said **10.3%**. The model overstates by roughly 2.5× because it assumes the
packed card's power barely rises — and it does rise, from 172.50 W to 251.83 W
at the 25% level.

This has never been run on H200, where ghost power is larger than on A100.

---

### 9. `ab_final.py` — 40 min — no root needed

**What it does.** End-to-end A/B. Arm one: FP8 precision with process exit
between batches. Arm two: TF32 with the context left alive. 2,339 samples per
arm.

**What it proves.** The combined saving from precision selection plus context
management. Measured at **54.0%** — the only number above 50% anywhere in the
measured data.

**Why it matters.** It demonstrates that savings applying to different GPU
states stack rather than overlap. Ghost recovery alone caps at 41.6%; this
combines two levers and clears 50%.

---

### 10. `decode_workload.py` — 3 h — no root needed

**What it does.** Drives a real LLM inference decode workload rather than
synthetic GEMM matmuls.

**What it proves.** That the finding survives a real workload. Every
measurement to date used bf16 matmul loops. A production inference server has
different idle patterns — short gaps between requests, KV cache resident,
bursty arrival.

**Why it matters for the clock-lock case.** Decode is the phase where a GPU
draws 137–300 W on a 700 W card because it waits on memory rather than
computing. That inefficiency is what the SM clock lock targets, and it only
appears under a real decode workload.

---

### 11. `memory_bound_test.py` — 1 h — no root needed

**What it does.** Measures arithmetic intensity and memory bandwidth
utilisation during decode.

**What it proves.** That decode is genuinely memory-bound, which is the premise
the entire clock-lock saving rests on. If decode were compute-bound, locking
the SM clock would cost throughput rather than saving power for free.

---

### 12. `dcgm_probe.py` — 10 min — no root needed

**What it does.** Enumerates which DCGM fields and NVML counters are available
on this specific host and driver.

**What it proves.** What can be measured here at all.

**Why it is worth running first.** On B200 and B300, `nvidia-smi
--query-gpu=power.draw` returns `[N/A]` — power is only readable through
`nvidia-smi -q -d POWER` in the Power Samples block. Any tool built on the
query interface is blind on those cards. This probe catches that class of
problem before six hours of sampling produces an empty file.

---

## THE SUPPORTING COMPONENTS

These are imported by the tests above. They are not run directly, but the
tests will fail without them.

### `duty_cycle_fix.py`

Generates calibrated duty-cycle workloads. **Critical — this fixed a real
measurement bug.**

The earlier harness measured CPU queue time rather than GPU time. `a@b` is
asynchronous, so queuing for 50 ms of wall clock let the GPU execute a much
larger backlog. Measured on H100: asked for 5% utilisation, got 48%. Asked for
10%, got 50%. Asked for 25%, got 59%.

The fix calibrates milliseconds-per-matmul with CUDA events, issues exactly N
iterations per window, uses a 4-second period to avoid aliasing against
nvidia-smi's ~1 s sampling, reuses the output tensor, and reports achieved duty
alongside the target. Worst error 0.79% across 300–1000 TFLOPS.

Any P7 or P9 row without `achieved_pct` close to `target_pct` is mislabelled.

### `gemm_workload.py`

Standard bf16 matmul workload used as the load generator across all tests.

### `measure_power.py`

Shared power sampling. Handles both the `--query-gpu` interface and the
`-q -d POWER` Power Samples block, so it works on drivers where the former
returns `[N/A]`.

---

## WHAT IS NOT IN THIS SET

Two tests do not exist yet and are worth knowing about:

**MIG partitioning.** Whether ghost power exists per-slice on a partitioned
GPU, and whether the context reset works there. Most enterprise H100
deployments run MIG. If the switch does not work under MIG, a significant part
of the market is closed. No script exists.

**Cross-driver reproducibility.** Running the same suite on different driver
versions and comparing. This is a procedure rather than a script — it just
means running `fullsuite.py` more than once on different hosts.

---

## SUGGESTED ORDER

**If only a few hours are available:**

1. `dcgm_probe.py` — 10 min, confirms what is measurable
2. `max_recovery_ladder.py` — 45 min, the combination arms
3. `memory_clock_arm.py` — 15 min, the >50% question
4. `sm_clock_lock_test.py` — 20 min, the non-destructive path

Those four decide whether 50% is reachable.

**If days are available:** add `fullsuite.py`, then `torture.py` and
`endurance.py` for the 72-hour campaign, then `fleet_consolidation.py` if two
GPUs are available.
