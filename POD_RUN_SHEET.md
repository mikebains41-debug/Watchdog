# POD RUN SHEET — 4× H200 SXM

**Companion to `POD_VALIDATION_PLAN.md`** (which defines the tier scheme). This is the sheet you tick through on the pod. Book **5 hours** — work is ~3.5h, the rest absorbs first-run fixes on code that has never touched hardware.

---

## Before booking
- [ ] 4× H200 **SXM** — PCIe has no NVLink, three stages can't run
- [ ] Whole GPUs, not fractions. Check Community Cloud pricing first
- [ ] PyTorch template · GitHub PAT ready

---

## STAGE 0 — Environment capture (20 min)

- [ ] `nvidia-smi --query-gpu=index,name,uuid,driver_version,vbios_version,memory.total,power.limit,ecc.mode.current,utilization.gpu,power.draw,clocks.mem,clocks.sm,ecc.errors.corrected.aggregate.total --format=csv`
- [ ] `nvidia-smi topo -m` → **save it.** Which pairs share NVLink vs PCIe. Without it "residual reproduced on 0→2" is uninterpretable
- [ ] `nvidia-smi -q > evidence/nvidia_smi_full_start.txt` — complete device state, one command, settles later questions
- [ ] **Arch guard:** confirm all four report H200. A B200 logged as an H200 invalidates the comparison
- [ ] **All GPUs ~0% util.** Not 0% = a neighbour. Kill the pod, get another
- [ ] **GPU3 is the cold reference. Never touch it all session.** No context, ever
- [ ] `git clone` Watchdog · `mkdir -p evidence`
- [ ] `python3 tests/test_engines.py` and `python3 tests/attack_injection_suite.py` → 17/17 and 36/36

---

## STAGE 1 — Dry run first (5 min)

- [ ] `python3 runtime/pod_runner.py`

Prints the plan, touches nothing. **Confirm it lists 8 stages and captures 4 GPUs.** If the environment block shows `gpu_count: 0`, stop — nvidia-smi isn't readable and nothing downstream will work.

---

## STAGE 2 — Daemon (15 min)

- [ ] `python3 runtime/watchdog_daemon.py --dry-run`
- [ ] `nohup python3 runtime/watchdog_daemon.py --live --duration 300 &`
- [ ] Check `incidents.jsonl` — the unified correlator assembling **real** telemetry into incidents. Never run on hardware before

---

## STAGE 3 — Validation harness (90 min) — the main event

- [ ] `python3 runtime/pod_runner.py --live --victim 0 --workers 1,2 --out evidence/pod_$(date +%s)`

**It will REFUSE to run if torch.cuda or nvidia-smi is unavailable.** That refusal is the safety feature — the FakeBackend hardcodes `pattern_found=True` for the VRAM stage and would report a confident 6/6 with no hardware touched. Never pass `--allow-fake` for anything you intend to cite.

Six Tier-1 stages. Each must **fire on the induced condition AND stay silent on clean**:

| Stage | GPUs | Tier |
|---|---|---|
| covert_compute | 2 | 1 |
| nvlink_livefire | 2 | 1 |
| vram_cross_process_read | 1 | 1 — **the headline** |
| cross_gpu_residual | 2 | 1 |
| ghost_power | 1 | 1 |
| sdc_drdna | 1 | 1 |
| rowhammer_capability | 1 | **2** — telemetry path only |
| quantum_control_plane | — | **3** — not attempted |

- [ ] Confirm `backend: real` and `is_evidence: True` in the output. If it says `fake`, nothing from that run is evidence
- [ ] **Never bit-flip rented hardware.** Rowhammer stays Tier 2 by design

---

## STAGE 4 — The SIGKILL question (15 min)

The README names this as unanswered: *"kill the process, watch memory.used, allocate nothing."* Both existing tests allocate a 256MB buffer to read, so they structurally cannot answer it.

- [ ] `WD_DRY_RUN=false python3 scripts/sigkill_residual_measure.py --gpu 1 --mb 512 --signal SIGKILL --watch 120 --out evidence/sigkill_residual.json`
- [ ] Repeat with `--signal SIGTERM` → does the residual differ by exit path?

Three possible verdicts: `SIGKILL_CLEARS_ACCOUNTING` · `RESIDUAL_DECAYS` · `RESIDUAL_SURVIVES_SIGKILL`.
**B200 found it exit-path independent (~1520MB either way).** If H200 reproduces that, the residual is a driver property, not an exit-path artifact — a stronger claim.

> This measures **accounting**, not recoverability. SIGKILL is already disproven as a remediation for cross-tenant residual (B200, zero recoveries). Never cite this as a remediation test.

---

## STAGE 5 — Hypervisor boundary (45 min) — highest-value open item

528MB GPU0→GPU1 measured **once**, inside the Serial Alice CVM. GPU property or CVM artifact — unknown.

- [ ] `python3 scripts/cross_gpu_isolation_check.py` for **0→1** and **0→2**
- [ ] Both reproduce → GPU property, real finding
- [ ] NVLink pair only → topology-dependent, different claim
- [ ] Neither → likely a CVM artifact (also a finding)
- [ ] Compare to baselines: A100 382MB · H100 625MB · H200 629MB · B200 726–728MB
- [ ] Compare against untouched GPU3

**Expect zero bytes recoverable.** Every prior test returned zero. The finding is the accounting gap and whether it crosses the hypervisor boundary — *not* data recovery. Log the zero either way.

---

## STAGE 6 — `gpu_memory_reset` effectiveness (10 min)

Exists in `remediation/response.py`, gated behind human approval, **never tested live.**

- [ ] After confirming residual, trigger it. Record exactly: **success / permission denied / device in use**
- [ ] **A FAIL is a valid loggable result**
- [ ] Update `EVIDENCE.md` and `HARDWARE_LIMITATIONS.md` either way
- [ ] **Deck fix regardless of outcome: remove "SIGKILL leak cleanup" from slide 9**

---

## STAGE 7 — Capability checks (15 min)

Confirm the telemetry field exists **before** writing any detector. "Not available" is a real answer — it tells you not to build that detector.

- [ ] NVML TLB miss counters
- [ ] MICRO Oct 2025 cache-eviction perf counters
- [ ] GPU.zip compression channel reachable from NVML
- [ ] Baddour et al. micro-architectural channel
- [ ] `python3 scripts/check_pcie_telemetry.py`
- [ ] `python3 -c "import detection.egress_collector"` — does `/proc/net/tcp` read in a container?

---

## STAGE 8 — The negative control (60 min)

README: *"the negative control needs an hour on a clean idle H200 before it means anything."*

- [ ] `nohup python3 scripts/run_negative_control.py &` on the **untouched GPU3**, one full hour
- [ ] Target: 3600 consecutive clean samples → **0 alerts**
- [ ] Run it during Stages 5–7 so it costs no extra wall-clock

---

## Free to capture while other things run

- [ ] `nvidia-smi -q > evidence/nvidia_smi_full_end.txt` at session end
- [ ] ECC corrected/uncorrected totals at start **and** end — did they move under load?
- [ ] `cat /proc/1/cgroup`, `ls /dev/nvidia*`, is `/dev/shm` visible? — container inspection
- [ ] Temperature alongside every power reading (CEI has ~20% variance from thermal throttling)
- [ ] Residual decay: measure at 0, 5, 15, 30 min after exit — transient or persistent?

---

## Rules during every run
- [ ] **Only this process reads the GPU.** No second terminal, no `nvidia-smi` elsewhere
- [ ] `nohup … &` — survives a browser reload
- [ ] Commit after each stage, not at the end
- [ ] **GPU3 untouched**

---

## Expected — not failures
- [ ] 1–2 telemetry field-name fixes on first run. This is why you booked 5h
- [ ] Ghost power on H100 would read ~0 (it's the documented negative control). **H200 is where ghost power lives** — 598.41W peak, 99.9% of cooldown samples
- [ ] Sample rate ~4–7 Hz not 100 Hz → `WORKLOAD_UNDERSAMPLED` firing is the blind-spot detector working
- [ ] Persistence mode / MIG refused → a result, not an error
- [ ] Zero bytes recoverable from VRAM residual → expected, log it

---

## Not on this pod
- [ ] `neutral_current_harmonic.py` — PDU SNMP/Modbus, no GPU involvement
- [ ] Quantum control-plane modules — no QPU
- [ ] Tenant /tmp residual — **no code exists**, and it needs two separate rental sessions
- [ ] Same-GPU cross-**tenant** — whole-GPU rental, can't simulate a co-tenant. The self-owned two-process read is the correct safe substitute; describe it that way
- [ ] Anything needing root
- [ ] GPU Optimizer scripts — separate session; they compete for the "only reader" constraint

---

## After
- [ ] `git add evidence/ && git commit -m "pod validation 4xH200 <date>" && git push`
- [ ] Update **EVIDENCE.md** and **HARDWARE_LIMITATIONS.md** — every deck claim maps to an EVIDENCE.md entry
- [ ] Only detectors with a **Tier-1 pass and a committed artifact** may drop the `NOTE: simulation-based` label
- [ ] Tier-2 note becomes: *"telemetry path validated on H200 <date>; true-positive pending owned-hardware trigger"*

---

## Time budget
Stage 0: 20 · Stage 1: 5 · Stage 2: 15 · Stage 3: 90 · Stage 4: 15 · Stage 5: 45 · Stage 6: 10 · Stage 7: 15 · Stage 8: 60 (parallel) · fixes: 30–60 · commit: 10 = **~3.5h of 5 booked**

---

## What this converts
All 670 tests are simulation-labelled today. A clean run earns six detectors **"fired on a real induced condition on real hardware, with a clean negative control"** — plus an answer to the SIGKILL accounting question and the hypervisor-boundary question that is currently one unreproduced measurement inside someone else's enclave.

**"PROVEN" / "VERIFIED ON REAL HARDWARE" only for findings with real hardware job IDs and commit hashes. No artifact = not validated.**
