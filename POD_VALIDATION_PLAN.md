# Watchdog — Real-Hardware Validation Plan (4× H200 RunPod)
**GPU Optimizer Inc. | Mike Bains | August 2026**
**Purpose:** define exactly what the RunPod 4× H200 session validates, at what confidence tier, so no result is ever over-claimed. This is the reference for building and running the pod harness (swarm #4). Read this before renting.

---

## The core principle: three confidence tiers

Every detector / swarm agent gets validated at exactly ONE of these tiers, and the result is labelled with which:

- **TIER 1 — TRUE-POSITIVE.** A real condition is induced on real hardware and the detector/agent is confirmed to fire on it (plus stays silent on a clean control). This is the strongest claim. Only these may lose the `NOTE: simulation-based` label.
- **TIER 2 — CAPABILITY CHECK.** The telemetry field is confirmed to exist on the H200, the detector reads it, and it correctly stays silent on clean data (negative control). Proves the detector *would* work on real telemetry, but no real attack was triggered. Keeps a qualified note: "telemetry path validated on H200; true-positive pending owned-hardware trigger."
- **TIER 3 — CANNOT VALIDATE HERE.** Needs owned bare-metal, out-of-band management, or a research partnership. Recorded with the reason. Stays fully simulation-based.

**Never label a Tier 2 result as Tier 1.** A capability check is not a true-positive. This is the same discipline as the existing test suite's "logic-tested ≠ hardware-validated."

---

## Key insight that unlocks the highest-value item

"Cross-tenant" does NOT require two hostile customers. On a pod you rent, you own every process on the card. Proving **Process B can read what Process A left in VRAM after A exits** IS the cross-tenant residual vulnerability, demonstrated safely — the two "tenants" are two processes you control, in different contexts, and the finding is "residual crosses the process boundary on the same physical GPU." Legitimate, safe, pod-runnable. This moves the single highest-value backlog item from "cannot validate" to **Tier 1**.

The distinction that matters: staging both sides of a residual read that YOU own = fine. Attacking another live customer's data = not fine, not needed, never do it.

---

## What the 4× H200 session validates, by tier

### TIER 1 — TRUE-POSITIVE (real trigger → confirm fire)

| # | Validation | How | Detector/agent confirmed |
|---|---|---|---|
| 1 | **Same-GPU cross-process VRAM read** — THE finding | Process A allocates + writes a known ~512MB pattern to VRAM, exits without cleanup. Process B (fresh process, ideally different UID/container context) allocates and scans for A's pattern. Pattern found → residual is readable across the process boundary. | Turns the confirmed "accounting gap" into a proven cross-process read. VRAMResidualDetector / LeftoverLocals (CVE-2023-4969). |
| 2 | **Cross-GPU residual (GPU0→GPU1)** | Allocate + compute on GPU0, exit. Scan GPU1 for residual originating from GPU0's compute. Reproduces the 528MB Serial Alice CVM measurement on bare RunPod. | Cross-GPU isolation finding, currently one CVM-only measurement. |
| 3 | **NVLink live-fire** | Induce a real cross-GPU NVLink transfer (2+ cards), confirm NVLinkContentionDetector fires end-to-end. Three bugs already fixed, rate math verified (~2.95M KB/s), never confirmed firing live. | NVLinkContentionDetector (SideLink/NVBleed/Spy-in-the-GPU-box research). |
| 4 | **Cryptojacking onset (agent 7)** | Run a real miner (e.g. a monero CPU/GPU miner in a controlled container) and watch agent 7 fire COVERT_COMPUTE_ONSET_PREDICTED on the real ramp. Negative control: legit memory-heavy training must NOT fire. | Swarm agent 7 + existing CovertMiningDetector. |
| 5 | **Model-extraction sweep (agent 8)** | Drive a real high-rate, low-variance inference query sweep against a served model, watch agent 8 fire MODEL_EXTRACTION_PRECURSOR_PREDICTED. Negative control: organic mixed traffic must NOT fire. | Swarm agent 8. |
| 6 | **Ghost power / VRAM residual / CEI** | Re-run existing measurement harnesses on 4 cards. Confirm ghost power floor, VRAM residual (0 bytes recoverable vs accounting residual), CEI ratios. | GhostPowerDetector, VRAMResidualDetector, CEI pipeline. |
| 7 | **Full swarm + response pipeline live** | Feed real 4-card telemetry through WatchdogSwarm.ingest() → SwarmResponsePipeline (correlator → remediation coordinator → investigator). Confirm the whole stack runs on real data and produces plans/investigations for real alerts. | All 8 agents + correlator + remediation + investigator, end-to-end. |

### TIER 2 — CAPABILITY CHECK (telemetry path + negative control only)

| # | Validation | How | Why not Tier 1 |
|---|---|---|---|
| 8 | **Agent 6 — Rowhammer/ECC-break telemetry path** | Confirm ECC corrected/uncorrectable fields exist on H200 (`nvidia-smi -q` / dmesg), agent 6 reads them, and stays SILENT on clean ECC. | Cannot SAFELY trigger a real bit-flip on a rented pod — GPUThor/GPUHammer tooling risks the provider's card and your account. True-positive needs owned bare metal or a U-Toronto partnership. |
| 9 | **ECC-break detector (batch 2) telemetry path** | Same as above for the detection-side gpu_memory_integrity ECC-break watcher. | Same reason. |

### TIER 3 — CANNOT VALIDATE HERE (recorded, not attempted)

| Item | Why | What it would need |
|---|---|---|
| Agent 6 / ECC-break TRUE-positive | Can't safely induce real bit-flips on rented infra | Owned GDDR6 bare-metal rig running the published GPUHammer harness, OR U-Toronto (GPUHammer) / GPUThor authors' flip-log traces replayed through agent 6 |
| BMC / IPMI / firmware / PMBus / liquid-cooling telemetry | Cloud pods don't expose out-of-band management | Bare metal with Redfish/IPMI, or colocation |
| Hostile-tenant PoC (attacking another customer) | Illegal / against provider ToS / never appropriate | Nothing — this is out of scope by design. The Tier 1 #1 self-owned two-process read is the correct, safe substitute. |
| EM / acoustic / vibration side-channel | Needs physical sensors near the card | SDR dongle, MEMS accelerometer, bare-metal wiring |

---

## Harness design (swarm #4 — to build before renting)

Structure: **one script, dry-run mode first.** `python3 pod_validation_harness.py --dry-run` prints the full plan and touches NOTHING. `--live` runs each stage sequentially, saving JSON evidence per stage (job-id-style: timestamp, GPU, tier, pass/fail, raw telemetry). Each stage self-labels its tier so results can never be mis-cited.

Language: **PyTorch cuda tensors primary** (almost certainly already on the pod), with notes where raw CUDA/cupy would give a stronger low-level residual scan.

Stage order (cheapest/safest first, so a failure early doesn't waste GPU-hours):
1. Environment capture — `nvidia-smi`, driver/VBIOS, NVLink topology, ECC config, arch confirm (guard against B200-logged-as-H200).
2. Tier 2 capability checks (agent 6 ECC path) — read-only, no risk.
3. Ghost power / VRAM / CEI re-run (Tier 1 #6) — known-safe.
4. Same-GPU cross-process read (Tier 1 #1) — two-process, the headline.
5. Cross-GPU residual (Tier 1 #2).
6. NVLink live-fire (Tier 1 #3).
7. Miner + query-sweep true-positives (Tier 1 #4, #5) — controlled containers.
8. Full swarm + pipeline on live telemetry (Tier 1 #7).
9. Evidence bundle — write all JSON to Watchdog-quantum-collab/results/ style, commit.

Each Tier 1 stage MUST include its negative control in the same run (the detector staying silent on clean data), or the positive result is not trustworthy — same rule as the existing test suite's negative-control discipline.

**Evidence rule:** a validation only counts if it produces a committed JSON artifact with a real timestamp, the GPU UUID, the raw telemetry, and the tier label. No artifact = not validated, exactly like the "PROVEN needs a job ID" rule already in the repo.

---

## What changes after a successful session

- Tier 1 passes: the specific detectors/agents may drop `NOTE: simulation-based` and cite the evidence artifact instead. ONLY those that got a Tier 1 true-positive.
- Tier 2 passes: note updates to "telemetry path validated on H200 <date>; true-positive pending owned-hardware trigger."
- Tier 3: unchanged, stays documented as needing bare metal / partnership.
- Update HARDWARE_LIMITATIONS.md and EVIDENCE.md with the artifact references.
- The same-GPU cross-process read (Tier 1 #1), if it passes, is the single biggest status change in the project — "accounting gap" becomes "proven cross-process residual read (CVE-2023-4969 class), demonstrated on H200 <date>, artifact <hash>."

---

## Honest guardrails (carry into any external material)

- Only Tier 1 results are "validated on real hardware." Tier 2 is "telemetry path confirmed." Never blur them.
- The self-owned two-process read is NOT an attack on another tenant and must be described that way — "cross-process residual read on hardware we controlled end-to-end," not "we broke another customer's isolation."
- Agent 6 stays simulation/capability-only until owned bare metal or a research partnership provides a real flip. Do not imply Watchdog has caught a live Rowhammer attack.
- Everything in this repo remains simulation-based until the specific artifact exists. This doc is the plan, not evidence.
