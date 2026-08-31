# Watchdog — SDC / Compute-Integrity: Build Brief
**GPU Optimizer Inc. | Mike Bains | August 2026**

Five compute-integrity detectors + a swarm correlation rule, catching Silent Data Corruption (SDC) — the case where hardware computes a WRONG answer with no error flag. 27 tests, 0 failures. This is **In-Flight Runtime Integrity**: the layer NVIDIA's DCGM/NVSentinel (health monitoring + offline diagnostics) does not cover.

---

## Why this matters

- SDC is real and worsening: ~1 in 1,000 machines (Google "Cores That Don't Count," Meta "SDC at Scale"); soft-error rate went from 1/year at 65nm to **1 per 1.5 hrs at 16nm**. Meta: 1.4% of Llama-3 interruptions were SDC. Google: an SDC event every 1–2 weeks at Gemini scale.
- **The gap:** DCGM reports "Healthy" while the customer gets garbage — it never verifies that a *running production computation* was correct.
- **Endorsed by the industry:** the OCP "Silent Data Corruption in AI" whitepaper (Nishant George, NVIDIA, Dec 2025; founded by AMD/ARM/Google/Intel/Meta/Microsoft/NVIDIA) explicitly endorses in-flight, low-overhead integrity checking.

## What was built

| Detector | What it catches | Precision | Cite |
|---|---|---|---|
| **DrDNAMonitor** (LEAD) | Deviation from the profiled normal Distribution of Neuron Activations — whole-model, precision-agnostic | FP8 + FP4 | Ma et al., ASPLOS '24 |
| **NullificationCascadeDetector** | Nullification (50.68% of SDCs) + NaN/Inf cascades (dominant at FP4, where a scaling-factor flip poisons 16 packed values) | all, FP4-aware | Anatomy of SDC (2605.04213) |
| **FreivaldsVerifier** | Corrupt matmul result via O(n²) probabilistic check — **FP8-only, matmul-only, honesty-gated to refuse FP4** | FP8 only | Freivalds; ABFT (2103.00130); OCP |
| **VoltageDroopCorrelator** | A dI/dt voltage/power droop co-occurring with an integrity flag = physically-grounded SDC; links to GPU Optimizer undervolting | all | NVIDIA/AMD droop patents; Anasim H100 PDN |
| **TMRVoter** | Triple-run majority vote — **high-value opt-in only** (OCP calls redundancy "unfeasible" at scale) | all | OCP whitepaper |
| **SDCSwarmCorrelator** | Fuses SDC + ECC-break + thermal → "degrading silicon incident"; droop-confirmed → its own incident | — | swarm discipline |

## Positioning (honest)

- **In-Flight Runtime Integrity, complementary to DCGM** — not competing with hardware-health monitoring.
- **Overhead numbers for buyers:** V-ABFT ~12%, SEVI 1.35% at 88–100% detection, vs DMR/redundancy >200% (the "unfeasible" approach). Watchdog leads with the lightweight distribution-based method, offers ABFT as the FP8 matmul layer, TMR only for high-value opt-in.
- **Two-product link:** GPU Optimizer undervolting *raises* droop-SDC risk → this suite is the safety net that lets Optimizer push efficiency harder. Pitch: *"we optimize your power AND guarantee the math stays correct."*
- **Buyer language:** SDC silently degrades **Model FLOPs Utilization (MFU)** and **protective goodput** "without appearing in any log."

## Honesty guardrails (baked into the code)

- **First-to-product, NOT first-to-idea** — academia is active (Dr. DNA, ATTNChecker, V-ABFT, FLARE, OVIG, Meta Hardware Sentinel). Never claim "world first."
- **ABFT is matmul-only (~75% of compute), not softmax/nonlinear** — that's why Dr. DNA leads. The Freivalds detector literally refuses FP4 (`FREIVALDS_NOT_APPLICABLE`).
- **Remediation is gated re-run, never default** (OCP: heavy overhead unfeasible).
- **Simulation/logic-tested, not hardware-validated** — validating against a silently-corrupting GPU needs an aged/defective card (why hyperscalers hunt "mercurial cores" across millions of machines). Per-model calibration required.

## Future extension (documented, not built)

- Attention-layer ABFT (ATTNChecker/Flash-ABFT), distributed all-reduce SDC (network-path), training-loss-trace SDC (LLM-PRISM), and the orbital/space market (same Dr. DNA detector extends to LEO, where SDC is worse and 3.6× costlier — a future market the terrestrial build reaches without redesign).

*Files: detection/sdc_compute_integrity.py, detection/sdc_compute_integrity2.py, intelligence/swarm/sdc_swarm_correlator.py, tests/test_sdc_compute_integrity.py.*
