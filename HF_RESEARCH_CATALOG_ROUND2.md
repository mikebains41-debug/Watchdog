# Watchdog — Hugging Face Research Catalog, Round 2
**GPU Optimizer Inc. | Mike Bains | September 2026**

A second systematic sweep of Hugging Face papers across Watchdog's four domains. **103 items catalogued.** Every entry is a real paper with a real arXiv ID surfaced by the Hub's own index.

## How to read this — the honest tiering

| Tier | Meaning | Count |
|---|---|---|
| **A — BUILDABLE** | a detector or capability Watchdog could implement from this | 11 |
| **B — REFERENCE** | cite it, calibrate against it, or use as a benchmark/dataset | 68 |
| **C — CONTEXT** | adjacent, useful to know, not actionable | 24 |

**Read this before using any of it:** the buildable yield is small *because Watchdog already covers most of this ground*. A catalog of 103 papers is not 103 features. Anyone presenting it that way is padding. Summaries are the Hub's own; papers marked with a dagger (†) were not individually fetched and their summaries are unverified.

---

# TIER A — BUILDABLE (11)

| # | Paper | arXiv | Why it's buildable |
|---|---|---|---|
| A1 | **Auditing Model Substitution in LLM APIs** (13 upvotes) | 2504.04715 | Detects when an API silently serves a cheaper/different model than billed. Directly extends Watchdog's model-integrity story to the *service* layer — "are you getting the model you paid for?" Output-based methods are weak; the paper points at hardware-based verification, which is Watchdog's strength. |
| A2 | **Crypto Miner Attack: GPU Remote Code Execution** | 2502.10439 | RCE on GPUs via *deserialization* vulnerabilities deploying mining. Your covert-mining detector catches the mining; this is the *entry vector*. A deserialization-surface check belongs next to the pickle/GGUF scanners. |
| A3 | **Silent Data Corruption by 10× Test Escapes** | 2508.01786 | Defective chips escaping manufacturing test at ≥10× industry targets. Real calibration for SDC base rates — how many bad chips are actually in a fleet. |
| A4 | **MemTrace: Tracing and Attributing Errors in LLM Memory Systems** (41 upvotes) | 2605.28732 | Fault *attribution* in memory systems — the "which component caused this" layer your SDC suite lacks. Highest-profile item in the sweep. |
| A5 | **Side-Channel Extraction of Dataflow AI Accelerator Parameters** | 2506.15432 | Recovers hardware config (folding, quantization) from side channels. An *IP-leakage* detector: your accelerator's configuration is extractable. New attack class for the hardware suite. |
| A6 | **THOR: Timing Side Channel Exploiting Intel AMX** | 2502.17658 | Infers NN weight *sparsity* via AMX timing. Your CPU-side detection covers context-switch timing; this is a specific, published AMX channel to add. |
| A7 | **Read Neural Network Architecture with Simple Power Analysis** | 2311.01344 | Model architecture extracted via EM/power analysis on microcontrollers. Directly relevant to the Jetson/edge deployment story — power side channel leaks the model. |
| A8 | **TPM-Based Continuous Remote Attestation for K8s** | 2510.03219 | TPM 2.0 + Linux IMA + Keylime for runtime integrity on Kubernetes. A concrete, standards-based path to make Watchdog's boot-attestation *continuous*. |
| A9 | **dstack-capsule: Pod-Level Remote Attestation on Intel TDX** | 2606.03323 | Pod-level attestation, multiple pods sharing one CVM. **Directly relevant to Serial Alice** (Phala dstack + Intel TDX + H200 — the exact stack in your validation). |
| A10 | **Fides: Low-Cost Result Validation of ML-as-a-Service** | 2304.00083 | Real-time integrity validation of inference results. Complements your SDC work at the *service* boundary. |
| A11 | **Mycroft: Tracing Dependencies in Collective Communication** | 2509.03018 | NCCL/collective-communication tracing and RCA. Your deferred RDMA/all-reduce SDC thread has been waiting for exactly this. |

---

# TIER B — REFERENCE (68)

## B1. GPU & hardware security (16)
| Paper | arXiv | Note |
|---|---|---|
| WarpGuard: CFI for CUDA SASS binaries | 2606.11871 | GPU control-flow attestation; needs SASS access |
| WarpGuard: heterogeneous CPU-GPU attestation | 2607.13640 | joint CPU+GPU CFG verification |
| The Correctness Illusion in LLM-Generated GPU Kernels | 2606.20128 | op-aware fuzzing oracle |
| Static PTX Metrics Track Structural Kernel Regressions | 2607.02541 | PTX diffs catch structural, miss semantic bugs |
| Robust Agentic CUDA Kernel Benchmarking † | 2509.14279 | agentic kernel verification |
| Test-Input Generation for Tensor Programs † | 2606.27396 | boundary-only sampling best bug recall |
| MABFuzz: multi-armed bandit processor fuzzing † | 2311.14594 | hardware fuzzing efficiency |
| PSOFuzz: particle-swarm processor fuzzing † | 2307.14480 | same family |
| LLM for SoC Security † | 2310.06046 | LLM-driven SoC security verification |
| AttackGNN: red-teaming GNNs in hardware security † | 2402.13946 | RL adversarial circuits |
| SYNFI: pre-silicon fault analysis † | 2205.04775 | formal fault-effect verification |
| Stealing Maggie's Secrets: FPGA reverse engineering † | 2312.06195 | IP theft via FPGA RE |
| Serialized Bridge: Blackwell CC performance | 2606.23969 | CC mode has measurable perf signature |
| GPUAlert: zero-instrumentation job-failure monitor † | 2607.01409 | competitor/reference for the daemon |
| FailureAtlas: silent LLM-serving errors † | 2607.17525 | your SDC thesis, serving layer |
| Characterizing LLM Development in the Datacenter † | 2403.07648 | fault-tolerant pretraining, scheduling |

## B2. Confidential computing / TEE / attestation (10)
| Paper | arXiv | Note |
|---|---|---|
| C8s: Confidential Kubernetes Architecture | 2604.26974 | hardware-TEE-backed cluster attestation |
| Dstack: Zero Trust Framework for Confidential Containers | 2509.11555 | **Serial Alice's stack** |
| TEERepair: automated repair of TEE partitioning † | 2605.22087 | DSL + LLM patching |
| SymTEE: missing input validation in TEEs † | 2605.22058 | LLM-assisted symbolic execution |
| What You Trust Is Insecure: TEE misuse in practice | 2512.17363 | 241 projects; widespread insecure practice |
| PipeLLM: confidential LLM with pipelined encryption † | 2411.03357 | CC overhead mitigation |
| TEE-Based Process Attestation † | 2603.00178 | attesting a *process occurred*, not just state |
| SPIDEr: encrypted de-identification with attestation † | 2412.09222 | privacy pipeline |
| Towards Secure and Private AI: decentralized inference † | 2407.19401 | ZK + consensus + hardware security |
| Securing LLM-Generated Embedded Firmware † | 2509.09970 | AI-agent firmware validation/patching |

## B3. Quantum (9)
| Paper | arXiv | Note |
|---|---|---|
| QuPort: topology/port/congestion-aware multi-QPU compilation | 2605.12583 | modular QPU resource contention |
| SQARL: RL circuit allocation, distributed QPUs | 2605.27027 | qubit allocation across cores |
| Circuit routing action-space engineering (RL) | 2605.02389 | distributed quantum compilation |
| QBalance: compilation + error-mitigation selection | 2605.02966 | Qiskit multi-objective |
| Benchmarking quantum optimization on real hardware | 2607.11637 | noise-dominated near fidelity thresholds |
| QAISim: AI in quantum cloud environments † | 2512.17918 | quantum cloud resource allocation |
| Multi-User Quantum Network QoS Architecture † | 2111.13124 | multi-tenant entanglement scheduling |
| Quantum Data Center with QRAM † | 2207.14336 | QDC architecture definition |
| Qute: Quantum-Native Database (14 upvotes) † | 2602.14699 | quantum as first-class execution |

## B4. Orbital / space (10)
| Paper | arXiv | Note |
|---|---|---|
| ESA-ADB: ESA anomaly benchmark | 2406.17826 | **real annotated satellite telemetry**; not on HF |
| OPS-SAT benchmark | 2407.04730 | second ESA telemetry benchmark |
| Detecting Spacecraft Anomalies Using LSTMs (NASA) | 1802.04431 | the classic; nonparametric dynamic thresholding |
| Spacecraft Power System Health, Mega-Constellation Era | 2601.12667 | validates your orbital power module set |
| Constraint-Aware Hybrid Space-Ground Execution Planning | 2605.04052 | 100× more data than downlink capacity |
| Mega-Constellation Data Quality & Decay (PIML) † | 2510.11242 | Starlink ephemeris accuracy |
| Real-time Faint Space Debris Detector † | 2309.08244 | debris detection, low SNR |
| SemSpaceFL: hierarchical FL for 6G LEO † | 2505.00966 | federated learning across satellites |
| ODS: radio-telescope/satellite coexistence † | 2502.15068 | RFI self-reporting |
| IceCube realtime system infrastructure † | 2308.01031 | realtime alert pipeline design |

## B5. Intrusion detection & network (subsea/network adjacent) (10)
| Paper | arXiv | Note |
|---|---|---|
| Cross-Domain Generalization Failure in IIoT IDS (11 upvotes) | 2607.00553 | **honest negative** — lightweight IDS doesn't transfer |
| CICAPT-IIOT: provenance-based APT dataset † | 2407.11278 | industrial APT dataset |
| FALCON: LLM CTI mining for IDS rule generation † | 2508.18684 | autonomous rule generation |
| Adaptive IDS for 5G/6G with adversarial learning † | 2512.10637 | resists dataset poisoning |
| MTH-IDS: multi-tiered hybrid IDS † | 2105.13289 | signature + anomaly |
| N-BaIoT: botnet detection via autoencoders † | 1805.03409 | classic IoT botnet dataset |
| GID: graph-based IDS on process traces † | 1608.02639 | process-trace graphs |
| GIDS: GAN-based IDS † | 1907.07377 | trains on normal data only |
| ECoLAD: deployment-oriented TSAD evaluation † | 2603.10926 | efficiency ladder under compute constraints |
| LSF-IDM: lightweight automotive IDS † | 2308.01237 | BERT+BiLSTM, resource-limited |

## B6. Power, grid & facility (10)
| Paper | arXiv | Note |
|---|---|---|
| Benchmarking ML/DL for Power Transformer Fault Detection | 2505.06295 | subsea transformer module (U-36) reference |
| Power Quality Event Classification with Transformers | 2402.14949 | your neutral-current harmonic detector's cousin |
| Multi-mode Fault Diagnosis of Three-phase Motors | 2601.02278 | **subsea coolant-pump seizure** (U-114) — vibration+current dataset |
| High-Fidelity Digital Twin, Inverter Microgrids | 2603.10262 | offshore-wind/microgrid dataset |
| PMU Synchrophasor IEEE C37.118.1 † | 2504.09883 | phasor measurement standard |
| Grid-Tied Smart Inverter Dynamics † | 2310.02056 | converter dynamics |
| Learning Distribution Grid Topologies † | 2206.10837 | grid topology from data |
| Time Series Similarity for Smart Grid † | 2310.12399 | amplitude+temporal distance measure |
| Power Grid Models from OpenStreetMap † | 2605.04289 | open grid model pipeline |
| LLM4DistReconfig † | 2501.14960 | LLM distribution-network reconfiguration |

## B7. Incident response, RCA & remediation (10)
| Paper | arXiv | Note |
|---|---|---|
| Stalled, Biased, and Confused: LLM RCA failures | 2601.22208 | **honest negative** — LLM multi-hop RCA fails; caution for the operator agent |
| LumiMAS: real-time multi-agent observability | 2508.12412 | monitoring + anomaly + RCA across MAS |
| Holmes: evidence-grounded LLM agent, auditable DDoS | 2601.14601 | auditable attribution — matches your evidence discipline |
| OpsAgent: evolving multi-agent incident management | 2510.24145 | observability → diagnosis |
| TrioXpert: automated incident management | 2506.10043 | multimodal, interpretable |
| RCA Copilot † | 2507.03224 | stats + LLM reasoning |
| PACE-LM: calibrated confidence in RCA † | 2309.05833 | confidence estimation for on-call |
| CORAL: online unsupervised RCA † | 2305.10638 | disentangled causal graphs |
| Adaptive RCA with Multi-Agent Recursion-of-Thought † | 2508.20370 | single-request localization |
| ByteRobust: robust LLM training infra (ByteDance) | 2509.16293 | production fault recovery |

## B8. Memory, SDC & reliability (3)
| Paper | arXiv | Note |
|---|---|---|
| From Detection to Recovery: 504 GPUs | 2605.09370 | real fleet failure patterns |
| MemFail: stress-testing LLM memory failure modes | 2605.26667 | diagnostic benchmark |
| Soft-Error Resiliency in Arm Ethos-U55 NPU | 2404.09317 | selective protection to ASIL-D; edge/orbital relevance |

---

# TIER C — CONTEXT (24)

Adjacent, worth knowing, not actionable for Watchdog: Cleaning up the Mess (2510.15744, methodology-correction case study); In-Memory Fault Tolerance for LLM Pretraining (2310.12670); SambaNova SN40L (2405.07518); InvAD (2504.05662); ImDiffusion (2307.00754); Free and Fair Hardware Verilog (2505.06096); Quantised NNs for automotive CAN IDS (2401.11030); T800 IoT packet filtering (2305.19214); Distortion of Partitioning by Random Quantum Circuits (2605.01974); Threat Modeling for AI-Agent Protocols — MCP/A2A/Agora/ANP (2602.11327, relevant if the operator agent uses MCP); plus, from earlier sweeps: Z-PEFT, Watch the Weights, Sponge Examples, architectural backdoors, LlamaFirewall, StepGuard, ToolSafe, Prompt Infection, SANDBOXESCAPEBENCH, AIOpsLab, Concordia, Unicron, C4, RAIL Guard, temporal-constraint enforcement, QDNA-ID (prior art — see PRIOR_ART_QDNA_ID.md), NVIDIA Ising decoders, Hypnos-Q1, OceanGym, UnderwaterVLA, OceanSim, NAUTILUS, NeuralOM, u0_final, Euclid anomaly detection, TRACE-C, GCR forecasting LSTM, EcoCompute, Watt Counts, WattGPU, GPU-to-Grid, POLCA.

---

# The honest nulls, restated

- **Subsea data centers: still zero papers on HF.** The closest are underwater *robotics/perception* (OceanGym, UnderwaterVLA) and now two genuinely useful *equipment* datasets — three-phase motor fault diagnosis (2601.02278) for coolant-pump seizure, and power-transformer fault detection (2505.06295) for the subsea transformer module. The data-center physics stays yours (Natick + first principles).
- **Quantum control-plane security: still zero products, sixth sweep.** Everything found is compilation, allocation, error mitigation, or QoS — not security. The niche holds. (Physics-as-attestation is *not* uniquely yours — QDNA-ID, Nov 2025 — see the prior-art notice.)
- **Ghost/idle power decomposition: still zero papers.** Nobody has published GPU idle-floor decomposition. This remains GPU Optimizer's open lane.

# What to actually do with this

1. **Build from Tier A only** — and only after checking each against the existing 41 engines for overlap.
2. **The three highest-value Tier A items:** A1 (model substitution — extends integrity to the service layer), A4 (MemTrace — fault *attribution*, the layer SDC lacks), A11 (Mycroft — unblocks the deferred RDMA/collective-communication thread).
3. **A9/B2 are Serial Alice-specific** — dstack/TDX pod attestation is literally the stack in your June validation. Worth reading before the next partner conversation.
4. **Two honest negatives worth citing** (2607.00553, 2601.22208): lightweight IDS doesn't generalize across networks, and LLM multi-hop RCA fails in measurable ways. Both are cautions for the operator-agent plan — cite them *for* your gated design, not against it.

*Catalogued Sep 2026. Summaries are Hugging Face's index text. Items marked † were not individually fetched; verify before external citation.*
