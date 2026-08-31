# Watchdog — Cross-Layer Fusion: The Competitive Superiority Layer
**GPU Optimizer Inc. | Mike Bains | August 2026**

Five competitor capabilities, each rebuilt fused with Watchdog's hardware/quantum layer so it does what a software-only platform (HiddenLayer, Lakera, Protect AI, Cisco AI Defense) **structurally cannot**. Substrate-aware: GPU (power/ECC/VRAM), CPU (context-switch/cache-timing), quantum (circuit-fidelity/CHSH physics). 27 tests, 0 failures.

---

## The core superiority principle

We do NOT try to out-detect Lakera on prompt-injection *content* — they have years of adversarial data we can't replicate, and building a worse copy would be dishonest. Instead, every fusion detector pairs the software signal with a **physical corroborator the competition can't see**. Same capability, plus a channel they structurally lack.

| # | Detector | Their version | Watchdog's superior version |
|---|---|---|---|
| 1 | `ModelScanHardwareFusion` | Scan the model file | Scan the file **+ verify the loaded model's runtime physical footprint matches its declared architecture**. Catches `MODEL_TAMPER_HARDWARE_MISMATCH` — a clean-scanning file whose real power/memory/timing diverges — which a file-scan-only tool misses entirely. |
| 2 | `PromptInjectionPhysicalFusion` | Detect injection in prompt text | Structural analysis **+ physical corroborator**. `PHYSICALLY_CONFIRMED` (text+physics), `PHYSICAL_ANOMALY` (benign text, anomalous signature — an injection that evaded content analysis, caught by physics). On quantum the corroborator is circuit fidelity. |
| 3 | `HardwareRedTeamHarness` | Red-team prompts and models | Red-teams the **hardware attack surface** (Rowhammer, VRAM residual, ghost power, quantum crosstalk/CHSH tamper) their red-teamers can't even generate. |
| 4 | `UnifiedAssetDiscovery` | Discover models and shadow AI | Discovers models **+ the GPU/CPU/QPU fleet they run on**, tied to per-region AIBOM compliance. "What AI, on what hardware, compliant where." |
| 5 | `HardwareThreatIntelFeed` | Jailbreak-signature feed | A **hardware/supply-chain + quantum threat feed** (GPUThor, GPUHammer, LeftoverLocals, ShaiWorm, qubit crosstalk) they don't maintain. |

---

## The swarm makes it unbeatable

`CrossLayerCorrelator` fuses these signals into single incidents no software-only competitor can assemble:

- `CONFIRMED_INJECTION_CAMPAIGN` — physically-confirmed injection + model tamper
- `STEALTH_MODEL_SWAP` — clean-scanning model with a divergent hardware footprint + a physical anomaly
- `EVASIVE_INJECTION_CAUGHT_BY_PHYSICS` — benign-reading prompt + corroborating compute anomaly
- `QUANTUM_JOB_TAMPER_CONFIRMED` — flagged quantum job + circuit-physics confirmation

A HiddenLayer sees the text half. Watchdog's swarm sees the text half AND the power/timing/fidelity half AND the model-file half — and correlates them into one high-confidence incident. **That correlation across substrates is the moat.**

---

## Honest positioning (for Paul / any deck)

- **Lead with:** "The only AI-security platform that confirms attacks with physical evidence — power, ECC, VRAM, and quantum-circuit physics — across GPU, CPU, and QPU. We catch injections and model tampers that evade content-only tools, because we see the hardware they can't."
- **Do NOT claim:** a better standalone prompt-injection content classifier. Our superiority is the *fusion*, not out-corpusing Lakera.
- **The unfakeable line:** every `differentiator_note` in the code states exactly why a software-only competitor structurally cannot produce that result. It's built into the output, not just the pitch.

*Simulation-based; physical thresholds grounded in Watchdog's measured findings (e.g. B200 +127.5W prompt-injection side-effect) but require per-deployment calibration and pod validation.*
