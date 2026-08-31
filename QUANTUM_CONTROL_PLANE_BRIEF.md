# Watchdog — Quantum Control-Plane Security: Research & Build Brief
**GPU Optimizer Inc. | Mike Bains | August 2026**

Six new quantum control-plane security detectors, each grounded in published 2023–2026 research and each using the QPU's own physics as the verifier. 22 tests, 0 failures. This is the layer that makes "quantum control-plane security + physics-as-verification — nobody's there" concrete and defensible.

---

## Why this is an uncontested market

The entire commercial quantum-security industry (PQShield, Post-Quantum, SandboxAQ, Palo Alto, Check Point, Fortinet) does **PQC/QKD** — protecting *classical* data against *future* quantum computers. **Nobody commercially monitors the QPU's own classical control plane** (transpilers, FPGA pulse generators, cryo controllers, job APIs) or uses the hardware's physics as a tamper-verifier.

The research confirms this is a live frontier, not a solved problem:
- **Google's Quantum Computing Security program** (decisions Oct 2026) explicitly solicits work on "real-time verification of pulse-level instructions against high-level gate manifests" to prevent 'Qubit Plunder'/'State-Hopping' attacks — exactly what detector #1 does.
- **Confirmed nation-state interest:** Dutch intelligence disclosed Chinese operations stealing quantum tech; Russian actors probing US quantum labs (2024–2025).
- The leading academic groups — **Jakub Szefer (Northwestern)** and **Swaroop Ghosh (Penn State)** — publish attacks and defenses, but there is no product layer productizing them. Watchdog can be that layer.

Watchdog already has the foundation validated on real hardware (IQM, Rigetti, IBM): circuit fingerprinting, cross-account isolation testing, CHSH/Bell physics verification. These six extend it into a coherent control-plane security suite.

---

## The six detectors

| # | Detector | What it catches | Grounded in |
|---|---|---|---|
| 1 | `PulseManifestVerifier` | Transpiled pulses implement a DIFFERENT gate sequence than declared (State-Hopping / circuit swap), or raw pulse tamper preserving logical gates | Google QC Security program (pulse-vs-manifest verification, the named open problem); extends Watchdog circuit fingerprinting |
| 2 | `SideChannelExposureAuditor` | Circuit is reconstructable via controller power / 4–8 GHz EM emissions, no decoy protection applied | Xu/Erata/Szefer, Power Side-Channel in QC Controllers (ACM CCS 2023); Bell/Trügler circuit reconstruction (IEEE QCE 2022) |
| 3 | `CrosstalkAttackDetector` | Co-tenant degrades/infers a victim circuit via crosstalk (fidelity degradation, readout-crosstalk leak) on a shared QPU | SWAP attack (arXiv:2502.10115); Harper et al. crosstalk attacks & defence (arXiv:2402.02753); readout crosstalk (ACM QSP 2025) |
| 4 | `QTEEVerifier` | Quantum-TEE protection defeated — decoy pulses stripped or pulse mask tampered | Trochatos/Szefer QTEE: IEEE CAL 2023, IEEE HOST 2024 (dynamic pulse switching), Frontiers in Computer Science 2025 |
| 5 | `ResetStateLeakageChecker` | Incomplete qubit reset leaks prior tenant's state — **the quantum analog of Watchdog's GPU VRAM residual / LeftoverLocals** | Xu/Chen/Mi/Szefer, Securing NISQ Reset Ops vs Higher-Energy-State Attacks (ACM CCS 2023) |
| 6 | `FaultInjectionDetector` | Result physics inconsistent with declared circuit (fidelity below floor, CHSH fails to violate when it should) — pulse-level fault injection betrayed by physics | QC fault-injection taxonomy (arXiv:2309.05478); Ghosh et al., Primer on QC Hardware Security (Proc. IEEE 2025) |

---

## The two strongest strategic wins

**#5 (Reset/state-leakage) ties the GPU and quantum stories together.** It is *literally* the quantum version of VRAM residual / LeftoverLocals — incomplete reset leaves readable state for the next tenant, exactly like GPU memory not zeroed between processes. This lets Watchdog tell one coherent story: "we detect cross-tenant state leakage on both GPUs and QPUs, from the hardware's own signals." No competitor spans both.

**#1 (Pulse-manifest verification) is the Google-named open problem, productized.** Google's own security program lists it as an open research challenge. Watchdog implementing it as a shipped verification layer — grounded in the physics-as-verification thesis already validated on IQM/Rigetti/IBM — is a genuine first-mover position.

---

## Physics-as-verification: the unifying thesis

Every detector uses the QPU's own physics as ground truth. A tampered pulse program *betrays itself* in the physics: fidelity drops below what the circuit should produce, CHSH fails to violate the classical bound, reset leaves residual population, crosstalk degrades gate fidelity. This is the same principle Watchdog already proved by catching the real CHSH bug (S=1.92 → fixed to S=−2.1396 on Rigetti) — a system that only reports clean results is not a verification system. These six turn that principle into a control-plane security product.

---

## Honest status

- All six are logic-tested in simulation (22 tests, 0 failures). The verification logic is real; thresholds are grounded in the cited papers but require per-backend calibration.
- Watchdog's *existing* quantum work (circuit fingerprinting, cross-account isolation, CHSH/Bell physics) is validated on real hardware (IQM Garnet, Rigetti Cepheus-1-108Q, IBM Kingston) — these detectors extend that foundation.
- EM side-channel *measurement* (detector 2) is hardware-gated (needs an SDR near the controller) — the detector honestly labels itself a structural exposure audit, not a live EM measurement.
- These feed the swarm's cross-layer correlator the same way GPU detectors do — a quantum control-plane incident can correlate with the broader security picture.

*Accurate framing: "six quantum control-plane security detectors grounded in published Szefer/Ghosh/Google research, built and logic-tested; extends Watchdog's real-hardware-validated quantum foundation; per-backend calibration and live-QPU validation pending."*
