# Prior Art Notice — Physics-as-Attestation in Quantum Computing
**Watchdog Quantum | GPU Optimizer Inc. | September 2026**

This note records prior art discovered during a systematic Hugging Face research sweep (Sep 2026) and states how Watchdog's quantum work is positioned relative to it. It exists because a technical reviewer who finds this paper and sees Watchdog did not cite it would be right to question everything else.

---

## The prior art

**QDNA-ID: Quantum Device Native Authentication** — Osamah N. Neamah, Karabuk University (Turkey). arXiv 2511.17692, **November 2025**. Verified by reading the full paper.

QDNA-ID is a "trust-chain framework that links physical quantum behavior to digitally verified records." Its method:
- Runs seeded test circuits on real QPUs (IBM) and collects measurement outcomes
- Uses a **Bell/CHSH test as the "origin lock"** — proving the source is a genuine quantum device, not a classical simulation
- Extracts information-theoretic fingerprints (Shannon entropy, Jensen–Shannon divergence, Gini, perplexity, p₀ bias) per device
- Binds fingerprint + metadata into **HMAC-SHA256 + RSA-signed, timestamped provenance artifacts**
- Tracks **entropy drift** and classifies devices over time with ML
- Exposes an external verification API to recompute hashes, signatures, and CHSH evidence
- Is written in patent-claim form (five numbered claims with prior-art/distinction analysis)

**This predates Watchdog's quantum work (August 2026) by nine months.**

## What this means honestly

Watchdog can no longer state, without qualification, that using Bell/CHSH as a device-integrity signal or building a signed physics-anchored evidence chain is unique to Watchdog. QDNA-ID did both first. Specifically, these Watchdog ideas have prior art in QDNA-ID:

| Watchdog element | QDNA-ID prior art |
|---|---|
| CHSH / Bell violation as proof of a real quantum source | "origin lock" — identical thesis |
| Cryptographically chained quantum evidence ledger | HMAC + RSA signed, timestamped provenance artifacts |
| Device drift / fingerprint tracking | entropy-drift ML engine |
| Crosstalk observed as a device property | crosstalk measured as a fingerprint feature |

## Where Watchdog is genuinely distinct

QDNA-ID answers **"is this the real device, and is it drifting?"** — device *authentication* and *provenance*. Watchdog Quantum answers **"is this device being *attacked* through its classical control plane?"** — *security*. The following Watchdog capabilities have no counterpart in QDNA-ID:

- **Pulse-manifest integrity verification** — detecting a transpiled pulse program that implements a different gate sequence than declared (State-Hopping / circuit swap)
- **Crosstalk-*attack* detection** — a co-tenant deliberately degrading or inferring a victim circuit (QDNA-ID measures crosstalk as a passive fingerprint feature, not as an adversary)
- **Quantum-TEE / decoy-pulse verification** — detecting defeated QTEE protection
- **Reset / state-leakage between tenant jobs** — the quantum analog of VRAM residual
- **Fault-injection-as-attack detection** via fidelity/CHSH
- **Cross-account tenant-isolation attack testing** on a live multi-tenant platform (real 403 denials, cancellation-authorization tests)
- **Multi-vendor real-hardware validation** across IBM, Rigetti, and IQM with sealed results (QDNA-ID is IBM-only)

## Repositioning (adopted)

**Before:** "Watchdog uses the hardware's own physics as a tamper-detection and integrity-verification mechanism."

**After:** "Watchdog *extends* physics-as-attestation — established by prior work including QDNA-ID (Neamah, 2025) — from device *authentication* into classical **control-plane attack detection**: pulse-manifest tampering, crosstalk attacks, QTEE defeat, cross-tenant state leakage, and fault injection, validated on real IBM, Rigetti, and IQM hardware."

This is a stronger position, not a weaker one: it shows Watchdog knows the field, and it draws the line exactly where Watchdog's real contribution is.

## Actions taken / required

- [x] This notice added to the repository
- [ ] Cite QDNA-ID in `QUANTUM_CONTROL_PLANE_BRIEF.md` (Watchdog) and the quantum section of `README.md`
- [ ] Cite in the `Watchdog-quantum-collab` README ("What this is" section)
- [ ] **Patent counsel:** if any CIPO filing claims physics-as-attestation / CHSH-based integrity generically, QDNA-ID (Nov 2025) is prior art against that claim. Control-plane-attack-detection claims are distinct. Flag before any filing proceeds.
- [ ] Update the investor status report's quantum line to the "extends … into control-plane attack detection" framing

## Related references from the same sweep (adjacent, not prior art for the security claims)

- Hypnos-Q1 (HF model, DOI 10.57967/hf/8879) — runtime injection of IBM Kingston measurements with a SHA-256 attestation ledger; a single-author project overlapping the ledger idea
- NVIDIA Ising decoders (surface/color-code QEC, Aug 2026, gated) — error *correction*, adjacent to fault-injection detection
- Q-Cluster (2504.10801), QAdapt (2607.28422) — error mitigation, adjacent
- Simon's algorithm cryptanalysis on IBM Kingston (2607.18340) — same QPU Watchdog validated on; citation only

*Honest status: the "quantum control-plane security is commercially uncontested" claim still holds (five searches, no products). The narrower claim that physics-as-attestation is novel does not — and is withdrawn.*
