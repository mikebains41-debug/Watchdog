# Watchdog — Continuous Model Integrity (CMI) Suite: Brief
**GPU Optimizer Inc. | Mike Bains | September 2026**

Four components that turn Watchdog from a *hardware-security* tool into **the continuous model-integrity monitoring that regulators now require** — which makes it a *compliance purchase* (budgets + deadlines) for pharma, insurance, and finance, not just a security purchase. 26 tests, 0 failures.

---

## Why: the regulatory convergence (verified Aug–Sep 2026)

Three sectors' regulators now demand the **same** thing — continuous model-performance monitoring, drift detection, revalidation triggers, and audit-ready evidence:

| Regime | Who it hits | What it requires | Deadline |
|---|---|---|---|
| **OSFI E-23** (final Sep 11 2025) | Canadian banks AND — for the first time — **insurers** | Model inventory w/ risk rating; monitoring that detects drift/threshold breaches and **triggers review** | **May 1, 2027** |
| **SR 26-2** (Fed/OCC/FDIC, Apr 2026, replaced SR 11-7) | US financial institutions | "Metric thresholds so drift and decay raise an alert instead of waiting for the next review" | In effect |
| **FDA AI in Drug Dev (Jan 2025) + FDA/EMA Good AI Practice (Jan 2026)** | Pharma | Prospective validation + ongoing monitoring; audit trails for any AI touching GxP data; inspection-ready evidence package | In effect / evolving |
| **NIST AI RMF / FedRAMP** | Government | Continuous monitoring and regular reassessment | In effect |

Watchdog already monitored **hardware** integrity (SDC catches *sudden* corruption). CMI adds **model** integrity **over time** (gradual drift/decay). Together = full integrity-over-time — exactly what the regulators wrote.

---

## What was built

| # | Component | What it does | Regulatory clause |
|---|---|---|---|
| 1 | `ModelDriftMonitor` | Seals a validation-time baseline (output distribution + metric); per window computes PSI drift + metric decay; fires `MODEL_REVALIDATION_REQUIRED` at threshold. Calibration anchor: documented AUC decay 0.9205→0.8579 (arXiv 2605.04076) = retrain trigger. | E-23 monitoring, SR 26-2 thresholds, FDA/EMA ongoing monitoring |
| 2 | `ModelRiskRegister` | The required model inventory: owner/purpose/inputs/methodology/limitations + risk tier from E-23's dimensions (autonomy, data-input reliability, customer impact, regulatory risk). Tracks third-party/feeder models. Flags inventory gaps as findings. | E-23 inventory + tiering, SR 26-2, OSFI B-10 third-party |
| 3 | `RevalidationTriggerEngine` | Watches Watchdog's existing signals (drift, SDC, weight tamper, AIBOM change, sandbox escape) and fires `REVALIDATION_TRIGGERED` per model, **scaled by risk tier** (HIGH fires on less — E-23 proportionality). | E-23 / SR 26-2 revalidation on breach/modification/data change |
| 4 | `EvidencePackageGenerator` | Assembles Watchdog's raw evidence into a regulator-facing package — FDA "inspection-ready validation package" framing or E-23/SR 26-2 "attestation roll-up" — with a **SHA-256 hash chain** so the package itself is tamper-evident (editing any section breaks the chain; tested). | 21 CFR Part 11 §11.10(a)/(e), FDA/EMA, E-23 attestation |

**Critical design rule (gated, never auto-block):** the trigger engine ALERTS and RECOMMENDS revalidation. It does **not** auto-block or disable a live production model — auto-blocking a live insurance/pharma model on a threshold could itself be a serious incident. The decision stays with a human, consistent with Watchdog's remediation discipline throughout.

**Feeds the swarm:** `MODEL_REVALIDATION_REQUIRED` is a swarm signal; the unified correlator can fuse model drift with hardware-integrity signals (e.g. drift + SDC + degrading silicon = a model failing for a physical reason).

---

## The "traps" — verified 100%, with one correction

Research was re-run to confirm each before building:

**1. FedRAMP — confirmed a trap to chase NOW, but stance corrected.**
- Traditional Moderate: $500K–$1.5M upfront + $200–500K/yr, 12–36 months. Confirmed.
- **Correction:** FedRAMP **20x** (automation-first path, submissions opened Aug 2026): $100K–$300K, 3–6 months, first pilot done in 119 days, explicitly "designed so smaller providers can realistically enter."
- **Verdict:** absolutely not now (pre-revenue, it's a certification not code) — but no longer a permanent wall. A realistic **post-funding, post-first-customer** gate, same tier as SOC 2. Roadmap item, not blocker.

**2. Explainability / bias / fairness tooling — confirmed a trap.**
E-23, NIST AI RMF, SR 26-2 all require it, but it's a *different product category* (model interpretability), crowded with specialists, and unrelated to the hardware/physics/integrity moat. Building it = competing off-strength. **Don't build.** Honest line to a buyer: "we do integrity + drift monitoring; pair us with an explainability tool."

**3. Full GRC platform — confirmed a trap.**
Continuum, VerifyWise, Qualys TotalAI (just FedRAMP-authorized), Secureframe, Paramify — crowded, well-funded, 1,000+ controls. **Don't build.** CMI is the *monitoring layer that feeds* those platforms, which is the right position.

---

## Honest framing for buyers

- **Say:** "Continuous model-integrity monitoring — drift detection, risk-tiered inventory, automatic revalidation triggers, and tamper-evident regulator evidence packages — aligned to OSFI E-23 (May 2027), SR 26-2, and FDA/EMA Good AI Practice."
- **Do NOT say:** "makes you compliant." It produces compliance **evidence** and monitoring; compliance is the buyer's program. Every output states "not legal advice."
- **Scope note:** SR 26-2 currently *excludes* generative/agentic AI from formal scope (too novel). Firm requirement for classical ML; evolving for LLMs/agents. Don't overclaim coverage of a regime that hasn't landed.

## Status

Logic-tested (26 tests). Thresholds (PSI 0.10/0.25, metric decay 0.05) require per-model calibration. This is monitoring tooling that produces evidence — not a compliance guarantee.

*Files: detection/model_drift_monitor.py, detection/model_revalidation_engine.py, tests/test_model_integrity.py.*
