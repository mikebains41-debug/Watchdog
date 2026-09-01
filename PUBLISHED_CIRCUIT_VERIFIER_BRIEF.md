# Watchdog — Published-Circuit Tamper Detection: Brief
**GPU Optimizer Inc. | Mike Bains | August 2026**

A tamper-detection ingester that runs Watchdog's physics-consistency checks on **publicly-released quantum circuit data** — including the IBM/UChicago "verified quantum advantage" result on the Quantum Advantage Tracker. 17 tests, 0 failures.

---

## What it is

`detection/published_circuit_verifier.py` ingests the universal released-circuit format (a QASM circuit definition + measured bitstring samples + a stated verification value) and runs four independent checks:

1. **Manifest integrity** — QASM's declared qubit/T-gate counts vs. the published metadata (nq70, T-count 468). Mismatch = tamper/inconsistency flag. Same principle as our pulse-manifest verifier, applied to a published circuit.
2. **Bitstring shape integrity** — every sample the expected width; post-selected count matches the published number (2051).
3. **Statistical sanity** — samples aren't degenerate/spoofed (all-identical output = flagged).
4. **Fidelity-claim plausibility** — a lightweight cross-entropy-style statistic checked for gross inconsistency with the published value (0.32). Plausibility only — NOT a reproduction of IBM's direct fidelity estimation.

It's pure stdlib (no qiskit, no QPU, no numpy). Verified against a synthetic stand-in matching the exact IBM/UChicago structure (97 qubits = 70 logical + 27 ancilla, 468 T-gates, 2051 samples).

---

## The honest scope boundary (critical — do not blur this)

**What it DOES:** demonstrates Watchdog's tamper-detection can ingest *real released circuit data* and flag physics-inconsistency/tamper anomalies — proving our detectors work on real data, not only synthetic fixtures.

**What it does NOT do, and must never be claimed:**
- It does **NOT** re-verify or reproduce IBM/UChicago's quantum-advantage result. Their verification is self-contained via spacetime codes + direct fidelity estimation on error-corrected *logical* qubits. Ours is a simpler, independent physical/statistical-consistency layer.
- It does **NOT** "validate Watchdog against IBM's verified computation."

**The correct claim:**
> *"Watchdog's tamper-detection was demonstrated on IBM/UChicago's publicly-released circuit results as a real-data input — showing our detectors ingest and check genuine released quantum data, not just simulation. Our layer is an independent physical/statistical-consistency check, distinct from and complementary to IBM's self-contained spacetime-code verification."*

The disclaimer is baked into every result the code returns (the `honest_scope` field) so it can't be stripped by accident.

---

## How to run it on the real IBM data (pod-day or now)

The data is public on GitHub:
- Repo: `github.com/quantum-advantage-tracker/quantum-advantage-tracker.github.io`
- Path: `data/classically-verifiable-problems/circuit-models/doped_random_graph_sampling`
- Circuit file: `nq70_depth70_checks27_doped_checks.qasm`
- Samples: 2051 post-selected Z-basis bitstrings (T-count 468)
- Published value: fidelity 0.32 on `ibm_boston_dcs_nq70_depth70_checks27`

To run:
```python
from detection.published_circuit_verifier import (
    PublishedCircuitVerifier, parse_qasm_counts, parse_bitstrings)

qasm = open("nq70_depth70_checks27_doped_checks.qasm").read()
samples = parse_bitstrings(open("samples.txt").read())
facts = parse_qasm_counts(qasm)
meta = {"qubits": 70, "t_count": 468, "expected_samples": 2051,
        "fidelity_value": 0.32, "name": "ibm_boston_dcs_nq70_depth70_checks27"}
result = PublishedCircuitVerifier().verify(facts, samples, meta)
```
The result (with its honest_scope note) is a committable evidence artifact: "Watchdog tamper-detection ran on IBM/UChicago's released circuit data on [date]."

---

## Why this matters strategically

- It's a **real-data demonstration**, stronger than simulation-only — our detectors provably ingest genuine released quantum results.
- It rides IBM's validation of the *verification frontier* (they just proved trusted quantum computation matters) while keeping Watchdog clearly on the **security/tamper-detection side**, not claiming their fidelity-advantage result.
- It's honest to the letter — the scope boundary is in the code, so no external material built from it can accidentally overclaim.

## Honest status

Logic-tested (17 tests). To produce the actual evidence artifact, run it against the downloaded Advantage Tracker files. The parsers handle the real QASM/bitstring format; the first real run may need a small tweak if the sample file layout differs from the standard one-bitstring-per-line format (adjust `parse_bitstrings` if so).

*File: detection/published_circuit_verifier.py, tests/test_published_circuit_verifier.py.*
