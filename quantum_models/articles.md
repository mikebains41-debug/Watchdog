# Articles - Quantum Infrastructure Watch List

Tracking external research and industry developments relevant to
gpu-quantum-core's AWAITING_HARDWARE_TEST assumptions. Not validation
data - just context to revisit when calibrating models against real
architectures.

---

## Yale ERASE Project - $4M NSF Grant (June 2026)

**Source:** Yale News, June 25 2026, by Jim Shelton
**Link:** https://news.yale.edu (search "ERASE quantum erasure qubits")

**Summary:**
Yale-led ERASE project (Erasure Qubits and Dynamic Circuits for Quantum
Advantage) received a $4M NSF grant for phase 2 of a 3-phase plan to
build a large-scale, error-correcting quantum computer. Follows an
earlier $1M NSF pilot grant. Industry partner is D-Wave Quantum, which
acquired Yale spinout Quantum Circuits Inc. in January 2026. D-Wave is
expanding R&D workforce in New Haven as part of this partnership.

**Architecture note:**
Uses "erasure flag" qubits (dual-resonator design) - a superconducting
qubit approach where the dominant error type raises a flag when it
occurs, making it easier to identify and correct than standard
undetected errors. Different error-correction philosophy than
standard transmon qubits, but still broadly in the superconducting
qubit family our multiplexing and coherence models are built around.

**Timeline:**
- Phase 1 (pilot, ~2025): $1M grant, proof of concept
- Phase 2 (current, 2026-2028): $4M grant, hardware/software blueprint
  development, no live hardware build yet
- Phase 3 (future, unfunded/unscheduled as of this writing): actual
  hardware build based on phase 2 blueprint

**Relevance to gpu-quantum-core modules:**
- M_multiplexing_correction.py assumes generic FDM readout-line sharing
  ratios (4-10 qubits per line) from superconducting qubit literature.
  Erasure qubit architecture may have different readout requirements
  since the error-flagging mechanism could need additional readout
  lines beyond a standard transmon design - UNCONFIRMED, no published
  wiring specs yet since this is still blueprint stage.
- M_coherence_per_watt.py uses representative T1 values (20/150/500us)
  from generic literature, not erasure-qubit-specific. Erasure qubits'
  whole premise is trading some T1 characteristics for error
  detectability - may need a qubit-type-specific T1 assumption if this
  becomes a target architecture.
- No hardware exists yet to validate against (phase 2 is blueprint
  only), consistent with AWAITING_HARDWARE_TEST status across this
  repo - nothing actionable yet, just a project to watch.

**Why tracked:**
D-Wave's physical R&D expansion in New Haven could eventually be a
hardware access point. Also a data point for GPU Optimizer's broader
thesis (see PHASE5_ROADMAP.md) that measurement/telemetry blindness
exists on every next-gen compute architecture - erasure qubits are
architecturally distinct enough from standard transmons that our
current generic models may need per-architecture variants once real
specs exist.

**Status:** WATCH_ONLY - no action needed until phase 3 hardware specs
or wiring/coherence data are published.

---
