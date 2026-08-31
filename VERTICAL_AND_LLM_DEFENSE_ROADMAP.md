# Watchdog — Vertical & LLM-Defense Roadmap
**GPU Optimizer Inc. | Mike Bains | August 2026**
**Purpose:** record what was BUILT from the AI-defense research, what is DESIGN-ONLY (needs the Pile 2 ingestion layer), and what was REJECTED with the research reason — so the rejected-but-tempting approaches don't get wired in later by mistake.

---

## BUILT this session (Tier A — shipped, tested)

| Component | What it does | Research basis |
|---|---|---|
| `detection/aibom_generator.py` | AI Bill of Materials: inventories models/datasets, records SHA-256, flags provenance gaps (unpinned, untrusted source, missing license, missing training-data), emits CycloneDX 1.7 ML-BOM | CycloneDX ML-BOM v1.7 / ECMA-424 2nd ed (Oct 2025); EU AI Act Art. 11 & 53(1d) (effective Aug 2025); CISA "SBOM for AI"; OWASP AIBOM Project; Frontiers arXiv/fcomp.2026.1735919 |
| `detection/aibom_vuln_crossref.py` | Cross-references AIBOM components + installed packages against a LOCAL known-vuln list (ShaiWorm, PickleScan CVEs, litellm SSTI, lmdeploy RCE) | CSAF-VEX AIBOM framework (arXiv:2606.19390); the AI-supply-chain CVEs already researched for Watchdog |
| `detection/dangerous_pattern_scanner.py` | AST-based SAST: subprocess shell=True, os.system, eval/exec, eval(input()), yaml unsafe load, hardcoded secrets, requests verify=False, Flask debug=True | Extends the existing `torch_load_auditor` AST approach; Semgrep/Tree-sitter SAST literature |
| `detection/sandbox_validator.py` | Runs a PROPOSED remediation action in a locked-down container (--network none, --read-only, --cap-drop ALL, resource caps) to confirm it works before human approval. Validates, never auto-applies | Isolated-validation / sandbox literature; gVisor/Docker hardening. Deliberately NOT auto-patching |
| `detection/prompt_spotlight.py` | Spotlighting prompt-hardener: control-token instruction/data separation + boundary-forgery detection, reusable across all LLM-touching components | Spotlighting (Hines 2024); DeepMind Gemini defense (arXiv:2505.14534) |

39 tests, 0 failures (`tests/test_aibom_and_hardening.py`).

**Integration note:** `prompt_spotlight` is the reusable hardener that `llm_incident_investigator` (and any future LLM component) should route untrusted data through. The investigator already fences untrusted data; spotlight is the upgrade to the DeepMind standard. Wire it in when convenient — the investigator works today; this strengthens it.

---

## DESIGN-ONLY (Pile 2 — needs the ingestion layer, not coded)

These are real and valuable but each needs a data source Watchdog doesn't ingest yet (per HARDWARE_LIMITATIONS.md and the Pile 2 spec). Documented so the direction is recorded; no stub detectors against non-existent inputs.

### Vertical detection (facility / industry signals beyond GPU telemetry)
- **Pharma SCADA / Modbus anomaly** — PLC logic-tampering detection (Stuxnet-class). Needs a Modbus/OPC-UA feed. The naive `temp > threshold` example from the research dump is toy-grade; the real version models expected PLC state transitions and flags deviations. Serves the pharma vertical + 21 CFR Part 11 audit story.
- **Insurance DB exfiltration patterns** — bulk-PII / mass-SELECT detection. Needs a DB query-log feed. The `"select *" in query` example is trivially bypassed; the real version is rate + shape + column-sensitivity analysis on query streams.
- **Crypto stratum-hijack detection** — mining-pool redirection / stratum tampering. Needs a network-traffic feed on stratum ports. Complements agent 7 (which watches GPU-side onset); this watches the pool-connection side.

These map onto Watchdog's existing move into facility-layer detection (the `NeutralCurrentHarmonicDetector` precedent) and are natural once the network/log ingestion collectors from the Pile 2 spec exist.

### LLM-gateway defense (needs prompt-ingestion layer)
- **Real semantic-embedding injection classifier** — embedding model + trained classifier (XGBoost on OpenAI/GTE embeddings) reaches ~97.7% on BIPIA (arXiv 10.3390/a19010092). Buildable ONLY with the prompt-ingestion layer + an embedding model; and note it is still bypassable by semantic-shift attacks (arXiv:2509.06338, arXiv:2511.21752), so it layers behind spotlighting, not instead of it.

---

## REJECTED (recorded so nobody adds them later)

Each of these appeared in the research dump as a tempting quick win. Each is rejected for a cited reason. **Do not add these to Watchdog.**

| Rejected approach | Why rejected | Citation |
|---|---|---|
| **Keyword/regex blacklist filter** (`["rm -rf","drop table","eval("]`, `re.sub("import os")`) | The weakest defense layer; defeated by rephrasing. Gives false confidence. | AttackEval "L1 keyword" (arXiv:2604.03598); Watchdog's own MCPTox 72.8% finding |
| **Mock-embedding cosine gateway** (hardcoded vector) | The dump's example uses a fake vector; a real version needs a trained classifier and is still bypassable, and belongs in the (unbuilt) prompt-ingestion layer, not shipped as a mock | arXiv:2509.06338 (Embedding Poisoning); arXiv:2511.21752 |
| **Auto-code-patching that deploys** ("AI writes the fix and pushes it") | LLM-generated security patches introduce their OWN vulnerabilities. Most dangerous item in the dump. | "How Safe Are AI-Generated Patches?" (arXiv:2507.02976) |
| **Full StruQ / SecAlign** | Stronger than spotlighting but require model FINE-TUNING — out of scope. Spotlighting is the deployable form and is what was built. | StruQ (USENIX Sec 2025, arXiv:2402.06363); SecAlign |

**The discipline:** Watchdog's LLM components use STRUCTURAL separation (spotlighting) + gated human approval + no execution. They do NOT use content-detection filters as a primary defense, and they NEVER auto-apply AI-generated fixes. Any future contributor tempted to add a keyword filter or an auto-patcher should read this table first.

---

## Confirmed-sound (the dump described what Watchdog already does)

For the record — several "recommended architectures" in the research dump are things Watchdog already implements correctly:
- AI-on-AI supervision / behavior watchdogs → the swarm + correlator
- Detection→remediation loop at machine speed → detection engines + remediation coordinator + investigator
- Human-in-the-loop before critical action → gated remediation
- Isolated session memory / no direct execution / untrusted-input guardrails → the investigator's defensive design (now upgradeable with `prompt_spotlight`)

No action needed on these; noted for confidence that the architecture matches current best practice.

---

*Everything built this session is simulation-based / logic-tested and requires real-hardware validation per the pod validation plan. AIBOM provenance and the CVE cross-reference are the exception in one sense — they operate on files and package metadata, not GPU telemetry, so they are directly usable on any real deployment today, though the known-vuln list must be kept current.*
