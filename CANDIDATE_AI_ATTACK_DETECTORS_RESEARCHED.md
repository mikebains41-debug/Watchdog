# Watchdog — Candidate AI-Attack Detectors (Researched, Not Yet Built)
**GPU Optimizer Inc. | August 2026**
**Sourced from:** USENIX Security, IEEE S&P, arXiv, NVD/CVE, ACM, university disclosures (U Toronto, ETH Zurich), CSA, NSA/DoD guidance. Every item below has a real citation. Nothing here is claimed as built. This is a candidate list for deciding what to build next, ranked by whether it's reachable on Watchdog's current telemetry.

---

## How this list is organized

Same discipline as the Pile 1 / Pile 2 split already in the repo:

- **TIER A — buildable now** on `nvidia-smi` fields, local file/process inspection, or the model-file bytes Watchdog can already read. Same pattern as the AI-attack detectors just shipped.
- **TIER B — needs one modest new local capability** (a `/var/log`/`dmesg` reader, a DCGM field, a MIG-enabled pod). Small lift, not a full ingestion layer.
- **TIER C — Pile 2** (needs the network/prompt/tool-descriptor ingestion layer already spec'd). Listed for completeness and deck honesty, not for this build.

Each item: what it is, the citation, why it's probable, and the honest detection ceiling.

---

## TIER A — buildable now (recommended next build)

### A1. GGUF / Jinja2 chat-template execution detector  ★ highest-value gap
**Threat:** GGUF model files (llama.cpp ecosystem) embed Jinja2 chat templates that execute at inference-initialization time in frameworks that don't sandbox the template engine. Same class as CVE-2024-2952 (BerriAI/litellm SSTI via `chat_template` in `tokenizer_config.json`). Also `tokenizer_config.json` template injection generally.
**Citations:** CVE-2024-2952 (litellm Jinja SSTI); CSA "Model Poisoning: Credential Exfiltration in Self-Hosted LLM Deployments" (May 2026); arXiv:2502.12497 "Demystifying LLM Supply Chain Vulnerabilities."
**Why probable:** GGUF is the dominant local-inference format; the template engine runs before any weights load; adoption of the vulnerable pattern is widespread.
**Why it matters for us:** **My just-shipped `model_weight_integrity_detector.py` treats `.safetensors` as auto-safe and doesn't scan GGUF templates or `tokenizer_config.json` at all.** This is a direct, honest extension of a detector already in the repo — parse the GGUF metadata / config JSON, flag Jinja constructs that call out to `os`/`subprocess`/`eval` or reach network/filesystem. Pure byte/JSON inspection, no execution. Fully testable with crafted fixtures.
**Ceiling:** static template analysis catches known-dangerous constructs; a novel obfuscated template could slip — flag-and-quarantine, not a guarantee.

### A2. safetensors / model-parse memory-corruption pre-load validator
**Threat:** Even "safe" formats have memory-corruption CVEs in the *parser*, not the payload: CVE-2024-41130 (null-ptr deref in `gguf_init_from_file`, ggml); a family of 6 model-parsing CVEs documented in the LLM-supply-chain study. A malformed-but-valid-looking header crashes or potentially executes in the loader.
**Citations:** CVE-2024-41130; arXiv:2502.12497 (6 memory-corruption-in-model-parsing CVEs); Trail of Bits safetensors audit (2023).
**Why probable:** parsers are C/C++ and under-fuzzed relative to their new criticality.
**Build:** validate structural invariants of the safetensors/GGUF header (offsets within bounds, sizes non-negative, name table well-formed) *before* handing the file to the real loader. Reject/quarantine malformed headers. Closes the exact gap where my current detector says "SAFETENSORS_OK" purely because there's no pickle.
**Ceiling:** structural validation, not a full memory-safety proof of the downstream parser.

### A3. torch.load weights_only-bypass config auditor
**Threat:** `torch.load()` without `weights_only=True` executes pickle on load. Real 2025 advisory: lmdeploy GHSA-9pf3-7rrr-x5jh (multiple `torch.load(shard)` sites missing the flag). This is a *code/config* smell detectable by scanning the serving stack, not the model file.
**Citations:** lmdeploy GHSA-9pf3-7rrr-x5jh (Dec 2025); PyTorch weights-only default since 2.6 but overridable.
**Why probable:** huge installed base of pre-2.6 code and code that explicitly passes `weights_only=False` for compatibility.
**Build:** static scan of the deployment's Python for `torch.load(` calls lacking `weights_only=True`, and for `pickle.load`/`pickle.loads` on model paths. AST-based, no execution. Complements the runtime file scanner with a code-hygiene check.
**Ceiling:** static — won't catch dynamically constructed load calls.

### A4. LeftoverLocals residual-read detector (CVE-2023-4969)
**Threat:** GPU local/shared memory not zeroed between kernel invocations — one process reads another's leftover data. This is *the same class* as Watchdog's confirmed VRAM-residual "accounting gap," with an assigned CVE and a demonstrated cross-process read.
**Citations:** CVE-2023-4969 (LeftoverLocals, Trail of Bits); ties directly to Watchdog's existing VRAM residual findings.
**Why probable / why us:** you already measure VRAM residual; this is the named, cited, cross-process-read version of the exact phenomenon. Strongest "turn accounting gap into a real security finding" candidate that already has a CVE behind it.
**Build:** the *detection* side (residual present after kernel exit, on affected vendor/driver combos) is buildable on current telemetry. The *proof-of-read* PoC is hardware-gated (already on your backlog as the same-GPU cross-tenant PoC — this gives it a CVE anchor).
**Ceiling:** detection of the precondition; the actual read demonstration remains the hardware-gated open item you already track.

### A5. Bit-flip / weight-integrity runtime monitor (model accuracy canary)
**Threat:** Rowhammer-class bit flips in weights drop accuracy 80%→0.1% with a *single* flip, silently (GPUHammer). The flip may be invisible to coarse monitoring.
**Citations:** GPUHammer, USENIX Security 2025 (U Toronto); DeepHammer (USENIX Sec 2020); TrojViT, ProFlip (bit-flip backdoors).
**Build:** periodic canary — hash a known subset of resident weights, or run a fixed reference input through the model and check the output against a sealed expected value. Drift = possible bit-flip/tamper. Pairs with the SHA-256 manifest already in `model_weight_integrity_detector.py` but extends it to *resident* (in-VRAM) weights, not just files at rest.
**Ceiling:** canary catches flips in monitored regions; full-coverage weight hashing every cycle is too expensive — sampling trade-off must be stated honestly.

---

## TIER B — needs one modest new local capability

### B1. GPUThor / ECC-break detector  ★ most timely (2 days old)
**Threat:** **GPUThor (U Toronto, Sept 2026) is the first Rowhammer attack on NVIDIA GPUs to break through ECC** — the exact defense NVIDIA recommended after GPUHammer. Predecessors: GPUHammer (2025, GDDR6 bit-flips), GPUBreach (2026, escalation to root shell on the CPU). Multi-bit flips in one ECC word cause silent mis-correction (ECCploit-class).
**Citations:** GPUThor (csoonline, Sept 2026, U Toronto); GPUHammer USENIX Sec 2025; GPUBreach 2026; NVIDIA Security Notice Rowhammer July 2025; ETH Zurich (Olgun et al.) HBM2 Rowhammer.
**Why probable:** actively researched, root-shell escalation demonstrated, ECC no longer a complete mitigation.
**Why us / why Tier B:** your existing `ECCAnomalyDetector` watches ECC *correction* events. GPUThor's whole point is that it can defeat/mis-correct ECC — so the detector needs to also watch for **ECC mis-correction signatures and double-bit-detection events**, read from `nvidia-smi -q | grep ECC` and `/var/log/syslog`/`dmesg` ECC lines (the one new capability: a dmesg/syslog reader). This is a direct upgrade of a detector you already ship, against an attack that post-dates it.
**Ceiling:** detects the ECC-event signature; cannot by itself prove the flip was adversarial vs. environmental — correlate with access-pattern anomaly.

### B2. MIG cache-partition side-channel validator ("Behind Bars")
**Threat:** On MIG-partitioned H100s, cache-partition cross-VM side channel. GPUHammer paper also notes MIG spatial partitioning implications for confidential computing.
**Citations:** "Behind Bars" MIG precondition (already noted in your `MIGCachePartitionSideChannelDetector` docstring); GPUHammer §MIG/CC.
**Status:** you already have the precondition detector at RESEARCH-STAGE. Tier B because completing it needs a real MIG-enabled pod to validate — already on your backlog.

### B3. KV-cache timing side-channel detector (LLM prompt theft)
**Threat:** Shared KV-cache and GPU memory-allocation timing let a co-tenant infer another user's prompts/outputs token-by-token. Multiple 2024-2025 papers, high reconstruction fidelity (94.8% output, 82.7% input on llama.cpp).
**Citations:** "The Early Bird Catches the Leak" (arXiv:2409.20002); InputSnatch (arXiv:2411.18191); "I Know What You Said" (arXiv:2505.06738); Carlini & Nasr remote timing (arXiv:2410.17175); mitigation: Selective KV-Cache Sharing (arXiv:2508.08438).
**Why probable:** cache-sharing is a default performance optimization; attack demonstrated on real frameworks.
**Why Tier B:** detecting the *attacker* side (anomalous fine-grained timing probes against the cache) needs response-latency telemetry from the serving layer — one new hook into the inference server, not a full network stack. Detecting your *own* exposure (is prefix-caching sharing across tenants?) is a config check, closer to Tier A.
**Ceiling:** timing-probe detection is noisy; strongest as a config-exposure auditor first.

---

## TIER C — Pile 2 (ingestion layer required; listed for completeness)

### C1. MCP tool-poisoning / rug-pull / tool-shadowing detector
**Threat:** the single largest new agentic attack surface. Malicious MCP server writes directives into tool *descriptions* (unsanitized free-text) that the agent hands to the model with full ambient authority. 30+ CVEs in early 2026.
**Citations:** CVE-2025-54136 (MCPoison/Cursor), CVE-2025-54135 (CurXecute), CVE-2025-6514 (mcp-remote RCE, CVSS 9.6), CVE-2025-49596 (MCP Inspector RCE), CVE-2026-12957/12958 (Amazon Q), CVE-2025-66414 (TS SDK DNS rebinding); MCPTox benchmark (arXiv:2508.14925, 36.5% avg / 72.8% peak attack success, <3% refusal); NSA/DoD CSI MCP Security (June 2026); OWASP MCP Top 10 (MCP03:2025); MITRE ATLAS agentic techniques (Oct 2025).
**Why Tier C:** requires visibility into tool descriptors / JSON-RPC `tools/list` responses — the prompt/tool-descriptor collector in the Pile 2 spec. Detector is cheap (schema validation, provenance, Unicode-tag-block concealment scan per arXiv:2607.05744); the collector is the work.

### C2. Indirect prompt injection / context poisoning (confused-deputy)
**Citations:** CVE-2026-13341 (Kong Konnect MCP confused deputy); Greshake et al. indirect injection; MITRE ATLAS "AI Agent Context Poisoning, Memory Manipulation, Thread Injection."
**Tier C:** needs prompt-content visibility. Partial signal today via existing GPU-telemetry `PROMPT_INJECTION_SIDEEFFECT` (already firing on B200) — say that, don't overclaim content inspection.

### C3. Agent memory / vector-DB / RAG poisoning
**Citations:** MITRE ATLAS Memory Manipulation; arXiv:2502.12497 (RAG/dataset loading attack surface).
**Tier C:** needs the shared-memory collector from the Pile 2 spec.

### C4. TEE / confidential-compute side-channel (autoregressive access pattern)
**Threat:** even inside a TEE, autoregressive token generation's predictable memory-access pattern is observable to a co-tenant; Feb 2026 attack undermined partial TEE shielding via crypto design flaw.
**Citations:** arXiv:2605.03213 "When Agents Handle Secrets" (survey, Feb 2026 attack); Foreshadow/SgxPectre lineage.
**Tier C:** needs enclave-level telemetry; overlaps your CC-mode detector (already shipped) which catches the *downgrade* precondition — extend that story rather than claiming full TEE side-channel detection.

---

## Recommended build order (my honest read)

1. **A1 (GGUF/Jinja template) + A2 (safetensors parse validator) + A3 (torch.load auditor)** — all three directly patch the "SAFETENSORS_OK / not-pickle-so-safe" blind spot in the detector I *just shipped*. Highest integrity-per-effort, closes a real gap I left open, all Tier A, all fixture-testable with no hardware. Ship as a follow-up commit to the same file.
2. **B1 (GPUThor/ECC-break upgrade)** — most timely in the whole list (2 days old), upgrades an existing detector against an attack that defeats the mitigation your current ECC detector assumes. Needs only a dmesg/syslog reader.
3. **A4 (LeftoverLocals) + A5 (weight-bitflip canary)** — both anchor Watchdog's existing VRAM-residual and weight-integrity work to named CVEs / USENIX papers, strengthening the security-finding narrative.
4. **B3 config-exposure half (KV-cache sharing auditor)** — cheap Tier-A-ish config check now; full timing detector later.
5. **Pile 2 collectors** — when you're ready to build the ingestion layer, MCP tool-poisoning (C1) is the highest-value target given the CVE volume, but it's gated on the collector.

**Honesty guardrails for any deck built on this:**
- "Researched and cited" ≠ "built." This document is a candidate list.
- GPUThor/GPUBreach/LeftoverLocals are *real named CVEs/papers* — cite them by ID, don't paraphrase into vague "advanced threats."
- Anything Tier C must be labeled "requires ingestion layer (roadmap)," matching the Pile 2 spec already in the repo.
- Don't claim HBM3/HBM3e Rowhammer detection as validated: per the research, whether GPUHammer-style flips occur on H100/H200/B200 HBM3/HBM3e was *not tested* as of the source; GPUThor breaks ECC but confirm the exact affected parts before claiming coverage.
