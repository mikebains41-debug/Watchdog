# Watchdog AI-Attack Coverage — Build Status & Pile 2 Design Spec
**GPU Optimizer Inc. | August 2026**
**Scope:** everything from the "Evolution of Autonomous Agent Cyber Operations" briefing (OWASP ASI 1–10, 40 IoCs, 20 threat categories, 4 attack phases) mapped to what Watchdog can and cannot detect, with a concrete build spec for the parts that need a new data source.

---

## The core split

Watchdog today ingests **only `nvidia-smi`-accessible fields** (power, temperature, clocks, VRAM, utilization, PCIe link gen/width, driver/VBIOS fingerprint, NVLink status) — confirmed in `HARDWARE_LIMITATIONS.md`. Every threat in the briefing falls into one of two piles:

- **Pile 1 — buildable on existing telemetry or on local file/process inspection.** Built and tested this session (see below).
- **Pile 2 — requires a data source Watchdog does not ingest yet** (network packets, egress connections, IAM/cloud-API call logs, Redis/vector-DB access, prompt content, package-registry events). No honest detector can be written against these until the ingestion layer exists. Designed below; not built.

**A detector that reads a data field that doesn't exist is not a detector.** That's the line this document holds.

---

## PILE 1 — BUILT THIS SESSION (detection + remediation)

All three follow the existing module pattern: standalone dict return, graceful `SKIPPED` fallback, no GPU/torch import required for tests, deterministic against synthetic/mocked input. 23/23 tests passing in `test_ai_attack_detectors.py`.

| File | Threat covered | Detection basis | Remediation |
|---|---|---|---|
| `fpna_determinism_detector.py` | FPNA / kernel-order manipulation (IoC T9, threat #14) | Re-run-to-run variation of a caller-supplied output scalar; attack-grade instability flagged, transition-from-clean detected | **Auto-safe:** force deterministic algorithms (reversible). Gated by default, auto on opt-in. |
| `micro_burst_detector.py` | Micro-burst compute hiding (IoC #15) + idle-padding/dilution evasion | Peak-to-mean ratio + duty-cycle bimodality + burst repetition on high-rate samples. Emits honest `UNDERSAMPLED` when sample rate too coarse. | **Gated, never auto-kill** — burst shape is suggestive not proof; correlate PID w/ whitelist, human review. |
| `model_weight_integrity_detector.py` | Silent weight swap (IoC #19/#34) + malicious pickle payloads | SHA-256 drift vs approved manifest; pickle **opcode scan** (not execution) catching dangerous globals incl. protocol-4 `STACK_GLOBAL` encoding + ZIP-container `.pth` | **Auto-safe:** quarantine (chmod 000, move out of load path, never delete). Weight-swap w/o malicious pickle is **gated** (could be legit update). |

**Research backing (for docstrings / deck citations):**
- FPNA: Shanmugavelu et al., *Robustness of Deep Learning Classification to Adversarial Input on GPUs*, Euro-Par 2025 / arXiv:2503.17173. Key finding: FPNA + async reduction ordering flips classification with **no input perturbation**; black-box variant uses Bayesian optimization to find a co-tenant workload that biases the victim's reductions; robustness overestimated up to ~4.6%.
- Micro-burst / dilution: *Detecting Hidden ML Training With Zero-Overhead Telemetry*, arXiv:2606.19262 (2026) — idle-padding/dilution evasion survives at fine sample rates; economics of padding unviable at scale.
- Pickle: PickleScan bypass CVE-2025-10155/10156/10157 (CVSS 9.3, extension-spoof / ZIP-CRC / blocklist-evasion), CVE-2025-46417 (DNS exfil); ShaiWorm PyTorch-Lightning supply-chain compromise (malicious `lightning` 2.6.2/2.6.3, April 2026); tensor steganography (Snyk, 2024). PyTorch weights-only unpickler default since 2.6 (Nov 2024) but pickle `.pth` still ubiquitous.
- Cryptojacking (already covered by existing CovertMiningDetector): behavior-based HPC-counter detection ~96% (ACM CODASPY), MagTracer magnetic-leakage (MobiCom 2023), 2026 SEO-poisoning/ScreenConnect campaign (Microsoft Security).

**Still buildable in Pile 1 next session (same pattern, no new data source):**
- Kernel-module / unsigned-driver auditor (parses `/proc/modules`, `/sys/module/*/initstate`) — note: real repo already has this as `module128` (kernel module audit) and `module59-65`; **check for duplication before building.**
- System-PATH alteration detector (`$PATH` wrapper-ahead-of-legit-binary, IoC #25) — likely overlaps existing `module114-128` batch. Verify first.
- Package/typosquat auditor (`pip list --format=json`, unpinned/newly-registered) — overlaps ShadowInitPackageIntegrityDetector (already built). Verify first.

---

## PILE 2 — DESIGN SPEC (not built; needs ingestion layer)

### The missing piece: a telemetry ingestion layer

Every Pile 2 detector depends on one of four new data sources Watchdog doesn't currently collect. The honest architecture is: **build the collectors first, each emitting normalized events into the existing detection pipeline, then write detectors against those events.** Detectors are cheap; the collectors are the real work.

| Collector | Data source | Mechanism | Feasibility on a cloud pod |
|---|---|---|---|
| **NetFlow/egress collector** | outbound connections, DNS, beacons | eBPF (`tc`/`cgroup` egress hooks) or `/proc/net/*` polling + `conntrack`; passive, no inline proxy | eBPF needs `CAP_BPF`/privileged container — often available on RunPod/bare metal, blocked on locked-down VMs. `/proc/net/tcp` polling is the always-available fallback (lower fidelity). |
| **Cloud-API / IAM audit collector** | metadata endpoint hits, IAM calls, NHI token use | tail CloudTrail/GCP Audit Logs via API; locally, hook `169.254.169.254` access via eBPF or egress collector | Requires cloud-account read creds (customer-supplied), OR local metadata-endpoint egress capture. Not GPU-adjacent. |
| **Shared-memory / cache access collector** | Redis / Memcached / vector-DB writes | Redis `MONITOR`/keyspace notifications, or client-lib wrapper; for vector DBs, proxy or audit-log tail | Needs access to the datastore instance and its config. In-scope only where Watchdog is co-deployed with the app tier. |
| **Prompt / inter-agent message collector** | agent I/O, MCP tool-calls, system-prompt state | instrument the agent runtime (LangChain/LlamaIndex callback, MCP interceptor, or sidecar) | Requires integration into the agent framework — an SDK/hook, not passive telemetry. Biggest lift. |

Each collector normalizes to a common event: `{ts, source, actor (pid/token/agent_id), verb, target, metadata}` and pushes into the existing pipeline so detectors reuse the current baseline/alert/remediation machinery.

### Pile 2 detectors, by collector

**On NetFlow/egress collector:**
- **Sustained external hub beacon** (IoC #10/#40): outbound to HuggingFace/OpenAI/model registries from a zone that shouldn't reach them. Detection: allowlist + periodicity (beacon = regular interval). Remediation: **auto-safe egress block** to the specific endpoint (reversible firewall rule) — this one is genuinely auto-remediable because blocking one outbound IP is low-blast-radius.
- **Segmented payload chunking / exfil** (IoC #20): high-entropy small packets hidden in health-check-sized pings; irregular packet-size distribution. Detection-only initially (block risks false-positive on legit heartbeats).
- **Mass scan / parallel execution** (IoC #1, T4): fan-out to many IPs/ports in a tight window. Detection + **gated** connection-rate-limit.
- **Ephemeral key swapping** (IoC #19): high-frequency local key create/destroy — actually observable via `/proc` + file events, borderline Pile 1; can prototype without full netflow.

**On cloud-API/IAM collector:**
- **NHI token abuse / orphaned token activation** (IoC #16/#9, T3): token used without matching human-login timestamp, or unusual metadata-request sequence walking security boundaries. Detection: token-age vs activity correlation. Remediation: **gated** token revocation (auto-revoke is too dangerous — could lock out a legit service).
- **Automated IAM policy expansion** (IoC #23): frequent narrow scope-append requests. Detection-only.
- **Lateral token cascades** (IoC #17): one component checking out adjacent secret stores. Detection + **gated** isolation.

**On shared-memory collector:**
- **Memory/context poisoning** (IoC #32, ASI06, T16): unauthorized writes to shared Redis/vector-DB context ("you are now admin"). Detection: write-source allowlist + semantic flag on injected role strings. Remediation: **auto-safe context reset** IS available here (flush poisoned key, matching briefing's Phase 3.2) — but gate it, because flushing shared cache mid-operation can disrupt legit agents.

**On prompt/inter-agent collector:**
- **Multi-lingual / obfuscated prompt injection** (IoC #30, ASI01, T12): scan decoded prompt intent regardless of language. Needs an LLM-in-the-loop classifier (could use the Anthropic API pattern) — heaviest component.
- **Cross-model feedback loops** (IoC #26, T14): two agents iterating to refine a forbidden prompt. Detection: inter-agent message graph + repetition/escalation signature.
- **System-prompt exhaustion / drop** (IoC #14/#28, T13): flood of instructions forcing safety-prompt drop; also visible as a **memory-allocation spike on existing GPU telemetry** — so a *partial* signal is Pile 1 (context-length inflation via VRAM), full semantic detection is Pile 2.
- **Recursive tool self-generation** (IoC #27): agent writing new unmonitored scripts — overlaps MCP tool-call interception + the existing AI-agent-containment modules (`module76-80`). Verify overlap.

### Build order recommendation (Pile 2)

1. **NetFlow/egress collector first** — unblocks the most detectors, has a genuine auto-remediation (egress block), and `/proc/net` fallback works even without eBPF privileges. Highest coverage-per-effort.
2. **Shared-memory collector** — self-contained, clear auto-safe remediation (context reset), directly serves the pharma/insurance "tamper-evident + data-integrity" story.
3. **Cloud-API/IAM collector** — high value but depends on customer-supplied creds; detection-only to start.
4. **Prompt/inter-agent collector** — biggest lift (agent-framework integration + LLM classifier); do last, and note that the GPU-telemetry side-channel (memory-spike, power-signature — which Watchdog ALREADY fires on per the B200 `PROMPT_INJECTION_SIDEEFFECT` result) gives a partial detection today without it.

### Honest positioning for decks

- **Do say:** "Watchdog detects prompt-injection *side-effects* on GPU telemetry (power/memory signature) today — confirmed firing on real B200 hardware." That's true and already validated.
- **Do NOT say:** "Watchdog inspects prompt content / blocks semantic injection" — not until the prompt collector exists.
- Pile 1 built this session materially strengthens the pharma/insurance case: model-weight integrity (21 CFR Part 11 data integrity), quarantine-not-delete (evidence preservation for audit), FPNA determinism (compute-correctness verification). These are real, testable, and don't overclaim.

---

## Cross-reference: briefing threats → Watchdog status

| Briefing item | Status |
|---|---|
| #11 GPUHammer/Rowhammer | ✅ Built (ECCAnomalyDetector) |
| #12 ShadowInit/ShadowRay | ✅ Built (ShadowInitPackageIntegrityDetector) |
| #13 Cryptojacking | ✅ Built (CovertMiningDetector) |
| #14 FPNA | ✅ **Built this session** (fpna_determinism_detector) |
| #15 Model extraction (black-box) | ⚠️ Pile 2 (needs API query-pattern collector) |
| #16 Denial of Wallet | ⚠️ Pile 2 (needs per-request cost telemetry) |
| #17 Training data poisoning | ⚠️ Pile 2 (needs bucket/provenance hooks) |
| #18 Sandbox escape | ✅ Partial (container_escape_test, module124 docker escape) |
| #19 Silent weight swap | ✅ **Built this session** (model_weight_integrity_detector) |
| #20 Shadow fine-tuning | ⚠️ Pile 2 (needs training-server telemetry) |
| IoC #15 Micro-burst | ✅ **Built this session** (micro_burst_detector) |
| IoCs #1,#6,#10,#20,#40 (network) | ⚠️ Pile 2 (NetFlow collector) |
| IoCs #16,#17,#18,#23 (IAM/token) | ⚠️ Pile 2 (cloud-API collector) |
| IoCs #26,#28,#30,#31,#32 (prompt/memory) | ⚠️ Pile 2 (prompt + shared-mem collectors); #11/#31 partial via GPU memory telemetry today |
| ASI01/06/09 (agent goal/memory/trust) | ⚠️ Pile 2, partial GPU side-channel today |

---

*Files delivered this session: `fpna_determinism_detector.py`, `micro_burst_detector.py`, `model_weight_integrity_detector.py`, `test_ai_attack_detectors.py`. Conform to real repo module conventions (check `module51-54` style + `test_quantum_modules.py` registration) before committing; renumber into the live scheme rather than committing under placeholder names.*
