# Watchdog — Mixture-of-Experts: Isolation Risks and Telemetry Behaviour

21 September 2026. Covers checklist items A–E.

---

## A. The research

**Two published attacks break isolation between users who share a batch in
a Mixture-of-Experts (MoE) model.**

1. **Buffer overflow in MoE** — Hayes et al., Google DeepMind, 2024
   (arXiv 2402.05526). Any routing strategy whose per-expert capacity is
   smaller than the tokens in the batch is vulnerable: an attacker's tokens
   fill an expert's buffer and change another user's routing, degrading
   their output. With sequential assignment, the last item in the batch is
   the most exposed.
2. **MoE Tiebreak Leakage** — Yona et al., Google DeepMind, 2024
   (arXiv 2410.22884). An attacker whose queries land in the same batch as a
   victim's can exploit expert-choice routing and deterministic tie-breaking
   (the `torch.topk` CUDA implementation) to recover the victim's prompt.
   Demonstrated on a two-layer Mixtral, averaging about 100 queries per
   token.

**Limits, stated with the finding:** the leakage demonstration used
white-box access; in production services users typically cannot choose
their batch or their position in it; path tracking gets exponentially
harder with depth. The authors' recommended mitigation is to randomise
tie-breaking.

**What this means for Watchdog:** this is tenant isolation broken *inside
the model server*, one layer above the GPU. GPU telemetry — power, clocks,
memory — cannot see it. It is a **configuration audit**, in the same family
as the post-quantum crypto audit, not a telemetry detector.

---

## B. Which deployments actually have the mechanism

Both attacks need **capacity-limited routing** (tokens can be dropped) or
**expert-choice routing**. Findings:

- Inference commonly runs **dropless** MoE. The AWS Neuron MoE inference
  guide states dropless (no capacity factor) is recommended for inference
  and lists GPT-OSS, Llama 4 and DBRX as dropless; dropping is enabled only
  by setting a capacity factor.
- Modern serving engines implement MoE with grouped GEMM kernels, which
  process every token routed to an expert with no buffer limit.
- Capacity-limited routing is mainly a **training** technique (Switch
  Transformer used capacity factors around 1.0–2.0).
- DeepSeek-V3 balances expert load without dropping, using a per-expert
  routing bias; vLLM's EPLB balances load by replicating hot experts.
- Dropless does not remove load imbalance — it converts it from dropped
  tokens into latency: an overloaded expert becomes a straggler.

**Conclusion:** mainstream MoE *inference* is usually not configured with
the mechanism either published attack uses. The risk concentrates in
capacity-limited or expert-choice deployments that batch requests from
different users. Not verified for every framework and version — which is
exactly what the audit checks per deployment.

---

## D. The audit tool — `scripts/moe_config_audit.py`

Reads a model's `config.json` and/or a server config or launch command.

| Verdict | Meaning |
|---|---|
| `NOT_MOE` | Attacks do not apply |
| `DROPLESS` | Neither published mechanism present |
| `TOKEN_CHOICE_NO_CAPACITY_FIELD` | Likely dropless; defaults not visible — **not** a clean bill |
| `CAPACITY_LIMITED` | Buffer-overflow mechanism present |
| `EXPERT_CHOICE_ROUTING` | Leakage mechanism present |

Combined with the operator's stated tenancy (`--tenancy shared|single`) the
risk becomes `EXPOSED`, `MECHANISM_PRESENT_NOT_REACHABLE`, or
`MECHANISM_PRESENT_TENANCY_UNKNOWN`. It never guesses tenancy.

Every result states: tie-breaking determinism lives in kernel code and
cannot be read from config; only these two attacks are assessed; a clean
result is not proof of isolation. 14 tests pass on example configs.

---

## C. Telemetry behaviour — `scripts/repro_moe_multi_gpu.py`

At 1 Hz, token-level expert switching averages out. What survives in
nvidia-smi telemetry is **request bursts** (busy periods and idle gaps) and
**per-GPU imbalance** (hot experts on some cards). Eight synthetic H200-like
GPUs holding a resident model, through the real `FullDetectionPipeline`:

- S1 steady dense · S2 bursty dense · S3 bursty MoE (skewed load) ·
  S4 = S3 plus a genuine ghost on GPU 7 (450 W at 0% utilisation, clocks
  stuck high)

Checks: the README's negative control ("resident model, process alive"
must stay silent), the ghost positive control, and any MoE-specific alerts.

**Results:** `evidence/moe_serving_check.txt`. Synthetic — shows behaviour,
validates nothing. NVLink traffic is not modelled, so
`NVLinkContentionDetector` is not exercised.

---

## E. Needs hardware

Run a real MoE model on a multi-GPU pod, capture telemetry with detection
off, and compare it with the synthetic pattern in C. Add NVLink traffic
capture so the all-to-all pattern can be measured against
`NVLinkContentionDetector`, whose own docstring notes that legitimate
collective traffic resembles contention.
