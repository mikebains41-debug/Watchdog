#!/usr/bin/env python3
"""Tests for scripts/moe_config_audit.py -- example configs, no network."""

import json
import os
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
for p in (os.path.join(HERE, "..", "scripts"), os.path.join(HERE, ".."), HERE):
    if p not in sys.path:
        sys.path.insert(0, p)

import moe_config_audit as m  # noqa: E402

PASSED, FAILED = [], []


def check(name, cond, detail=""):
    (PASSED if cond else FAILED).append(name)
    print("[%s] %s %s" % ("PASS" if cond else "FAIL", name, "" if cond else detail))


def run(obj_or_text, tenancy="unknown"):
    d = tempfile.mkdtemp()
    p = os.path.join(d, "cfg")
    with open(p, "w") as fh:
        fh.write(obj_or_text if isinstance(obj_or_text, str) else json.dumps(obj_or_text))
    pairs, text = m.read_pairs(p)
    return m.audit(pairs, text, tenancy)


DENSE = {"architectures": ["LlamaForCausalLM"], "hidden_size": 4096, "num_hidden_layers": 32}
MIXTRAL = {"architectures": ["MixtralForCausalLM"], "num_local_experts": 8, "num_experts_per_tok": 2}
DEEPSPEED_DROP = {"moe": {"num_experts": 16, "capacity_factor": 1.25, "drop_tokens": True}}
EXPERT_CHOICE = {"num_experts": 64, "router_type": "expert_choice", "capacity_factor": 2.0}
DROPLESS = {"num_experts": 128, "moe_top_k": 8, "capacity_factor": None, "dropless": True}
CLI = "vllm serve some-moe --moe-capacity-factor 1.5 --drop_tokens true --num_experts 32"


def main():
    print("=" * 60)
    print("MoE CONFIG AUDIT -- TESTS")
    print("=" * 60)

    r = run(DENSE)
    check("dense model -> NOT_MOE, not applicable", r["verdict"] == "NOT_MOE" and r["risk"] == "NOT_APPLICABLE")

    r = run(MIXTRAL)
    check("Mixtral-style, no capacity field -> likely dropless, NOT called safe",
          r["verdict"] == "TOKEN_CHOICE_NO_CAPACITY_FIELD" and "Not a clean bill" in " ".join(r["findings"]))
    check("no capacity field -> not exposed to the published attacks",
          r["risk"] == "NOT_EXPOSED_TO_PUBLISHED_ATTACKS")

    r = run(DEEPSPEED_DROP, "shared")
    check("capacity 1.25 + drop_tokens + shared -> CAPACITY_LIMITED / EXPOSED",
          r["verdict"] == "CAPACITY_LIMITED" and r["risk"] == "EXPOSED", str(r["verdict"]) + " " + r["risk"])
    check("capacity-limited cites the buffer-overflow paper", any("2402.05526" in f for f in r["findings"]))

    r = run(DEEPSPEED_DROP, "single")
    check("same config, single-tenant -> mechanism present, not reachable",
          r["risk"] == "MECHANISM_PRESENT_NOT_REACHABLE")

    r = run(DEEPSPEED_DROP)
    check("same config, tenancy unknown -> says so, does not guess",
          r["risk"] == "MECHANISM_PRESENT_TENANCY_UNKNOWN")

    r = run(EXPERT_CHOICE, "shared")
    check("expert-choice routing + shared -> EXPOSED, cites the leakage paper",
          r["verdict"] == "EXPERT_CHOICE_ROUTING" and r["risk"] == "EXPOSED"
          and any("2410.22884" in f for f in r["findings"]))
    check("exposed findings state the white-box caveat",
          any("white-box" in l for l in r["limits"]))

    r = run(DROPLESS, "shared")
    check("explicit dropless -> DROPLESS, not exposed even when shared",
          r["verdict"] == "DROPLESS" and r["risk"] == "NOT_EXPOSED_TO_PUBLISHED_ATTACKS")

    r = run(CLI, "shared")
    check("server launch args parsed: capacity + dropping flagged",
          r["verdict"] == "CAPACITY_LIMITED" and r["risk"] == "EXPOSED", r["verdict"])

    r = run("vllm serve some-moe --num_experts 32 --moe-capacity-factor 1.5", "shared")
    check("prefixed flag --moe-capacity-factor recognised on its own (no drop flag)",
          r["verdict"] == "CAPACITY_LIMITED" and r["risk"] == "EXPOSED", r["verdict"])

    r = run(MIXTRAL)
    check("every result states tie-breaking cannot be checked from config",
          any("Tie-breaking" in l for l in r["limits"]))
    check("every result states a clean result is not proof of isolation",
          any("not proof of isolation" in l for l in r["limits"]))

    print("\n" + "=" * 60)
    print("PASSED: %d FAILED: %d" % (len(PASSED), len(FAILED)))
    for f in FAILED:
        print("  FAILED: %s" % f)
    return 1 if FAILED else 0


if __name__ == "__main__":
    sys.exit(main())
