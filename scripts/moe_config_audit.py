#!/usr/bin/env python3
"""
Watchdog -- MoE serving configuration audit.
Author: Manmohan (Mike) Bains / GPU Optimizer Inc.

WHAT IT CHECKS
  Two published attacks break isolation BETWEEN USERS WHO SHARE A BATCH in a
  Mixture-of-Experts model:

  1. Buffer overflow in MoE (Hayes et al., 2024, arXiv 2402.05526): when each
     expert has a capacity limit smaller than the tokens in the batch, one
     user's tokens can fill an expert's buffer and change another user's
     routing -- degrading their output (a denial-of-service class).
  2. MoE Tiebreak Leakage (Yona et al., Google DeepMind, 2024,
     arXiv 2410.22884): with expert-choice routing and deterministic
     tie-breaking, an attacker in the same batch can extract a victim's
     prompt. Demonstrated on a two-layer Mixtral with white-box access.

  Both depend on CAPACITY-LIMITED routing (tokens can be dropped) or
  EXPERT-CHOICE routing. Dropless token-choice MoE -- common in inference
  serving -- does not have the mechanism either attack uses.

WHAT IT CANNOT CHECK
  - Whether tie-breaking is deterministic (that lives in kernel code, not
    config). The authors' recommended mitigation is to randomise it.
  - Whether requests from DIFFERENT users are batched together. The operator
    must state tenancy (--tenancy shared|single); otherwise it is UNKNOWN.
  - Framework defaults that are not written in the config. Absent a
    capacity field, the verdict is 'likely dropless', never 'safe'.
  - Anything beyond these two published attacks. A clean result is not a
    proof of isolation.

USAGE
  python3 scripts/moe_config_audit.py MODEL_CONFIG.json [SERVER_CONFIG ...]
          [--tenancy shared|single|unknown] [--json out.json]
"""

import argparse
import json
import re
import sys

MOE_KEYS = ("num_experts", "num_local_experts", "n_routed_experts", "moe_num_experts",
            "num_experts_per_tok", "moe_top_k", "expert_capacity", "router_type",
            "moe_layer_freq", "n_shared_experts")
CAPACITY_KEYS = ("capacity_factor", "eval_capacity_factor", "train_capacity_factor",
                 "expert_capacity", "min_capacity")
DROP_KEYS = ("drop_tokens", "token_dropping", "moe_token_dropping")
DROPLESS_KEYS = ("dropless", "moe_dropless")
EC_PATTERN = re.compile(r"expert[_\- ]?choice|\bec[_\- ]?rout", re.I)
TEXT_KV = re.compile(r"--?([A-Za-z0-9_\-]+)[=\s:]+([^\s,}]+)")

REF_OVERFLOW = "Hayes et al. 2024, arXiv 2402.05526"
REF_LEAK = "Yona et al. (Google DeepMind) 2024, arXiv 2410.22884"


def _norm(k):
    return str(k).strip().lower().replace("-", "_")


def flatten(obj, prefix=""):
    """Yield (key, value) pairs from nested JSON."""
    if isinstance(obj, dict):
        for k, v in obj.items():
            yield _norm(k), v
            for kv in flatten(v, prefix + str(k) + "."):
                yield kv
    elif isinstance(obj, list):
        for v in obj:
            for kv in flatten(v, prefix):
                yield kv


def read_pairs(path):
    """JSON if it parses; otherwise scan text for key=value / --flag value."""
    with open(path, "r", errors="replace") as fh:
        text = fh.read()
    try:
        return list(flatten(json.loads(text))), text
    except ValueError:
        pairs = [(_norm(k), v) for k, v in TEXT_KV.findall(text)]
        for line in text.splitlines():
            if ":" in line and not line.strip().startswith("#"):
                k, _, v = line.partition(":")
                if k.strip():
                    pairs.append((_norm(k), v.strip()))
        return pairs, text


def _num(v):
    try:
        if isinstance(v, bool):
            return None
        return float(str(v).strip().strip('"').strip("'"))
    except (ValueError, TypeError):
        return None


def _truthy(v):
    return str(v).strip().strip('"').lower() in ("true", "1", "yes", "on")


def audit(pairs, text, tenancy="unknown"):
    keys = {k for k, _ in pairs}
    is_moe = any(k in keys for k in MOE_KEYS) or any(k.startswith("moe_") for k in keys)
    evidence = []

    expert_choice = bool(EC_PATTERN.search(text))
    if expert_choice:
        evidence.append("expert-choice routing mentioned in config")

    capacity = None
    for k, v in pairs:
        if k in CAPACITY_KEYS or k.endswith("capacity_factor"):
            n = _num(v)
            if n is not None and n > 0:
                capacity = n
                evidence.append("%s = %s (capacity-limited)" % (k, v))
    dropping = any(k in DROP_KEYS and _truthy(v) for k, v in pairs)
    if dropping:
        evidence.append("token dropping enabled")
    dropless = any(k in DROPLESS_KEYS and _truthy(v) for k, v in pairs)
    if dropless:
        evidence.append("dropless explicitly enabled")

    findings = []
    if not is_moe:
        verdict = "NOT_MOE"
        findings.append("No Mixture-of-Experts fields found. These two attacks do not apply.")
    elif expert_choice:
        verdict = "EXPERT_CHOICE_ROUTING"
        findings.append("Expert-choice routing: the mechanism used by MoE Tiebreak Leakage (%s)." % REF_LEAK)
    elif (capacity is not None or dropping) and not dropless:
        verdict = "CAPACITY_LIMITED"
        findings.append("Capacity-limited routing: the mechanism used by the MoE buffer-overflow attack (%s)." % REF_OVERFLOW)
    elif dropless:
        verdict = "DROPLESS"
        findings.append("Dropless routing: neither published attack's mechanism is present.")
    else:
        verdict = "TOKEN_CHOICE_NO_CAPACITY_FIELD"
        findings.append("MoE with no capacity or dropping fields in these configs -- likely dropless, "
                        "but framework defaults are not visible here. Not a clean bill.")

    exposed = verdict in ("EXPERT_CHOICE_ROUTING", "CAPACITY_LIMITED")
    if exposed:
        if tenancy == "shared":
            risk = "EXPOSED"
            findings.append("Requests from different users share batches: the attack precondition is met.")
        elif tenancy == "single":
            risk = "MECHANISM_PRESENT_NOT_REACHABLE"
            findings.append("Single-tenant: these cross-batch attacks need another user in the batch.")
        else:
            risk = "MECHANISM_PRESENT_TENANCY_UNKNOWN"
            findings.append("Tenancy unknown: state --tenancy shared|single to resolve.")
    else:
        risk = "NOT_EXPOSED_TO_PUBLISHED_ATTACKS" if is_moe else "NOT_APPLICABLE"

    limits = [
        "Tie-breaking determinism is in kernel code, not config; cannot be checked here. "
        "Mitigation recommended by the authors: randomise tie-breaking.",
        "Only the two published attacks are assessed. A clean result is not proof of isolation.",
        "Framework defaults not written in the config are invisible to this audit.",
    ]
    if exposed:
        limits.append("The published leakage demonstration used white-box access and a controlled "
                      "batch position; real exploitability in a given service is not established here.")
    return dict(verdict=verdict, risk=risk, is_moe=is_moe, evidence=evidence,
                findings=findings, limits=limits, tenancy=tenancy,
                references=[REF_OVERFLOW, REF_LEAK])


def main(argv=None):
    ap = argparse.ArgumentParser(description="Watchdog MoE serving configuration audit")
    ap.add_argument("configs", nargs="+", help="model config.json and/or server config / launch args")
    ap.add_argument("--tenancy", choices=("shared", "single", "unknown"), default="unknown")
    ap.add_argument("--json")
    a = ap.parse_args(argv)
    pairs, text = [], ""
    for p in a.configs:
        pp, tt = read_pairs(p)
        pairs += pp
        text += "\n" + tt
    r = audit(pairs, text, a.tenancy)
    print("MoE CONFIGURATION AUDIT")
    print("configs :", ", ".join(a.configs))
    print("verdict : %s" % r["verdict"])
    print("risk    : %s" % r["risk"])
    for e in r["evidence"]:
        print("  evidence: %s" % e)
    for f in r["findings"]:
        print("  - %s" % f)
    print("limits:")
    for l in r["limits"]:
        print("  * %s" % l)
    if a.json:
        with open(a.json, "w") as fh:
            json.dump(r, fh, indent=2)
        print("written:", a.json)
    return 0


if __name__ == "__main__":
    sys.exit(main())
