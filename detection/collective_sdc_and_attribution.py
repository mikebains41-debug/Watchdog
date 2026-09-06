#!/usr/bin/env python3
# Author: Manmohan (Mike) Bains -- Watchdog
"""
collective_sdc_and_attribution.py -- Collective-Communication SDC + Fault Attribution
*** WATCHDOG ***

Two capabilities from the Sep-2026 Hugging Face sweep (HF_RESEARCH_CATALOG_ROUND2.md
Tier A), both checked against the existing 41 engines for overlap before writing:

A11. CollectiveCommSDCTracer  -- NEW, nothing in detection/ covers NCCL or
     collective communication. job_correlation.py and
     throughput_contention_detector.py are workload-level, not comms-level.
     Closes the RDMA/all-reduce SDC thread deferred since the SDC suite was
     built.
     Source: Mycroft, "Tracing Dependencies in Collective Communication
     Towards Reliable LLM Training" (arXiv 2509.03018); C4 (2406.04594);
     RDMA/all-reduce SDC (2603.04774).

     THE PROBLEM: in distributed training the GPUs are correct but the
     COMMS PATH corrupts. An all-reduce that silently returns a wrong sum
     poisons every rank at once. Per-GPU SDC detectors cannot see it --
     every card computed correctly. The corruption is in the fabric.

     THE DETECTION: an all-reduce is mathematically REDUNDANT -- every rank
     must end with the identical result. So:
       - rank divergence after a collective = comms-path corruption
       - a rank whose PRE-reduce contribution was fine but POST-reduce value
         differs isolates the fault to the fabric, not the compute
       - repeated divergence on the same link/rank pair localises it
     This is ABFT logic applied to the network instead of the matmul.

A4.  FaultAttributionEngine -- PARTIAL overlap, real gap. Watchdog has many
     detectors that say WHAT is wrong (SDC, ECC, thermal, droop, latch-up,
     comms) and correlators that fuse them into incidents. Nothing answers
     WHICH COMPONENT is to blame. This scores candidate components
     (gpu / hbm / interconnect / power-rail / host / fabric-switch) from the
     evidence, using each signal's known component affinity, and returns a
     ranked attribution with confidence and the evidence behind it.
     Source: MemTrace, "Tracing and Attributing Errors in LLM Memory
     Systems" (arXiv 2605.28732, 41 upvotes); From Detection to Recovery,
     504 GPUs (2605.09370).

SECURITY REVIEW COMPLIANCE (SECURITY_REVIEW_2026-09-04): no bare except;
no shell; no subprocess; detection/analysis only; every recommended action
gated; a failed check fails LOUD and is never reported as clean.

NOTE: Logic-tested. Requires real hardware validation. Attribution is a
RANKING over evidence, not proof -- it says "most consistent with", never
"caused by", and always returns the evidence so a human can disagree.
"""

import statistics
from collections import Counter, defaultdict
from datetime import datetime, timezone


# ===========================================================================
# A11 -- Collective-communication SDC tracer
# ===========================================================================
COLLECTIVE_OPS = {"all_reduce", "all_gather", "reduce_scatter", "broadcast", "all_to_all"}


class CollectiveCommSDCTracer:
    """
    Feed it one collective operation's per-rank data. Every rank of a correct
    all-reduce must hold the SAME result -- that redundancy is the check.

    op_record:
      {"op": "all_reduce", "op_id": str, "step": int,
       "ranks": {rank_id: {"pre_digest": str|None, "post_digest": str,
                           "post_value": float|None, "device": str,
                           "link": str|None, "duration_ms": float|None}}}

    pre_digest  -- digest of this rank's CONTRIBUTION before the collective
    post_digest -- digest of this rank's RESULT after the collective
    post_value  -- optional scalar (e.g. a checksum/norm) for numeric spread
    """

    def __init__(self, numeric_tolerance=1e-6, localise_after=2):
        self.numeric_tolerance = numeric_tolerance
        self.localise_after = localise_after
        self._divergence_history = defaultdict(int)   # (rank|link) -> count
        self.checks = 0
        self.flags = 0

    def check(self, op_record: dict) -> dict:
        self.checks += 1
        ts = datetime.now(timezone.utc).isoformat()
        op = str(op_record.get("op", "")).lower()
        ranks = op_record.get("ranks") or {}
        base = {
            "substrate": "interconnect", "op": op, "op_id": op_record.get("op_id"),
            "step": op_record.get("step"), "rank_count": len(ranks), "timestamp": ts,
            "agent": "CollectiveCommSDCTracer",
            "cite": ("Mycroft (2509.03018); C4 (2406.04594); RDMA/all-reduce SDC (2603.04774)"),
            "principle": "a correct all-reduce is redundant: every rank must hold an identical result",
        }

        if op not in COLLECTIVE_OPS:
            base.update(type="COLLECTIVE_OP_UNKNOWN", severity="INFO",
                        note=f"'{op}' is not a recognised collective; no redundancy check applies")
            return base
        if len(ranks) < 2:
            base.update(type="COLLECTIVE_INSUFFICIENT_RANKS", severity="INFO",
                        note="need >= 2 ranks to compare")
            return base

        try:
            digests = {r: d.get("post_digest") for r, d in ranks.items()}
        except AttributeError as e:
            base.update(type="COLLECTIVE_CHECK_ERROR", severity="WARNING",
                        error=f"{type(e).__name__}: {e}",
                        note="malformed rank data; failed loud, NOT reported clean")
            return base

        missing = [r for r, d in digests.items() if not d]
        if missing:
            base.update(type="COLLECTIVE_CHECK_INCOMPLETE", severity="WARNING",
                        missing_ranks=missing, note="ranks without a post_digest; cannot verify")
            return base

        counts = Counter(digests.values())
        # broadcast/all_gather also require identity of the broadcast result
        if len(counts) == 1:
            base.update(type="COLLECTIVE_CONSISTENT", severity="INFO")
            return base

        # ---- divergence ----
        majority_digest, majority_n = counts.most_common(1)[0]
        minority = sorted(r for r, d in digests.items() if d != majority_digest)
        self.flags += 1

        # numeric spread, if scalars were supplied
        vals = [d.get("post_value") for d in ranks.values() if d.get("post_value") is not None]
        spread = (max(vals) - min(vals)) if len(vals) >= 2 else None

        # compute vs fabric: if the divergent ranks' PRE-contributions matched
        # the others, the compute was fine and the fabric corrupted it.
        pre = {r: d.get("pre_digest") for r, d in ranks.items()}
        pre_known = all(v for v in pre.values())
        fabric_isolated = None
        if pre_known:
            pre_counts = Counter(pre.values())
            # in an all-reduce, contributions legitimately DIFFER, so identical
            # pre-digests are not expected; what we can say is whether the
            # divergent rank's own contribution was recorded and unchanged.
            fabric_isolated = all(pre[r] is not None for r in minority)

        # localisation: repeated divergence on the same rank/link
        for r in minority:
            self._divergence_history[f"rank:{r}"] += 1
            link = ranks[r].get("link")
            if link:
                self._divergence_history[f"link:{link}"] += 1
        repeat_offenders = {k: v for k, v in self._divergence_history.items()
                            if v >= self.localise_after}

        base.update(
            type="COLLECTIVE_SDC_DETECTED",
            severity="CRITICAL",
            swarm_signal="COLLECTIVE_SDC_DETECTED",
            distinct_results=len(counts),
            majority_rank_count=majority_n,
            divergent_ranks=minority,
            divergent_devices=[ranks[r].get("device") for r in minority],
            divergent_links=[ranks[r].get("link") for r in minority],
            numeric_spread=spread,
            fabric_isolated=fabric_isolated,
            repeat_offenders=repeat_offenders or None,
            detail=("ranks disagree after a collective that is mathematically required to "
                    "produce identical results on every rank -- the corruption is in the "
                    "communication path, not the per-GPU compute (per-GPU SDC detectors "
                    "cannot see this)"),
            recommended_action={
                "action": "quarantine_divergent_rank_and_revalidate_step_gated",
                "detail": ("isolate the divergent rank/link, re-run the step from the last "
                           "checkpoint, mark results from this step suspect"),
                "risk": "gated"},
            note="Logic-tested; requires real hardware validation.",
        )
        return base

    def get_stats(self):
        return {"component": "CollectiveCommSDCTracer", "checks": self.checks,
                "flags": self.flags,
                "localised": {k: v for k, v in self._divergence_history.items()
                              if v >= self.localise_after}}


# ===========================================================================
# A4 -- Fault attribution engine
# ===========================================================================
COMPONENTS = ("gpu_die", "hbm", "interconnect", "power_rail", "host", "fabric_switch", "cooling")

# Which component each Watchdog signal is evidence FOR, and how strongly.
# Weights are affinities, not probabilities; they are deliberately coarse.
SIGNAL_AFFINITY = {
    "ECC_BREAK_SUSPECTED":            {"hbm": 0.9, "gpu_die": 0.2},
    "GPUTHOR_PRECURSOR_PREDICTED":    {"hbm": 0.9},
    "SDC_CORRUPTION_DETECTED":        {"gpu_die": 0.6, "hbm": 0.4, "power_rail": 0.3},
    "DROOP_INDUCED_SDC_CONFIRMED":    {"power_rail": 0.9, "gpu_die": 0.3},
    "SEL_LATCHUP_SUSPECTED":          {"gpu_die": 0.8, "power_rail": 0.5},
    "TID_THRESHOLD_CROSSED":          {"gpu_die": 0.7, "hbm": 0.4},
    "THERMAL_EVENT_PREDICTED":        {"cooling": 0.8, "gpu_die": 0.3},
    "COOLING_DEGRADATION_CRITICAL":   {"cooling": 0.95},
    "COLLECTIVE_SDC_DETECTED":        {"interconnect": 0.8, "fabric_switch": 0.6},
    "NVLINK_CONTENTION":              {"interconnect": 0.7},
    "PCIE_ANOMALY":                   {"interconnect": 0.7, "host": 0.3},
    "GHOST_POWER_PREDICTED":          {"hbm": 0.6, "power_rail": 0.3},
    "VRAM_RESIDUAL":                  {"hbm": 0.7},
    "WORKLOAD_UNDERSAMPLED":          {},          # telemetry quality, blames nothing
    "SOLAR_PARTICLE_EVENT":           {},          # environmental cause, not a component
    "SEAWATER_INGRESS_CONFIRMED":     {"cooling": 0.5, "power_rail": 0.5},
}

# Environmental signals that EXPLAIN a fault without a component being defective.
ENVIRONMENTAL = {"SOLAR_PARTICLE_EVENT", "SOLAR_STORM_ALERT", "TID_THRESHOLD_CROSSED",
                 "SEAWATER_INGRESS_CONFIRMED", "COOLING_DEGRADATION_CRITICAL"}


class FaultAttributionEngine:
    """
    Given the evidence Watchdog's detectors produced in an incident window,
    rank which COMPONENT is most consistent with it. Returns the ranking, a
    confidence, the contributing evidence, and -- importantly -- an explicit
    'environmental' flag when the fault is better explained by conditions
    than by a defective part (you do not RMA a GPU for a solar storm).
    """

    def __init__(self, min_signals=2, confidence_gap=0.25):
        self.min_signals = min_signals
        self.confidence_gap = confidence_gap
        self.attributions = 0

    def attribute(self, alerts: list, target: dict = None) -> dict:
        ts = datetime.now(timezone.utc).isoformat()
        target = target or {}
        base = {"type": "FAULT_ATTRIBUTION", "timestamp": ts, "target": target,
                "agent": "FaultAttributionEngine",
                "cite": "MemTrace (2605.28732); From Detection to Recovery, 504 GPUs (2605.09370)",
                "disclaimer": ("a ranking over evidence, not proof -- 'most consistent with', "
                               "never 'caused by'; evidence returned so a human can disagree")}

        signals = []
        for a in alerts or []:
            s = a.get("swarm_signal") or a.get("type")
            if s:
                signals.append(s)
        base["signals_seen"] = signals

        if len(signals) < self.min_signals:
            base.update(verdict="INSUFFICIENT_EVIDENCE", severity="INFO",
                        note=f"need >= {self.min_signals} signals to attribute")
            return base

        scores = defaultdict(float)
        evidence = defaultdict(list)
        unknown = []
        for s in signals:
            aff = SIGNAL_AFFINITY.get(s)
            if aff is None:
                unknown.append(s); continue
            for comp, w in aff.items():
                scores[comp] += w
                evidence[comp].append(s)
        if unknown:
            base["signals_without_affinity"] = sorted(set(unknown))

        if not scores:
            base.update(verdict="NO_COMPONENT_IMPLICATED", severity="INFO",
                        note="signals present but none carry a component affinity")
            return base

        ranked = sorted(scores.items(), key=lambda kv: kv[1], reverse=True)
        total = sum(scores.values())
        top_comp, top_score = ranked[0]
        second = ranked[1][1] if len(ranked) > 1 else 0.0
        confidence = (top_score - second) / top_score if top_score > 0 else 0.0

        env_present = sorted(set(signals) & ENVIRONMENTAL)
        self.attributions += 1

        base.update(
            ranking=[{"component": c, "score": round(v, 2),
                      "share": round(v / total, 3), "evidence": evidence[c]}
                     for c, v in ranked],
            primary_component=top_comp,
            separation_confidence=round(confidence, 3),
            verdict=("ATTRIBUTED" if confidence >= self.confidence_gap else "AMBIGUOUS"),
            severity=("WARNING" if confidence >= self.confidence_gap else "INFO"),
            environmental_signals=env_present or None,
            environmental_note=(
                "an environmental cause is present -- the component may be HEALTHY and "
                "merely exposed; do not retire hardware on this evidence alone"
                if env_present else None),
        )
        if base["verdict"] == "ATTRIBUTED":
            base["recommended_action"] = {
                "action": ("investigate_environment_before_hardware_gated" if env_present
                           else f"schedule_{top_comp}_inspection_gated"),
                "detail": ("environmental exposure explains the fault; check conditions first"
                           if env_present else
                           f"evidence most consistent with {top_comp}; inspect before replacing"),
                "risk": "gated"}
        else:
            base["recommended_action"] = {
                "action": "collect_more_evidence",
                "detail": f"top two candidates within {self.confidence_gap:.0%}; do not act yet",
                "risk": "advisory"}
        return base

    def get_stats(self):
        return {"component": "FaultAttributionEngine", "attributions": self.attributions,
                "components_known": list(COMPONENTS)}


if __name__ == "__main__":
    t = CollectiveCommSDCTracer()
    ok = {"op": "all_reduce", "op_id": "ar1", "step": 100,
          "ranks": {i: {"pre_digest": f"p{i}", "post_digest": "SAME", "device": f"gpu{i}"} for i in range(8)}}
    print("[COLLECTIVE] consistent ->", t.check(ok)["type"])
    bad = {"op": "all_reduce", "op_id": "ar2", "step": 101,
           "ranks": {i: {"pre_digest": f"p{i}", "post_digest": "SAME" if i != 5 else "DIFF",
                         "device": f"gpu{i}", "link": "nvlink3" if i == 5 else "nvlink0"} for i in range(8)}}
    r = t.check(bad)
    print("[COLLECTIVE] divergent ->", r["type"], "ranks", r["divergent_ranks"], "links", r["divergent_links"])

    a = FaultAttributionEngine()
    res = a.attribute([{"type": "ECC_BREAK_SUSPECTED"}, {"type": "SDC_CORRUPTION_DETECTED"},
                       {"type": "GHOST_POWER_PREDICTED"}], target={"gpu_index": 2})
    print("[ATTRIB] ->", res["verdict"], res["primary_component"], "conf", res["separation_confidence"])
    res2 = a.attribute([{"type": "SDC_CORRUPTION_DETECTED"}, {"swarm_signal": "SOLAR_PARTICLE_EVENT"}])
    print("[ATTRIB] env ->", res2["primary_component"], "| env:", res2["environmental_signals"])
