#!/usr/bin/env python3
# Author: Manmohan (Mike) Bains -- Watchdog
"""
tests/test_collective_sdc_attribution.py  *** WATCHDOG ***

Tests the collective-communication SDC tracer (redundancy check, divergence
localisation, malformed input fails loud) and the fault-attribution engine
(component ranking, ambiguity, and the environmental carve-out that stops
Watchdog blaming hardware for a solar storm).
"""
import os
import sys

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from detection.collective_sdc_and_attribution import (
    CollectiveCommSDCTracer, FaultAttributionEngine, SIGNAL_AFFINITY, ENVIRONMENTAL,
)

PASSED, FAILED = [], []


def check(name, cond, detail=""):
    (PASSED if cond else FAILED).append(name)
    print(f"[{'PASS' if cond else 'FAIL'}] {name}{'' if cond else ' ' + detail}")


def _ranks(n=8, bad=None, link_of_bad="nvlink3"):
    out = {}
    for i in range(n):
        out[i] = {"pre_digest": f"p{i}", "post_digest": "DIFF" if i == bad else "SAME",
                  "device": f"gpu{i}", "link": link_of_bad if i == bad else "nvlink0",
                  "post_value": 1.0 if i != bad else 1.5}
    return out


def _op(bad=None, op="all_reduce", n=8, step=1, link="nvlink3"):
    return {"op": op, "op_id": f"ar{step}", "step": step, "ranks": _ranks(n, bad, link)}


# ---- collective tracer ------------------------------------------------------
def test_consistent_all_reduce():
    r = CollectiveCommSDCTracer().check(_op())
    check("collective: all ranks identical -> COLLECTIVE_CONSISTENT",
          r["type"] == "COLLECTIVE_CONSISTENT", f"got {r['type']}")


def test_divergence_detected_and_localised():
    r = CollectiveCommSDCTracer().check(_op(bad=5))
    check("collective: one divergent rank -> COLLECTIVE_SDC_DETECTED (CRITICAL)",
          r["type"] == "COLLECTIVE_SDC_DETECTED" and r["severity"] == "CRITICAL", f"got {r['type']}")
    check("collective: names the divergent rank and its link",
          r["divergent_ranks"] == [5] and r["divergent_links"] == ["nvlink3"], f"got {r.get('divergent_ranks')}")
    check("collective: reports numeric spread when scalars supplied",
          abs(r["numeric_spread"] - 0.5) < 1e-9, f"got {r.get('numeric_spread')}")
    check("collective: emits COLLECTIVE_SDC_DETECTED swarm signal",
          r["swarm_signal"] == "COLLECTIVE_SDC_DETECTED")
    check("collective: remediation is gated", r["recommended_action"]["risk"] == "gated")


def test_repeat_offender_localisation():
    t = CollectiveCommSDCTracer(localise_after=2)
    t.check(_op(bad=5, step=1)); r = t.check(_op(bad=5, step=2))
    check("collective: same rank diverging twice -> repeat offender localised",
          r["repeat_offenders"] and "rank:5" in r["repeat_offenders"], f"got {r.get('repeat_offenders')}")
    check("collective: the link is localised too", "link:nvlink3" in (r["repeat_offenders"] or {}))


def test_non_collective_op_skipped():
    r = CollectiveCommSDCTracer().check({"op": "matmul", "ranks": _ranks()})
    check("collective: non-collective op -> UNKNOWN, no false verdict",
          r["type"] == "COLLECTIVE_OP_UNKNOWN")


def test_single_rank_insufficient():
    r = CollectiveCommSDCTracer().check({"op": "all_reduce", "ranks": {0: {"post_digest": "X"}}})
    check("collective: <2 ranks -> INSUFFICIENT_RANKS", r["type"] == "COLLECTIVE_INSUFFICIENT_RANKS")


def test_missing_digest_incomplete_not_clean():
    ranks = _ranks(4)
    ranks[2]["post_digest"] = None
    r = CollectiveCommSDCTracer().check({"op": "all_reduce", "ranks": ranks})
    check("collective: a missing post_digest -> INCOMPLETE (never 'consistent')",
          r["type"] == "COLLECTIVE_CHECK_INCOMPLETE" and 2 in r["missing_ranks"], f"got {r['type']}")


def test_malformed_fails_loud():
    r = CollectiveCommSDCTracer().check({"op": "all_reduce", "ranks": {0: "not-a-dict", 1: "also-not"}})
    check("collective: malformed rank data -> CHECK_ERROR, fails loud not clean",
          r["type"] == "COLLECTIVE_CHECK_ERROR" and "NOT reported clean" in r["note"], f"got {r['type']}")


def test_other_collectives_supported():
    for op in ("all_gather", "broadcast", "reduce_scatter", "all_to_all"):
        r = CollectiveCommSDCTracer().check(_op(bad=3, op=op))
        check(f"collective: {op} divergence detected", r["type"] == "COLLECTIVE_SDC_DETECTED")


# ---- attribution ------------------------------------------------------------
def test_insufficient_evidence():
    r = FaultAttributionEngine().attribute([{"type": "SDC_CORRUPTION_DETECTED"}])
    check("attrib: one signal -> INSUFFICIENT_EVIDENCE", r["verdict"] == "INSUFFICIENT_EVIDENCE")


def test_hbm_attribution():
    r = FaultAttributionEngine().attribute(
        [{"type": "ECC_BREAK_SUSPECTED"}, {"type": "GPUTHOR_PRECURSOR_PREDICTED"},
         {"type": "VRAM_RESIDUAL"}], target={"gpu_index": 2})
    check("attrib: ECC + Rowhammer + VRAM residual -> hbm",
          r["primary_component"] == "hbm" and r["verdict"] == "ATTRIBUTED", f"got {r.get('ranking')}")
    check("attrib: evidence returned for the primary component",
          any(e["component"] == "hbm" and len(e["evidence"]) >= 3 for e in r["ranking"]))


def test_interconnect_attribution_from_collective():
    r = FaultAttributionEngine().attribute(
        [{"swarm_signal": "COLLECTIVE_SDC_DETECTED"}, {"type": "NVLINK_CONTENTION"}])
    check("attrib: collective SDC + NVLink contention -> interconnect",
          r["primary_component"] == "interconnect", f"got {r.get('ranking')}")


def test_power_rail_attribution():
    r = FaultAttributionEngine().attribute(
        [{"type": "DROOP_INDUCED_SDC_CONFIRMED"}, {"type": "SEL_LATCHUP_SUSPECTED"}])
    check("attrib: droop + latch-up implicates power_rail or gpu_die",
          r["primary_component"] in ("power_rail", "gpu_die"), f"got {r['primary_component']}")


def test_environmental_carveout():
    r = FaultAttributionEngine().attribute(
        [{"type": "SDC_CORRUPTION_DETECTED"}, {"swarm_signal": "SOLAR_PARTICLE_EVENT"},
         {"type": "ECC_BREAK_SUSPECTED"}])
    check("attrib: solar storm flagged as environmental",
          r["environmental_signals"] and "SOLAR_PARTICLE_EVENT" in r["environmental_signals"], f"got {r}")
    check("attrib: environmental note warns against retiring healthy hardware",
          "may be HEALTHY" in (r["environmental_note"] or ""), f"got {r.get('environmental_note')}")
    if r["verdict"] == "ATTRIBUTED":
        check("attrib: environmental -> action investigates conditions BEFORE hardware",
              "environment_before_hardware" in r["recommended_action"]["action"], f"got {r['recommended_action']}")
    else:
        check("attrib: environmental -> action investigates conditions BEFORE hardware", True)


def test_ambiguous_verdict():
    # two signals implicating different components with equal weight
    r = FaultAttributionEngine(confidence_gap=0.5).attribute(
        [{"type": "COOLING_DEGRADATION_CRITICAL"}, {"type": "GPUTHOR_PRECURSOR_PREDICTED"}])
    check("attrib: near-tied candidates -> AMBIGUOUS, advises collecting more evidence",
          r["verdict"] == "AMBIGUOUS" and r["recommended_action"]["risk"] == "advisory", f"got {r['verdict']}")


def test_signals_without_affinity_reported():
    r = FaultAttributionEngine().attribute(
        [{"type": "ECC_BREAK_SUSPECTED"}, {"type": "SOME_BRAND_NEW_SIGNAL"},
         {"type": "GPUTHOR_PRECURSOR_PREDICTED"}])
    check("attrib: unknown signal reported, not silently dropped",
          "SOME_BRAND_NEW_SIGNAL" in r.get("signals_without_affinity", []), f"got {r.get('signals_without_affinity')}")


def test_undersampled_blames_nothing():
    r = FaultAttributionEngine().attribute(
        [{"swarm_signal": "WORKLOAD_UNDERSAMPLED"}, {"swarm_signal": "SOLAR_PARTICLE_EVENT"}])
    check("attrib: telemetry-quality + environmental signals implicate NO component",
          r["verdict"] == "NO_COMPONENT_IMPLICATED", f"got {r['verdict']}")


def test_disclaimer_always_present():
    r = FaultAttributionEngine().attribute([{"type": "ECC_BREAK_SUSPECTED"}, {"type": "VRAM_RESIDUAL"}])
    check("attrib: states 'ranking not proof' every time",
          "never 'caused by'" in r["disclaimer"])


def test_environmental_set_sane():
    check("attrib: environmental set excludes pure-hardware signals",
          "ECC_BREAK_SUSPECTED" not in ENVIRONMENTAL and "SOLAR_PARTICLE_EVENT" in ENVIRONMENTAL)
    check("attrib: affinity table covers the collective signal",
          "COLLECTIVE_SDC_DETECTED" in SIGNAL_AFFINITY)


if __name__ == "__main__":
    for name, fn in sorted(globals().items()):
        if name.startswith("test_"):
            try:
                fn()
            except Exception as e:
                check(name, False, f"EXCEPTION {e!r}")
    print("\n" + "=" * 60 + f"\nPASSED: {len(PASSED)}   FAILED: {len(FAILED)}\n" + "=" * 60)
    sys.exit(1 if FAILED else 0)
