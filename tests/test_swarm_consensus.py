#!/usr/bin/env python3
"""
Tests for the swarm coordination layers and derived fields.

Follows the pattern already established in tests/: a check(name, condition,
detail) helper, PASSED/FAILED lists, and a "PASSED: N FAILED: N" summary line
that run_all.py parses. Add this filename to TEST_FILES in run_all.py
explicitly.

These use injectable fakes with known behaviour, so they prove the scoring
and correlation math is correct independently of whether any real agent
performs well. That separation is the same reason
tests/test_validate_swarm_prediction.py exists.

No GPU required. No network. Deterministic.
"""

import os
import sys
import json
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

from intelligence.swarm.swarm_consensus import (
    Emission, from_agent_alert, CorrelationWindow,
    WeightedConsensus, SwarmPipeline)
from intelligence.swarm.swarm_derived_fields import (
    GhostPowerPercent, CrashCounter, IsolationScore, DerivedFieldEnricher)

PASSED, FAILED = [], []


def check(name, condition, detail=""):
    if condition:
        PASSED.append(name)
        print("[PASS] %s" % name)
    else:
        FAILED.append(name)
        print("[FAIL] %s  %s" % (name, detail))


def ts(sec):
    return "2026-09-21T00:%02d:%02d+00:00" % (sec // 60, sec % 60)


# ----- Layer 1 ------------------------------------------------------------

def test_emission():
    e = Emission("agent1", 0, "GHOST_POWER", 0.8, 0.9, {"power": 126.0})
    check("emission: required fields survive round-trip",
          e.as_dict()["agent_id"] == "agent1" and e.as_dict()["signal"] == "GHOST_POWER")

    for bad, label in [(1.5, "above 1"), (-0.1, "below 0"), ("x", "non-numeric")]:
        try:
            Emission("a", 0, "S", bad)
            check("emission: rejects severity %s" % label, False, "accepted %r" % bad)
        except ValueError:
            check("emission: rejects severity %s" % label, True)

    try:
        Emission("", 0, "S")
        check("emission: rejects empty agent_id", False)
    except ValueError:
        check("emission: rejects empty agent_id", True)

    check("adapter: None alert yields no emission",
          from_agent_alert("a1", 0, None) is None)

    e2 = from_agent_alert("a1", 0, {"type": "ECC_BREAK", "severity": "CRITICAL"})
    check("adapter: maps string severity CRITICAL to 0.9",
          e2.severity == 0.9, "got %r" % e2.severity)

    e3 = from_agent_alert("a1", 0, {"swarm_signal": "X"})
    check("adapter: missing severity defaults to explicit 0.5, not 0",
          e3.severity == 0.5, "got %r" % e3.severity)


# ----- Layer 2 ------------------------------------------------------------

def test_correlation():
    w = CorrelationWindow(window_seconds=60.0)

    ems = [Emission("a1", 0, "S1", 0.5, 0.9, timestamp=ts(0)),
           Emission("a2", 0, "S2", 0.5, 0.9, timestamp=ts(30)),
           Emission("a3", 0, "S3", 0.5, 0.9, timestamp=ts(200))]
    g = w.group(ems)
    check("correlation: splits on the window boundary",
          len(g) == 2, "got %d groups" % len(g))

    ems = [Emission("a1", 0, "S", 0.5, 0.9, timestamp=ts(0)),
           Emission("a1", 1, "S", 0.5, 0.9, timestamp=ts(1))]
    check("correlation: separates GPUs", len(w.group(ems)) == 2)

    # The volume problem: a fast agent firing 60 times must not outweigh a
    # slow agent firing once.
    ems = [Emission("fast", 0, "S", 0.3, 0.9, timestamp=ts(i)) for i in range(60)]
    ems.append(Emission("slow", 0, "T", 0.9, 0.9, timestamp=ts(30)))
    g = w.group(ems)[0]
    check("correlation: dedupes per agent within a window",
          g["deduped_count"] == 2 and g["raw_count"] == 61,
          "raw=%d kept=%d" % (g["raw_count"], g["deduped_count"]))
    kept = {e.agent_id: e.severity for e in g["emissions"]}
    check("correlation: dedupe keeps the highest severity per agent",
          abs(kept["fast"] - 0.3) < 1e-9 and abs(kept["slow"] - 0.9) < 1e-9)

    ems = [Emission("a1", 0, "S", 0.5, 0.9, timestamp="not-a-timestamp"),
           Emission("a2", 0, "T", 0.5, 0.9, timestamp=ts(0))]
    groups = w.group(ems)
    check("correlation: flags unparseable timestamps instead of folding them in",
          any("timestamp_warning" in gg for gg in groups))

    check("correlation: empty input yields no groups", w.group([]) == [])


# ----- Layer 3 ------------------------------------------------------------

def test_consensus():
    c = WeightedConsensus(weights={"good": 0.9, "ok": 0.6, "broken": 0.0},
                          threshold=0.25, min_agents=2)
    w = CorrelationWindow(60.0)

    g = w.group([Emission("good", 0, "A", 0.8, 1.0, timestamp=ts(0)),
                 Emission("ok", 0, "B", 0.7, 1.0, timestamp=ts(5))])[0]
    r = c.score(g)
    check("consensus: fires when qualified agents agree",
          r["fires"] and r["verdict"] == "CONSENSUS_REACHED", json.dumps(r["verdict"]))

    g = w.group([Emission("broken", 0, "A", 1.0, 1.0, timestamp=ts(0)),
                 Emission("broken", 0, "A", 1.0, 1.0, timestamp=ts(5))])[0]
    r = c.score(g)
    check("consensus: a zero-weight agent cannot fire alone at severity 1.0",
          not r["fires"] and r["verdict"] == "NO_QUALIFIED_AGENT_CONTRIBUTED")
    check("consensus: names the ignored agent and why",
          len(r["ignored_agents"]) == 1 and "zero weight" in r["ignored_agents"][0]["reason"])

    g = w.group([Emission("good", 0, "A", 0.9, 1.0, timestamp=ts(0))])[0]
    r = c.score(g)
    check("consensus: one agent is not a consensus",
          not r["fires"] and r["verdict"] == "INSUFFICIENT_AGENTS")

    g = w.group([Emission("good", 0, "A", 0.1, 0.5, timestamp=ts(0)),
                 Emission("ok", 0, "B", 0.1, 0.5, timestamp=ts(5))])[0]
    r = c.score(g)
    check("consensus: low severity stays below threshold",
          not r["fires"] and r["verdict"] == "BELOW_THRESHOLD",
          "score=%r" % r["consensus_score"])

    # Weighting must be ordered: the stronger agent moves the score more.
    g_hi = w.group([Emission("good", 0, "A", 0.8, 1.0, timestamp=ts(0)),
                    Emission("ok", 0, "B", 0.2, 1.0, timestamp=ts(5))])[0]
    g_lo = w.group([Emission("good", 0, "A", 0.2, 1.0, timestamp=ts(0)),
                    Emission("ok", 0, "B", 0.8, 1.0, timestamp=ts(5))])[0]
    check("consensus: higher-weight agent has more influence",
          c.score(g_hi)["consensus_score"] > c.score(g_lo)["consensus_score"])

    check("consensus: every result carries the not-a-diagnosis disclaimer",
          "not a diagnosis" in c.score(g_hi)["disclaimer"])


def test_weights_from_file():
    blob = {"per_agent": {
        "agent1": {"status": "QUALIFIED", "tpr": 0.965, "fpr": 0.0},
        "agent3": {"status": "QUALIFIED", "tpr": 0.63, "fpr": 0.005},
        "agent4": {"status": "BELOW_BAR", "tpr": 0.245, "fpr": 0.0},
        "agent2": {"status": "STRUCTURALLY_SILENT", "tpr": 0.0, "fpr": 0.0},
    }}
    fd, path = tempfile.mkstemp(suffix=".json")
    with os.fdopen(fd, "w") as f:
        json.dump(blob, f)
    try:
        c = WeightedConsensus.from_qualification(path)
        check("weights: qualified agent weight = TPR - FPR",
              abs(c.weight_of("agent1") - 0.965) < 1e-9)
        check("weights: BELOW_BAR agent gets exactly zero, not a small weight",
              c.weight_of("agent4") == 0.0, "got %r" % c.weight_of("agent4"))
        check("weights: structurally silent agent gets zero",
              c.weight_of("agent2") == 0.0)
        check("weights: unknown agent defaults to zero",
              c.weight_of("nonexistent") == 0.0)
    finally:
        os.unlink(path)


def test_pipeline():
    c = WeightedConsensus(weights={"a1": 0.9, "a2": 0.8}, threshold=0.25, min_agents=2)
    out = SwarmPipeline(c, window_seconds=60.0).process(
        [Emission("a1", 0, "X", 0.9, 1.0, timestamp=ts(0)),
         Emission("a2", 0, "Y", 0.8, 1.0, timestamp=ts(10)),
         Emission("a1", 1, "X", 0.9, 1.0, timestamp=ts(0))])
    check("pipeline: one scored result per GPU group", len(out) == 2)
    check("pipeline: the two-agent GPU reaches consensus",
          any(r["fires"] for r in out))
    check("pipeline: the single-agent GPU does not",
          any(r["verdict"] == "INSUFFICIENT_AGENTS" for r in out))


# ----- Derived fields -----------------------------------------------------

def test_derived():
    g = GhostPowerPercent(idle_floor_w=78.4, margin_w=15.0, window=120)
    check("ghost_pct: None before enough history",
          g.update({"power_watts": 126.0, "gpu_util": 0.0}) is None)
    for _ in range(40):
        v = g.update({"power_watts": 126.0, "gpu_util": 0.0})
    check("ghost_pct: 100% when every sample is ghost", v == 100.0, "got %r" % v)

    g.reset()
    for _ in range(40):
        v = g.update({"power_watts": 78.5, "gpu_util": 0.0})
    check("ghost_pct: 0% at the idle floor", v == 0.0, "got %r" % v)

    check("ghost_pct: missing power returns None, never 0.0",
          GhostPowerPercent().update({"gpu_util": 0.0}) is None)
    check("ghost_pct: missing util returns None, never 0.0",
          GhostPowerPercent().update({"power_watts": 126.0}) is None)

    c = CrashCounter()
    check("crash_count: clean telemetry counts zero",
          c.update({"ecc_uncorrectable_total": 0, "xid_error": None}) == 0)
    c.update({"ecc_uncorrectable_total": 0})
    check("crash_count: an uncorrectable ECC increment counts once",
          c.update({"ecc_uncorrectable_total": 1}) == 1)
    check("crash_count: the same XID is not double-counted",
          c.update({"xid_error": 79}) == 2 and c.update({"xid_error": 79}) == 2)

    i = IsolationScore()
    check("isolation: None when nothing is measurable", i.update({}) is None)
    r = i.update({"compute_apps": [], "memory_used_mb": 620.0})
    check("isolation: empty compute_apps lowers the score and says why",
          r["isolation_score"] < 1.0 and "compute_apps empty" in r["detail"]["per_process_note"])

    i = IsolationScore()
    base = [{"gpu_id": 1, "memory_used_mb": 1.0}]
    i.update({"compute_apps": [{"pid": 1}], "memory_used_mb": 500.0}, peer_rows=base)
    r = i.update({"compute_apps": [{"pid": 1}], "memory_used_mb": 500.0},
                 peer_rows=[{"gpu_id": 1, "memory_used_mb": 4.0}])
    check("isolation: a 3MB peer delta is context peer-mapping, not bleed",
          "peer_gpus_moved" not in r["detail"],
          "3MB was flagged: %r" % r["detail"].get("peer_gpus_moved"))
    r = i.update({"compute_apps": [{"pid": 1}], "memory_used_mb": 500.0},
                 peer_rows=[{"gpu_id": 1, "memory_used_mb": 530.0}])
    check("isolation: a 529MB peer delta is flagged",
          "peer_gpus_moved" in r["detail"])

    e = DerivedFieldEnricher(idle_floor_w=78.4)
    out = e.enrich({"gpu_id": 0, "power_watts": 126.0, "gpu_util": 0.0,
                    "memory_used_mb": 620.0, "compute_apps": [],
                    "ecc_uncorrectable_total": 0})
    check("enricher: never fabricates cei_flops_per_joule",
          "cei_flops_per_joule" not in out)
    check("enricher: names the missing field explicitly",
          out["_derived_missing"] == ["cei_flops_per_joule"])
    check("enricher: crash_count is always present",
          "crash_count" in out)


def main():
    print("=" * 66)
    print("SWARM COORDINATION LAYERS — TESTS")
    print("=" * 66)
    for fn in (test_emission, test_correlation, test_consensus,
               test_weights_from_file, test_pipeline, test_derived):
        print()
        print("--- %s ---" % fn.__name__)
        fn()
    print()
    print("=" * 66)
    print("PASSED: %d FAILED: %d" % (len(PASSED), len(FAILED)))
    if FAILED:
        for f in FAILED:
            print("  FAILED: %s" % f)
    return 1 if FAILED else 0


if __name__ == "__main__":
    sys.exit(main())
