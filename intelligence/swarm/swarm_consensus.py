#!/usr/bin/env python3
"""
Watchdog Swarm — Coordination Layers 1 to 3
Author: Manmohan (Mike) Bains / GPU Optimizer Inc.

    Layer 1  Independent emission   — uniform record, agents never talk
    Layer 2  Correlation            — group by GPU + time window
    Layer 3  Weighted consensus     — weights from MEASURED TPR only

Layers 4 (root-cause synthesis) and 5 (remediation ranking) are deliberately
absent. Build them when a 15-agent pool starts producing real multi-signal
incidents, not before: a rules table written against imagined combinations is
a rules table that will be wrong.

Layer 6 (human approval) is not implemented here because it already exists in
remediation/response.py and orchestration/cluster_actions.py. NOTHING in this
module executes anything. It ranks and explains. That is a correctness
requirement: a swarm consensus being confidently wrong on a production
cluster is a worse failure than one detector being wrong.

WHY AGENTS NEVER CALL EACH OTHER
The moment agent A reads agent B's output, a false positive can no longer be
attributed to one of them, and per-agent TPR stops meaning anything. That
attribution is what makes the weights in Layer 3 defensible. Independence is
not a style choice.
"""

import json
from collections import defaultdict
from datetime import datetime, timezone

SCHEMA_VERSION = "1.0"


# --------------------------------------------------------------------------
# Layer 1 — uniform emission
# --------------------------------------------------------------------------

class Emission(object):
    """One agent's observation. The only thing an agent ever produces."""

    __slots__ = ("agent_id", "gpu_id", "timestamp", "signal",
                 "severity", "confidence", "evidence")

    def __init__(self, agent_id, gpu_id, signal, severity=0.5,
                 confidence=0.5, evidence=None, timestamp=None):
        if not agent_id:
            raise ValueError("agent_id is required")
        if not signal:
            raise ValueError("signal is required")
        self.agent_id = str(agent_id)
        self.gpu_id = str(gpu_id)
        self.signal = str(signal)
        self.severity = self._unit(severity, "severity")
        self.confidence = self._unit(confidence, "confidence")
        self.evidence = dict(evidence or {})
        self.timestamp = timestamp or datetime.now(timezone.utc).isoformat()

    @staticmethod
    def _unit(v, name):
        try:
            f = float(v)
        except (TypeError, ValueError):
            raise ValueError("%s must be a number, got %r" % (name, v))
        if not (0.0 <= f <= 1.0):
            raise ValueError("%s must be in [0,1], got %r" % (name, f))
        return f

    def as_dict(self):
        return {"schema": SCHEMA_VERSION, "agent_id": self.agent_id,
                "gpu_id": self.gpu_id, "timestamp": self.timestamp,
                "signal": self.signal, "severity": self.severity,
                "confidence": self.confidence, "evidence": self.evidence}

    def __repr__(self):
        return "<Emission %s gpu%s %s sev=%.2f>" % (
            self.agent_id, self.gpu_id, self.signal, self.severity)


def from_agent_alert(agent_id, gpu_id, alert):
    """Adapt an existing agent's alert dict to an Emission.

    Existing agents predate this schema, so field names vary. This maps what
    is present and does not invent what is not: a missing severity becomes
    0.5, explicitly, rather than a guess dressed up as a measurement.
    Returns None for a falsy alert, matching agent.update()'s contract.
    """
    if not alert:
        return None
    if not isinstance(alert, dict):
        return Emission(agent_id, gpu_id, str(alert), evidence={"raw": str(alert)})

    signal = (alert.get("signal") or alert.get("type")
              or alert.get("alert_type") or alert.get("swarm_signal")
              or "UNSPECIFIED")

    sev = alert.get("severity")
    if isinstance(sev, str):                      # WARNING / CRITICAL / INFO
        sev = {"INFO": 0.25, "WARNING": 0.6, "CRITICAL": 0.9}.get(sev.upper(), 0.5)
    elif sev is None:
        sev = 0.5
    else:
        sev = max(0.0, min(1.0, float(sev)))

    conf = alert.get("confidence")
    conf = 0.5 if conf is None else max(0.0, min(1.0, float(conf)))

    return Emission(agent_id, gpu_id, signal, sev, conf, evidence=alert)


# --------------------------------------------------------------------------
# Layer 2 — correlation
# --------------------------------------------------------------------------

def _parse_ts(ts):
    try:
        s = ts.replace("Z", "+00:00")
        return datetime.fromisoformat(s)
    except Exception:
        return None


class CorrelationWindow(object):
    """Group emissions sharing a GPU within a time window.

    Pure deterministic grouping. No inference, no scoring, no judgement about
    what the group means. That belongs in Layer 3 and above.

    PER-AGENT DEDUPE is the important part. Agents run at different cadences:
    a sub-second agent can fire 60 times while a minutes-tier agent fires
    once. Without dedupe the fast agent dominates any vote by sheer volume,
    which measures sampling rate rather than evidence. Within one window each
    agent contributes exactly one emission: the one with the highest severity.
    """

    def __init__(self, window_seconds=60.0):
        self.window_seconds = float(window_seconds)

    def group(self, emissions):
        by_gpu = defaultdict(list)
        for e in emissions:
            by_gpu[e.gpu_id].append(e)

        groups = []
        for gpu_id, items in by_gpu.items():
            keyed = []
            for e in items:
                dt = _parse_ts(e.timestamp)
                keyed.append((dt, e))
            undated = [e for dt, e in keyed if dt is None]
            dated = sorted([(dt, e) for dt, e in keyed if dt is not None],
                           key=lambda p: p[0])

            current, start = [], None
            for dt, e in dated:
                if start is None or (dt - start).total_seconds() <= self.window_seconds:
                    if start is None:
                        start = dt
                    current.append(e)
                else:
                    groups.append(self._finish(gpu_id, current))
                    current, start = [e], dt
            if current:
                groups.append(self._finish(gpu_id, current))
            if undated:
                # Emissions with unparseable timestamps are grouped separately
                # and flagged, not silently folded into a real window.
                g = self._finish(gpu_id, undated)
                g["timestamp_warning"] = "unparseable timestamps; grouped separately"
                groups.append(g)
        return groups

    def _finish(self, gpu_id, emissions):
        best = {}
        for e in emissions:
            prev = best.get(e.agent_id)
            if prev is None or e.severity > prev.severity:
                best[e.agent_id] = e
        deduped = list(best.values())
        return {"gpu_id": gpu_id,
                "emissions": deduped,
                "raw_count": len(emissions),
                "deduped_count": len(deduped),
                "agents": sorted(best.keys()),
                "signals": sorted(set(e.signal for e in deduped))}


# --------------------------------------------------------------------------
# Layer 3 — weighted consensus
# --------------------------------------------------------------------------

class WeightedConsensus(object):
    """Score a correlated group. Weight per agent = measured TPR - FPR.

    Weights are LOADED FROM MEASURED RESULTS, never hand-tuned. The file they
    come from is written by swarm_qualification.py. If you find yourself
    editing a weight by hand to make an outcome look better, the honest move
    is to re-run qualification instead.

    An agent below the qualification bar carries weight 0.0, not a small
    weight. A broken agent that votes is worse than one that abstains: at
    24.5% TPR with a permanently-zeroed input signal it contributes noise to
    every decision it touches.
    """

    def __init__(self, weights=None, threshold=0.25, min_agents=2):
        self.weights = dict(weights or {})
        self.threshold = float(threshold)
        self.min_agents = int(min_agents)

    @classmethod
    def from_qualification(cls, path, threshold=0.25, min_agents=2):
        with open(path) as f:
            blob = json.load(f)
        weights = {}
        for agent_id, r in (blob.get("per_agent") or {}).items():
            if r.get("status") in ("QUALIFIED", "NOISY") and r.get("tpr") is not None:
                weights[agent_id] = max(0.0, float(r["tpr"]) - float(r.get("fpr") or 0.0))
            else:
                weights[agent_id] = 0.0
        return cls(weights, threshold, min_agents)

    def weight_of(self, agent_id):
        return float(self.weights.get(agent_id, 0.0))

    def score(self, group):
        emissions = group["emissions"]
        contributing, ignored = [], []
        num = den = 0.0

        for e in emissions:
            w = self.weight_of(e.agent_id)
            if w <= 0.0:
                ignored.append({"agent_id": e.agent_id, "signal": e.signal,
                                "reason": ("zero weight: not qualified, or "
                                           "absent from the qualification file")})
                continue
            contributing.append({"agent_id": e.agent_id, "signal": e.signal,
                                 "weight": w, "severity": e.severity,
                                 "confidence": e.confidence})
            num += w * e.severity * e.confidence
            den += w

        consensus = (num / den) if den > 0 else 0.0
        enough = len(contributing) >= self.min_agents
        fires = enough and consensus >= self.threshold

        if not contributing:
            verdict = "NO_QUALIFIED_AGENT_CONTRIBUTED"
        elif not enough:
            verdict = "INSUFFICIENT_AGENTS"
        elif fires:
            verdict = "CONSENSUS_REACHED"
        else:
            verdict = "BELOW_THRESHOLD"

        return {
            "gpu_id": group["gpu_id"],
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "consensus_score": round(consensus, 4),
            "threshold": self.threshold,
            "fires": fires,
            "verdict": verdict,
            "contributing_agents": sorted(contributing, key=lambda c: -c["weight"]),
            "ignored_agents": ignored,
            "signals": group["signals"],
            "dedupe": {"raw": group["raw_count"], "kept": group["deduped_count"]},
            "disclaimer": ("A weighted ranking over agent evidence, not a "
                           "diagnosis. No root cause is claimed and no action "
                           "is taken. Layer 6 human approval is unchanged."),
        }


# --------------------------------------------------------------------------

class SwarmPipeline(object):
    """Layers 1 to 3 end to end. Emissions in, scored groups out."""

    def __init__(self, consensus, window_seconds=60.0):
        self.consensus = consensus
        self.window = CorrelationWindow(window_seconds)

    def process(self, emissions):
        return [self.consensus.score(g) for g in self.window.group(emissions)]


if __name__ == "__main__":
    # Smoke demo with hand-built emissions. Proves the layers compose.
    w = WeightedConsensus(weights={"agent1": 0.965, "agent3": 0.625,
                                   "agent4": 0.0, "agent7": 0.71},
                          threshold=0.25, min_agents=2)
    ems = [
        Emission("agent1", 0, "GHOST_POWER_PREDICTED", 0.8, 0.9),
        Emission("agent1", 0, "GHOST_POWER_PREDICTED", 0.6, 0.9),   # deduped
        Emission("agent7", 0, "CRYPTOJACKING_ONSET", 0.7, 0.8),
        Emission("agent4", 0, "TENANT_ISOLATION_RISK", 0.9, 0.9),   # weight 0
    ]
    for out in SwarmPipeline(w).process(ems):
        print(json.dumps(out, indent=2))
