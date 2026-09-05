#!/usr/bin/env python3
# Author: Manmohan (Mike) Bains -- Watchdog
"""
hf_derived_detectors2.py -- Detectors derived from Hugging Face research (Part 2)
Part of Watchdog AI-Attack Detection Suite.

3. SampleRateBlindSpotDetector
   Watchdog's own B200 campaign found: achieved sampling was 3.7-7.1 Hz
   against a requested 100 Hz, and "short bursty (agentic-style) workloads
   are largely invisible at the current achieved sample rate." That is a
   documented blind spot. This detector makes it an HONEST SIGNAL: it
   measures the achieved inter-sample delta (per the README's rule -- never
   trust the requested rate), estimates the fastest burst the sampler can
   resolve (Nyquist: 2 samples per burst), and flags any workload whose
   burst cadence is faster than that as UNDERSAMPLED with degraded
   detection confidence. Generalizes micro_burst_detector's UNDERSAMPLED
   pattern fleet-wide. A detector that says "I cannot see this reliably"
   beats one that silently misses it.

4. BatchedInferenceBackdoorDetector
   "Architectural Backdoors for Within-Batch Data Stealing and Model
   Inference Manipulation" (arXiv 2505.18323): a malicious model
   ARCHITECTURE lets one user's request read or manipulate ANOTHER user's
   data inside the same inference batch. This is cross-tenant leakage at
   the model layer -- the software twin of Watchdog's VRAM-residual finding.
   Detection principle: a correctly isolated model's output for request A
   must be INDEPENDENT of request B's input. Run the same request A with
   different batch-mates; if A's output changes, information is flowing
   across the batch boundary. Detects the effect without needing to
   inspect the architecture.

SECURITY REVIEW COMPLIANCE: no bare except, no shell, detection only,
gated actions, never inspects request CONTENT (works on output hashes /
divergence metrics only, so no tenant data is read by the detector).

NOTE: Logic-tested. Requires real hardware validation.
"""

import hashlib
import statistics
from datetime import datetime, timezone


# ---------------------------------------------------------------------------
# 3 -- Sample-rate blind-spot detector
# ---------------------------------------------------------------------------
class SampleRateBlindSpotDetector:
    """
    Feed it the real sample timestamps (seconds) as they arrive. It computes
    the ACHIEVED rate from measured deltas -- never the requested rate -- and
    the resolvable burst floor. Then, given an observed or declared workload
    burst cadence, it says whether that workload is visible.
    """

    def __init__(self, requested_hz: float = 100.0, window: int = 200,
                 nyquist_samples_per_burst: float = 2.0):
        self.requested_hz = requested_hz
        self.window = window
        self.nyquist = nyquist_samples_per_burst
        self._ts = []
        self.checks = 0
        self.flags = 0

    def observe_sample(self, t_seconds: float) -> None:
        self._ts.append(float(t_seconds))
        if len(self._ts) > self.window:
            self._ts.pop(0)

    def achieved(self) -> dict:
        if len(self._ts) < 3:
            return {"achieved_hz": None, "delta_ms_median": None, "delta_ms_p95": None,
                    "samples": len(self._ts)}
        deltas = [b - a for a, b in zip(self._ts, self._ts[1:]) if b > a]
        if not deltas:
            return {"achieved_hz": None, "delta_ms_median": None, "delta_ms_p95": None,
                    "samples": len(self._ts)}
        med = statistics.median(deltas)
        p95 = sorted(deltas)[int(0.95 * (len(deltas) - 1))]
        return {"achieved_hz": round(1.0 / med, 2) if med > 0 else None,
                "delta_ms_median": round(med * 1000, 2),
                "delta_ms_p95": round(p95 * 1000, 2),
                "samples": len(self._ts)}

    def resolvable_burst_ms(self) -> float:
        """Shortest burst duration this sampler can reliably resolve."""
        a = self.achieved()
        if not a["delta_ms_median"]:
            return float("inf")
        return a["delta_ms_median"] * self.nyquist

    def assess(self, workload_burst_ms: float, workload_label: str = "workload") -> dict:
        self.checks += 1
        a = self.achieved()
        floor = self.resolvable_burst_ms()
        ts = datetime.now(timezone.utc).isoformat()
        base = {"substrate": "telemetry", "workload": workload_label,
                "requested_hz": self.requested_hz, "achieved": a,
                "resolvable_burst_ms": None if floor == float("inf") else round(floor, 2),
                "workload_burst_ms": workload_burst_ms, "timestamp": ts,
                "agent": "SampleRateBlindSpotDetector",
                "cite": "Watchdog B200 campaign: 3.7-7.1 Hz achieved vs 100 Hz requested; "
                        "bursty agentic workloads invisible (README)"}

        if a["achieved_hz"] is None:
            base.update(type="SAMPLE_RATE_UNKNOWN", severity="INFO",
                        note="not enough measured samples to estimate the achieved rate")
            return base

        shortfall = self.requested_hz / a["achieved_hz"] if a["achieved_hz"] else None
        base["rate_shortfall_factor"] = round(shortfall, 1) if shortfall else None

        if workload_burst_ms < floor:
            self.flags += 1
            confidence = max(0.0, min(1.0, workload_burst_ms / floor))
            base.update(type="WORKLOAD_UNDERSAMPLED",
                        severity="WARNING",
                        swarm_signal="WORKLOAD_UNDERSAMPLED",
                        detection_confidence=round(confidence, 2),
                        detail=(f"bursts of {workload_burst_ms} ms are shorter than the "
                                f"{floor:.1f} ms this sampler can resolve at the ACHIEVED "
                                f"{a['achieved_hz']} Hz -- detectors on this workload are "
                                "degraded; do not read silence as clean"),
                        recommended_action={"action": "raise_sample_rate_or_flag_low_confidence",
                                            "detail": "increase collector cadence / switch to "
                                                      "eBPF sampling; until then mark all "
                                                      "alerts on this workload low-confidence",
                                            "risk": "advisory"})
        else:
            base.update(type="WORKLOAD_RESOLVABLE", severity="INFO")
        return base

    def get_stats(self):
        return {"component": "SampleRateBlindSpotDetector", "checks": self.checks,
                "flags": self.flags, **self.achieved()}


# ---------------------------------------------------------------------------
# 4 -- Batched-inference architectural-backdoor detector
# ---------------------------------------------------------------------------
class BatchedInferenceBackdoorDetector:
    """
    Independence test across the batch boundary. Never sees request content:
    the caller supplies OUTPUT DIGESTS (or numeric divergence scores) for the
    same probe request run with different batch-mates.

    probe_runs: list of {"batch_mates_id": str, "output_digest": str}  OR
                list of {"batch_mates_id": str, "output_vector": [floats]}
    A clean model yields identical digests (or near-zero divergence). Any
    variation means request-A's output depends on who shares its batch.
    """

    def __init__(self, divergence_threshold: float = 1e-3, min_runs: int = 3):
        self.divergence_threshold = divergence_threshold
        self.min_runs = min_runs
        self.checks = 0
        self.flags = 0

    @staticmethod
    def digest(output_bytes: bytes) -> str:
        return hashlib.sha256(output_bytes).hexdigest()

    @staticmethod
    def _l2(a, b) -> float:
        if len(a) != len(b):
            return float("inf")
        return sum((x - y) ** 2 for x, y in zip(a, b)) ** 0.5

    def analyze(self, model_id: str, probe_runs: list) -> dict:
        self.checks += 1
        ts = datetime.now(timezone.utc).isoformat()
        base = {"substrate": "model", "model_id": model_id, "runs": len(probe_runs),
                "timestamp": ts, "agent": "BatchedInferenceBackdoorDetector",
                "cite": "Architectural Backdoors for Within-Batch Data Stealing (arXiv 2505.18323)",
                "privacy_note": "operates on output digests/divergence only; never reads request content"}

        if len(probe_runs) < self.min_runs:
            base.update(type="BATCH_ISOLATION_INSUFFICIENT_RUNS", severity="INFO",
                        note=f"need >= {self.min_runs} runs with different batch-mates")
            return base

        try:
            if all("output_digest" in r for r in probe_runs):
                digests = {r["output_digest"] for r in probe_runs}
                dependent = len(digests) > 1
                base["distinct_outputs"] = len(digests)
                base["max_divergence"] = None
            elif all("output_vector" in r for r in probe_runs):
                ref = probe_runs[0]["output_vector"]
                divs = [self._l2(ref, r["output_vector"]) for r in probe_runs[1:]]
                mx = max(divs) if divs else 0.0
                dependent = mx > self.divergence_threshold
                base["distinct_outputs"] = None
                base["max_divergence"] = round(mx, 6)
            else:
                base.update(type="BATCH_ISOLATION_BAD_INPUT", severity="WARNING",
                            error="runs must all carry output_digest or all carry output_vector")
                return base
        except Exception as e:
            base.update(type="BATCH_ISOLATION_ERROR", severity="WARNING",
                        error=f"{type(e).__name__}: {e}", note="failed loud; not clean")
            return base

        if dependent:
            self.flags += 1
            base.update(type="BATCH_BOUNDARY_LEAK_SUSPECTED",
                        severity="CRITICAL",
                        swarm_signal="BATCH_BOUNDARY_LEAK_SUSPECTED",
                        detail=("the same request produced different outputs depending on its "
                                "batch-mates -- information is crossing the batch boundary "
                                "(architectural backdoor / within-batch data-stealing signature)"),
                        recommended_action={"action": "disable_batching_for_model_gated",
                                            "detail": "serve this model batch-size-1 until reviewed; "
                                                      "quarantine architecture for inspection",
                                            "risk": "gated"},
                        tenant_isolation_note=("model-layer twin of the VRAM-residual finding: "
                                               "cross-tenant leakage without touching hardware"))
        else:
            base.update(type="BATCH_BOUNDARY_ISOLATED", severity="INFO")
        return base

    def get_stats(self):
        return {"component": "BatchedInferenceBackdoorDetector",
                "checks": self.checks, "flags": self.flags}


if __name__ == "__main__":
    # blind spot: 100 Hz requested, ~6 Hz achieved (real B200 figure)
    sr = SampleRateBlindSpotDetector(requested_hz=100.0)
    t = 0.0
    for _ in range(50):
        t += 1 / 6.0
        sr.observe_sample(t)
    print("[BLINDSPOT] 50ms agentic bursts:", sr.assess(50.0, "agentic")["type"])
    print("[BLINDSPOT] 2000ms training steps:", sr.assess(2000.0, "training")["type"])

    bd = BatchedInferenceBackdoorDetector()
    clean = [{"batch_mates_id": f"b{i}", "output_digest": "abc"} for i in range(4)]
    leaky = [{"batch_mates_id": "b0", "output_digest": "abc"},
             {"batch_mates_id": "b1", "output_digest": "abc"},
             {"batch_mates_id": "b2", "output_digest": "zzz"}]
    print("[BATCH] clean:", bd.analyze("m", clean)["type"])
    print("[BATCH] leaky:", bd.analyze("m", leaky)["type"])
