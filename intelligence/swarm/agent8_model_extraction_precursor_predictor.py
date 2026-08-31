#!/usr/bin/env python3
# Author: Manmohan (Mike) Bains -- Watchdog
"""
Watchdog Swarm Intelligence — Agent 8
Model-Extraction / Abnormal-Inference Precursor Predictor

Watches the inference-load telemetry signature that precedes a
model-extraction (model-stealing) or denial-of-wallet campaign, and fires
before the query flood fully accrues cost or leaks the model.

This is prediction -- not detection.
There is no after-the-fact model-extraction detector in the current
engine set; this agent provides the early-warning signal from telemetry
Watchdog already collects.

Research basis:
- Black-box model extraction via high, structured query volume
  (Tramer et al.; Cache Telepathy USENIX Sec 2020 for architecture leak).
- Denial-of-Wallet / unbounded consumption (OWASP LLM: unbounded
  resource consumption) -- variable-length input floods driving
  unsustainable cost.
- InputSnatch / KV-cache timing (arXiv:2411.18191): repeated near-boundary
  probing queries to hit cached prefixes.
- Extraction signature: sustained high inference-request RATE with LOW
  per-request compute variance (systematic sweeping) and rising power at
  steady memory footprint -- distinct from organic, bursty user traffic.

NOTE: Simulation-based. Requires real hardware validation. The precursor
signature is derived from published extraction/DoW dynamics, not
validated against a live extraction campaign. Fires WARNING for review;
rate-limiting is a gated action, never an auto-block on this signal alone
(legitimate batch inference can resemble it early).

Commercial value:
- Early warning on model theft and cost-exhaustion attacks
- Directly serves the pharma/insurance IP-protection story
"""
import collections
import time
import statistics
from datetime import datetime, timezone

WINDOW = 60
RAMP_WINDOW = 12
PREDICTION_THRESHOLD = 0.80
COOLDOWN_S = 120


class ModelExtractionPrecursorPredictor:
    """
    Agent 8 -- Model-Extraction / Abnormal-Inference Precursor Predictor

    Fires MODEL_EXTRACTION_PRECURSOR_PREDICTED when inference telemetry
    shows the ramp into a sustained, high-rate, low-variance query pattern
    consistent with systematic model sweeping or a cost-exhaustion flood.

    Precursor signature:
    1. Inference request rate ramping up and holding high
    2. LOW per-request compute variance (systematic sweep, not organic mix)
    3. Rising power at STEADY memory footprint (many small inferences, not
       a growing working set)
    4. Sustained -- not a brief legitimate burst
    """

    def __init__(self, gpu_id=0, baseline_req_per_s=5.0):
        self.gpu_id = gpu_id
        self.baseline_req_per_s = baseline_req_per_s

        self.req_rate_history = collections.deque(maxlen=WINDOW)
        self.req_compute_ms_history = collections.deque(maxlen=WINDOW)
        self.power_history = collections.deque(maxlen=WINDOW)
        self.vram_history = collections.deque(maxlen=WINDOW)

        self.last_prediction_ts = 0
        self.prediction_count = 0
        self.confirmed_count = 0
        self.false_positive_count = 0

    def update(self, telemetry: dict) -> dict | None:
        """
        telemetry keys expected:
            inference_req_per_s, avg_req_compute_ms, power_watts,
            vram_used_mb, timestamp
        """
        req_rate = float(telemetry.get('inference_req_per_s', 0))
        req_ms = float(telemetry.get('avg_req_compute_ms', 0))
        power = float(telemetry.get('power_watts', 0))
        vram = float(telemetry.get('vram_used_mb', 0))
        ts = telemetry.get('timestamp', datetime.now(timezone.utc).isoformat())

        self.req_rate_history.append(req_rate)
        self.req_compute_ms_history.append(req_ms)
        self.power_history.append(power)
        self.vram_history.append(vram)

        if len(self.req_rate_history) < RAMP_WINDOW:
            return None

        now = time.time()
        if now - self.last_prediction_ts < COOLDOWN_S:
            return None

        confidence, signature = self._calculate_confidence()

        if confidence >= PREDICTION_THRESHOLD:
            self.last_prediction_ts = now
            self.prediction_count += 1
            alert = {
                'type': 'MODEL_EXTRACTION_PRECURSOR_PREDICTED',
                'severity': 'WARNING',
                'gpu': self.gpu_id,
                'confidence': round(confidence, 3),
                'confidence_pct': round(confidence * 100, 1),
                'timestamp': ts,
                'prediction_horizon_s': '0-60',
                'signature': signature,
                'threat_context': ['model extraction (black-box)',
                                   'denial-of-wallet / unbounded consumption'],
                'prediction_count': self.prediction_count,
                'agent': 'ModelExtractionPrecursorPredictor',
                'agent_version': '1.0',
                'message': (
                    f"Model-extraction / cost-exhaustion precursor predicted "
                    f"on GPU{self.gpu_id}: sustained high-rate low-variance "
                    f"query sweep. Confidence: {confidence*100:.1f}%. "
                    f"Pattern: {signature['pattern']}"
                ),
                'recommended_action': (
                    "Raise for review and consider gated per-client rate "
                    "limiting. Do NOT auto-block on this signal alone -- "
                    "legitimate batch inference can resemble it early."
                ),
                'note': ('Simulation-based. Signature from published '
                         'extraction/DoW dynamics, not live-campaign validated.'),
            }
            print(f"[SWARM AGENT 8] MODEL_EXTRACTION_PRECURSOR_PREDICTED "
                  f"GPU{self.gpu_id} confidence={confidence*100:.1f}%")
            return alert
        return None

    def _calculate_confidence(self) -> tuple:
        rates = list(self.req_rate_history)[-RAMP_WINDOW:]
        req_ms = list(self.req_compute_ms_history)[-RAMP_WINDOW:]
        powers = list(self.power_history)[-RAMP_WINDOW:]
        vrams = list(self.vram_history)[-RAMP_WINDOW:]

        # Signal 1 -- request rate ramping up and holding above baseline.
        rate_ramp = rates[-1] - rates[0]
        rate_score = 0.0
        if rates[-1] > self.baseline_req_per_s * 5 and rate_ramp > 0:
            rate_score = 1.0
        elif rates[-1] > self.baseline_req_per_s * 3:
            rate_score = 0.6
        elif rates[-1] > self.baseline_req_per_s * 2:
            rate_score = 0.3

        # Signal 2 -- low per-request compute variance = systematic sweep.
        var_score = 0.0
        if len(req_ms) > 1 and statistics.fmean(req_ms) > 0:
            cv = statistics.pstdev(req_ms) / statistics.fmean(req_ms)
            if cv < 0.05:
                var_score = 1.0
            elif cv < 0.15:
                var_score = 0.6
            elif cv < 0.30:
                var_score = 0.3

        # Signal 3 -- rising power at STEADY memory footprint.
        power_ramp = powers[-1] - powers[0]
        vram_stable = False
        if len(vrams) > 1 and statistics.fmean(vrams) > 0:
            vram_cv = statistics.pstdev(vrams) / statistics.fmean(vrams)
            vram_stable = vram_cv < 0.05
        footprint_score = 1.0 if (power_ramp > 40 and vram_stable) else \
            (0.5 if vram_stable else 0.0)

        # Signal 4 -- sustained (rate has stayed elevated across the window).
        sustained = all(r > self.baseline_req_per_s * 2 for r in rates[-RAMP_WINDOW // 2:])
        sustained_score = 1.0 if sustained else 0.0

        confidence = (rate_score * 0.30 + var_score * 0.30
                      + footprint_score * 0.20 + sustained_score * 0.20)

        if var_score > 0.8 and rate_score > 0.8:
            pattern = "SYSTEMATIC_HIGH_RATE_SWEEP"
        elif footprint_score > 0.8 and rate_score > 0.6:
            pattern = "STEADY_FOOTPRINT_QUERY_FLOOD"
        elif rate_score > 0.8:
            pattern = "SUSTAINED_RATE_SPIKE"
        else:
            pattern = "COMPOSITE_PRECURSOR"

        signature = {
            'pattern': pattern,
            'rate_score': round(rate_score, 2),
            'compute_variance_score': round(var_score, 2),
            'footprint_score': round(footprint_score, 2),
            'sustained_score': round(sustained_score, 2),
            'current_req_per_s': round(rates[-1], 2),
        }
        return confidence, signature

    def get_stats(self) -> dict:
        return {
            'agent': 'ModelExtractionPrecursorPredictor',
            'gpu_id': self.gpu_id,
            'samples_processed': len(self.req_rate_history),
            'predictions_fired': self.prediction_count,
            'confirmed': self.confirmed_count,
            'false_positives': self.false_positive_count,
            'baseline_req_per_s': self.baseline_req_per_s,
        }


if __name__ == "__main__":
    import random
    print("=" * 55)
    print("Watchdog Swarm — Agent 8: Model-Extraction Precursor")
    print("Simulation test")
    print("=" * 55)
    agent = ModelExtractionPrecursorPredictor(gpu_id=0)

    print("\n[Phase 1] Organic traffic — mixed rate and compute")
    for i in range(20):
        agent.update({'inference_req_per_s': random.uniform(2, 8),
                      'avg_req_compute_ms': random.uniform(10, 60),  # varied
                      'power_watts': 200 + random.uniform(-30, 30),
                      'vram_used_mb': 8000 + random.uniform(-500, 500),
                      'timestamp': datetime.now(timezone.utc).isoformat()})

    print("\n[Phase 2] Extraction sweep — high uniform rate, uniform compute, steady vram")
    for i in range(20):
        r = agent.update({'inference_req_per_s': min(80, 20 + i * 4) + random.uniform(-1, 1),
                          'avg_req_compute_ms': 25 + random.uniform(-0.5, 0.5),  # uniform
                          'power_watts': 260 + i * 6 + random.uniform(-2, 2),
                          'vram_used_mb': 8200 + random.uniform(-50, 50),  # steady
                          'timestamp': datetime.now(timezone.utc).isoformat()})
        if r:
            print(f"\n*** PREDICTION FIRED ***")
            print(f"  Pattern: {r['signature']['pattern']}")
            print(f"  Confidence: {r['confidence_pct']}%")

    print("\nAgent 8 stats:", agent.get_stats())
