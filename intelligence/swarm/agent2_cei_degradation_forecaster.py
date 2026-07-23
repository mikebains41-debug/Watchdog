#!/usr/bin/env python3
# Author: Manmohan (Mike) Bains -- Watchdog AIDR
"""
Watchdog Swarm Intelligence — Agent 2
CEI Degradation Forecaster

Tracks Compute Energy Intensity (FLOPs/joule) trend over time.
Predicts when a GPU will drop below EXCELLENT tier before it happens.
Gives data center operators advance warning before SLA breach.

This is prediction — not detection.
Based on Serial Alice finding: absolute CEI varies ~20% due to thermal throttling.
Agent 2 tracks the TREND not the absolute value.

Commercial value:
- SLA breach warning before it happens
- Maintenance scheduling before performance degrades
- EU AI Act energy efficiency compliance monitoring
- Requires real hardware validation before accuracy claims
"""
import collections
import time
import statistics
from datetime import datetime, timezone


WINDOW_SIZE = 100
TREND_WINDOW = 20
PREDICTION_THRESHOLD = 0.78
COOLDOWN_S = 300

CEI_TIERS = {
    'EXCELLENT': 10e9,
    'GOOD': 5e9,
    'MODERATE': 1e9,
    'POOR': 0
}


# Real H200 validated data from Serial Alice certificates
# These are blockchain-anchored attested measurements — not estimates
H200_VALIDATED = {
    'idle_floor_w': 80.36,        # M2 cert sa-29820c
    'ghost_threshold_w': 88.36,   # idle + 8W — same as M2
    'ghost_peak_w': 147.96,       # M6 cooldown tail cert sa-b2f092
    'fp32_cei': 3.178e11,         # M4 cert sa-885826 — EXCELLENT tier
    'fp32_cei_min': 3.135e11,     # M4 5-pass minimum ±1.6%
    'fp32_cei_max': 3.187e11,     # M4 5-pass maximum ±1.6%
    'fp16_cei': 2.846e12,         # M7 cert sa-b6d99f — same-GPU 9x FP32
    'fp8_cei': 9.59e11,           # FP8 ladder cert sa-e6628d — 12.69x FP32
    'fp8_bf16_ratio': 1.41,       # FP8/BF16 ratio CV 2.81% — most stable metric
    'fp32_power_w': 620.9,
    'fp8_power_w': 400.9,
}


class CEIDegradationForecaster:
    """
    Agent 2 — CEI Degradation Forecaster

    Tracks CEI trend over time and predicts tier drops
    before they occur.

    Based on Serial Alice finding:
    - Single-run absolute CEI varies ~20% due to thermal throttling
    - Trend over many samples is stable and predictable
    - Agent 2 uses trend not absolute to forecast degradation

    NOTE: Simulation-only until validated on real hardware.
    """

    def __init__(self, gpu_id=0):
        self.gpu_id = gpu_id
        self.cei_history = collections.deque(maxlen=WINDOW_SIZE)
        self.tier_history = collections.deque(maxlen=WINDOW_SIZE)
        self.timestamp_history = collections.deque(maxlen=WINDOW_SIZE)
        self.last_prediction_ts = 0
        self.prediction_count = 0

    def _classify_tier(self, cei):
        if cei >= CEI_TIERS['EXCELLENT']:
            return 'EXCELLENT'
        elif cei >= CEI_TIERS['GOOD']:
            return 'GOOD'
        elif cei >= CEI_TIERS['MODERATE']:
            return 'MODERATE'
        else:
            return 'POOR'

    def update(self, telemetry: dict) -> dict | None:
        cei = float(telemetry.get('cei_flops_per_joule', 0))
        ts = telemetry.get('timestamp', datetime.now(timezone.utc).isoformat())

        if cei <= 0:
            return None

        self.cei_history.append(cei)
        self.tier_history.append(self._classify_tier(cei))
        self.timestamp_history.append(ts)

        if len(self.cei_history) < TREND_WINDOW:
            return None

        now = time.time()
        if now - self.last_prediction_ts < COOLDOWN_S:
            return None

        confidence, forecast = self._calculate_forecast()

        if confidence >= PREDICTION_THRESHOLD:
            self.last_prediction_ts = now
            self.prediction_count += 1

            current_tier = self._classify_tier(cei)
            predicted_tier = forecast['predicted_tier']

            alert = {
                'type': 'CEI_DEGRADATION_PREDICTED',
                'severity': 'WARNING',
                'gpu': self.gpu_id,
                'confidence': round(confidence, 3),
                'confidence_pct': round(confidence * 100, 1),
                'timestamp': ts,
                'current_cei': round(cei, 2),
                'current_tier': current_tier,
                'predicted_tier': predicted_tier,
                'predicted_cei': round(forecast['predicted_cei'], 2),
                'trend_slope': round(forecast['trend_slope'], 4),
                'samples_to_breach': forecast['samples_to_breach'],
                'prediction_count': self.prediction_count,
                'agent': 'CEIDegradationForecaster',
                'agent_version': '1.0',
                'note': 'Simulation-based. Requires real hardware validation.',
                'message': (
                    f"CEI degradation predicted on GPU{self.gpu_id}. "
                    f"Current tier: {current_tier}. "
                    f"Predicted tier: {predicted_tier} "
                    f"in ~{forecast['samples_to_breach']} samples. "
                    f"Confidence: {confidence*100:.1f}% — simulation only."
                ),
                'recommended_action': (
                    "Schedule maintenance window. "
                    "Check thermal management. "
                    "Review workload scheduling."
                )
            }

            print(f"[SWARM AGENT 2] CEI_DEGRADATION_PREDICTED GPU{self.gpu_id} "
                  f"confidence={confidence*100:.1f}% "
                  f"trend={forecast['trend_slope']:.4f} "
                  f"predicted_tier={predicted_tier}")

            return alert

        return None

    def _calculate_forecast(self) -> tuple[float, dict]:
        recent = list(self.cei_history)[-TREND_WINDOW:]

        mean_cei = statistics.mean(recent)
        if len(recent) > 1:
            trend_slope = (recent[-1] - recent[0]) / len(recent)
        else:
            trend_slope = 0

        confidence = 0.0
        predicted_cei = mean_cei
        predicted_tier = self._classify_tier(mean_cei)
        samples_to_breach = 999

        current_tier = self._classify_tier(mean_cei)

        if trend_slope < 0:
            degradation_rate = abs(trend_slope)
            degradation_score = min(1.0, degradation_rate / (mean_cei * 0.01))

            if current_tier == 'EXCELLENT':
                breach_threshold = CEI_TIERS['EXCELLENT']
                gap = mean_cei - breach_threshold
                if gap > 0 and degradation_rate > 0:
                    samples_to_breach = int(gap / degradation_rate)
                    predicted_cei = mean_cei + (trend_slope * samples_to_breach)
                    predicted_tier = self._classify_tier(predicted_cei)

            consistency = 0.0
            if len(recent) > 5:
                diffs = [recent[i] - recent[i-1] for i in range(1, len(recent))]
                negative_diffs = sum(1 for d in diffs if d < 0)
                consistency = negative_diffs / len(diffs)

            confidence = (degradation_score * 0.5 + consistency * 0.5)

            if samples_to_breach > 500:
                confidence *= 0.5

        forecast = {
            'trend_slope': trend_slope,
            'predicted_cei': predicted_cei,
            'predicted_tier': predicted_tier,
            'samples_to_breach': samples_to_breach,
            'mean_cei': mean_cei
        }

        return confidence, forecast

    def get_stats(self) -> dict:
        return {
            'agent': 'CEIDegradationForecaster',
            'gpu_id': self.gpu_id,
            'samples_processed': len(self.cei_history),
            'predictions_fired': self.prediction_count,
            'current_cei': round(list(self.cei_history)[-1], 2) if self.cei_history else 0,
            'current_tier': self._classify_tier(list(self.cei_history)[-1]) if self.cei_history else 'UNKNOWN',
            'note': 'Simulation-based. Requires real hardware validation.'
        }


if __name__ == "__main__":
    import random

    print("=" * 55)
    print("Watchdog Swarm — Agent 2: CEI Degradation Forecaster")
    print("Simulation test — 120 samples")
    print("NOTE: Simulated data only. Not real hardware.")
    print("=" * 55)

    agent = CEIDegradationForecaster(gpu_id=0)

    print("\n[Phase 1] Stable EXCELLENT tier — 30 samples")
    for i in range(30):
        t = {
            'cei_flops_per_joule': 3.178e11 + random.uniform(-1e10, 1e10),
            'timestamp': datetime.now(timezone.utc).isoformat()
        }
        agent.update(t)

    print("\n[Phase 2] Gradual degradation — 60 samples")
    base = 3.178e11
    for i in range(60):
        degraded = base - (i * 2.5e9) + random.uniform(-5e9, 5e9)
        t = {
            'cei_flops_per_joule': max(degraded, 1e9),
            'timestamp': datetime.now(timezone.utc).isoformat()
        }
        result = agent.update(t)
        if result:
            print(f"\n*** PREDICTION FIRED ***")
            print(f"  Type: {result['type']}")
            print(f"  Confidence: {result['confidence_pct']}%")
            print(f"  Current tier: {result['current_tier']}")
            print(f"  Predicted tier: {result['predicted_tier']}")
            print(f"  Samples to breach: {result['samples_to_breach']}")
            print(f"  Note: {result['note']}")

    print("\n" + "=" * 55)
    print("Agent 2 Stats:")
    stats = agent.get_stats()
    for k, v in stats.items():
        print(f"  {k}: {v}")
