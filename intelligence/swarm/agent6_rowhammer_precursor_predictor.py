#!/usr/bin/env python3
# Author: Manmohan (Mike) Bains -- Watchdog
"""
Watchdog Swarm Intelligence — Agent 6
Rowhammer / ECC-Break Precursor Predictor

Watches ECC error telemetry and learns the signature that PRECEDES a
Rowhammer bit-flip / ECC-break event -- the rising trail of corrected
(single-bit) errors that hammering leaves behind BEFORE it produces an
uncorrectable (multi-bit) flip.

This is prediction -- not detection.
The batch-2 gpu_memory_integrity detector catches the ECC break after
uncorrectable errors appear. This agent catches the ACCELERATING
corrected-error rate that comes first, and fires an early warning before
the flip lands.

Research basis:
- GPUHammer (USENIX Security 2025, U Toronto): first Rowhammer bit-flips
  on GPU memory; a single flip drops model accuracy ~80% -> ~0.1%.
- GPUThor (U Toronto, Sept 2026): first GPU Rowhammer to break through
  ECC -- the mitigation NVIDIA recommended after GPUHammer.
- GPUBreach (2026): escalation to root shell.
- ECCploit: multi-bit flips in one ECC word cause silent mis-correction.

NOTE: Simulation-based. Requires real hardware validation. The precursor
signature (accelerating corrected-error rate) is derived from published
Rowhammer dynamics, NOT yet validated against a live hammered GPU.

Commercial value:
- Evacuate a workload off an at-risk GPU BEFORE weights are corrupted
- Turns ECC telemetry (already collected) into an early-warning signal
- Pairs with the existing at-rest weight-integrity detector
"""
import collections
import time
import statistics
from datetime import datetime, timezone

ECC_WINDOW = 60          # samples of ECC history
RAMP_WINDOW = 10         # samples for rate-acceleration calculation
PREDICTION_THRESHOLD = 0.80
COOLDOWN_S = 120


class RowhammerPrecursorPredictor:
    """
    Agent 6 -- Rowhammer / ECC-Break Precursor Predictor

    Fires GPUTHOR_PRECURSOR_PREDICTED when the corrected-ECC-error rate is
    accelerating in a way consistent with active memory hammering, before
    an uncorrectable flip occurs.

    Precursor signature:
    1. Corrected (single-bit) ECC errors rising sample-over-sample
    2. The RATE of that rise accelerating (2nd-derivative positive)
    3. Corrected errors concentrated (bursty), not spread evenly like
       environmental single-event upsets
    """

    def __init__(self, gpu_id=0, baseline_corrected_per_min=2.0):
        self.gpu_id = gpu_id
        # Environmental/background corrected-error rate to subtract out.
        self.baseline_corrected_per_min = baseline_corrected_per_min

        self.corrected_history = collections.deque(maxlen=ECC_WINDOW)
        self.uncorrectable_history = collections.deque(maxlen=ECC_WINDOW)

        self.last_prediction_ts = 0
        self.prediction_count = 0
        self.confirmed_count = 0
        self.false_positive_count = 0

    def update(self, telemetry: dict) -> dict | None:
        """
        telemetry keys expected:
            ecc_corrected_total, ecc_uncorrectable_total, timestamp
        (cumulative counters, as nvidia-smi reports them)
        """
        corrected = float(telemetry.get('ecc_corrected_total', 0))
        uncorrectable = float(telemetry.get('ecc_uncorrectable_total', 0))
        ts = telemetry.get('timestamp', datetime.now(timezone.utc).isoformat())

        self.corrected_history.append(corrected)
        self.uncorrectable_history.append(uncorrectable)

        if len(self.corrected_history) < RAMP_WINDOW:
            return None

        now = time.time()
        if now - self.last_prediction_ts < COOLDOWN_S:
            return None

        confidence, signature = self._calculate_confidence()

        if confidence >= PREDICTION_THRESHOLD:
            self.last_prediction_ts = now
            self.prediction_count += 1

            alert = {
                'type': 'GPUTHOR_PRECURSOR_PREDICTED',
                'severity': 'WARNING',
                'gpu': self.gpu_id,
                'confidence': round(confidence, 3),
                'confidence_pct': round(confidence * 100, 1),
                'timestamp': ts,
                'prediction_horizon_s': '10-60',
                'signature': signature,
                'cve_context': ['GPUHammer (USENIX Sec 2025)',
                                'GPUThor (2026)', 'GPUBreach (2026)'],
                'prediction_count': self.prediction_count,
                'agent': 'RowhammerPrecursorPredictor',
                'agent_version': '1.0',
                'message': (
                    f"ECC-break precursor predicted on GPU{self.gpu_id}: "
                    f"accelerating corrected-error rate consistent with "
                    f"active hammering. Confidence: {confidence*100:.1f}%. "
                    f"Pattern: {signature['pattern']}"
                ),
                'recommended_action': (
                    "Evacuate workload off this GPU and escalate BEFORE an "
                    "uncorrectable flip corrupts weights. Do NOT auto-reset "
                    "-- preserve state for forensics."
                ),
                'note': ('Simulation-based. Precursor signature derived from '
                         'published Rowhammer dynamics, not live-hardware '
                         'validated.'),
            }
            print(f"[SWARM AGENT 6] GPUTHOR_PRECURSOR_PREDICTED GPU{self.gpu_id} "
                  f"confidence={confidence*100:.1f}%")
            return alert
        return None

    def _calculate_confidence(self) -> tuple:
        corrected = list(self.corrected_history)[-RAMP_WINDOW:]

        # Per-sample deltas (new corrected errors each sample).
        deltas = [corrected[i] - corrected[i - 1] for i in range(1, len(corrected))]
        deltas = [max(d, 0.0) for d in deltas]  # counters are monotonic

        # Signal 1 -- sustained elevated rate above baseline.
        mean_delta = statistics.fmean(deltas) if deltas else 0.0
        baseline_per_sample = self.baseline_corrected_per_min / 60.0
        rate_score = 0.0
        if mean_delta > baseline_per_sample * 10:
            rate_score = 1.0
        elif mean_delta > baseline_per_sample * 4:
            rate_score = 0.6
        elif mean_delta > baseline_per_sample * 2:
            rate_score = 0.3

        # Signal 2 -- acceleration (2nd derivative): later deltas > earlier.
        accel_score = 0.0
        if len(deltas) >= 4:
            first_half = statistics.fmean(deltas[:len(deltas) // 2])
            second_half = statistics.fmean(deltas[len(deltas) // 2:])
            if second_half > first_half * 2 and second_half > baseline_per_sample:
                accel_score = 1.0
            elif second_half > first_half * 1.3:
                accel_score = 0.6

        # Signal 3 -- burstiness: high variance relative to mean = hammering,
        # not the near-uniform trickle of environmental SEUs.
        burst_score = 0.0
        if len(deltas) > 1 and mean_delta > 0:
            cv = statistics.pstdev(deltas) / mean_delta
            if cv > 1.5:
                burst_score = 1.0
            elif cv > 0.8:
                burst_score = 0.5

        confidence = (rate_score * 0.45 + accel_score * 0.35 + burst_score * 0.20)

        if accel_score > 0.8 and rate_score > 0.8:
            pattern = "ACCELERATING_HAMMER"
        elif rate_score > 0.8:
            pattern = "SUSTAINED_ELEVATED_RATE"
        elif burst_score > 0.8:
            pattern = "BURSTY_CORRECTED_ERRORS"
        else:
            pattern = "COMPOSITE_PRECURSOR"

        signature = {
            'pattern': pattern,
            'rate_score': round(rate_score, 2),
            'accel_score': round(accel_score, 2),
            'burst_score': round(burst_score, 2),
            'mean_corrected_per_sample': round(mean_delta, 3),
            'baseline_per_sample': round(baseline_per_sample, 4),
        }
        return confidence, signature

    def get_stats(self) -> dict:
        return {
            'agent': 'RowhammerPrecursorPredictor',
            'gpu_id': self.gpu_id,
            'samples_processed': len(self.corrected_history),
            'predictions_fired': self.prediction_count,
            'confirmed': self.confirmed_count,
            'false_positives': self.false_positive_count,
            'baseline_corrected_per_min': self.baseline_corrected_per_min,
        }


if __name__ == "__main__":
    import random
    print("=" * 55)
    print("Watchdog Swarm — Agent 6: Rowhammer/ECC-Break Precursor")
    print("Simulation test")
    print("=" * 55)
    agent = RowhammerPrecursorPredictor(gpu_id=0)

    corrected = 0
    print("\n[Phase 1] Normal — trickle of environmental SEUs")
    for i in range(30):
        corrected += random.choice([0, 0, 0, 1])
        agent.update({'ecc_corrected_total': corrected,
                      'ecc_uncorrectable_total': 0,
                      'timestamp': datetime.now(timezone.utc).isoformat()})

    print("\n[Phase 2] Active hammering — accelerating bursty corrected errors")
    for i in range(20):
        corrected += random.randint(i, i * 3 + 2)  # accelerating + bursty
        r = agent.update({'ecc_corrected_total': corrected,
                          'ecc_uncorrectable_total': 0,
                          'timestamp': datetime.now(timezone.utc).isoformat()})
        if r:
            print(f"\n*** PREDICTION FIRED ***")
            print(f"  Pattern: {r['signature']['pattern']}")
            print(f"  Confidence: {r['confidence_pct']}%")

    print("\nAgent 6 stats:", agent.get_stats())
