#!/usr/bin/env python3
# Author: Manmohan (Mike) Bains -- Watchdog
"""
Watchdog Swarm Intelligence — Agent 7
Cryptojacking / Covert-Compute Onset Predictor

Watches the power + utilization + clock signature that ramps up as an
unauthorized miner or covert compute job SPINS UP, and fires before it
locks into a steady stolen-compute pattern.

This is prediction -- not detection.
The existing CovertMiningDetector catches covert mining once it is
running steadily. This agent catches the ONSET transient -- the ramp into
sustained-high-utilization-at-uniform-clocks -- and warns earlier.

Research basis:
- Behavior-based GPU cryptojacking detection via hardware performance
  counters ~96% accuracy (ACM CODASPY 2023).
- MagTracer: GPU cryptojacking via magnetic-leakage signals (MobiCom 2023).
- 2026 SEO-poisoning / ScreenConnect GPU-mining campaign (Microsoft
  Security, May 2026) -- active in the wild.
- Miner signature: sustained ~100% utilization at UNIFORM SM clocks with
  LOW memory-bandwidth variance (compute-bound hashing), distinct from
  legitimate training (bursty, memory-heavy).

NOTE: Simulation-based. Requires real hardware validation. Signature is
derived from published miner behavior, not validated on a live infected
pod. Onset prediction is inherently probabilistic -- a legitimate
sustained-compute job can look similar at onset; this fires a WARNING for
review, never an auto-kill.

Commercial value:
- Catch resource theft in the first seconds, before billing accrues
- Complements after-the-fact CovertMiningDetector with early warning
"""
import collections
import time
import statistics
from datetime import datetime, timezone

WINDOW = 60
RAMP_WINDOW = 12
PREDICTION_THRESHOLD = 0.80
COOLDOWN_S = 120


class CryptojackingOnsetPredictor:
    """
    Agent 7 -- Cryptojacking / Covert-Compute Onset Predictor

    Fires COVERT_COMPUTE_ONSET_PREDICTED when telemetry shows the ramp
    into a sustained, uniform-clock, high-utilization, low-memory-variance
    pattern characteristic of GPU mining onset.

    Onset signature:
    1. Utilization ramping up toward and holding ~100%
    2. SM clock UNIFORM (low variance) -- steady hashing, not bursty training
    3. Power climbing to a sustained plateau
    4. Memory-bandwidth utilization LOW relative to compute (hashing is
       compute-bound; training is memory-heavy)
    """

    def __init__(self, gpu_id=0):
        self.gpu_id = gpu_id
        self.util_history = collections.deque(maxlen=WINDOW)
        self.sm_clock_history = collections.deque(maxlen=WINDOW)
        self.power_history = collections.deque(maxlen=WINDOW)
        self.mem_bw_history = collections.deque(maxlen=WINDOW)

        self.last_prediction_ts = 0
        self.prediction_count = 0
        self.confirmed_count = 0
        self.false_positive_count = 0

    def update(self, telemetry: dict) -> dict | None:
        """
        telemetry keys expected:
            gpu_util, sm_clock_mhz, power_watts,
            mem_bw_util_pct (memory-bandwidth utilization %), timestamp
        mem_bw_util_pct is optional; if absent, that signal is neutral.
        """
        util = float(telemetry.get('gpu_util', 0))
        sm_clock = float(telemetry.get('sm_clock_mhz', 0))
        power = float(telemetry.get('power_watts', 0))
        mem_bw = telemetry.get('mem_bw_util_pct', None)
        ts = telemetry.get('timestamp', datetime.now(timezone.utc).isoformat())

        self.util_history.append(util)
        self.sm_clock_history.append(sm_clock)
        self.power_history.append(power)
        if mem_bw is not None:
            self.mem_bw_history.append(float(mem_bw))

        if len(self.util_history) < RAMP_WINDOW:
            return None

        now = time.time()
        if now - self.last_prediction_ts < COOLDOWN_S:
            return None

        confidence, signature = self._calculate_confidence()

        if confidence >= PREDICTION_THRESHOLD:
            self.last_prediction_ts = now
            self.prediction_count += 1
            alert = {
                'type': 'COVERT_COMPUTE_ONSET_PREDICTED',
                'severity': 'WARNING',
                'gpu': self.gpu_id,
                'confidence': round(confidence, 3),
                'confidence_pct': round(confidence * 100, 1),
                'timestamp': ts,
                'prediction_horizon_s': '0-30',
                'signature': signature,
                'prediction_count': self.prediction_count,
                'agent': 'CryptojackingOnsetPredictor',
                'agent_version': '1.0',
                'message': (
                    f"Covert-compute onset predicted on GPU{self.gpu_id}: "
                    f"ramp into sustained uniform-clock high utilization "
                    f"(mining signature). Confidence: {confidence*100:.1f}%. "
                    f"Pattern: {signature['pattern']}"
                ),
                'recommended_action': (
                    "Correlate the ramping PID against the process whitelist "
                    "and raise for review. Do NOT auto-kill on onset alone -- "
                    "a legitimate sustained-compute job can look similar early."
                ),
                'note': ('Simulation-based. Onset signature from published '
                         'miner behavior, not validated on a live infected pod.'),
            }
            print(f"[SWARM AGENT 7] COVERT_COMPUTE_ONSET_PREDICTED GPU{self.gpu_id} "
                  f"confidence={confidence*100:.1f}%")
            return alert
        return None

    def _calculate_confidence(self) -> tuple:
        utils = list(self.util_history)[-RAMP_WINDOW:]
        clocks = list(self.sm_clock_history)[-RAMP_WINDOW:]
        powers = list(self.power_history)[-RAMP_WINDOW:]

        # Signal 1 -- utilization ramping up and holding high.
        util_ramp = utils[-1] - utils[0]
        util_score = 0.0
        if utils[-1] > 90 and util_ramp > 20:
            util_score = 1.0
        elif utils[-1] > 85:
            util_score = 0.6
        elif utils[-1] > 70 and util_ramp > 10:
            util_score = 0.3

        # Signal 2 -- SM clock uniform (low variance) = steady hashing.
        clock_score = 0.0
        if len(clocks) > 1 and statistics.fmean(clocks) > 0:
            clock_cv = statistics.pstdev(clocks) / statistics.fmean(clocks)
            if clock_cv < 0.01:
                clock_score = 1.0
            elif clock_cv < 0.03:
                clock_score = 0.6
            elif clock_cv < 0.05:
                clock_score = 0.3

        # Signal 3 -- power climbing to a sustained plateau.
        power_ramp = powers[-1] - powers[0]
        power_score = 0.0
        if power_ramp > 100 and powers[-1] > statistics.fmean(powers):
            power_score = 1.0
        elif power_ramp > 40:
            power_score = 0.5

        # Signal 4 -- low memory-bandwidth utilization (compute-bound hashing).
        mem_score = 0.5  # neutral default when mem_bw not provided
        if len(self.mem_bw_history) >= RAMP_WINDOW:
            recent_mem = list(self.mem_bw_history)[-RAMP_WINDOW:]
            avg_mem_bw = statistics.fmean(recent_mem)
            if avg_mem_bw < 15:      # hashing barely touches memory bandwidth
                mem_score = 1.0
            elif avg_mem_bw < 30:
                mem_score = 0.6
            elif avg_mem_bw > 60:    # memory-heavy => looks like training
                mem_score = 0.0

        confidence = (util_score * 0.30 + clock_score * 0.30
                      + power_score * 0.15 + mem_score * 0.25)

        if clock_score > 0.8 and util_score > 0.8 and mem_score > 0.6:
            pattern = "UNIFORM_CLOCK_COMPUTE_BOUND_HASH"
        elif util_score > 0.8 and clock_score > 0.6:
            pattern = "SUSTAINED_HIGH_UTIL_STEADY_CLOCK"
        elif util_score > 0.5 and power_score > 0.5:
            pattern = "RAMPING_PLATEAU"
        else:
            pattern = "COMPOSITE_ONSET"

        signature = {
            'pattern': pattern,
            'util_score': round(util_score, 2),
            'clock_score': round(clock_score, 2),
            'power_score': round(power_score, 2),
            'mem_bw_score': round(mem_score, 2),
            'current_util_pct': round(utils[-1], 1),
        }
        return confidence, signature

    def get_stats(self) -> dict:
        return {
            'agent': 'CryptojackingOnsetPredictor',
            'gpu_id': self.gpu_id,
            'samples_processed': len(self.util_history),
            'predictions_fired': self.prediction_count,
            'confirmed': self.confirmed_count,
            'false_positives': self.false_positive_count,
        }


if __name__ == "__main__":
    import random
    print("=" * 55)
    print("Watchdog Swarm — Agent 7: Cryptojacking Onset Predictor")
    print("Simulation test")
    print("=" * 55)
    agent = CryptojackingOnsetPredictor(gpu_id=0)

    print("\n[Phase 1] Idle / light load")
    for i in range(20):
        agent.update({'gpu_util': random.uniform(0, 15),
                      'sm_clock_mhz': 1400 + random.uniform(-100, 100),
                      'power_watts': 90 + random.uniform(-10, 10),
                      'mem_bw_util_pct': random.uniform(5, 20),
                      'timestamp': datetime.now(timezone.utc).isoformat()})

    print("\n[Phase 2] Miner spin-up — util climbs, clock locks uniform, low mem-bw")
    for i in range(20):
        r = agent.update({'gpu_util': min(99, 40 + i * 4) + random.uniform(-2, 2),
                          'sm_clock_mhz': 1980 + random.uniform(-3, 3),  # uniform
                          'power_watts': 150 + i * 12 + random.uniform(-3, 3),
                          'mem_bw_util_pct': random.uniform(3, 10),  # compute-bound
                          'timestamp': datetime.now(timezone.utc).isoformat()})
        if r:
            print(f"\n*** PREDICTION FIRED ***")
            print(f"  Pattern: {r['signature']['pattern']}")
            print(f"  Confidence: {r['confidence_pct']}%")

    print("\nAgent 7 stats:", agent.get_stats())
