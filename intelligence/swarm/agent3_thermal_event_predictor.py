#!/usr/bin/env python3
# Author: Manmohan (Mike) Bains -- Watchdog
"""
Watchdog Swarm Intelligence — Agent 3
Thermal Event Predictor

Watches GPU temperature climb rate and predicts thermal
throttling events before they hit.

Commercial value:
- Prevents performance degradation before it happens
- Enables proactive workload rebalancing
- Reduces hardware wear from thermal stress
- EU AI Act energy efficiency — thermal waste = energy waste

NOTE: Simulation-based. Requires real hardware validation.
"""
import collections
import time
import statistics
from datetime import datetime, timezone


WINDOW_SIZE = 60
RAMP_WINDOW = 15
PREDICTION_THRESHOLD = 0.70
COOLDOWN_S = 180

# Throttle limits from Serial Alice validated H200 testing
# Certificate sa-b2f092 — M6 sustained run — 11052 samples — 0 crashes
# H200 operated at sustained load with cooldown tail ghost at 147.96W
THROTTLE_TEMP_LIMITS = {
    'A100': 83.0,
    'H100': 83.0,
    'H200': 85.0,   # Validated in Serial Alice M6 run — cert sa-b2f092
    'B200': 85.0,
    'B300': 85.0,
    'DEFAULT': 83.0
}

# Real H200 ghost power data from Serial Alice certificates
# Used to ground simulation in validated measurements
H200_VALIDATED = {
    'idle_floor_w': 80.36,        # M2 cert sa-29820c
    'ghost_threshold_w': 88.36,   # idle + 8W — same as M2
    'ghost_peak_w': 147.96,       # M6 cooldown tail cert sa-b2f092
    'compute_peak_w': 486.9,      # M2 peak at 0% util cert sa-29820c
    'fp32_cei': 3.178e11,         # M4 cert sa-885826
    'fp32_cei_range': (3.135e11, 3.187e11),  # 5-pass range ±1.6%
    'fp8_cei': 9.59e11,           # FP8 ladder cert sa-e6628d
    'fp8_power_w': 400.9,         # FP8 lowest power
    'fp32_power_w': 620.9,        # FP32 highest power
}

WARNING_MARGIN_C = 5.0


class ThermalEventPredictor:
    """
    Agent 3 — Thermal Event Predictor

    Watches temperature climb rate and predicts throttling
    before it occurs.

    Throttling signature:
    1. Temperature climbing steadily under sustained load
    2. Climb rate accelerating — cooling falling behind
    3. Temperature approaching throttle threshold
    4. Result: clock speed reduction, CEI drop, SLA risk

    This agent detects steps 1-2 and predicts step 3-4.

    NOTE: Simulation-based. Requires real hardware validation.
    """

    def __init__(self, gpu_id=0, gpu_arch='DEFAULT'):
        self.gpu_id = gpu_id
        self.gpu_arch = gpu_arch
        self.throttle_limit = THROTTLE_TEMP_LIMITS.get(gpu_arch, THROTTLE_TEMP_LIMITS['DEFAULT'])
        self.warning_threshold = self.throttle_limit - WARNING_MARGIN_C

        self.temp_history = collections.deque(maxlen=WINDOW_SIZE)
        self.util_history = collections.deque(maxlen=WINDOW_SIZE)
        self.power_history = collections.deque(maxlen=WINDOW_SIZE)
        self.clock_history = collections.deque(maxlen=WINDOW_SIZE)

        self.last_prediction_ts = 0
        self.prediction_count = 0

    def update(self, telemetry: dict) -> dict | None:
        temp = float(telemetry.get('temp_c', 0))
        util = float(telemetry.get('gpu_util', 0))
        power = float(telemetry.get('power_watts', 0))
        clock = float(telemetry.get('sm_clock_mhz', 0))
        ts = telemetry.get('timestamp', datetime.now(timezone.utc).isoformat())

        self.temp_history.append(temp)
        self.util_history.append(util)
        self.power_history.append(power)
        self.clock_history.append(clock)

        if len(self.temp_history) < RAMP_WINDOW:
            return None

        now = time.time()
        if now - self.last_prediction_ts < COOLDOWN_S:
            return None

        confidence, forecast = self._calculate_forecast(temp)

        if confidence >= PREDICTION_THRESHOLD:
            self.last_prediction_ts = now
            self.prediction_count += 1

            alert = {
                'type': 'THERMAL_THROTTLE_PREDICTED',
                'severity': 'WARNING',
                'gpu': self.gpu_id,
                'confidence': round(confidence, 3),
                'confidence_pct': round(confidence * 100, 1),
                'timestamp': ts,
                'current_temp_c': round(temp, 1),
                'throttle_limit_c': self.throttle_limit,
                'warning_threshold_c': self.warning_threshold,
                'temp_gap_c': round(self.throttle_limit - temp, 1),
                'climb_rate_c_per_sample': round(forecast['climb_rate'], 3),
                'estimated_samples_to_throttle': forecast['samples_to_throttle'],
                'gpu_arch': self.gpu_arch,
                'prediction_count': self.prediction_count,
                'agent': 'ThermalEventPredictor',
                'agent_version': '1.0',
                'note': 'Simulation-based. Requires real hardware validation.',
                'message': (
                    f"Thermal throttling predicted on GPU{self.gpu_id}. "
                    f"Current temp: {temp:.1f}C. "
                    f"Throttle limit: {self.throttle_limit}C. "
                    f"Climb rate: {forecast['climb_rate']:.3f}C/sample. "
                    f"Est. {forecast['samples_to_throttle']} samples to throttle. "
                    f"Confidence: {confidence*100:.1f}% — simulation only."
                ),
                'recommended_action': (
                    "Rebalance workload to adjacent GPU. "
                    "Increase cooling airflow if possible. "
                    "Monitor for clock speed reduction."
                )
            }

            print(f"[SWARM AGENT 3] THERMAL_THROTTLE_PREDICTED GPU{self.gpu_id} "
                  f"confidence={confidence*100:.1f}% "
                  f"temp={temp:.1f}C "
                  f"throttle_at={self.throttle_limit}C "
                  f"est={forecast['samples_to_throttle']} samples")

            return alert

        return None

    def _calculate_forecast(self, current_temp: float) -> tuple[float, dict]:
        recent_temps = list(self.temp_history)[-RAMP_WINDOW:]
        recent_utils = list(self.util_history)[-RAMP_WINDOW:]

        climb_rate = (recent_temps[-1] - recent_temps[0]) / len(recent_temps)

        temp_gap = self.throttle_limit - current_temp
        samples_to_throttle = int(temp_gap / climb_rate) if climb_rate > 0 else 999

        # Signal 1 — positive climb rate under load
        climb_score = 0.0
        if climb_rate > 0.3 and statistics.mean(recent_utils) > 50:
            climb_score = min(1.0, climb_rate / 0.8)
        elif climb_rate > 0.1:
            climb_score = 0.4

        # Signal 2 — proximity to warning threshold
        proximity_score = 0.0
        if current_temp >= self.warning_threshold:
            proximity_score = 1.0
        elif current_temp >= self.warning_threshold - 3:
            proximity_score = 0.7
        elif current_temp >= self.warning_threshold - 6:
            proximity_score = 0.4

        # Signal 3 — consistent upward trend
        consistency_score = 0.0
        if len(recent_temps) > 3:
            diffs = [recent_temps[i] - recent_temps[i-1]
                     for i in range(1, len(recent_temps))]
            positive = sum(1 for d in diffs if d > 0)
            consistency_score = positive / len(diffs)

        # Signal 4 — accelerating climb
        acceleration_score = 0.0
        if len(recent_temps) > 6:
            first_half = recent_temps[:len(recent_temps)//2]
            second_half = recent_temps[len(recent_temps)//2:]
            first_rate = (first_half[-1] - first_half[0]) / len(first_half)
            second_rate = (second_half[-1] - second_half[0]) / len(second_half)
            if second_rate > first_rate:
                acceleration_score = min(1.0, (second_rate - first_rate) / 0.5)

        confidence = (
            climb_score * 0.35 +
            proximity_score * 0.35 +
            consistency_score * 0.20 +
            acceleration_score * 0.10
        )

        forecast = {
            'climb_rate': climb_rate,
            'samples_to_throttle': samples_to_throttle,
            'proximity_score': proximity_score
        }

        return confidence, forecast

    def get_stats(self) -> dict:
        return {
            'agent': 'ThermalEventPredictor',
            'gpu_id': self.gpu_id,
            'gpu_arch': self.gpu_arch,
            'throttle_limit_c': self.throttle_limit,
            'warning_threshold_c': self.warning_threshold,
            'samples_processed': len(self.temp_history),
            'predictions_fired': self.prediction_count,
            'note': 'Simulation-based. Requires real hardware validation.'
        }


if __name__ == "__main__":
    import random

    print("=" * 55)
    print("Watchdog Swarm — Agent 3: Thermal Event Predictor")
    print("Simulation test — 100 samples")
    print("NOTE: Simulated data only. Not real hardware.")
    print("=" * 55)

    agent = ThermalEventPredictor(gpu_id=0, gpu_arch='H200')

    print(f"\nH200 throttle limit: {agent.throttle_limit}C")
    print(f"Warning threshold: {agent.warning_threshold}C")

    print("\n[Phase 1] Normal operating temp — 30 samples at 65C")
    for i in range(30):
        t = {
            'temp_c': 65 + random.uniform(-1, 1),
            'gpu_util': 85 + random.uniform(-5, 5),
            'power_watts': 350 + random.uniform(-10, 10),
            'sm_clock_mhz': 1800 + random.uniform(-50, 50),
            'timestamp': datetime.now(timezone.utc).isoformat()
        }
        agent.update(t)

    print("\n[Phase 2] Temperature climbing — 50 samples 65C to 86C")
    for i in range(50):
        climbing_temp = 65 + (i * 0.42) + random.uniform(-0.3, 0.3)
        t = {
            'temp_c': climbing_temp,
            'gpu_util': 90 + random.uniform(-3, 3),
            'power_watts': 380 + random.uniform(-10, 10),
            'sm_clock_mhz': 1800 + random.uniform(-50, 50),
            'timestamp': datetime.now(timezone.utc).isoformat()
        }
        result = agent.update(t)
        if result:
            print(f"\n*** PREDICTION FIRED ***")
            print(f"  Type: {result['type']}")
            print(f"  Confidence: {result['confidence_pct']}%")
            print(f"  Current temp: {result['current_temp_c']}C")
            print(f"  Gap to throttle: {result['temp_gap_c']}C")
            print(f"  Climb rate: {result['climb_rate_c_per_sample']}C/sample")
            print(f"  Est. samples to throttle: {result['estimated_samples_to_throttle']}")
            print(f"  Note: {result['note']}")

    print("\n" + "=" * 55)
    print("Agent 3 Stats:")
    stats = agent.get_stats()
    for k, v in stats.items():
        print(f"  {k}: {v}")
