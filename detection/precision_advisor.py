# Author: Manmohan (Mike) Bains -- Watchdog
"""
Watchdog v2.0 - Adaptive Precision Recommendation Engine
Monitors real-time GPU telemetry and recommends precision switches
(FP32 -> FP16 -> BF16 -> FP8) based on energy state and thermal state.

Integration point: output feeds directly into external precision
controllers (e.g. Cadence) via the alert pipeline.

Alert type: PRECISION_SWITCH_RECOMMENDED

NOTE: CEI degradation trigger is not yet wired — cei_baseline is
stored for future use. Power reduction estimates are derived from
Serial Alice FP8 ladder cert sa-e6628d and are marked as estimated,
not independently measured by this codebase.
"""
import time
from collections import deque
from datetime import datetime, timezone

CEI_BASELINES = {
    "H200": 3.178e11,  # Serial Alice M4 cert sa-885826
    "H100": 15.2e9,    # validated — no Serial Alice cert yet
    "A100": 5.68e9,    # validated — no Serial Alice cert yet
    "B200": 450.0e9,   # estimated — no Serial Alice cert yet
    "B300": 900.0e9,   # estimated — not yet validated
}

PRECISION_LADDER = ["FP32", "FP16", "BF16", "FP8"]

# Power reduction estimates derived from Serial Alice FP8 ladder
# cert sa-e6628d (Nelson Vicente / Sirius GreenTech, 2026-06-27)
# These are ESTIMATED from a single H200 run — not independently
# verified by this codebase. Mark as estimated until confirmed.
POWER_REDUCTION_ESTIMATED = {
    "FP32->FP16": 0.15,   # 620.9W -> 525.2W = 15.4% (sa-e6628d)
    "FP16->BF16": 0.02,   # 525.2W -> 517.3W = 1.5%  (sa-e6628d)
    "BF16->FP8":  0.22,   # 517.3W -> 400.9W = 22.5% (sa-e6628d)
}

class PrecisionAdvisor:
    def __init__(self, ghost_margin_w=8.0, thermal_warning_c=80.0, window=30, cooldown_s=60):
        self.ghost_margin_w = ghost_margin_w
        self.thermal_warning_c = thermal_warning_c
        self.window = window
        self.cooldown_s = cooldown_s
        self.history = deque(maxlen=window)
        self.idle_baseline_w = None
        self.current_precision = "FP32"
        self.last_alert = None
        self.cei_baseline = None

    def _next_precision(self):
        idx = PRECISION_LADDER.index(self.current_precision)
        if idx < len(PRECISION_LADDER) - 1:
            return PRECISION_LADDER[idx + 1]
        return None

    def _power_reduction_pct(self, from_p, to_p):
        return POWER_REDUCTION_ESTIMATED.get(f"{from_p}->{to_p}", 0.10)

    def set_idle_baseline(self, idle_w):
        self.idle_baseline_w = idle_w

    def set_cei_baseline(self, cei):
        self.cei_baseline = cei

    def update_cei(self, cei_value):
        """Feed current CEI measurement for degradation detection."""
        self._recent_cei = cei_value

    def set_current_precision(self, precision):
        if precision in PRECISION_LADDER:
            self.current_precision = precision

    def update(self, row):
        power = float(row.get('power.draw', 0))
        util = float(row.get('utilization.gpu', 0))
        temp = float(row.get('temperature.gpu', 0))
        gpu_name = row.get('name', '')
        ts = row.get('iso_timestamp', datetime.now(timezone.utc).isoformat())

        if self.idle_baseline_w is None:
            if util == 0:
                self.idle_baseline_w = power
            return None

        if self.cei_baseline is None:
            for arch, val in CEI_BASELINES.items():
                if arch in gpu_name.upper():
                    self.cei_baseline = val
                    break

        self.history.append({'power': power, 'util': util, 'temp': temp, 'ts': ts})

        if len(self.history) < 5:
            return None

        now = time.time()
        if self.last_alert and now - self.last_alert < self.cooldown_s:
            return None

        next_p = self._next_precision()
        if next_p is None:
            return None

        ghost_threshold = (self.idle_baseline_w or 80.0) + self.ghost_margin_w
        recent = list(self.history)[-10:]
        avg_power = sum(x['power'] for x in recent) / len(recent)
        avg_util = sum(x['util'] for x in recent) / len(recent)
        avg_temp = sum(x['temp'] for x in recent) / len(recent)

        reason = None
        detail = {}

        # CEI degradation check
        cei_reason, cei_detail = self._check_cei_degradation(recent, None)
        if cei_reason and not reason:
            reason = cei_reason
            detail = cei_detail

        if avg_util < 5 and avg_power > ghost_threshold:
            reason = "GHOST_POWER_DETECTED"
            detail = {'avg_power_w': round(avg_power, 2), 'avg_util_pct': round(avg_util, 2), 'ghost_threshold_w': ghost_threshold}
        elif avg_temp >= self.thermal_warning_c:
            reason = "THERMAL_WARNING"
            detail = {'avg_temp_c': round(avg_temp, 2)}
        elif avg_util > 50 and avg_power > 500:
            reason = "HIGH_POWER_UNDER_LOAD"
            detail = {'avg_power_w': round(avg_power, 2), 'avg_util_pct': round(avg_util, 2)}

        if reason:
            self.last_alert = now
            reduction_pct = self._power_reduction_pct(self.current_precision, next_p)
            return {
                'type': 'PRECISION_SWITCH_RECOMMENDED',
                'severity': 'WARNING',
                'gpu': row.get('index', 0),
                'timestamp': ts,
                'current_precision': self.current_precision,
                'recommended_precision': next_p,
                'reason': reason,
                'expected_power_reduction_pct_estimated': round(reduction_pct * 100, 1),
                'expected_power_after_w': round(avg_power * (1 - reduction_pct), 2),
                'message': f"Switch {self.current_precision} -> {next_p}: {reason} — expected {reduction_pct*100:.0f}% power reduction",
                **detail
            }
        return None
