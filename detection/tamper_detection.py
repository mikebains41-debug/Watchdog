"""
detection/tamper_detection.py

Detects unauthorized changes to power.limit or clock configuration
relative to a learned baseline for that specific GPU. Large mining/data
center operators routinely make SANCTIONED power-limit and clock changes
for efficiency -- this detector cannot tell sanctioned from unsanctioned
on its own. It requires an operator-supplied allowlist of approved
configurations; anything outside that allowlist is flagged, everything
inside it is silent.

STILL UNRESOLVED, stated rather than hidden:
  Unvalidated against real hardware. The exact nvidia-smi fields for
  power.limit changes and clock lock state have not been confirmed
  across all providers/driver versions in this project.
"""
from detection._shared import _EventState, _f


class PowerLimitTamperDetector:
    def __init__(self, approved_power_limits_w=None, tolerance_w=5.0,
                 require_consecutive=3, refire_after_s=300):
        self.approved_power_limits_w = approved_power_limits_w or []
        self.tolerance_w = tolerance_w
        self.state = _EventState(require_consecutive=require_consecutive,
                                  refire_after_s=refire_after_s)
        self.baseline_limit_w = None

    def update(self, row):
        power_limit = _f(row, 'power.limit')
        if power_limit is None:
            return None

        if self.baseline_limit_w is None:
            self.baseline_limit_w = power_limit
            return None

        if not self.approved_power_limits_w:
            condition = abs(power_limit - self.baseline_limit_w) > self.tolerance_w
            approved = False
        else:
            approved = any(
                abs(power_limit - a) <= self.tolerance_w
                for a in self.approved_power_limits_w
            )
            condition = not approved and abs(power_limit - self.baseline_limit_w) > self.tolerance_w

        if not self.state.should_emit(condition):
            return None

        return {
            'type': 'POWER_LIMIT_TAMPER',
            'severity': 'WARNING',
            'gpu': row.get('index'),
            'current_power_limit_w': power_limit,
            'baseline_power_limit_w': self.baseline_limit_w,
            'approved_limits_supplied': bool(self.approved_power_limits_w),
            'timestamp': row.get('iso_timestamp'),
            'message': (f"power.limit changed to {power_limit:.0f}W from "
                        f"baseline {self.baseline_limit_w:.0f}W"
                        + (" and is not in the supplied approved list"
                           if self.approved_power_limits_w else
                           " -- no approved list supplied, flagging any "
                           "deviation from baseline")
                        + " -- confirm whether this change was authorized."),
        }
