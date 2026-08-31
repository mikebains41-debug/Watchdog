"""
detection/neutral_current_harmonic.py

NeutralCurrentHarmonicDetector

Detects unsafe neutral conductor loading in 480V three-phase four-wire
data center electrical systems. Non-linear loads (server power supplies
drawing current in short pulses) cause third-harmonic currents to ADD in
the neutral instead of cancelling -- a balanced-looking three-phase
system can still have a neutral carrying as much or more current than any
single phase, overheating a conductor sized for the old balanced-linear
assumption.

DATA SOURCE is PDU/panel-level, NOT GPU telemetry. NVML/nvidia-smi have
nothing to do with facility electrical distribution. Modern rack PDUs
(APC, Vertiv, ServerTech, Sunbird) expose phase and neutral current via
SNMP or Modbus. No physical presence required once a data source is
wired in.

STATUS: BUILT, NOT TESTED AGAINST REAL HARDWARE. No real PDU has been
queried. Thresholds come from published electrical design guidance (the
173% neutral ampacity sizing rule for non-linear loads), not from
Watchdog's own measurement. Unit tests prove the detector LOGIC against
synthetic samples; they do not validate the thresholds against a real
facility.
"""

import time
from dataclasses import dataclass
from typing import List, Optional, Protocol


@dataclass
class ElectricalSample:
    timestamp: float
    phase_a_current: float
    phase_b_current: float
    phase_c_current: float
    neutral_current: float
    third_harmonic_pct: Optional[float] = None
    conductor_temp_c: Optional[float] = None


class PDUDataSource(Protocol):
    """Implement against a real PDU's SNMP/Modbus API. Vendor-specific."""
    def read_sample(self) -> ElectricalSample: ...


@dataclass
class Alert:
    timestamp: float
    severity: str
    detector: str
    message: str
    neutral_pct_of_phase: float
    third_harmonic_pct: Optional[float]
    raw_sample: ElectricalSample


class NeutralCurrentHarmonicDetector:
    """Flags neutral current approaching or exceeding the highest phase
    current, and/or a third-harmonic component high enough to explain it.

    HONEST LIMITS:
      - Thresholds are from published electrical design guidance, not
        Watchdog measurement. Tune to the specific conductor ampacity and
        panel design once real PDU data exists.
      - A single reading is a snapshot. Sustained overload matters more
        than one spike; require_consecutive debounces transients.
      - Reports an electrical condition. Does NOT remediate -- neutral
        overloading is fixed by an electrician (upsized neutral, harmonic
        filter, load rebalancing), not by software.
      - Reads whatever the PDU reports; does not verify sensor calibration.
    """

    WARNING_THRESHOLD_PCT = 80.0
    CRITICAL_THRESHOLD_PCT = 100.0
    HARMONIC_CRITICAL_PCT = 33.0

    def __init__(self, source: PDUDataSource, require_consecutive: int = 3):
        self.source = source
        self.require_consecutive = require_consecutive
        self.history: List[ElectricalSample] = []
        self._consecutive = 0

    def check(self) -> Optional[Alert]:
        sample = self.source.read_sample()
        self.history.append(sample)
        self.history = self.history[-100:]

        max_phase = max(sample.phase_a_current,
                        sample.phase_b_current,
                        sample.phase_c_current)
        if max_phase <= 0:
            self._consecutive = 0
            return None

        neutral_pct = (sample.neutral_current / max_phase) * 100.0
        severity = None
        reasons = []

        if neutral_pct >= self.CRITICAL_THRESHOLD_PCT:
            severity = "CRITICAL"
            reasons.append(
                f"neutral current {neutral_pct:.1f}% of highest phase "
                f"(>= {self.CRITICAL_THRESHOLD_PCT}%)")
        elif neutral_pct >= self.WARNING_THRESHOLD_PCT:
            severity = "WARNING"
            reasons.append(
                f"neutral current {neutral_pct:.1f}% of highest phase "
                f"(>= {self.WARNING_THRESHOLD_PCT}%)")

        if (sample.third_harmonic_pct is not None
                and sample.third_harmonic_pct >= self.HARMONIC_CRITICAL_PCT):
            severity = "CRITICAL"
            reasons.append(
                f"third-harmonic component {sample.third_harmonic_pct:.1f}% "
                f"of fundamental")

        if severity is None:
            self._consecutive = 0
            return None

        self._consecutive += 1
        if self._consecutive < self.require_consecutive:
            return None

        return Alert(
            timestamp=sample.timestamp,
            severity=severity,
            detector="NeutralCurrentHarmonicDetector",
            message=("; ".join(reasons)
                     + ". Data-center 3-phase 4-wire neutral overloading "
                       "from non-linear (switching PSU) loads: third "
                       "harmonics sum in the neutral rather than "
                       "cancelling. Remediation is electrical (upsized "
                       "neutral, harmonic filter, load rebalancing), not "
                       "software."),
            neutral_pct_of_phase=neutral_pct,
            third_harmonic_pct=sample.third_harmonic_pct,
            raw_sample=sample,
        )


class NullPDUSource:
    """Placeholder for local dev -- clean balanced sample, never fires.
    Replace with a real SNMP/Modbus client before this means anything."""
    def read_sample(self) -> ElectricalSample:
        return ElectricalSample(
            timestamp=time.time(),
            phase_a_current=100.0, phase_b_current=100.0,
            phase_c_current=100.0, neutral_current=5.0,
            third_harmonic_pct=2.0, conductor_temp_c=30.0,
        )


if __name__ == "__main__":
    detector = NeutralCurrentHarmonicDetector(NullPDUSource())
    alert = detector.check()
    print(alert if alert else
          "No alert -- sample within safe range "
          "(NullPDUSource, not real data)")
