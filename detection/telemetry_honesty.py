"""
detection/telemetry_honesty.py

Three checks for whether NVML's own reported fields can be trusted, in
the same spirit as the ghost-power and VRAM-residual findings this
project is built around: NVML gives one aggregate number, and the real
state underneath doesn't always match it.

NONE of these three have been run against real hardware. All three
require fields not currently collected by agent/telemetry.py's
QUERY_FIELDS (pstate is collected; PCIe and NVLink fields are not).
They are built here as detector logic ready to receive that data once
it's wired in and a real GPU is available -- not as a claim that the
phenomena have been observed.
"""
from detection._shared import _EventState, _f


class PStateHonestyDetector:
    """
    Checks whether NVML's reported p-state (e.g. P0, P8) is consistent
    with actual measured power draw. P8 is a low-power idle state; if a
    GPU reports P8 while drawing power consistent with P0 (full
    performance), that's a third instance of the same "telemetry lies"
    pattern as ghost power and VRAM residual -- directly relevant to
    anyone doing power-capping or demand-response in a data center.

    STILL UNRESOLVED, stated rather than hidden:
      The power threshold distinguishing "P8-consistent" from
      "P0-consistent" draw is architecture-specific and has not been
      measured on any real GPU in this project. The placeholder below
      (P8_MAX_EXPECTED_W) is a guess, not a validated constant.
    """
    P8_MAX_EXPECTED_W = 30.0

    def __init__(self, require_consecutive=5, refire_after_s=120):
        self.state = _EventState(require_consecutive=require_consecutive,
                                  refire_after_s=refire_after_s)

    def update(self, row):
        pstate = row.get('pstate')
        power = _f(row, 'power.draw')
        if pstate is None or power is None:
            return None

        condition = (pstate == 'P8' and power > self.P8_MAX_EXPECTED_W)
        if not self.state.should_emit(condition):
            return None

        return {
            'type': 'PSTATE_POWER_MISMATCH',
            'severity': 'INFO',
            'gpu': row.get('index'),
            'reported_pstate': pstate,
            'power_w': power,
            'p8_max_expected_w': self.P8_MAX_EXPECTED_W,
            'timestamp': row.get('iso_timestamp'),
            'message': (f"NVML reports {pstate} (low-power idle) but power "
                        f"draw is {power:.1f}W -- above the expected P8 "
                        f"ceiling of {self.P8_MAX_EXPECTED_W:.0f}W "
                        f"(unvalidated threshold). Possible NVML "
                        f"power-state misreport, not yet observed on "
                        f"real hardware."),
        }


class PCIeBandwidthMismatchDetector:
    """
    Checks whether reported PCIe bandwidth utilization is consistent with
    reported compute utilization. A GPU showing near-zero compute but
    high PCIe throughput may indicate bulk data movement (legitimate
    checkpoint I/O, or bulk exfiltration -- same discrimination gap as
    DMAAttackDetector/SequentialVRAMReadDetector) invisible to compute-
    utilization-only monitoring.

    Requires PCIe fields (pcie.link.gen.current, throughput readings)
    that agent/telemetry.py's QUERY_FIELDS does NOT currently collect --
    this detector cannot be wired into the live pipeline until that is
    added. scripts/check_pcie_telemetry.py exists to determine whether a
    given rented instance even exposes these fields; it has not been run.
    """
    def __init__(self, bandwidth_threshold_pct=50.0, util_gpu_ceiling=10.0,
                 require_consecutive=5, refire_after_s=120):
        self.bandwidth_threshold_pct = bandwidth_threshold_pct
        self.util_gpu_ceiling = util_gpu_ceiling
        self.state = _EventState(require_consecutive=require_consecutive,
                                  refire_after_s=refire_after_s)

    def update(self, row):
        pcie_util_pct = _f(row, 'pcie.bandwidth.util_pct')
        util_gpu = _f(row, 'utilization.gpu')
        if pcie_util_pct is None or util_gpu is None:
            return None

        condition = (pcie_util_pct > self.bandwidth_threshold_pct
                     and util_gpu < self.util_gpu_ceiling)
        if not self.state.should_emit(condition):
            return None

        return {
            'type': 'PCIE_BANDWIDTH_MISMATCH',
            'severity': 'INFO',
            'gpu': row.get('index'),
            'pcie_bandwidth_util_pct': pcie_util_pct,
            'gpu_util_pct': util_gpu,
            'timestamp': row.get('iso_timestamp'),
            'message': (f"PCIe bandwidth at {pcie_util_pct:.0f}% while GPU "
                        f"compute is {util_gpu:.0f}% -- bulk data transfer "
                        f"pattern invisible to compute-only monitoring. "
                        f"Cannot distinguish legitimate checkpoint I/O from "
                        f"exfiltration from this signal alone."),
        }
