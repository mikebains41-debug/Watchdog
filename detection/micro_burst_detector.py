#!/usr/bin/env python3
"""
micro_burst_detector.py -- Micro-Burst Compute Surge & Idle-Padding
Evasion Detector.
Part of Watchdog AI-Attack Detection Suite.

THREAT
------
Two related evasions of coarse utilization monitoring:

1. Micro-burst compute surges (IoC #15 in the agentic-attack briefing):
   short, intense processing spikes lasting milliseconds, timed to hide
   inside normal server noise. A per-second average utilization sampler
   sees ~normal load; the burst is invisible because it is diluted by
   surrounding idle time.

2. Idle-padding / dilution evasion of compute-monitoring, formalized in
   "Detecting Hidden ML Training With Zero-Overhead Telemetry"
   (arXiv:2606.19262, 2026): an adversary hides sustained training/mining
   by interleaving forced idle so any windowed average stays under a
   threshold, while the WORK still completes. The paper's point: at a
   fine enough sample rate the burst structure survives dilution and is
   detectable; the economics of padding become unviable at scale.

DETECTION APPROACH
------------------
Given a high-rate time series of utilization or power samples (each with
a timestamp), this looks for the burst signature that averaging destroys:
  - a high PEAK-to-MEAN ratio (short peaks far above the window average),
  - a bimodal duty cycle (samples cluster near "idle floor" and near
    "busy ceiling" rather than sitting at a middling average),
  - repetition: many such bursts across the window (periodic hiding),
which together distinguish deliberate burst-hide from one honest spike.

This is intentionally a STATISTICAL SHAPE test on samples the caller
provides. It makes no GPU calls and is fully deterministic/testable.

IMPORTANT HONESTY NOTE
----------------------
Per Watchdog's own achieved-sample-rate finding (3.7-7.1 Hz actual vs a
requested 100 Hz on RunPod/Vast.ai pods), sub-second micro-bursts are
LARGELY INVISIBLE at the current real sample rate. This detector's
sensitivity is bounded by the sampler feeding it. It reports the
effective sample interval it was given and will emit
MICRO_BURST_UNDERSAMPLED when the input rate is too coarse to make a
claim, rather than silently returning "clean." That undersampled result
is itself the honest finding, not a pass.

REMEDIATION (safe / auto vs. gated)
-----------------------------------
- MICRO_BURST_UNDERSAMPLED / MICRO_BURST_NONE: log only, auto-safe.
- MICRO_BURST_PATTERN (repeated bursts, dilution signature): this is a
  DETECTION-grade alert, not an auto-kill trigger. Killing a process on
  a burst-shape alone risks terminating a legitimate bursty inference
  server. Remediation is GATED: emit a recommended action to correlate
  the bursting PID against the process whitelist and raise for human
  review. No auto-kill from this signal alone.
"""

import statistics


def _duty_cycle_bimodality(samples: list, idle_ref: float, busy_ref: float) -> float:
    """Fraction of samples sitting near either extreme (idle or busy)
    rather than in the middle third. High value == bimodal == burst-hide
    shape. idle_ref/busy_ref bound the range of interest."""
    if busy_ref <= idle_ref:
        return 0.0
    span = busy_ref - idle_ref
    low_edge = idle_ref + span / 3.0
    high_edge = idle_ref + 2.0 * span / 3.0
    extreme = sum(1 for s in samples if s <= low_edge or s >= high_edge)
    return extreme / len(samples)


def detect_micro_bursts(timestamps: list,
                         samples: list,
                         idle_floor: float,
                         peak_to_mean_min: float = 3.0,
                         bimodality_min: float = 0.85,
                         min_bursts: int = 3,
                         min_effective_hz: float = 20.0) -> dict:
    """
    timestamps: monotonically increasing sample times (seconds, float).
    samples:    utilization % or power (W) aligned with timestamps.
    idle_floor: the documented idle value for this GPU (e.g. B200 idle
                power floor ~194W, or 0% util). Bursts are measured above
                this.

    A burst = a run of consecutive samples above the mid threshold,
    bracketed by samples at/below it.
    """
    n = len(samples)
    if n < 4 or len(timestamps) != n:
        return {"status": "SKIPPED",
                "message": "need >= 4 aligned (timestamp, sample) points"}

    duration = timestamps[-1] - timestamps[0]
    effective_hz = (n - 1) / duration if duration > 0 else 0.0

    # Guard: if the sampler is too coarse, do NOT claim clean. Say so.
    if effective_hz < min_effective_hz:
        return {
            "status": "MICRO_BURST_UNDERSAMPLED",
            "effective_hz": round(effective_hz, 2),
            "required_hz": min_effective_hz,
            "note": ("sample rate too coarse to resolve millisecond bursts; "
                     "this is a measurement limitation, not an all-clear"),
        }

    mean = statistics.fmean(samples)
    peak = max(samples)
    busy_ref = peak
    mean_above_floor = max(mean - idle_floor, 1e-9)
    peak_to_mean = (peak - idle_floor) / mean_above_floor

    bimodality = _duty_cycle_bimodality(samples, idle_floor, busy_ref)

    # Count discrete bursts (runs above the midpoint between floor and peak).
    mid = idle_floor + (peak - idle_floor) / 2.0
    burst_count = 0
    in_burst = False
    for s in samples:
        if s >= mid and not in_burst:
            in_burst = True
            burst_count += 1
        elif s < mid:
            in_burst = False

    result = {
        "effective_hz": round(effective_hz, 2),
        "mean": round(mean, 3),
        "peak": round(peak, 3),
        "idle_floor": idle_floor,
        "peak_to_mean_ratio": round(peak_to_mean, 3),
        "bimodality": round(bimodality, 3),
        "burst_count": burst_count,
    }

    is_burst_hide = (peak_to_mean >= peak_to_mean_min
                     and bimodality >= bimodality_min
                     and burst_count >= min_bursts)

    if is_burst_hide:
        result["status"] = "MICRO_BURST_PATTERN"
        result["recommended_action"] = {
            "action": "correlate_pid_with_whitelist_and_raise",
            "detail": ("repeated diluted bursts consistent with micro-burst "
                       "hiding / idle-padding; correlate offending PID against "
                       "process whitelist, raise for human review"),
            "risk": "do_not_auto_kill",
        }
        result["note"] = "gated: burst shape is suggestive, not proof; human review"
    else:
        result["status"] = "MICRO_BURST_NONE"
        result["note"] = "no repeated burst-hide signature at this sample rate"

    return result


if __name__ == "__main__":
    # Synthetic burst-hide: idle 0, spikes to 100, repeated, high rate.
    ts, sm = [], []
    t = 0.0
    for cycle in range(6):
        for _ in range(2):   # short burst
            ts.append(t); sm.append(100.0); t += 0.01
        for _ in range(8):   # long idle pad
            ts.append(t); sm.append(0.0); t += 0.01
    r = detect_micro_bursts(ts, sm, idle_floor=0.0)
    print(f"[MICRO-BURST] {r['status']} "
          f"(bursts={r.get('burst_count')}, hz={r.get('effective_hz')})")
