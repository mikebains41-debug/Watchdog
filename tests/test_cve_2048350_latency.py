# Author: Manmohan (Mike) Bains -- Watchdog
"""
Watchdog v2.0 - CVE-2048350 Detection Latency

FIXED vs. original:
  - The original "scavenger" allocated a NEW tensor in the SAME process
    after deleting the "victim" tensor, then checked whether old values
    were still present. That tests whether PyTorch's own caching
    allocator reuses freed blocks without zeroing them -- normal,
    expected behavior for any allocator, completely unrelated to the
    real vulnerability (a DIFFERENT process reading memory after the
    ORIGINAL process has fully exited). Printing "CVE-2048350 CONFIRMED"
    for that would have been a false claim about an unrelated, benign
    phenomenon.
  - evaluate_detector_latency() never queried VRAMResidualDetector at
    all. It slept in a loop and picked a RANDOM iteration count
    (random.randint(3,8)) to declare as "when the detector fired", then
    reported that random delay as a benchmark result. Every run reported
    success regardless of any real detection happening.
  - This conflated two genuinely different claims: (1) does physical
    VRAM retain stale bytes after a process exits -- a hardware fact,
    needs a real GPU to test; and (2) how fast does the DETECTOR react
    once it's given telemetry matching that pattern -- pure software
    logic, needs no GPU at all. This file now tests only (2), honestly,
    and does not claim anything about (1).

Detection latency is measured in SAMPLES: how many telemetry rows after
a PID disappears from compute_apps (while memory.used doesn't drop to
match) before VRAMResidualDetector actually fires. With the default
grace_samples=2, that's exactly 2 samples after exit, confirmed by
reading the real source in detection/engines.py -- not assumed.
Converting samples to seconds depends entirely on your real telemetry
sample rate, which this file does not claim to know; it reports both,
clearly labeled.

Run: python3 tests/test_cve_2048350_latency.py
"""
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from detection.engines import VRAMResidualDetector, VRAMResidualUnavailable

PASSED = []
FAILED = []


def check(name, condition, detail=""):
    if condition:
        PASSED.append(name)
        print(f"[PASS] {name}")
    else:
        FAILED.append(name)
        print(f"[FAIL] {name} {detail}")


def measure_latency(retention_mb=500, threshold_mb=100, grace_samples=2,
                     max_samples=10):
    """Feeds VRAMResidualDetector the real documented CVE-2048350
    pattern: a PID present and holding memory, then that PID
    disappearing from compute_apps while memory.used doesn't drop to
    match. Returns (fired, samples_after_exit_to_fire) -- both real,
    not fabricated."""
    d = VRAMResidualDetector(residual_threshold_mb=threshold_mb,
                              grace_samples=grace_samples, strict=True)
    d.update({
        'index': 0, 'iso_timestamp': '2026-01-01T00:00:00Z',
        'memory.used': retention_mb,
        'compute_apps': [{'pid': 4242, 'used_memory': retention_mb}],
    })
    row_after_exit = {
        'index': 0, 'iso_timestamp': '2026-01-01T00:00:01Z',
        'memory.used': retention_mb,
        'compute_apps': [],
    }
    for i in range(1, max_samples + 1):
        alert = d.update(row_after_exit)
        if alert:
            return True, i, alert
    return False, None, None


def test_fires_on_the_real_documented_pattern():
    fired, samples, alert = measure_latency()
    check("fires on the real pattern: PID exits, memory doesn't drop",
          fired and alert["type"] == "VRAM_RESIDUAL", f"got fired={fired}, alert={alert}")


def test_fires_at_exactly_grace_samples_not_before_not_after():
    """The exact number that matters: confirmed by reading the real
    source, not assumed. Must fire at exactly grace_samples, given the
    default grace_samples=2."""
    fired, samples, alert = measure_latency(grace_samples=2)
    check("fires at exactly grace_samples=2 telemetry rows after exit, "
          "confirmed against the real detector logic",
          fired and samples == 2, f"got fired={fired}, samples={samples}")


def test_higher_grace_samples_delays_firing_proportionally():
    fired5, samples5, _ = measure_latency(grace_samples=5)
    check("grace_samples=5 takes correspondingly longer to fire",
          fired5 and samples5 == 5, f"got fired={fired5}, samples={samples5}")


def test_silent_on_clean_exit_memory_actually_freed():
    """A PID exits and memory.used correctly drops with it -- nothing
    left unclaimed. Must not fire."""
    d = VRAMResidualDetector(residual_threshold_mb=100, grace_samples=2, strict=True)
    d.update({
        'index': 0, 'iso_timestamp': '2026-01-01T00:00:00Z',
        'memory.used': 5000,
        'compute_apps': [{'pid': 4242, 'used_memory': 5000}],
    })
    fired = False
    for i in range(5):
        alert = d.update({
            'index': 0, 'iso_timestamp': f'2026-01-01T00:00:0{i+1}Z',
            'memory.used': 50,  # dropped with the process -- clean exit
            'compute_apps': [],
        })
        if alert:
            fired = True
    check("stays silent on a genuinely clean exit (memory actually freed)",
          not fired)


def test_silent_when_unclaimed_amount_is_below_threshold():
    d = VRAMResidualDetector(residual_threshold_mb=1000, grace_samples=2, strict=True)
    d.update({
        'index': 0, 'iso_timestamp': '2026-01-01T00:00:00Z',
        'memory.used': 500,
        'compute_apps': [{'pid': 4242, 'used_memory': 500}],
    })
    fired = False
    for i in range(5):
        alert = d.update({
            'index': 0, 'iso_timestamp': f'2026-01-01T00:00:0{i+1}Z',
            'memory.used': 500,  # only 500MB unclaimed, threshold is 1000MB
            'compute_apps': [],
        })
        if alert:
            fired = True
    check("stays silent when unclaimed memory is below the configured "
          "threshold, even though a PID did exit", not fired)


def test_strict_mode_raises_without_compute_apps():
    d = VRAMResidualDetector(strict=True)
    try:
        d.update({'index': 0, 'memory.used': 500, 'iso_timestamp': 't'})
        check("strict=True raises when compute_apps is absent", False, "did not raise")
    except VRAMResidualUnavailable:
        check("strict=True raises when compute_apps is absent", True)


if __name__ == '__main__':
    tests = [v for k, v in sorted(globals().items()) if k.startswith('test_')]
    for t in tests:
        try:
            t()
        except Exception as e:
            check(t.__name__, False, f"EXCEPTION {e!r}")

    print("\n" + "=" * 60)
    print(f"PASSED: {len(PASSED)}   FAILED: {len(FAILED)}")
    if FAILED:
        print("\nFailures:")
        for f in FAILED:
            print(f"  - {f}")
    print("=" * 60)

    print("\n" + "=" * 60)
    print("LATENCY SUMMARY (samples after PID exit until detector fires)")
    print("=" * 60)
    for gs in (1, 2, 5, 10):
        fired, samples, _ = measure_latency(grace_samples=gs)
        print(f"  grace_samples={gs:<3} -> fires after {samples} samples"
              if fired else f"  grace_samples={gs:<3} -> did not fire")
    print("\nTo convert to real seconds: samples / your_actual_sample_hz.")
    print("This file does not assume a sample rate -- see agent/telemetry.py's")
    print("SAMPLE_HZ for the configured default, and")
    print("tests/test_telemetry_sampler_wiring.py for the REAL measured rate,")
    print("which differs from the requested rate.")

    sys.exit(1 if FAILED else 0)
