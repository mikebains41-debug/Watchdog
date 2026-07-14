# stability_test.py / false_positive_benchmark.py / latency_test.py

**Author:** Manmohan (Mike) Bains
**Status:** Real code, syntax-verified, NOT yet run -- all three
require nvidia-smi and a real GPU. Confirmed absent on this device
(Termux/Android, no GPU hardware).

## stability_test.py

Runs the full DetectionPipeline continuously for a set duration
(default 72 hours) at a set sample rate (default 100Hz), tracking
memory usage over time and logging any crashes. Purpose: prove
Watchdog does not leak memory or crash during extended real-world
operation. Success = zero errors, memory variance under 10MB,
fewer than 10 alerts on a workload with no real attacks present.

Run: python3 tests/stability_test.py --duration 72

## false_positive_benchmark.py

Runs the full DetectionPipeline against a real, known-clean
production inference workload for a set duration (default 24 hours),
counting how many alerts fire. Purpose: measure the false positive
rate on real hardware doing real, legitimate work -- a high FPR here
would mean the detectors are too noisy for production use. Success =
false positive rate under 1%.

Run: python3 tests/false_positive_benchmark.py --duration 24

## latency_test.py

Repeatedly establishes a clean baseline, then injects a synthetic
ghost-power pattern (matching the exact pattern already verified in
this repo's positive control tests) and measures how long the
DetectionPipeline takes to fire an alert. Purpose: prove detection
happens fast enough to be useful in production, not just eventually.
Success = average detection latency under 100ms, over 90% detection
rate across iterations.

Run: python3 tests/latency_test.py --iterations 100

## Honest Status For All Three

None of these three have been executed. They require a real GPU
rental (RunPod, Verda, etc.) with nvidia-smi installed. Running them
on this device will fail immediately when TelemetryCollector tries
to call nvidia-smi, which does not exist here.
