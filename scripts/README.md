# scripts/

## run_negative_control.py

Runs the real DetectionPipeline against LIVE nvidia-smi output on real GPU
hardware for a set duration, expecting zero alerts on a genuinely idle
GPU. This is the actual proof that the detectors don't cry wolf -- but it
requires renting a real GPU and has not been run yet by anyone.

Usage:
Requires nvidia-smi on PATH and a GPU that is genuinely idle for the
entire run -- any other workload on it invalidates the result.

### Three layers of confidence -- do not conflate them

**Layer 1 -- detector logic.** `tests/test_engines.py` and friends prove
the detection code is correct against synthetic data. Real, but says
nothing about real hardware noise.

**Layer 2 -- harness wiring.** `tests/test_run_negative_control_harness.py`
proves THIS script's argument parsing, sample loop, and output format work
correctly, using a mocked nvidia-smi. Real, but the mock always returns
clean data -- it cannot catch real hardware behaving unexpectedly. This
layer exists so a bug in the script itself doesn't waste paid GPU rental
time. It found one already: an early test draft passed `--seconds 0.2` and
was rejected by argparse, because `--seconds` is an int, not a float --
caught here, for free, instead of on a rented pod.

**Layer 3 -- actual hardware.** Not done. Nothing in this repository
proves the detectors behave correctly on a real GPU until this script is
actually run on one and the output reviewed. Layers 1 and 2 make it very
likely the script will run cleanly when that happens. Neither one is a
substitute for it.

### If nvidia-smi isn't found

The script will crash with a raw `FileNotFoundError` traceback rather than
silently continuing with fake data. That's intentional -- check
`which nvidia-smi` first rather than expecting a friendly error message.

### Known gap

`compute_apps` (required by `VRAMResidualDetector`) is not queried by this
harness. It runs with `vram_strict=False`, so that detector is constructed
but does not evaluate. Wiring in
`nvidia-smi --query-compute-apps=pid,used_memory` is separate follow-up
work, not done here.
