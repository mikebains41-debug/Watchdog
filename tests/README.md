# Tests

Run everything:
Expected output ends with `TOTAL: 733 passed, 0 failed across 34 files`.

Or run any file alone: `python3 tests/test_engines.py`. Every file is
independently runnable and prints its own PASSED/FAILED breakdown.

---

## What's actually tested vs. what isn't

**Automated below (709 tests, run on every commit, all synthetic data):**
the 32 files in this directory.

**Not automated, not run by `run_all.py`, not executed by anyone yet:**
`scripts/run_negative_control.py`. It needs a live idle GPU for up to an
hour and a human to confirm nothing else was running on it. Including it
in an automated suite would misrepresent it as something that passes on
every commit -- it doesn't run at all until someone executes it manually
on real hardware. See that script's own docstring for usage.

None of the 709 tests below have touched real GPU hardware. They test logic
correctness against synthetic data and mocked filesystem states. That is
a meaningfully weaker claim than "validated on hardware," and is stated as
such deliberately -- see the main README's Limitations section.

---

## test_engines.py -- 17 tests

Tests the 4 detectors in `detection/engines.py`: `GhostPowerDetector`,
`VRAMResidualDetector`, `PowerPeriodicityDetector`, `MultiGPUCorrelation`.

Every detector has a **positive control** (a synthetic pattern it must
fire on) paired with a **negative control** (a state documented as
architecturally normal -- idle floor, cooldown tail, a resident model with
a live process, a coordinated multi-GPU burst -- which it must stay silent
on). The negative controls are the ones that matter: a detector that fires
on everything passes every positive control trivially and is worthless.

The one to know by name: `PIPELINE NEGATIVE CONTROL` feeds 3600
consecutive clean idle samples through the whole pipeline and asserts zero
alerts. That's the headline number for "this doesn't cry wolf."

## test_throughput_contention.py -- 8 tests

Tests `detection/throughput_contention_detector.py`. The positive control
uses the actual documented event (372.32 -> 336.96 iter/sec, -9.5%), not a
made-up number. Negative controls cover: normal jitter, calling `update()`
before calibration (must do nothing, not guess), and a poisoned
calibration sample (one contended reading mixed into 9 clean ones must not
collapse the baseline -- this is checked with a median, not a mean).

## test_sampler.py -- 7 tests

Tests `telemetry/sampler.py`, which measures the *actual* wall-clock gap
between samples instead of assuming the requested rate was achieved. Tests
use an injected fake clock (no real sleeping), so they're deterministic
and fast. One test reconstructs the ~2Hz-actual-vs-faster-requested
pattern that Serial Alice Test 4 forensics found, to confirm the module
would have caught it.

## test_cei_report.py -- 8 tests

Tests `telemetry/cei_report.py`. The core behavior: `CEIDistribution`
*refuses* to be constructed from a single value -- given the documented
~20% coefficient of variation across 30 runs, a single CEI number is not
a fact, and the code makes it structurally impossible to accidentally
report one as if it were. Also tests that the median resists a single
outlier, and that `precision_ratio()` rejects a zero-median input instead
of returning inf/nan.

## test_verify_ebpf_quarantine_core.py -- 12 tests

Tests `detection/verify_ebpf_quarantine_core.py`, the preflight checker
that runs before `EBPFQuarantine` activation. Uses mocked filesystem
states (`/proc/mounts` contents, `os.access` results, kernel version
strings) so every branch is deterministic regardless of what machine runs
the tests. The test worth reading is
`test_cgroup2_fails_when_mounted_rw_but_no_process_access` -- it's a
regression test proving the fixed code correctly fails a scenario the
original version would have silently passed (host mount is rw, but this
process doesn't actually have write permission).

---

## Adding a new test file

1. Write `tests/test_yourthing.py` following the existing pattern: a
   `check(name, condition, detail)` helper, `PASSED`/`FAILED` lists, and a
   `PASSED: N   FAILED: N` summary line at the end (copy any existing file
   as a template -- `run_all.py` parses that exact line format).
2. Add the filename to `TEST_FILES` in `run_all.py`. It's an explicit
   list, not a glob, on purpose: a new test file with real GPU
   requirements or long runtimes shouldn't silently join the automated
   suite without a decision to put it there.
3. Add a section to this file describing what it tests and what its
   positive/negative controls are.

## test_run_negative_control_harness.py -- 9 tests

Tests `scripts/run_negative_control.py` itself, using a mocked
`nvidia-smi`. This is Layer 2 confidence, not Layer 3 -- see
`scripts/README.md` for what that distinction means and why it matters.
Proves argument parsing, the sample loop, error propagation on a missing
or failing `nvidia-smi`, and that clean mocked data produces zero alerts
through the actual CLI entry point -- not just through the underlying
pipeline object directly.

## test_check_pcie_telemetry.py -- 15 tests

Tests `scripts/check_pcie_telemetry.py`, a reconnaissance script (not a
detector) checking whether this environment's nvidia-smi exposes enough
PCIe telemetry to build a PCIe-bandwidth detector idea before any
detection code is written for it. Mocked at the subprocess level, so
these tests prove the script's own error handling and output shape --
they cannot and do not prove anything about what real hardware will
actually report.
