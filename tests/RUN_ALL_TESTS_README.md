# run_all_tests.py

**Author:** Manmohan (Mike) Bains
**Status:** Honest orchestrator -- only runs the tests confirmed to
actually work standalone on this device.

## What This Is

A single entry point that runs container_escape_test.py and
compliance_evidence_test.py (the two tests in this batch confirmed
working without real GPU hardware) and prints a pass/fail summary.

## Honest Correction From Original

The original pasted version listed 7+ tests including several that
either require real GPU hardware not present on this device, or
reference scripts (attack_injection_suite.py, resource_benchmark.py,
competitor_benchmark.py) that were never actually provided and do not
exist in this repo. Running the original version would have crashed
immediately on missing files. This version only includes what is
real and confirmed.

## How To Run

python3 tests/run_all_tests.py

## What It Does NOT Run (and why)

stability_test.py, false_positive_benchmark.py, latency_test.py --
require real GPU hardware (nvidia-smi), confirmed absent here.
swarm_test.py -- requires real running API server instances.
attack_injection_suite.py, resource_benchmark.py,
competitor_benchmark.py -- never provided, do not exist.
