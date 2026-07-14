# resource_benchmark.py

**Author:** Manmohan (Mike) Bains
**Status:** Built AND run live -- 40,466 rows/sec confirmed

## What This Is

Measures Watchdog's own CPU/memory overhead by feeding synthetic
telemetry rows through the real DetectionPipeline at high volume.

## Why Built This Way

Unlike stability_test.py/latency_test.py/false_positive_benchmark.py,
this uses synthetic rows directly instead of nvidia-smi, so it runs
on any device -- no GPU needed.

## Confirmed Run Result

40,466 rows/sec, memory variance 0.1MB across 2000 iterations, live
on this device.

## How To Run

python3 tests/resource_benchmark.py --iterations 10000

## Requirements

psutil (install via: pkg install python-psutil on Termux)
