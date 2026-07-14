# attack_injection_suite.py

**Author:** Manmohan (Mike) Bains
**Status:** Built AND run live -- 45/45 tests passing

## What This Is

A single entry point that runs every positive-control test built
across all 8 test files tonight, dynamically discovering every
test_* function via Python's inspect module, and producing one
consolidated report covering all 27 detection capabilities.

## Why Built This Way

Rather than re-implementing attack patterns a second time and risking
drift from the already-verified versions, this reuses the exact,
already-proven test functions from the individual positive-control
files. No duplicated logic.

## Confirmed Run Result

45/45 tests passed across 8 modules, live on this device.

## How To Run

python3 tests/attack_injection_suite.py

## Requirements

None -- fully runnable with no GPU, since all underlying tests use
synthetic data.
