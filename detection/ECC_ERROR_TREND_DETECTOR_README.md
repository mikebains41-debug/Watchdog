# ECCErrorTrendDetector

**Author:** Manmohan (Mike) Bains
**Company:** GPU Optimizer Inc. / Watchdog AIDR
**Status:** Detection logic complete, tested with synthetic data (4/4
tests passing). Not yet run against real ECC error events on live
hardware.

## What This Is

Watches two real, standard NVML/nvidia-smi fields present on all ECC-
protected data center GPUs (A100, H100, H200, B200, B300):
ecc.errors.corrected.volatile.total and
ecc.errors.uncorrected.volatile.total.

## What It Detects

1. ECC_UNCORRECTABLE_ERROR (EMERGENCY) -- fires on ANY increase in
   uncorrectable ECC errors. Rare and serious on healthy hardware.
2. ECC_CORRECTABLE_TREND (WARNING) -- fires when the rate of
   correctable errors rises above a threshold over a rolling window,
   an early-warning signal for memory degradation before it becomes
   uncorrectable.

## Why It Matters

Academic Rowhammer research (GPUHammer, USENIX Security 2025) found
that HBM-based data center GPUs rely on on-die ECC to mask single
bit-flips from memory-disturbance events. This means ECC error counts
are the correct, legitimate, non-exploit way to gain visibility into
that class of phenomenon -- watching a real hardware counter, not
running an attack.

## Requirements

nvidia-smi must expose the ECC query fields (standard on ECC-capable
data center GPUs; not available on most consumer cards).

## How To Test

No GPU required for the logic test -- feed synthetic rows matching
the real field names. On real hardware, call .update() once per
nvidia-smi sample including the ECC fields.

## Honest Status

Detection logic verified against synthetic data only. Real-world
validation requires either live hardware with an actual ECC event
(rare, cannot be manufactured safely) or a long-running production
deployment to observe real trend data over time.
