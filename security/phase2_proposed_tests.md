# Phase 2 Security Tests — Internal

## Test 1: Power State Shift as Covert Cross-GPU Side Channel
Hypothesis: B300 permanent power state shift (+72W) can be used as a binary
communication channel between isolated tenants on the same physical node.

## Test 2: Power State Shift as Financial DoS
Hypothesis: A malicious tenant permanently elevates idle power to 235W.
All subsequent tenants pay the +72W energy penalty indefinitely.

## Test 3: Power State Shift as Persistent Hardware Fingerprint
Hypothesis: Exact shift magnitude varies per GPU due to manufacturing differences,
creating a unique persistent identifier that survives tenant boundaries.

## Test 4: Cross-MIG Partition Power State Leakage
Hypothesis: Shift triggered in one MIG partition elevates power across all
partitions on the same GPU, violating MIG isolation claims.

## Test 5: Recovery Attempts - Driver Reset vs Power Cycle
Hypothesis: Shift is not cleared by nvidia-smi -r or driver reload.
Only full AC power cycle restores baseline.

## Test 6: Thermal and Acoustic Side Effects
Hypothesis: +72W elevation raises temperature and fan speed detectable
externally via thermal camera or microphone.

## Test 7: Memory Clock Lock After Shift
Hypothesis: After permanent shift, SM clock also locks at higher idle
frequency, pinpointing root cause within GPU clock tree.

All tests require bare metal infrastructure.
