# Contention Benchmark Note

Quantified performance impact (not detector response) of noisy-neighbor
GPU contention on matmul throughput.

Baseline: 372.32 iter/sec (22,340 matmuls in 60s, no contention)
Contention: 336.96 iter/sec (20,218 matmuls in 60s, simultaneous
noisy-neighbor simulation running)
Change: -9.5% throughput

This demonstrates real, measurable performance degradation from shared
GPU resource contention, independent of whether any detector alerts on
it (the Watchdog detectors tested earlier showed zero response to this
same type of contention, despite a real, measurable performance cost
existing).
