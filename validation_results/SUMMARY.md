# Watchdog Validation - Summary

## 1. VRAM Full Rigor Tests
- Graceful exit: clean (matches=0, nonzero=0), memory.used stays elevated (1417MB)
- SIGKILL: same result, confirmed twice
- Cross-GPU: no leak to GPU1, same elevated-accounting pattern
- 16-min reproduction: 527MB residual confirmed (memory-accounting, not byte-recoverable)
Finding: real, reproducible memory-accounting residual. NOT a data leak -
actual content not recoverable in any variant tested.

## 2. Cross-Tenant A/B PoC
Genuinely separate processes (the design reviewers can't dismiss).
Graceful: 0/20 marker recovery. SIGKILL: 0/20 marker recovery.
Finding: isolation holds under the most rigorous test run this session.

## 3. Watchdog Detector Validation
Cache-timing probe: 0 alerts baseline, 0 alerts under simulated contention.
Memory-attacks detectors: same - 0/35099 baseline, 0/35068 contention.
Finding: the Watchdog detector CODE has not yet proven it can detect
anything. Marked "unvalidated" in its own source before this test;
still unvalidated after.

## 4. Contention Benchmark
Baseline: 372.32 iter/sec. Contention: 336.96 iter/sec. -9.5% throughput.
Finding: a REAL, measurable performance cost from contention exists -
but the Watchdog detectors (#3) did not catch it. This is the most
important cross-test finding: there is a real phenomenon to detect,
and the current detector code isn't detecting it.

## 5. Host Isolation Audit
One real, solid, reproducible finding: 16-day-old leftover files in
shared /tmp storage, confirmed across 4 independent runs. Plus one
significant external finding: kernel CVE-2026-31431 ("Copy Fail"),
a real, severe, recently disclosed container-escape vulnerability -
version-checked, not exploited. Recommend responsible disclosure to
Vast.ai rather than public demonstration.
Everything else: clean, standard, properly isolated (AppArmor, seccomp,
namespaces, ASLR, cgroup resource limits all confirmed working correctly).

---

## What This Means for Watchdog's Importance

Honest assessment, not hype:

**The case FOR Watchdog mattering:** the contention benchmark proves
the underlying problem is real - shared GPU infrastructure has a
measurable, quantified performance cost from contention (-9.5% in this
test) and at least one real isolation gap exists at the host level
(stale /tmp data, and a serious unpatched kernel CVE found through this
same audit process). These are exactly the kinds of problems a tool
like Watchdog should exist to catch automatically, instead of requiring
a 6+ hour manual audit to find.

**The gap Watchdog still needs to close:** the actual detector code
tested today did not catch the real phenomenon that was independently
proven to exist (the contention benchmark's measured 9.5% drop).
That's the core product gap - detection logic needs to be tuned against
real measured signals, not just GPU utilization heuristics.

**Bottom line:** this session strengthens the case that the problem
Watchdog is trying to solve is real and worth solving (proven via the
benchmark and the manual audit findings), but does NOT yet show that
Watchdog's current detectors solve it. That's the honest, accurate
state of the product today - real problem, not-yet-proven solution.
