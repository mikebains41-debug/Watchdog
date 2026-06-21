# Host Isolation Audit - Attempt 3 (Confirmation Run)
Date: 2026-06-21
Instance: 41986069 (Datacenter 317686, US)

## Purpose
Third run of the same 5 checks to confirm consistency with Attempts 1 and 2.

## Results
1. Network capability check: PASS - network isolated (consistent with attempts 1-2)
2. Raw device check: PASS - no raw block devices visible (consistent with attempts 1-2)
3. GPU topology: GPU0-GPU1 via NVLink NV18 (consistent with attempts 1-2)
4. Shared temp storage: Same 3 directories and lock file dated June 5
   2026 still present (tmp3j31amsg_kernels, tmp5viu561v_kernels,
   tmpap3y5yro_kernels, uv-e147f089dc971b1b.lock). Third consecutive
   confirmation of this finding.
5. Network exposure: Same port configuration as prior attempts.

## Conclusion
Results consistent across all three runs. The June 5 temp file finding
is confirmed stable and reproducible across three independent checks.
File contents were not inspected in any attempt, in order to avoid
accessing another party's data without authorization - only existence
and timestamps were recorded as evidence.
