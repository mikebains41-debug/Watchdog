# Host Isolation Audit - Attempt 2 (Confirmation Run)
Date: 2026-06-21
Instance: 41986069 (Datacenter 317686, US)

## Purpose
Second run of the same 5 checks to confirm consistency with Attempt 1.

## Results
1. Network capability check: PASS - network isolated (same as attempt 1)
2. Raw device check: PASS - no raw block devices visible (same as attempt 1)
3. GPU topology: GPU0-GPU1 via NVLink NV18 (same as attempt 1)
4. Shared temp storage: Same 3 directories and lock file dated June 5
   2026 still present (tmp3j31amsg_kernels, tmp5viu561v_kernels,
   tmpap3y5yro_kernels, uv-e147f089dc971b1b.lock). Confirms the
   residual finding is stable, not a one-off artifact.
5. Network exposure: Same port configuration as attempt 1, one
   additional transient UDP listener on [::]:53243 (inconsequential).

## Conclusion
Results are consistent across both runs. The June 5 temp file finding
is confirmed stable and reproducible, strengthening the host isolation
finding documented in host_isolation_audit.md.
