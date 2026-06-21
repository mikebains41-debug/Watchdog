# Summary

Instance: Vast.ai 41986069 (Datacenter 317686, US), 2x H200 SXM
Date: 2026-06-21
Confidential Computing: OFF (confirmed via nvidia-smi conf-compute -q)

## Key finding
Shared temp storage (/tmp) contains 3 directories and 1 lock file
timestamped June 5 2026 - 16 days before this rental began. This
indicates the host does not wipe shared temp storage between tenants.
Confirmed identically across 3 independent runs.

## Other checks
Container network capabilities, raw host device visibility, and
network port exposure all returned expected/clean results across all
3 attempts. GPU interconnect (NVLink NV18) confirmed present, expected
for a dual-GPU configuration.

## Scope and limitations
File contents of the residual temp files were not inspected. This
finding documents existence and timestamps only, not contents or
sensitivity of any leftover data.
