# Host Isolation Audit - Vast.ai 2x H200 Instance
Date: 2026-06-21
Instance: 41986069 (Datacenter 317686, US)

## Summary
Five non-destructive checks of container/host isolation boundaries on a
rented Vast.ai 2x H200 instance with Confidential Computing disabled
(CC State: OFF, confirmed via nvidia-smi conf-compute -q).

## Results

### 1. Container privilege check
Command: `ip link add dummy0 type dummy`
Result: PASS - network isolated, no excess capabilities.

### 2. Raw host device check
Command: `ls -l /dev/nvme* /dev/sd*`
Result: PASS - no raw host block devices visible from container.

### 3. GPU interconnect topology
Command: `nvidia-smi topo -m`
Result: GPU0-GPU1 connected via NVLink (NV18). Expected configuration,
not a demonstrated leak on its own.

### 4. Shared temp storage residual check
Command: `ls -la /dev/shm /tmp`
Result: /dev/shm clean. /tmp contains 3 directories
(tmp3j31amsg_kernels, tmp5viu561v_kernels, tmpap3y5yro_kernels) and one
lock file (uv-e147f089dc971b1b.lock), all dated June 5 2026 - 16 days
before this rental session began (started June 21 2026). This predates
the current tenancy and indicates shared temp storage is not wiped
between rentals on this host.
Contents of these files were NOT inspected or read, in order to avoid
accessing any other party's data without authorization. Only file
existence and timestamps were recorded as evidence.

### 5. Network exposure check
Command: `ss -tulnp`
Result: Most services bound to 127.0.0.1 (localhost only). Jupyter
(8080) and several other ports bound to 0.0.0.0/wildcard - consistent
with Vast.ai's standard port-forwarding model for user access, not
independently confirmed as a misconfiguration.

## Conclusion
Container-level isolation (network capabilities, raw devices) appears
properly configured. However, shared temp storage (/tmp) shows evidence
of inadequate sanitization between tenants, with files predating the
current rental by 16 days. This is consistent with and reinforces the
broader VRAM residual findings from this same session: shared GPU cloud
infrastructure may not fully clear state between tenants at multiple
levels (VRAM and filesystem).
