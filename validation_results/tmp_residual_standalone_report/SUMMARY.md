# Summary

Instance: Vast.ai 41986069 (Datacenter 317686, US), 2x H200 SXM
Rental start: 2026-06-21
Confidential Computing: OFF

## Finding
ls -la /tmp revealed 3 directories and 1 lock file:
- tmp3j31amsg_kernels (directory)
- tmp5viu561v_kernels (directory)
- tmpap3y5yro_kernels (directory)
- uv-e147f089dc971b1b.lock (file, 0 bytes)

All four timestamped 2026-06-05 14:43 - 16 days before this rental's
container started (2026-06-21 17:06, per /dev/shm directory timestamps
on the same instance).

## Reproducibility
Confirmed identically across 4 independent checks, run at different
times during the same session (attempts 1-4, all in
host_isolation_audit/).

## Scope and Limitations
File CONTENTS were not inspected or read, to avoid accessing another
party's data without authorization. This report documents file
EXISTENCE and TIMESTAMPS only. Severity of any data inside these files
is unknown and not claimed.

## Recommendation
Responsible disclosure to Vast.ai: shared temp storage should be wiped
or namespaced per-rental. This is a sanitization gap, not a data
breach - no data was read.
