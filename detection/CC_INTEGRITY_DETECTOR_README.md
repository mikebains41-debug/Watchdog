# ConfidentialComputingIntegrityDetector

**Author:** Manmohan (Mike) Bains
**Company:** GPU Optimizer Inc. / Watchdog AIDR
**Status:** Detection logic complete, tested with mocked nvidia-smi
output (4/4 tests passing). NOT yet run against real Confidential
Computing hardware.

## What This Is

Watches the real, standard `nvidia-smi conf-compute -q` command --
the same command already used in this repo's host_isolation_audit
findings -- for unexpected changes to a GPU's Confidential Computing
status.

## Why It Matters

Independent security research from IBM and Ohio State University
(July 2025) reverse-engineered NVIDIA's GPU Confidential Computing
(GPU-CC) and found it does NOT encrypt GPU memory at runtime --
instead relying on access-control mechanisms (firewalls). The same
research found attackers with physical or remote access could
manipulate GPU-CC security configuration via tools like nvTrust or
out-of-band BMC interfaces. Since GPU-CC's security model depends on
that access-control configuration staying intact, monitoring for
unexpected state changes is a legitimate, real defensive measure.

## What This Detects

CC_STATE_CHANGE -- fires when Confidential Computing status changes
from its established baseline. An ON-to-OFF transition is flagged
CRITICAL; other changes are WARNING.

## What This Does NOT Do

Does not attempt to manipulate GPU-CC settings, use nvTrust, or
access any BMC/out-of-band interface. Pure read-only monitoring of
standard, documented nvidia-smi output.

## Requirements

nvidia-smi with Confidential Computing support (H100/H200/B200-class
hardware with CC enabled).

## Honest Status

Tested with mocked subprocess output confirming parsing and
state-change logic are correct. Real-world validation requires
access to actual Confidential Computing-capable hardware, which was
not available during this development session.
