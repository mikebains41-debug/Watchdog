# container_escape_test.py

**Author:** Manmohan (Mike) Bains
**Status:** Working, tested live on this device (2/3 checks passed)

## What This Is

Checks the HOST machine it runs on for three signs relevant to
container escape risk: an unpatched kernel matching CVE-2026-31431
(the specific vulnerable version found on a real Vast.ai H200 rental
during this research), stale files left in /tmp older than 7 days,
and whether /proc/self/fd is visible.

## What It Actually Checks

1. Kernel version match against the known-vulnerable string
   5.15.0-140-generic
2. Files in /tmp with modification time older than 7 days
3. Whether /proc/self/fd can be listed

## Honest Result Interpretation

This test reports on WHATEVER HOST it is run on, not on Watchdog
itself. Running it on a personal phone/Termux environment will show
different results than running it on a real cloud GPU rental --
/proc visibility in particular is normal on most Linux systems and
only meaningful in a real multi-tenant cloud context.

## Confirmed Run Result (this device, Termux)

2/3 passed: kernel not vulnerable, /tmp clean, /proc visible (expected
and not meaningful on a personal device with no other tenants).

## How To Run

python3 tests/container_escape_test.py
