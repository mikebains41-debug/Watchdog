=== STATUS (2026-07-29) ===
Tools built and committed:
  - gpu_audit.py          -> Step 1 (contention, tenant files, stale CVE)
  - capture_contention.py -> Step 2 capture-first (records + offline verdict)
  - aggregate_audits.py   -> the Step 1 comparison table
All three tested on phone: correct NOT_RUN with no GPU. Unproven on real hardware.

BLOCKED ON: one rented GPU instance.
NEXT ACTION: rent one cheap box, git pull, pip install torch,
  run gpu_audit.py then capture_contention.py, scp JSON+CSV back.
Nothing goes in a pitch/doc/chart unless it's in EVIDENCE.md with a source.
===========================

Multi-Provider Audit Plan (Step 1 — the whole game)

Goal: prove the Vast.ai finding is industry-wide, not a one-off.
Headline target: "N of 5 providers left tenant data or unpatched hosts behind."

Providers to test:

Vast.ai (re-confirm original finding)
RunPod
Lambda
Jarvis Labs
Spheron AI

Architectures per provider (where available): H100, H200, B200, B300 — 2x or 3x GPU

What to check on each instance (host_isolation_audit.sh + additions):

Leftover tenant files in container filesystem — record age + count, do NOT inspect contents
Unpatched kernel CVEs — check against CISA KEV, specifically:
  - CVE-2026-31431 ("Copy Fail") — kernel version string check, known fragile to backports
  - CVE-2026-64600 ("RefluXFS") — scripts/check_refluxfs_exposure.sh, checks kernel version + XFS + reflink. NVD: https://nvd.nist.gov/vuln/detail/CVE-2026-64600 (CVSS 3.1 7.8 HIGH, local-access-only, not remotely exploitable)
Container overlay sanitization gap
Host isolation: network, namespaces, IPC sockets, mount hygiene
Noisy-neighbor throughput degradation (contention_benchmark.py) — repeat 3x for a real number
Confirm none of it is visible to GPU telemetry (nvidia-smi / NVML)

Record per instance (buyer-grade):

Provider, GPU model, GPU count, region
Instance ID, date/time
Kernel version
Each finding + severity
"Contents not inspected" confirmation
Date provider security team notified

Output: one comparison table — providers down the side, findings across the top. That table IS the pitch.


---

Step 2 — Detector validation (the harder half, same instances)

Goal: prove Watchdog's detection code fires on real signals.
Status: unproven. A validation session on real H200 hardware ran the
cache-timing and memory-attack detectors against a measured contention
event and got zero alerts across 35,099 baseline and 35,068 contention
samples. The event was independently confirmed real (-9.5% throughput).
The detectors did not see it. That is the central product gap and this
step exists to close it.

Run Step 1 and Step 2 on the same instances. Same cost, both answers.

CAPTURE FIRST, TUNE SECOND — do not skip this ordering:

The detectors were tuned against synthetic patterns built from an
assumption about what the real signal looks like. If that assumption was
wrong, the detector is tuned for a signal that does not exist, and the
synthetic tests pass anyway because the same assumption generated both
the test and the detector. That is likely why they found nothing.

So on the first session, do NOT start by running detectors:

1. Start the collector recording raw telemetry at full rate, all fields,
   detection logic off
2. Induce the event deliberately (contention_benchmark.py's competing
   process, same method that measured the -9.5%)
3. Stop recording, keep the CSV
4. Analyze offline, at no hourly cost

That answers the question that actually matters: is the signal present
in NVML telemetry at all?
  - Present -> real numbers to tune thresholds against, and the exact
    magnitude to look for
  - Absent -> detection from telemetry alone is impossible for this
    phenomenon, learned in hours instead of after 360 hours

Only after that, run the detectors against the same conditions and see
whether the tuned thresholds fire.

Specific checks to run while an instance is up:

Throttle reason fields — added recently, never run on hardware. Confirm
  the driver accepts them; the fallback to core fields on rejection is
  written but untested. These are flags (Active / Not Active), not
  thresholds, so if they track the contention event they are the most
  promising signal available.
scripts/check_pcie_telemetry.py — settles whether pcie.bandwidth.util_pct
  is obtainable. PCIeBandwidthMismatchDetector reads that field, nothing
  supplies it, and it is currently the one engine of 32 that cannot fire.
run_cei_benchmark() — produces a real FLOPs/joule figure. Unblocks
  CEIDegradationForecaster, which cannot fire without one.
run_residency_probe() — produces a real memory-latency figure. Unblocks
  TenantIsolationRiskScorer's timing signal, which currently reads zero.
parse_nvlink_output() — verify against real `nvidia-smi nvlink -g N -gt d`
  output. The parser matches NVIDIA's documented format but has never seen
  real output. Needs a multi-GPU instance with NVLink present.
Sampling rate — record the achieved rate from DeltaTimedSampler against
  the requested rate. Any figure not derived from measured intervals is
  unreliable and this settles it.
Negative control — one hour on a clean idle GPU, no workload. Confirm
  zero alerts. An always-firing detector is indistinguishable from no
  detector, and this is the only way to prove it stays quiet.

Record per instance, alongside Step 1's fields:

Raw telemetry CSV filename and sample count
Whether throttle fields were accepted or fell back
Detector alerts fired: type, count, timestamp relative to induced event
Detector alerts during clean baseline (false positives)
Measured achieved sample rate vs requested
CEI figure if the benchmark ran
Residency latency figure if the probe ran

Output: for each detector, one of three verdicts —
  FIRES CORRECTLY (fired on the event, silent on baseline)
  NEEDS TUNING (signal present in capture, threshold wrong)
  NOT DETECTABLE (signal absent from telemetry entirely)

That table is the other half of the pitch. Step 1 proves the problem is
real. Step 2 proves the product solves it. Neither alone is enough.

ADDED — SIGKILL accounting measurement (few minutes, high value)

Open question the existing tests cannot answer: does SIGKILL release the
527MB accounting residual that a graceful exit leaves behind?

Both existing tests allocate a 256MB buffer to read memory back, so their
reported memory figures include the instrument. One of them showed 863MB
before the kill and 1417MB after -- an increase, which is the monitor's
own allocation, not residue. That figure was cited as a finding in an
earlier draft of the investor document and has been corrected.

Correct method, allocate nothing:
  1. Start a process that allocates a known amount of VRAM
  2. Record memory.used while it holds
  3. SIGKILL it
  4. Record memory.used for 60s after, reading telemetry only
  5. Repeat with a graceful exit for direct comparison

Outcome either way is worth having: if SIGKILL releases it and graceful
exit does not, that is a sharper and more interesting finding than the
current one. If neither releases it, the residual is exit-path
independent.
