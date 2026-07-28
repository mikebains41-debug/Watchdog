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
