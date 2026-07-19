
## Multi-Provider Audit Plan (Step 1 — the whole game)

Goal: prove the Vast.ai finding is industry-wide, not a one-off.
Headline target: "N of 4 providers left tenant data or unpatched hosts behind."

Providers to test:
- Vast.ai (re-confirm original finding)
- RunPod
- Lambda
- Jarvis Labs

Architectures per provider (where available): H100, H200, B200, B300 — 2x or 3x GPU

What to check on each instance (host_isolation_audit.sh + additions):
1. Leftover tenant files in container filesystem — record age + count, do NOT inspect contents
2. Unpatched kernel CVEs — check against CISA KEV (e.g. CVE-2026-31431)
3. Container overlay sanitization gap
4. Host isolation: network, namespaces, IPC sockets, mount hygiene
5. Noisy-neighbor throughput degradation (contention_benchmark.py) — repeat 3x for a real number
6. Confirm none of it is visible to GPU telemetry (nvidia-smi / NVML)

Record per instance (buyer-grade):
- Provider, GPU model, GPU count, region
- Instance ID, date/time
- Kernel version
- Each finding + severity
- "Contents not inspected" confirmation
- Date provider security team notified

Output: one comparison table — providers down the side, findings across the top.
That table IS the pitch.
