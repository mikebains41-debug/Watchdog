# Findings — Vast.ai H200 tenant residue + host security

**Provider:** Vast.ai · datacenter 214845 · **machine 51172** (same physical box both days)
**Method:** `scripts/handover_capture.py` + `provider_probe.py` + `provider_probe2.py`,
run as the first commands on the rented instance, before any workload. Open-source,
reproducible. Metadata only — no file contents opened, read, copied, or hashed.

**Two rentals of the same machine:**
- 2026-09-24, instance 52332336, host `dfa5e32169cd` — handover scan
- 2026-09-25, instance 52509247, host `7ff12d1760d2` — handover scan + full 26-test benchmark

Confirmed same machine: identical NVLink counter total, same `.condarc` aged one
day (16.4 → 17.4). This is one machine seen twice (dirty both days), **not two
independent samples.** June's 5-of-5 remains the multi-machine sample.

---

## Handover residue (the June question — still failing)

**Irrefutable item:** `/home/user/.condarc`, 273 bytes, owned by a previous tenant
(uid 1001), dated **16–17 days before each rental** — provably not from the session
and not a base-image default (the genuine image files are 906 days old and
correctly excluded). Present and readable at handover. One file proves the machine
was not wiped between tenants.

**Other previous-tenant files:** `/home/user/.ssh/authorized_keys` and
`/home/ubuntu/.ssh/authorized_keys` (both empty). `/home/user/.bashrc` (4896 B)
present but 0-day age, not counted as proof. `/root/onstart.sh` is Vast's own
provisioning script, excluded.

**NVLink counters not reset:** 1,065,509,220,356 KiB ≈ **1.09 PB** of the previous
tenant's GPU-to-GPU traffic, handed over unreset across 36 counters (~29.5–29.9
billion KiB each direction per link). June did not check this.

---

## Full benchmark — additional host-security failures (2026-09-25, real GPU)

The 26-test benchmark on the live H200 surfaced failures the handover scan alone
did not. On this machine:

| Test | Result | Detail |
|---|---|---|
| HH-04 Live Context at Handover | **FAIL** | ~1131 MB already in use before any workload — prior context resident |
| HH-08 GPU State at Handover | **FAIL** | application clock left pinned by previous tenant |
| HH-09 Disk & Log Residue | **FAIL** | a previous tenant's home directory readable |
| HS-02 Container Escape Surface | **FAIL** | host firmware / kernel-log paths mounted into the container |
| HS-08 Provider Agent Reachable | **FAIL** | a host-management port reachable from inside the tenant |
| HS-04 Baked-in Credentials | FAIL* | env var `JUPYTER_TOKEN` set — **Vast's own Jupyter token, likely a false positive**, noted not counted |

**Passed (provider did the right thing):** VRAM zeroed at handover (HH-02 — 512 MB
fresh allocation read back all zero, consistent with NVIDIA not being affected by
LeftoverLocals), host RAM scrubbed, IPC clean, no ARP/DNS residue, namespaces
contained, cloud metadata endpoint not reachable, IMDS not exposed, GPU matches
advertised H200.

**Most serious of the FAILs:** HS-02 (container escape surface — host paths mounted
in) and HS-08 (reachable host-management port). These are paths an attacker on a
rented instance could use to reach beyond their own container.

---

## What is proven — and what is deliberately NOT

**Proven:** the provider handed over a machine carrying a previous tenant's file,
GPU counters (~1 PB), live memory, and pinned GPU state — plus a container-escape
surface and a reachable management port. All observed on our own instance.

**Deliberately not done:** contents never opened. The scan records that data
*exists and is readable* — its metadata — never what it contains. This keeps the
work legal and the claim precise: *"the provider fails to wipe machines and exposes
host surfaces to tenants,"* not *"we accessed another customer's data."*

**Exact claim:** *"Vast.ai handed over an H200 carrying a previous tenant's file
(16+ days old), ~1 PB of un-reset GPU traffic counters, resident memory, and a
container-escape surface — all readable/reachable by the next renter. No tenant
data was opened or exfiltrated in demonstrating this."*

---

## Disclosure history
- **June 2026:** unpatched-kernel finding reported to security@vast.ai. No response.
  Leftover-files finding not separately reported.
- **2026-09-24/25:** these results. Not yet reported.

## Limits
- One physical machine (51172), seen twice. Confirms persistence, not a rate.
  June's 5-of-5 is the multi-machine evidence.
- HS-04 is Vast's own Jupyter token — a false positive on this instance type.
- Single operator, no third-party audit. Metadata only.
- To establish a rate: run the scan on machines in **other datacenters** (Vast
  repeatedly returns 51172 in datacenter 214845 as the cheapest H200 there).
