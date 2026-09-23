"""
Watchdog provider benchmark -- registry EXTENSION (round 2, researched).

Imported by wd_benchmark_tests via `from wd_benchmark_tests_ext import EXT_TESTS,
CITATIONS`. Keeps the new test IDs, titles and their published sources in one
place so probe output, result JSON, scoreboard and the sources file all agree.

Same verdict meaning as the base registry (PASS = provider did the right thing).
Every probe measures YOUR OWN instance or what the provider handed you. Two
lines that never move:
  - the metadata probe detects which IMDS version is exposed; it never walks the
    credential path (that path is the Capital One attack).
  - the side-channel probe is a CONFIG check ("this machine is arranged so a
    co-tenant could be observed"); it never reads another tenant.
"""

# id -> (title, group, one-line what-it-checks)
EXT_TESTS = {
    # Handover Hygiene -- more of what a previous tenant leaves behind
    "HH-06": ("Host RAM Scrubbed", "Handover Hygiene",
              "a fresh host-memory allocation read back -- zero, or previous contents"),
    "HH-07": ("Shared Memory / IPC Residue", "Handover Hygiene",
              "leftover /dev/shm files, SysV shm segments, semaphores, message queues"),
    "HH-08": ("GPU State at Handover", "Handover Hygiene",
              "MIG left configured, ECC disabled, persistence, clocks/power pinned by prior tenant"),
    "HH-09": ("Disk & Log Residue", "Handover Hygiene",
              "readable shell history, journald/auth logs, prior tenant's home dirs"),
    "HH-10": ("Network Trace Residue", "Handover Hygiene",
              "DNS cache, ARP table, known_hosts entries from the previous tenant"),
    "HH-11": ("GPU Local-Memory Residue (LeftoverLocals class)", "Handover Hygiene",
              "GPU shared/local memory readable across kernels -- the CVE-2023-4969 mechanism"),
    # Host Security -- deeper
    "HS-06": ("Container Toolkit Version (NVIDIAScape)", "Host Security",
              "NVIDIA Container Toolkit version vs the CVE-2025-23266 / CVE-2024-0132 patched line"),
    "HS-07": ("Metadata IMDS Version", "Host Security",
              "which cloud-metadata version is exposed: v1 (SSRF-open) vs v2-only vs blocked"),
    "HS-08": ("Provider Agent Reachable", "Host Security",
              "the marketplace's host-management daemon socket/API reachable from the container"),
    "HS-09": ("VBIOS / Firmware Integrity", "Host Security",
              "GPU VBIOS version present and matching an expected value at handover"),
    "HS-10": ("Network Egress Openness", "Host Security",
              "what the container can reach outbound -- wide-open egress is an exfiltration path"),
    # Billing Honesty already covered by base BH-01..BH-04
    # Side-channel: CONFIG check only, never observes a neighbour
    "SC-01": ("Co-Tenant Side-Channel Exposure (config only)", "Side-Channel Exposure",
              "is the machine arranged (shared GPU, MPS, no MIG isolation) so a co-tenant COULD be observed"),
}

# test_id -> list of (label, url) published sources
CITATIONS = {
    "HH-02": [("LeftoverLocals CVE-2023-4969 (Trail of Bits) -- NVIDIA confirmed NOT affected",
               "https://blog.trailofbits.com/2024/01/16/leftoverlocals-listening-to-llm-responses-through-leaked-gpu-local-memory/")],
    "HH-06": [("Same clearing principle as LeftoverLocals, applied to host RAM",
               "https://arxiv.org/html/2401.16603v1")],
    "HH-11": [("LeftoverLocals: GPU local memory not cleared between kernels; ~5.5MB/invocation on affected GPUs",
               "https://kb.cert.org/vuls/id/446598"),
              ("NVIDIA not affected by CVE-2023-4969 -- a non-zero read on NVIDIA would be new",
               "https://leftoverlocals.com/")],
    "HS-06": [("NVIDIAScape CVE-2025-23266 (CVSS 9.0), toolkit <=1.17.7 / GPU Operator <=25.3.0 (Wiz)",
               "https://www.wiz.io/blog/nvidia-ai-vulnerability-cve-2025-23266-nvidiascape"),
              ("Earlier NVIDIA Container Toolkit escape CVE-2024-0132 (Wiz deep dive)",
               "https://github.com/winmin/awesome-vm-escape")],
    "HS-07": [("Capital One 2019: SSRF -> IMDSv1 -> IAM creds -> 100M records; IMDSv2 requires a token",
               "https://securitylabs.datadoghq.com/articles/misconfiguration-spotlight-imds/")],
    "HS-09": [("VBIOS/BMC firmware as a GPU attack vector (arXiv 2507.02770)",
               "https://arxiv.org/html/2507.02770")],
    "SC-01": [("GPU side/covert channels: Spy-in-the-GPU-box / NVBleed / SideLink -- shared-hardware observation",
               "https://leftoverlocals.com/")],
}

# supply-chain / agentic frontier -- research follow-ups, not pod probes
FRONTIER_NOTES = [
    ("Shai-Hulud npm worm (Sep 2026): poisoned 11 seed packages, spread to 400+ -- ties to ShadowInit "
     "package-integrity detector", "https://www.kodemsecurity.com/resources/vulnerability-alert-cve-2025-23266"),
    ("Prompt injection rewrote AWS Kiro's own MCP config for code execution -- ties to the MoE/agent work",
     "https://www.kodemsecurity.com/resources/vulnerability-alert-cve-2025-23266"),
]
