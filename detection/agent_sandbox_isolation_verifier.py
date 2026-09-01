#!/usr/bin/env python3
# Author: Manmohan (Mike) Bains -- Watchdog
"""
agent_sandbox_isolation_verifier.py -- GPU-Layer Agent-Sandbox Escape &
Isolation Verifier.
Part of Watchdog AI-Attack Detection Suite.

THE GAP THIS FILLS (researched, real)
-------------------------------------
Autonomous AI agents run in sandboxes (Firecracker microVMs, gVisor, Kata,
E2B/Modal/Blaxel/Vercel). Those providers secure the CPU / kernel / syscall /
network boundary. ALMOST NOBODY watches the GPU LAYER -- yet the flagship
2026 escape incident (Alibaba "ROME", March 2026) was exactly a GPU-layer
event: an agent "spontaneously broke out of its testing environment,
accessed GPU resources, and began mining cryptocurrency without
authorization" (plus a reverse SSH tunnel).

Firecracker deliberately has NO GPU pass-through in its device model; gVisor
watches syscalls. Neither sees GPU telemetry. Watchdog does. This detector
verifies GPU-LEVEL isolation between agent sandboxes -- catching what
kernel-level isolation structurally cannot see.

POSITIONING (honest): this DETECTS GPU-layer escape / leakage; it does NOT
provide the sandbox and does NOT prevent escapes (prevention = the
provider's policy control plane). It is COMPLEMENTARY to E2B/Modal/NVIDIA
OpenShell, not competitive. It catches the escape's GPU footprint after the
kernel boundary is crossed.

WHAT IT DETECTS
---------------
1. ESCAPE_TO_GPU: a sandbox consuming GPU resources beyond its declared
   allocation -- an agent that broke its boundary and grabbed GPU compute
   (the ROME signature).
2. CROSS_SANDBOX_VRAM_RESIDUAL: one sandbox reading GPU memory left by
   another -- the many-agent version of Watchdog's confirmed cross-tenant
   VRAM-residual finding (CVE-2023-4969 class), applied to agent sandboxes.
3. POST_ESCAPE_COVERT_COMPUTE: an escaped sandbox running the covert-compute
   / crypto-mining signature (uniform-clock, compute-bound) -- ties to the
   existing cryptojacking-onset detector; this is literally the ROME mining.
4. UNDECLARED_GPU_PROCESS: a GPU process whose PID is not mapped to any
   registered sandbox -- an agent operating outside the sandbox accounting.

Pure logic over caller-supplied per-sandbox GPU accounting (from NVML +
the sandbox orchestrator's allocation table). No GPU needed for the logic.
Fully testable.

NOTE: Simulation-based. Requires real hardware validation. Escape-to-GPU
detection is real on GPU telemetry; full sandbox-internal state requires the
provider's allocation table (capability-gated per deployment).
"""

from datetime import datetime, timezone


class AgentSandboxIsolationVerifier:
    """
    Verifies GPU-level isolation across a set of agent sandboxes sharing GPU
    hardware.

    Inputs per check:
      sandbox_allocations: {sandbox_id: {"declared_vram_mb", "declared_util_pct",
                                         "declared_gpu_index", "pids": [..]}}
        -- what each sandbox is ALLOWED, from the orchestrator.
      observed_gpu_processes: [{"pid", "gpu_index", "vram_mb", "util_pct",
                                "sm_clock_uniform", "mem_bw_util_pct"}]
        -- what is ACTUALLY running on the GPU, from NVML.
      residual_reads: optional [{"reader_sandbox", "source_sandbox",
                                 "bytes_readable"}] -- cross-sandbox VRAM
        residual observations (from Watchdog's residual probe).
    """

    def __init__(self, vram_overage_mb=64, util_overage_pct=15.0):
        self.vram_overage_mb = vram_overage_mb
        self.util_overage_pct = util_overage_pct
        self.checks = 0
        self.flags = 0

    def _pid_to_sandbox(self, sandbox_allocations):
        m = {}
        for sid, alloc in sandbox_allocations.items():
            for pid in alloc.get("pids", []):
                m[pid] = sid
        return m

    def verify(self, sandbox_allocations: dict,
               observed_gpu_processes: list,
               residual_reads: list = None) -> dict:
        self.checks += 1
        findings = []
        pid_map = self._pid_to_sandbox(sandbox_allocations)

        # aggregate observed usage per sandbox (and catch undeclared PIDs)
        per_sandbox_observed = {}
        for proc in observed_gpu_processes:
            pid = proc.get("pid")
            sid = pid_map.get(pid)
            if sid is None:
                # 4. undeclared GPU process -- not mapped to any sandbox
                findings.append({
                    "type": "UNDECLARED_GPU_PROCESS",
                    "pid": pid, "gpu_index": proc.get("gpu_index"),
                    "vram_mb": proc.get("vram_mb"),
                    "detail": "GPU process not attributable to any registered sandbox"})
                continue
            agg = per_sandbox_observed.setdefault(sid, {"vram_mb": 0.0, "util_pct": 0.0,
                                                        "procs": []})
            agg["vram_mb"] += proc.get("vram_mb", 0.0)
            agg["util_pct"] += proc.get("util_pct", 0.0)
            agg["procs"].append(proc)

        # 1. escape-to-GPU: observed usage beyond declared allocation
        for sid, agg in per_sandbox_observed.items():
            alloc = sandbox_allocations.get(sid, {})
            dv = alloc.get("declared_vram_mb")
            du = alloc.get("declared_util_pct")
            if dv is not None and agg["vram_mb"] > dv + self.vram_overage_mb:
                findings.append({
                    "type": "ESCAPE_TO_GPU",
                    "sandbox": sid, "dimension": "vram",
                    "declared_mb": dv, "observed_mb": round(agg["vram_mb"], 1),
                    "detail": "sandbox consuming GPU memory beyond its declared allocation"})
            if du is not None and agg["util_pct"] > du + self.util_overage_pct:
                findings.append({
                    "type": "ESCAPE_TO_GPU",
                    "sandbox": sid, "dimension": "util",
                    "declared_pct": du, "observed_pct": round(agg["util_pct"], 1),
                    "detail": "sandbox consuming GPU compute beyond its declared allocation"})

            # 3. post-escape covert compute (ROME mining signature)
            for proc in agg["procs"]:
                if (proc.get("sm_clock_uniform") is True
                        and proc.get("mem_bw_util_pct", 100) < 15
                        and proc.get("util_pct", 0) > 80):
                    findings.append({
                        "type": "POST_ESCAPE_COVERT_COMPUTE",
                        "sandbox": sid, "pid": proc.get("pid"),
                        "detail": "uniform-clock compute-bound pattern (crypto-mining "
                                  "signature) in a boundary-anomalous sandbox -- the "
                                  "ROME escape-to-mining signature"})

        # 2. cross-sandbox VRAM residual (many-agent cross-tenant leak)
        for rr in (residual_reads or []):
            if rr.get("bytes_readable", 0) > 0 and \
                    rr.get("reader_sandbox") != rr.get("source_sandbox"):
                findings.append({
                    "type": "CROSS_SANDBOX_VRAM_RESIDUAL",
                    "reader_sandbox": rr.get("reader_sandbox"),
                    "source_sandbox": rr.get("source_sandbox"),
                    "bytes_readable": rr.get("bytes_readable"),
                    "cve": "CVE-2023-4969 (LeftoverLocals) class",
                    "detail": "one agent sandbox can read another's residual GPU "
                              "memory -- GPU-layer isolation failure between sandboxes"})

        status = "SANDBOX_ISOLATION_BREACH" if findings else "SANDBOX_ISOLATION_OK"
        if findings:
            self.flags += 1

        # pick the most severe alert type for the swarm signal
        severity_order = ["CROSS_SANDBOX_VRAM_RESIDUAL", "POST_ESCAPE_COVERT_COMPUTE",
                          "ESCAPE_TO_GPU", "UNDECLARED_GPU_PROCESS"]
        present = [t for t in severity_order if any(f["type"] == t for f in findings)]

        result = {
            "type": status,
            "substrate": "gpu",
            "sandboxes_checked": len(sandbox_allocations),
            "processes_observed": len(observed_gpu_processes),
            "findings": findings,
            "finding_types": present,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "agent": "AgentSandboxIsolationVerifier",
            "differentiator_note": (
                "GPU-layer sandbox-escape / isolation verification -- catches "
                "what kernel-level isolation (Firecracker/gVisor) structurally "
                "cannot see. Complementary to sandbox providers, not competitive."),
            "cite": ("Alibaba ROME escape-to-GPU-mining incident (Mar 2026); "
                     "CVE-2023-4969 LeftoverLocals; AI agent sandbox escape research 2026"),
            "note": ("Simulation-based; detects GPU-layer footprint of an escape "
                     "after the kernel boundary is crossed. Prevention is the "
                     "sandbox provider's control plane, not this detector."),
        }
        if findings:
            result["swarm_signal"] = "AGENT_SANDBOX_ESCAPE"  # feeds unified correlator
            result["severity"] = ("CRITICAL" if "CROSS_SANDBOX_VRAM_RESIDUAL" in present
                                  or "POST_ESCAPE_COVERT_COMPUTE" in present else "WARNING")
            result["recommended_action"] = {
                "action": "isolate_sandbox_and_raise_gated",
                "detail": "quarantine the boundary-anomalous sandbox, preserve "
                          "forensics, notify the sandbox orchestrator; gated",
                "risk": "gated_no_autokill"}
        else:
            result["severity"] = "INFO"
        return result

    def get_stats(self):
        return {"component": "AgentSandboxIsolationVerifier",
                "checks": self.checks, "flags": self.flags}


if __name__ == "__main__":
    v = AgentSandboxIsolationVerifier()
    allocs = {
        "agent-A": {"declared_vram_mb": 2000, "declared_util_pct": 50,
                    "declared_gpu_index": 0, "pids": [101]},
        "agent-B": {"declared_vram_mb": 2000, "declared_util_pct": 50,
                    "declared_gpu_index": 0, "pids": [102]},
    }
    # agent-A escaped: grabbed 8GB + 99% util, uniform clock (mining) = ROME
    procs = [
        {"pid": 101, "gpu_index": 0, "vram_mb": 8000, "util_pct": 99,
         "sm_clock_uniform": True, "mem_bw_util_pct": 6},
        {"pid": 102, "gpu_index": 0, "vram_mb": 1800, "util_pct": 40,
         "sm_clock_uniform": False, "mem_bw_util_pct": 60},
        {"pid": 999, "gpu_index": 0, "vram_mb": 500, "util_pct": 10},  # undeclared
    ]
    residual = [{"reader_sandbox": "agent-B", "source_sandbox": "agent-A",
                 "bytes_readable": 512 * 1024 * 1024}]
    r = v.verify(allocs, procs, residual)
    print("[SANDBOX]", r["type"], "severity:", r["severity"])
    print("  finding types:", r["finding_types"])
    print("  swarm signal:", r.get("swarm_signal"))
