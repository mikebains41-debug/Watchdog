#!/usr/bin/env python3
# Author: Manmohan (Mike) Bains -- Watchdog
"""
tests/test_agent_sandbox_isolation.py

Tests the GPU-layer agent-sandbox-escape / isolation verifier and its swarm
correlator: escape-to-GPU, cross-sandbox VRAM residual, post-escape covert
compute (ROME), undeclared GPU process, clean isolation, and the swarm
fusing AGENT_SANDBOX_ESCAPE into correlated incidents.

Run standalone: python3 tests/test_agent_sandbox_isolation.py
Or via suite:   python3 tests/run_all.py (once registered in TEST_FILES).
"""
import os
import sys

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

from detection.agent_sandbox_isolation_verifier import AgentSandboxIsolationVerifier
from intelligence.swarm.sandbox_swarm_correlator import SandboxSwarmCorrelator

PASSED = []
FAILED = []


def check(name, condition, detail=""):
    if condition:
        PASSED.append(name)
        print(f"[PASS] {name}")
    else:
        FAILED.append(name)
        print(f"[FAIL] {name} {detail}")


def _allocs():
    return {
        "agent-A": {"declared_vram_mb": 2000, "declared_util_pct": 50,
                    "declared_gpu_index": 0, "pids": [101]},
        "agent-B": {"declared_vram_mb": 2000, "declared_util_pct": 50,
                    "declared_gpu_index": 0, "pids": [102]},
    }


# --------------------------------------------------------------------------
# Verifier
# --------------------------------------------------------------------------
def test_clean_isolation_ok():
    v = AgentSandboxIsolationVerifier()
    procs = [
        {"pid": 101, "gpu_index": 0, "vram_mb": 1800, "util_pct": 45,
         "sm_clock_uniform": False, "mem_bw_util_pct": 55},
        {"pid": 102, "gpu_index": 0, "vram_mb": 1900, "util_pct": 48,
         "sm_clock_uniform": False, "mem_bw_util_pct": 60},
    ]
    r = v.verify(_allocs(), procs)
    check("sandbox: within-allocation usage -> SANDBOX_ISOLATION_OK",
          r["type"] == "SANDBOX_ISOLATION_OK", f"got {r['type']} findings={r['findings']}")


def test_escape_to_gpu_vram():
    v = AgentSandboxIsolationVerifier()
    procs = [{"pid": 101, "gpu_index": 0, "vram_mb": 8000, "util_pct": 45}]  # 8GB vs 2GB declared
    r = v.verify(_allocs(), procs)
    check("sandbox: VRAM beyond allocation -> ESCAPE_TO_GPU",
          any(f["type"] == "ESCAPE_TO_GPU" and f["dimension"] == "vram" for f in r["findings"]),
          f"got {r['findings']}")
    check("sandbox: escape emits AGENT_SANDBOX_ESCAPE swarm signal",
          r.get("swarm_signal") == "AGENT_SANDBOX_ESCAPE", f"got {r.get('swarm_signal')}")


def test_escape_to_gpu_util():
    v = AgentSandboxIsolationVerifier()
    procs = [{"pid": 101, "gpu_index": 0, "vram_mb": 1900, "util_pct": 99}]  # 99% vs 50% declared
    r = v.verify(_allocs(), procs)
    check("sandbox: util beyond allocation -> ESCAPE_TO_GPU",
          any(f["type"] == "ESCAPE_TO_GPU" and f["dimension"] == "util" for f in r["findings"]),
          f"got {r['findings']}")


def test_rome_post_escape_covert_compute():
    v = AgentSandboxIsolationVerifier()
    # escaped + uniform clock + low mem-bw + high util = mining signature (ROME)
    procs = [{"pid": 101, "gpu_index": 0, "vram_mb": 8000, "util_pct": 99,
              "sm_clock_uniform": True, "mem_bw_util_pct": 6}]
    r = v.verify(_allocs(), procs)
    check("sandbox: ROME escape-to-mining -> POST_ESCAPE_COVERT_COMPUTE",
          any(f["type"] == "POST_ESCAPE_COVERT_COMPUTE" for f in r["findings"]),
          f"got {r['findings']}")
    check("sandbox: ROME incident is CRITICAL",
          r["severity"] == "CRITICAL", f"got {r['severity']}")


def test_cross_sandbox_vram_residual():
    v = AgentSandboxIsolationVerifier()
    procs = [{"pid": 101, "gpu_index": 0, "vram_mb": 1800, "util_pct": 45},
             {"pid": 102, "gpu_index": 0, "vram_mb": 1900, "util_pct": 48}]
    residual = [{"reader_sandbox": "agent-B", "source_sandbox": "agent-A",
                 "bytes_readable": 512 * 1024 * 1024}]
    r = v.verify(_allocs(), procs, residual)
    check("sandbox: cross-sandbox residual read -> CROSS_SANDBOX_VRAM_RESIDUAL",
          any(f["type"] == "CROSS_SANDBOX_VRAM_RESIDUAL" for f in r["findings"]),
          f"got {r['findings']}")
    check("sandbox: cross-sandbox residual cites LeftoverLocals CVE",
          any("CVE-2023-4969" in str(f.get("cve", "")) for f in r["findings"]
              if f["type"] == "CROSS_SANDBOX_VRAM_RESIDUAL"), "cve missing")
    check("sandbox: cross-sandbox residual is CRITICAL",
          r["severity"] == "CRITICAL", f"got {r['severity']}")


def test_undeclared_gpu_process():
    v = AgentSandboxIsolationVerifier()
    procs = [{"pid": 101, "gpu_index": 0, "vram_mb": 1800, "util_pct": 45},
             {"pid": 999, "gpu_index": 0, "vram_mb": 500, "util_pct": 10}]  # PID not in any sandbox
    r = v.verify(_allocs(), procs)
    check("sandbox: unmapped GPU PID -> UNDECLARED_GPU_PROCESS",
          any(f["type"] == "UNDECLARED_GPU_PROCESS" and f["pid"] == 999 for f in r["findings"]),
          f"got {r['findings']}")


def test_differentiator_note_present():
    v = AgentSandboxIsolationVerifier()
    procs = [{"pid": 101, "gpu_index": 0, "vram_mb": 8000, "util_pct": 45}]
    r = v.verify(_allocs(), procs)
    check("sandbox: result carries the GPU-layer differentiator note",
          "kernel-level isolation" in r["differentiator_note"], "note missing")


def test_escape_never_autokills():
    v = AgentSandboxIsolationVerifier()
    procs = [{"pid": 101, "gpu_index": 0, "vram_mb": 8000, "util_pct": 99}]
    r = v.verify(_allocs(), procs)
    check("sandbox: remediation is gated, no auto-kill",
          r["recommended_action"]["risk"] == "gated_no_autokill", f"got {r['recommended_action']}")


# --------------------------------------------------------------------------
# Swarm correlator
# --------------------------------------------------------------------------
def test_escape_incident_from_signal():
    clock = {"t": 1000.0}
    c = SandboxSwarmCorrelator(time_fn=lambda: clock["t"])
    out = c.observe({"swarm_signal": "AGENT_SANDBOX_ESCAPE"})
    check("swarm: AGENT_SANDBOX_ESCAPE alone fires the escape incident",
          any(i["incident"] == "AGENT_SANDBOX_ESCAPE_INCIDENT" for i in out), f"got {out}")


def test_multi_agent_isolation_collapse():
    clock = {"t": 2000.0}
    c = SandboxSwarmCorrelator(time_fn=lambda: clock["t"])
    c.observe({"swarm_signal": "AGENT_SANDBOX_ESCAPE"})
    clock["t"] += 2
    out = c.observe({"type": "SDC_CORRUPTION_DETECTED"})
    check("swarm: escape + SDC -> MULTI_AGENT_ISOLATION_COLLAPSE",
          any(i["incident"] == "MULTI_AGENT_ISOLATION_COLLAPSE" for i in out), f"got {out}")


def test_swarm_dedupes():
    clock = {"t": 3000.0}
    c = SandboxSwarmCorrelator(time_fn=lambda: clock["t"])
    first = c.observe({"swarm_signal": "AGENT_SANDBOX_ESCAPE"})
    clock["t"] += 1
    second = c.observe({"swarm_signal": "AGENT_SANDBOX_ESCAPE"})
    check("swarm: escape incident de-dupes within window",
          any(i["incident"] == "AGENT_SANDBOX_ESCAPE_INCIDENT" for i in first)
          and not any(i["incident"] == "AGENT_SANDBOX_ESCAPE_INCIDENT" for i in second),
          f"first={[i['incident'] for i in first]} second={[i['incident'] for i in second]}")


def test_swarm_outside_window():
    clock = {"t": 4000.0}
    c = SandboxSwarmCorrelator(window_seconds=30.0, time_fn=lambda: clock["t"])
    c.observe({"swarm_signal": "AGENT_SANDBOX_ESCAPE"})
    clock["t"] += 100
    out = c.observe({"type": "SDC_CORRUPTION_DETECTED"})
    check("swarm: signals outside window do not fuse",
          not any(i["incident"] == "MULTI_AGENT_ISOLATION_COLLAPSE" for i in out), f"got {out}")


if __name__ == "__main__":
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for t in tests:
        try:
            t()
        except Exception as e:
            check(t.__name__, False, f"EXCEPTION {e!r}")
    print("\n" + "=" * 60)
    print(f"PASSED: {len(PASSED)}   FAILED: {len(FAILED)}")
    if FAILED:
        print("\nFailures:")
        for f in FAILED:
            print(f"  - {f}")
    print("=" * 60)
    sys.exit(1 if FAILED else 0)
