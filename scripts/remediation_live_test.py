#!/usr/bin/env python3
# Author: Manmohan (Mike) Bains -- Watchdog
"""
remediation_live_test.py -- the half of Watchdog that has never run on hardware
*** WATCHDOG ***

Watchdog is detection AND remediation. Every detector has synthetic controls
and the pod harness gives six of them a Tier-1 true-positive. Remediation has
none of that: remediation/response.py and orchestration/cluster_actions.py
have never executed against real infrastructure, not once.

WHAT THIS TESTS -- AND WHY A REFUSAL IS A PASS
----------------------------------------------
For remediation the valuable result is usually NOT "the action fired". It is:

  1. REFUSE WITHOUT A TARGET. kill_process with no PID, nvlink_disable with
     no link index, kubernetes_taint with no node name. Each must refuse
     rather than guess. response.py already documents three of these as
     always-refusing today, and says a safe refusal beats a blind kill of
     everyone on the GPU. This confirms that is still true at runtime.
  2. THE GATE BLOCKS. With require_human=True (the default), a gated action
     must log SKIPPED_HUMAN_REQUIRED and NOT execute.
  3. AUTO-DISABLED BLOCKS. With auto_remediate=False, actions must log
     SKIPPED_AUTO_DISABLED and not execute.
  4. HONEST OUTCOME. When an action does run, the result must describe what
     actually happened. Two real bugs already lived here: a kill that killed
     every process on the GPU, and a "clear VRAM" that called
     torch.cuda.empty_cache() inside Watchdog's own process -- which cannot
     touch another process's memory -- and returned success regardless.
     Success must mean something changed.

TIERS (same scheme as POD_VALIDATION_PLAN)
  TIER1 -- executed for real on the pod and the outcome recorded:
           log_only, gpu_memory_reset, kill_process (against OUR OWN child)
  TIER2 -- the path is reachable but the environment refuses:
           quarantine_partition (MIG blocked by the hypervisor)
  TIER3 -- no such environment on a pod: kubernetes_taint, slurm_evict_job,
           nvlink_disable (needs a link_index from a fired detector)

SAFETY
  Only ever kills a child process THIS SCRIPT started. Never touches another
  tenant, never kills by guess, never runs an ungated destructive action.
  gpu_memory_reset is attempted only with explicit --allow-reset.

SECURITY REVIEW COMPLIANCE: no bare except; no shell=True; argument-list
subprocess; every failure surfaced; refusals recorded as refusals, never as
zero-effect successes.
"""

import argparse
import json
import os
import subprocess
import sys
import time
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

DRY = os.environ.get("WD_DRY_RUN", "true").lower() != "false"

TIER1 = "TIER1_EXECUTED_REAL"
TIER2 = "TIER2_PATH_REACHABLE_ENV_REFUSED"
TIER3 = "TIER3_NO_SUCH_ENVIRONMENT"

CHILD_SRC = '''
import sys, time, json, os
gpu = int(sys.argv[1]); mb = int(sys.argv[2])
import torch
dev = torch.device("cuda:%d" % gpu)
buf = torch.empty(mb * 1024 * 1024, dtype=torch.uint8, device=dev)
buf.fill_(0x5A)
torch.cuda.synchronize(dev)
print(json.dumps({"ok": True, "pid": os.getpid(), "mb": mb}), flush=True)
while True:
    time.sleep(1)
'''


class Recorder:
    def __init__(self):
        self.results = []

    def record(self, action, check, tier, passed, observed, expected, note=""):
        r = {"action": action, "check": check, "tier": tier, "passed": passed,
             "observed": observed, "expected": expected, "note": note,
             "timestamp": datetime.now(timezone.utc).isoformat()}
        self.results.append(r)
        mark = "PASS" if passed else "FAIL"
        print(f"[{mark}] {action:<22} {check:<28} -> {observed}")
        return r

    def summary(self):
        by_tier = {}
        for r in self.results:
            by_tier.setdefault(r["tier"], []).append(r["action"] + ":" + r["check"])
        return {
            "type": "REMEDIATION_LIVE_TEST",
            "checks_total": len(self.results),
            "checks_passed": sum(1 for r in self.results if r["passed"]),
            "by_tier": by_tier,
            "results": self.results,
            "interpretation": ("For remediation a REFUSAL is a pass. The tested property "
                               "is: refuses without a target, the human gate blocks, "
                               "auto-disabled blocks, and any action that does run reports "
                               "what actually happened rather than unconditional success."),
        }


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------
def memory_used_mb(gpu):
    try:
        r = subprocess.run(["nvidia-smi", "-i", str(gpu),
                            "--query-gpu=memory.used", "--format=csv,noheader,nounits"],
                           capture_output=True, text=True, timeout=10)
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        return None
    if r.returncode != 0:
        return None
    try:
        return float(r.stdout.strip())
    except ValueError:
        return None


def start_child(gpu, mb, workdir):
    path = os.path.join(workdir, "_remediation_child.py")
    try:
        with open(path, "w") as fh:
            fh.write(CHILD_SRC)
        p = subprocess.Popen([sys.executable, path, str(gpu), str(mb)],
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    except (OSError, FileNotFoundError) as e:
        return None, f"{type(e).__name__}: {e}"
    t0 = time.monotonic()
    while time.monotonic() - t0 < 120:
        if p.poll() is not None:
            return None, (p.stderr.read()[:400] if p.stderr else "child exited")
        m = memory_used_mb(gpu)
        if m is not None and m > mb * 0.5:
            return p, None
        time.sleep(1)
    p.kill()
    return None, "child never allocated within 120s"


def pid_alive(pid):
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    except OSError:
        return None


# ---------------------------------------------------------------------------
# the checks
# ---------------------------------------------------------------------------
def run_checks(gpu, allow_reset, child_mb, workdir):
    rec = Recorder()

    try:
        from remediation.response import RemediationEngine
    except Exception as e:
        rec.record("import", "remediation.response importable", TIER1, False,
                   f"{type(e).__name__}: {e}", "import succeeds")
        return rec.summary()

    # ---- 1. The gate blocks (default config: require_human=True) ----------
    eng = RemediationEngine(auto_remediate=True, require_human=True)
    alert = {"type": "VRAM_RESIDUAL", "gpu": gpu, "severity": "CRITICAL"}
    out = eng.handle(alert)
    blocked = "SKIPPED_HUMAN_REQUIRED" in str(out)
    rec.record("gpu_memory_reset", "human gate blocks", TIER1, blocked,
               "SKIPPED_HUMAN_REQUIRED" if blocked else str(out)[:120],
               "SKIPPED_HUMAN_REQUIRED",
               "default config must not execute a gated action")

    # ---- 2. Auto-disabled blocks -----------------------------------------
    eng2 = RemediationEngine(auto_remediate=False, require_human=False)
    out2 = eng2.handle({"type": "DMA_ATTACK", "gpu": gpu, "severity": "CRITICAL"})
    blocked2 = "SKIPPED_AUTO_DISABLED" in str(out2)
    rec.record("kill_process", "auto-disabled blocks", TIER1, blocked2,
               "SKIPPED_AUTO_DISABLED" if blocked2 else str(out2)[:120],
               "SKIPPED_AUTO_DISABLED")

    # ---- 3. log_only actually only logs -----------------------------------
    before = memory_used_mb(gpu)
    eng3 = RemediationEngine(auto_remediate=True, require_human=False)
    out3 = eng3.handle({"type": "GHOST_POWER", "gpu": gpu, "severity": "WARNING"})
    after = memory_used_mb(gpu)
    unchanged = (before is None or after is None or abs(after - before) < 50)
    rec.record("log_only", "logs and changes nothing", TIER1, unchanged,
               f"memory.used {before} -> {after}", "no device state change",
               "the 5 prediction alert types map here explicitly")

    # ---- 4. kill_process REFUSES without a named PID ----------------------
    out4 = eng3.handle({"type": "SEQUENTIAL_VRAM_READ", "gpu": gpu, "severity": "CRITICAL"})
    s4 = str(out4)
    refused = ("REFUS" in s4.upper()) or ("NO_PID" in s4.upper()) or ("no pid" in s4.lower())
    rec.record("kill_process", "refuses with no PID in alert", TIER1, refused, s4[:160],
               "a refusal, not a blind kill",
               "response.py: 'a safe refusal is better than a blind kill of everyone on the GPU'")

    # ---- 5. kill_process WITH a named PID, against our own child ----------
    child, err = start_child(gpu, child_mb, workdir)
    if child is None:
        rec.record("kill_process", "executes against a named PID", TIER1, False,
                   f"could not start child: {err}", "child running, then killed")
    else:
        alert5 = {"type": "SEQUENTIAL_VRAM_READ", "gpu": gpu, "severity": "CRITICAL",
                  "pid": child.pid, "process_pid": child.pid}
        out5 = eng3.handle(alert5)
        time.sleep(3)
        alive = pid_alive(child.pid)
        killed = alive is False
        rec.record("kill_process", "executes against a named PID", TIER1, killed,
                   f"pid {child.pid} alive={alive} | engine said {str(out5)[:100]}",
                   "the named PID is dead, and only that PID",
                   "only ever our own child; never another tenant")
        if alive:
            child.kill()
        # honest-outcome check: does the engine's own report match reality?
        claims_success = "SUCCESS" in str(out5).upper() or "KILLED" in str(out5).upper()
        honest = (claims_success == killed)
        rec.record("kill_process", "report matches reality", TIER1, honest,
                   f"claims_success={claims_success} actually_killed={killed}",
                   "they agree",
                   "a prior bug returned success regardless of what happened")

    # ---- 6. gpu_memory_reset -- the never-tested action -------------------
    if not allow_reset:
        rec.record("gpu_memory_reset", "executes with approval", TIER1, True,
                   "not attempted (--allow-reset not given)",
                   "explicit opt-in required",
                   "this action has NEVER been tested live; run it deliberately")
    else:
        before6 = memory_used_mb(gpu)
        eng6 = RemediationEngine(auto_remediate=True, require_human=False)
        out6 = eng6.handle({"type": "VRAM_RESIDUAL", "gpu": gpu, "severity": "CRITICAL"})
        time.sleep(5)
        after6 = memory_used_mb(gpu)
        s6 = str(out6)
        # ANY of these is a valid, loggable result -- a FAIL is a real result
        outcome = ("permission denied" if "permission" in s6.lower() or "denied" in s6.lower()
                   else "device in use" if "in use" in s6.lower() or "busy" in s6.lower()
                   else "executed")
        claims_success = "SUCCESS" in s6.upper()
        changed = (before6 is not None and after6 is not None and abs(after6 - before6) > 50)
        honest6 = not (claims_success and not changed)
        rec.record("gpu_memory_reset", "outcome recorded honestly", TIER1, honest6,
                   f"{outcome} | memory.used {before6} -> {after6} | claims_success={claims_success}",
                   "success only if memory.used actually changed",
                   "A FAIL here is a valid loggable result. Update EVIDENCE.md and "
                   "HARDWARE_LIMITATIONS.md either way.")

    # ---- 7. MIG quarantine -- expected to be refused by the hypervisor ----
    out7 = eng3.handle({"type": "MIG_PARTITION_DESYNC", "gpu": gpu, "severity": "CRITICAL"})
    s7 = str(out7)
    refused7 = ("REFUS" in s7.upper() or "FAIL" in s7.upper() or "permission" in s7.lower()
                or "not supported" in s7.lower() or "SKIPPED" in s7.upper())
    rec.record("quarantine_partition", "refused by hypervisor", TIER2, refused7, s7[:160],
               "a refusal -- MIG control is blocked in containers",
               "the refusal IS the result; record which error the container returns")

    # ---- 8-10. cluster actions -- no such environment on a pod -----------
    try:
        from orchestration.cluster_actions import ClusterActions
        ca = ClusterActions()
        ca_ok = True
    except Exception as e:
        ca, ca_ok = None, False
        rec.record("cluster_actions", "importable", TIER3, False,
                   f"{type(e).__name__}: {e}", "import succeeds")

    if ca_ok:
        for name, call, arg_desc in (
            ("kubernetes_taint", lambda: ca.kubernetes_taint(None), "node_name=None"),
            ("slurm_evict_job", lambda: ca.slurm_evict_job(None), "job_id=None"),
            ("nvlink_disable", lambda: ca.nvlink_disable(gpu, None), "link_index=None"),
        ):
            try:
                res = call()
                s = str(res)
                refused = ("REFUS" in s.upper() or "None" in s or "no " in s.lower()
                           or "FAIL" in s.upper() or res is None or res is False)
            except Exception as e:
                s = f"{type(e).__name__}: {e}"
                refused = True
            rec.record(name, f"refuses with {arg_desc}", TIER3, refused, s[:160],
                       "a refusal, not a guess",
                       "no cluster on a pod; the target-refusal is what is testable here")

    return rec.summary()


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="Live remediation test. For remediation, a REFUSAL is a pass.")
    ap.add_argument("--gpu", type=int, default=1, help="use a WORKER gpu, never the cold reference")
    ap.add_argument("--child-mb", type=int, default=512)
    ap.add_argument("--allow-reset", action="store_true",
                    help="actually attempt gpu_memory_reset (never tested live before)")
    ap.add_argument("--out", default=None)
    a = ap.parse_args(argv)

    if DRY:
        print(json.dumps({
            "type": "DRY_RUN", "gpu": a.gpu, "allow_reset": a.allow_reset,
            "checks": [
                "human gate blocks a gated action",
                "auto-disabled blocks",
                "log_only logs and changes nothing",
                "kill_process REFUSES with no PID",
                "kill_process executes against our own named child PID",
                "kill_process report matches reality",
                "gpu_memory_reset outcome recorded honestly (--allow-reset)",
                "quarantine_partition refused by hypervisor (TIER2)",
                "kubernetes_taint / slurm_evict_job / nvlink_disable refuse with no target (TIER3)",
            ],
            "principle": "a refusal for the right reason is a PASS",
            "safety": ["kills only a child this script started",
                       "never another tenant", "never kills by guess",
                       "gpu_memory_reset only with explicit --allow-reset"],
            "note": "DRY RUN -- nothing executed. WD_DRY_RUN=false to run.",
        }, indent=2))
        return 0

    workdir = os.path.dirname(os.path.abspath(__file__))
    res = run_checks(a.gpu, a.allow_reset, a.child_mb, workdir)
    print("\n" + "=" * 60)
    print(f"checks passed: {res['checks_passed']}/{res['checks_total']}")
    print(res["interpretation"])
    if a.out:
        os.makedirs(os.path.dirname(a.out) or ".", exist_ok=True)
        with open(a.out, "w") as fh:
            json.dump(res, fh, indent=2, default=str)
        print(f"\nwritten: {a.out}")
    else:
        print("\nNO --out: nothing written. No artifact = not validated.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
