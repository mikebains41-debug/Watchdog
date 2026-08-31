#!/usr/bin/env python3
# Author: Manmohan (Mike) Bains -- Watchdog
"""
sandbox_validator.py -- Isolated Remediation-Action Validator
Part of Watchdog AI-Attack Detection Suite.

PURPOSE
-------
When the remediation coordinator proposes an action (or a human is about
to approve one), this validates that the action's script runs correctly
inside a LOCKED-DOWN, network-isolated, resource-capped container BEFORE
it is ever run against real infrastructure. It confirms the action does
what it claims without breaking, without reaching the network, and within
strict resource bounds.

This is explicitly NOT auto-patching. It does not write fixes and it does
not deploy anything. It is a safety gate: run the proposed action in a
sandbox, capture the result, hand the result to a human for the final
gated approval. Validates, never auto-applies.

HARDENING (the container flags this builds)
-------------------------------------------
- --network none          : no network egress at all
- --memory / --cpus       : hard resource caps (Denial-of-Wallet / runaway guard)
- --read-only             : read-only root filesystem
- --cap-drop ALL          : drop all Linux capabilities
- --security-opt no-new-privileges
- --pids-limit            : bound process count (fork-bomb guard)
- non-root user           : run as an unprivileged uid
- --rm                    : ephemeral, auto-removed

DESIGN
------
Two modes:
  build_sandbox_command(...)  -> returns the exact hardened `docker run`
      argument list WITHOUT running it (pure, always testable).
  validate(...)               -> optionally executes it via an injected
      runner (subprocess.run by default). Left un-run in tests.

If Docker is unavailable, validate() returns SANDBOX_UNAVAILABLE (graceful
fallback) rather than silently doing nothing dangerous.

NOTE: Simulation-based. Requires real hardware validation. On a real
deployment the container image must contain the action runtime; this
module builds the invocation + interprets the result, it does not ship
the image.
"""

import shlex
import subprocess
from datetime import datetime, timezone


DEFAULT_LIMITS = {
    "memory": "256m",
    "cpus": "0.5",
    "pids_limit": 128,
    "timeout_s": 60,
    "user": "65534:65534",   # nobody:nogroup
}


def build_sandbox_command(image: str,
                          action_cmd: list,
                          limits: dict = None) -> list:
    """
    Build the hardened `docker run` argument list. Pure -- does not execute.
    action_cmd: the command (as a list) to run INSIDE the container.
    """
    lim = {**DEFAULT_LIMITS, **(limits or {})}
    cmd = [
        "docker", "run", "--rm",
        "--network", "none",
        "--read-only",
        "--cap-drop", "ALL",
        "--security-opt", "no-new-privileges",
        "--memory", str(lim["memory"]),
        "--cpus", str(lim["cpus"]),
        "--pids-limit", str(lim["pids_limit"]),
        "--user", str(lim["user"]),
        # writable scratch only in a capped tmpfs, nothing else writable
        "--tmpfs", "/tmp:rw,noexec,nosuid,size=64m",
        image,
    ]
    cmd.extend(action_cmd)
    return cmd


def _docker_available(runner) -> bool:
    try:
        r = runner(["docker", "version"], capture_output=True, text=True, timeout=10)
        return r.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        return False


def validate(image: str,
             action_cmd: list,
             expected_substring: str = None,
             limits: dict = None,
             runner=subprocess.run) -> dict:
    """
    Run the proposed action in the hardened sandbox and report the result.
    expected_substring: if given, the action PASSES only if stdout contains it.
    """
    lim = {**DEFAULT_LIMITS, **(limits or {})}
    if not _docker_available(runner):
        return {"status": "SANDBOX_UNAVAILABLE",
                "message": "docker not available; cannot validate in isolation",
                "note": "action must NOT be applied without sandbox validation"}

    cmd = build_sandbox_command(image, action_cmd, limits)
    try:
        proc = runner(cmd, capture_output=True, text=True, timeout=lim["timeout_s"])
    except subprocess.TimeoutExpired:
        return {"status": "SANDBOX_TIMEOUT",
                "command": " ".join(shlex.quote(c) for c in cmd),
                "detail": f"action exceeded {lim['timeout_s']}s in sandbox -- treat as FAIL",
                "note": "do NOT apply an action that hangs the sandbox"}

    passed = (proc.returncode == 0)
    if passed and expected_substring is not None:
        passed = expected_substring in (proc.stdout or "")

    return {
        "status": "SANDBOX_VALIDATED" if passed else "SANDBOX_FAILED",
        "passed": passed,
        "returncode": proc.returncode,
        "stdout_tail": (proc.stdout or "")[-500:],
        "stderr_tail": (proc.stderr or "")[-500:],
        "command": " ".join(shlex.quote(c) for c in cmd),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "execution": "SANDBOX_ONLY -- result routed to human for gated approval",
        "note": ("Simulation-based. A PASS here means the action ran cleanly "
                 "in isolation; it still requires human approval before being "
                 "applied to real infrastructure."),
    }


if __name__ == "__main__":
    # Show the hardened command it would build (no docker needed to see this).
    cmd = build_sandbox_command("watchdog/action-runtime:latest",
                                ["python", "-c", "print('remediation ok')"])
    print("[SANDBOX] hardened command:")
    print("  " + " ".join(cmd))
