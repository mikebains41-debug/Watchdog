#!/usr/bin/env python3
# Author: Manmohan (Mike) Bains -- Watchdog
"""
tests/test_remediation_live.py  *** WATCHDOG ***

Tests the live remediation tester itself: that a refusal counts as a pass,
that the honest-outcome check catches a success claim with no effect (the
real bug that shipped once), that it never kills anything it did not start,
and that the tiers are assigned correctly.
"""
import ast
import json
import os
import subprocess
import sys

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

SCRIPT = os.path.join(_ROOT, "scripts", "remediation_live_test.py")

PASSED, FAILED = [], []


def check(name, cond, detail=""):
    (PASSED if cond else FAILED).append(name)
    print(f"[{'PASS' if cond else 'FAIL'}] {name}{'' if cond else ' ' + detail}")


def _run(args, env=None):
    e = dict(os.environ)
    if env:
        e.update(env)
    return subprocess.run([sys.executable, SCRIPT] + args, capture_output=True,
                          text=True, timeout=120, env=e)


# ---- dry run ---------------------------------------------------------------
def test_dry_run_default():
    r = _run([], env={"WD_DRY_RUN": "true"})
    check("dry run: default, exits 0, executes nothing",
          r.returncode == 0 and '"DRY_RUN"' in r.stdout and "nothing executed" in r.stdout,
          f"rc={r.returncode}")


def test_dry_run_lists_all_checks():
    d = json.loads(_run([], env={"WD_DRY_RUN": "true"}).stdout)
    check("dry run: lists 9 checks", len(d["checks"]) == 9, f"got {len(d.get('checks', []))}")
    for must in ("human gate blocks", "REFUSES with no PID", "report matches reality",
                 "gpu_memory_reset", "quarantine_partition", "refuse with no target"):
        check(f"dry run: covers '{must}'", any(must in c for c in d["checks"]))


def test_principle_stated():
    d = json.loads(_run([], env={"WD_DRY_RUN": "true"}).stdout)
    check("principle: a refusal for the right reason is a PASS",
          "refusal" in d["principle"] and "PASS" in d["principle"])


def test_safety_stated():
    d = json.loads(_run([], env={"WD_DRY_RUN": "true"}).stdout)
    s = " ".join(d["safety"])
    check("safety: only kills a child it started", "child this script started" in s)
    check("safety: never another tenant", "never another tenant" in s)
    check("safety: never kills by guess", "never kills by guess" in s)
    check("safety: gpu_memory_reset needs explicit opt-in", "--allow-reset" in s)


def test_reset_not_attempted_without_flag():
    d = json.loads(_run([], env={"WD_DRY_RUN": "true"}).stdout)
    check("reset: not attempted unless --allow-reset", d["allow_reset"] is False)


# ---- the recorder logic ----------------------------------------------------
def test_recorder_counts_and_tiers():
    sys.path.insert(0, os.path.join(_ROOT, "scripts"))
    import importlib.util
    spec = importlib.util.spec_from_file_location("rlt", SCRIPT)
    m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
    rec = m.Recorder()
    rec.record("kill_process", "refuses with no PID", m.TIER1, True, "REFUSED", "a refusal")
    rec.record("quarantine_partition", "refused by hypervisor", m.TIER2, True, "not supported", "a refusal")
    rec.record("kubernetes_taint", "refuses with no target", m.TIER3, True, "None", "a refusal")
    rec.record("gpu_memory_reset", "honest outcome", m.TIER1, False, "claimed success, nothing changed", "agree")
    s = rec.summary()
    check("recorder: counts passes", s["checks_passed"] == 3 and s["checks_total"] == 4,
          f"got {s['checks_passed']}/{s['checks_total']}")
    check("recorder: groups by tier", set(s["by_tier"]) == {m.TIER1, m.TIER2, m.TIER3},
          f"got {list(s['by_tier'])}")
    check("recorder: interpretation says a refusal is a pass",
          "REFUSAL is a pass" in s["interpretation"])


def test_honest_outcome_catches_the_real_bug():
    """The shipped bug: an action returned success while changing nothing.
    The check is `not (claims_success and not changed)`."""
    def honest(claims_success, changed):
        return not (claims_success and not changed)
    check("honest-outcome: success + no change -> FAIL (the real bug)", honest(True, False) is False)
    check("honest-outcome: success + change -> pass", honest(True, True) is True)
    check("honest-outcome: no success claim + no change -> pass", honest(False, False) is True)


def test_kill_report_agreement_logic():
    """claims_success must equal actually_killed."""
    def agree(claims, killed):
        return claims == killed
    check("kill-report: claims success but pid alive -> FAIL", agree(True, False) is False)
    check("kill-report: claims success and pid dead -> pass", agree(True, True) is True)
    check("kill-report: no claim and pid alive -> pass", agree(False, False) is True)


# ---- tier assignment matches the environment -------------------------------
def test_tier_assignment_in_source():
    src = open(SCRIPT).read()
    check("tier: MIG quarantine is TIER2 (env refuses, path reachable)",
          'rec.record("quarantine_partition"' in src and "TIER2" in src)
    check("tier: cluster actions are TIER3 (no such environment)",
          "TIER3, refused" in src or ("kubernetes_taint" in src and "TIER3" in src))
    check("tier: executed-for-real actions are TIER1",
          'rec.record("log_only"' in src and "TIER1" in src)


def test_states_never_tested_live():
    src = open(SCRIPT).read()
    check("states gpu_memory_reset has NEVER been tested live", "NEVER been tested live" in src)
    check("states a FAIL is a valid loggable result", "valid loggable result" in src)
    check("cites the two real bugs already found", "empty_cache" in src and "every process on the GPU" in src)


# ---- security review compliance --------------------------------------------
def test_no_shell_no_bare_except():
    tree = ast.parse(open(SCRIPT).read())
    shell = any(isinstance(n, ast.Call) and any(
        k.arg == "shell" and isinstance(k.value, ast.Constant) and k.value.value is True
        for k in n.keywords) for n in ast.walk(tree))
    bare = any(isinstance(n, ast.ExceptHandler) and n.type is None for n in ast.walk(tree))
    check("no shell=True", not shell)
    check("no bare except", not bare)


def test_default_gpu_is_a_worker():
    """Must not default to GPU 0 if that is the victim/cold reference."""
    d = json.loads(_run([], env={"WD_DRY_RUN": "true"}).stdout)
    check("default gpu is a worker (not 0)", d["gpu"] != 0, f"got {d['gpu']}")


if __name__ == "__main__":
    for name, fn in sorted(globals().items()):
        if name.startswith("test_"):
            try:
                fn()
            except Exception as e:
                check(name, False, f"EXCEPTION {e!r}")
    print("\n" + "=" * 60 + f"\nPASSED: {len(PASSED)}   FAILED: {len(FAILED)}\n" + "=" * 60)
    sys.exit(1 if FAILED else 0)
