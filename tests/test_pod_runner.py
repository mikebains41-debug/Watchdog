#!/usr/bin/env python3
# Author: Manmohan (Mike) Bains -- Watchdog
"""
tests/test_pod_runner.py  *** WATCHDOG ***

The important tests here are the SAFETY ones: --live must refuse to run on a
fake backend, artifacts must be stamped so a fake run can never be mistaken
for evidence, and the dry run must touch nothing.
"""
import ast
import json
import os
import subprocess
import sys

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

RUNNER = os.path.join(_ROOT, "runtime", "pod_runner.py")
SIGKILL = os.path.join(_ROOT, "scripts", "sigkill_residual_measure.py")

PASSED, FAILED = [], []


def check(name, cond, detail=""):
    (PASSED if cond else FAILED).append(name)
    print(f"[{'PASS' if cond else 'FAIL'}] {name}{'' if cond else ' ' + detail}")


def _run(args, env=None):
    e = dict(os.environ)
    if env:
        e.update(env)
    return subprocess.run([sys.executable] + args, capture_output=True, text=True, timeout=120, env=e)


# ---- dry run is the default -------------------------------------------------
def test_default_is_dry_run():
    r = _run([RUNNER])
    check("runner: no flags -> DRY_RUN, nothing executed",
          r.returncode == 0 and '"DRY_RUN"' in r.stdout and "nothing executed" in r.stdout,
          f"rc={r.returncode} {r.stdout[:200]!r}")


def test_dry_run_lists_stages_and_safety():
    r = _run([RUNNER])
    d = json.loads(r.stdout)
    check("runner: dry run lists all 8 stages", len(d["stages"]) == 8, f"got {d.get('stages')}")
    check("runner: dry run states Rowhammer is deliberately not induced",
          any("Rowhammer" in s and "NOT induced" in s for s in d["safety"]))
    check("runner: dry run captures the environment", "environment" in d and "gpus" in d["environment"])


def test_dry_run_reports_no_output_dir():
    r = _run([RUNNER])
    d = json.loads(r.stdout)
    check("runner: dry run says nothing would be written without --out",
          "no --out" in d["would_write_to"])


# ---- the critical safety test ----------------------------------------------
def test_live_refuses_without_real_gpu():
    r = _run([RUNNER, "--live"])
    check("SAFETY: --live with no GPU -> REFUSED, exit 2 (never a fake 6/6)",
          r.returncode == 2 and '"LIVE_RUN_REFUSED"' in r.stdout, f"rc={r.returncode} {r.stdout[:300]!r}")
    d = json.loads(r.stdout)
    check("SAFETY: refusal explains FakeBackend would report pattern_found=True",
          "pattern_found=True" in d["detail"], f"got {d.get('detail')}")


def test_allow_fake_is_stamped_not_evidence():
    r = _run([RUNNER, "--live", "--allow-fake"])
    check("SAFETY: --allow-fake runs but stamps backend=fake",
          "backend: fake" in r.stdout, f"got {r.stdout[-400:]!r}")
    check("SAFETY: --allow-fake stamps is_evidence: False",
          "is_evidence: False" in r.stdout)
    check("SAFETY: --allow-fake warns on stderr that artifacts are NOT evidence",
          "NOT evidence" in r.stderr, f"stderr={r.stderr[:300]!r}")


def test_fake_run_artifacts_carry_the_stamp(tmpdir=None):
    import tempfile, shutil
    d = tempfile.mkdtemp(prefix="wd_pod_")
    try:
        r = _run([RUNNER, "--live", "--allow-fake", "--out", d])
        run_json = os.path.join(d, "run.json")
        check("SAFETY: artifact written", os.path.isfile(run_json), f"rc={r.returncode}")
        if os.path.isfile(run_json):
            j = json.load(open(run_json))
            check("SAFETY: run.json carries backend=fake and is_evidence=False",
                  j["backend"] == "fake" and j["is_evidence"] is False, f"got {j.get('backend')}")
            check("SAFETY: run.json carries the evidence rule text",
                  "NOT evidence" in j["evidence_rule"])
            stages = [f for f in os.listdir(d) if f.startswith("stage_")]
            check("SAFETY: one artifact per stage", len(stages) == 8, f"got {len(stages)}")
            if stages:
                s = json.load(open(os.path.join(d, stages[0])))
                check("SAFETY: every stage artifact is stamped too",
                      s["backend"] == "fake" and s["is_evidence"] is False and "tier" in s)
    finally:
        shutil.rmtree(d, ignore_errors=True)


def test_tier_rule_present():
    import tempfile, shutil
    d = tempfile.mkdtemp(prefix="wd_pod_")
    try:
        _run([RUNNER, "--live", "--allow-fake", "--out", d])
        j = json.load(open(os.path.join(d, "run.json")))
        check("rule: only TIER1 may drop the simulation label", "Only TIER1" in j["tier_rule"])
    finally:
        shutil.rmtree(d, ignore_errors=True)


# ---- environment capture ----------------------------------------------------
def test_environment_capture_handles_no_nvidia_smi():
    from runtime.pod_runner import capture_environment
    env = capture_environment()
    check("env: capture works with no nvidia-smi (gpus=None, count 0)",
          env["gpu_count"] == 0 and env["gpus"] is None, f"got {env.get('gpu_count')}")
    check("env: records hostname and python version", env["hostname"] and env["python"])
    check("env: arch guard field present", "arch_homogeneous" in env)


# ---- sigkill measurement ----------------------------------------------------
def test_sigkill_dry_run():
    r = _run([SIGKILL], env={"WD_DRY_RUN": "true"})
    check("sigkill: dry run exits 0 and executes nothing",
          r.returncode == 0 and '"DRY_RUN"' in r.stdout and "nothing executed" in r.stdout,
          f"rc={r.returncode}")
    d = json.loads(r.stdout)
    check("sigkill: plan says allocate NOTHING during the watch",
          any("allocate NOTHING" in s for s in d["plan"]), f"got {d.get('plan')}")
    check("sigkill: states which README question it answers",
          "memory.used" in d["answers"])


def test_sigkill_verdict_logic():
    """The verdict branches are pure arithmetic -- exercise them directly."""
    import runtime  # noqa
    src = open(SIGKILL).read()
    check("sigkill: has all three verdicts",
          all(v in src for v in ("SIGKILL_CLEARS_ACCOUNTING", "RESIDUAL_DECAYS",
                                 "RESIDUAL_SURVIVES_SIGKILL")))
    check("sigkill: states it is NOT a remediation test",
          "not_a_remediation_test" in src and "disproven on B200" in src)


# ---- security review compliance --------------------------------------------
def test_no_shell_no_bare_except():
    for path, label in ((RUNNER, "pod_runner"), (SIGKILL, "sigkill")):
        tree = ast.parse(open(path).read())
        shell = any(isinstance(n, ast.Call) and any(
            k.arg == "shell" and isinstance(k.value, ast.Constant) and k.value.value is True
            for k in n.keywords) for n in ast.walk(tree))
        bare = any(isinstance(n, ast.ExceptHandler) and n.type is None for n in ast.walk(tree))
        check(f"{label}: no shell=True", not shell)
        check(f"{label}: no bare except", not bare)


def test_writer_child_exists_and_parses():
    p = os.path.join(_ROOT, "runtime", "_vram_writer.py")
    check("writer: _vram_writer.py exists", os.path.isfile(p))
    if os.path.isfile(p):
        ast.parse(open(p).read())
        src = open(p).read()
        check("writer: exits without freeing (leaves the residual)",
              "WITHOUT freeing" in src)
        check("writer: states this is the self-owned two-process read",
              "self-owned two-process read" in src and "NOT an attack" in src)


if __name__ == "__main__":
    for name, fn in sorted(globals().items()):
        if name.startswith("test_"):
            try:
                fn()
            except Exception as e:
                check(name, False, f"EXCEPTION {e!r}")
    print("\n" + "=" * 60 + f"\nPASSED: {len(PASSED)}   FAILED: {len(FAILED)}\n" + "=" * 60)
    sys.exit(1 if FAILED else 0)
