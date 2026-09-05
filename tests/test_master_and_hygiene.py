#!/usr/bin/env python3
# Author: Manmohan (Mike) Bains -- Watchdog
"""
tests/test_master_and_hygiene.py  *** WATCHDOG ***

Tests MasterCorrelator (composes all correlators, fail-loud on a broken sub,
master cross-suite rules, full-spectrum) and the AST hygiene auditor
(bare-except detection incl. silent handlers, safe narrowing fix, and the
dead-code audit's inheritance awareness -- the blind spot that would have
deleted a live base class).
"""
import os
import sys
import tempfile
import shutil
import importlib.util

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from intelligence.swarm.master_correlator import MasterCorrelator

PASSED, FAILED = [], []


def check(name, cond, detail=""):
    (PASSED if cond else FAILED).append(name)
    print(f"[{'PASS' if cond else 'FAIL'}] {name}{'' if cond else ' ' + detail}")


class FakeSub:
    def __init__(self, emit_on=None):
        self.seen = []; self.emit_on = emit_on
    def observe(self, a):
        t = a.get("swarm_signal") or a.get("type"); self.seen.append(t)
        return [{"type": "SUB", "incident": "SUB_FIRED"}] if t == self.emit_on else []


class BoomSub:
    def observe(self, a): raise RuntimeError("sub crashed")


# ---- master correlator -----------------------------------------------------
def test_master_loads_or_records_each_spec():
    m = MasterCorrelator()
    s = m.get_stats()
    check("master: every spec is either loaded or recorded not_loaded (never silent)",
          len(s["loaded"]) + len(s["not_loaded"]) == 7, f"got {s}")


def test_master_forwards_and_passes_through():
    sub = FakeSub(emit_on="MICRO_BURST_PATTERN")
    m = MasterCorrelator(extra_correlators=[sub])
    out = m.observe({"type": "MICRO_BURST_PATTERN"})
    check("master: forwards to injected sub and passes its incident through",
          "MICRO_BURST_PATTERN" in sub.seen and any(i.get("incident") == "SUB_FIRED" for i in out), f"got {out}")


def test_master_broken_sub_fails_loud_not_fatal():
    m = MasterCorrelator(extra_correlators=[BoomSub()])
    out = m.observe({"type": "SDC_CORRUPTION_DETECTED"})
    check("master: broken sub -> SUB_CORRELATOR_ERROR surfaced, master continues",
          any(i.get("type") == "SUB_CORRELATOR_ERROR" and "RuntimeError" in i["error"] for i in out), f"got {out}")


def test_master_coordinated_multi_vector():
    clock = {"t": 1000.0}
    m = MasterCorrelator(time_fn=lambda: clock["t"], extra_correlators=[])
    m.observe({"swarm_signal": "AGENT_SANDBOX_ESCAPE"}); clock["t"] += 5
    out = m.observe({"swarm_signal": "REVERSE_TUNNEL"})
    check("master: sandbox escape + reverse tunnel -> COORDINATED_MULTI_VECTOR_ATTACK",
          any(i.get("incident") == "COORDINATED_MULTI_VECTOR_ATTACK" for i in out), f"got {out}")


def test_master_environment_induced():
    clock = {"t": 2000.0}
    m = MasterCorrelator(time_fn=lambda: clock["t"], extra_correlators=[])
    m.observe({"swarm_signal": "SOLAR_PARTICLE_EVENT"}); clock["t"] += 5
    out = m.observe({"type": "SDC_CORRUPTION_DETECTED"})
    check("master: solar storm + SDC -> ENVIRONMENT_INDUCED_INTEGRITY_FAILURE",
          any(i.get("incident") == "ENVIRONMENT_INDUCED_INTEGRITY_FAILURE" for i in out), f"got {out}")


def test_master_low_confidence_window():
    clock = {"t": 3000.0}
    m = MasterCorrelator(time_fn=lambda: clock["t"], extra_correlators=[])
    m.observe({"swarm_signal": "WORKLOAD_UNDERSAMPLED"}); clock["t"] += 1
    out = m.observe({"type": "COMPUTE_INTEGRITY_OK"})
    check("master: undersampled + 'clean' -> LOW_CONFIDENCE_WINDOW (clean is not clean)",
          any(i.get("incident") == "LOW_CONFIDENCE_WINDOW" for i in out), f"got {out}")


def test_master_full_spectrum():
    clock = {"t": 4000.0}
    m = MasterCorrelator(time_fn=lambda: clock["t"], full_spectrum_threshold=4, extra_correlators=[])
    for sig in ("SDC_CORRUPTION_DETECTED", "QUANTUM_CIRCUIT_TAMPER", "REVERSE_TUNNEL"):
        m.observe({"swarm_signal": sig}); clock["t"] += 1
    out = m.observe({"swarm_signal": "SEAWATER_INGRESS_CONFIRMED"})   # 4th distinct suite
    fs = [i for i in out if i.get("incident") == "FULL_SPECTRUM_INCIDENT"]
    check("master: 4 distinct suites -> FULL_SPECTRUM_INCIDENT listing suites",
          fs and len(fs[0]["suites_involved"]) >= 4, f"got {out}")


def test_master_dedupes_and_windows():
    clock = {"t": 5000.0}
    m = MasterCorrelator(window_seconds=60, time_fn=lambda: clock["t"], extra_correlators=[])
    m.observe({"swarm_signal": "AGENT_SANDBOX_ESCAPE"}); clock["t"] += 1
    a = m.observe({"swarm_signal": "REVERSE_TUNNEL"}); clock["t"] += 1
    b = m.observe({"swarm_signal": "REVERSE_TUNNEL"})
    fired = lambda o: any(i.get("incident") == "COORDINATED_MULTI_VECTOR_ATTACK" for i in o)
    check("master: incident fires once, not again within window", fired(a) and not fired(b))
    clock["t"] += 500
    m2 = MasterCorrelator(window_seconds=60, time_fn=lambda: clock["t"], extra_correlators=[])
    m2.observe({"swarm_signal": "AGENT_SANDBOX_ESCAPE"}); clock["t"] += 500
    check("master: signals outside window do not fuse",
          not fired(m2.observe({"swarm_signal": "REVERSE_TUNNEL"})))


# ---- hygiene audit -----------------------------------------------------------
def _load_audit():
    p = os.path.join(_ROOT, "scripts", "repo_hygiene_audit.py")
    spec = importlib.util.spec_from_file_location("repo_hygiene_audit", p)
    mod = importlib.util.module_from_spec(spec); spec.loader.exec_module(mod)
    return mod


def _mini_repo():
    d = tempfile.mkdtemp(prefix="wd_hyg_")
    os.makedirs(os.path.join(d, "scripts")); os.makedirs(os.path.join(d, "detection")); os.makedirs(os.path.join(d, "intelligence"))
    open(os.path.join(d, "intelligence", "base.py"), "w").write(
        "class ThreatIntelEngine:\n    def run(self): return 0\n")
    open(os.path.join(d, "intelligence", "airgap.py"), "w").write(
        "from intelligence.base import ThreatIntelEngine\n"
        "class AirGapped(ThreatIntelEngine):\n    pass\n")
    open(os.path.join(d, "intelligence", "orphan.py"), "w").write("def lonely():\n    return 1\n")
    open(os.path.join(d, "detection", "bad.py"), "w").write(
        "def f():\n    try:\n        x = 1\n    except:\n        pass\n"
        "def g():\n    try:\n        y = 2\n    except Exception:\n        pass\n"
        "def h():\n    try:\n        z = 3\n    except Exception as e:\n        print(e)\n")
    return d


def test_hygiene_finds_bare_and_silent():
    mod = _load_audit(); d = _mini_repo()
    try:
        mod.REPO = d
        f = mod.sweep_bare_except(fix=False)
        kinds = sorted(x["kind"] for x in f)
        check("hygiene: finds 1 BARE_EXCEPT and 1 SILENT_EXCEPTION, not the good handler",
              kinds == ["BARE_EXCEPT", "SILENT_EXCEPTION"], f"got {kinds}")
    finally:
        shutil.rmtree(d, ignore_errors=True)


def test_hygiene_safe_fix_narrows_only_bare():
    mod = _load_audit(); d = _mini_repo()
    try:
        mod.REPO = d
        mod.sweep_bare_except(fix=True)
        src = open(os.path.join(d, "detection", "bad.py")).read()
        check("hygiene: --fix rewrites `except:` -> `except Exception:` only",
              "except Exception:\n        pass" in src and "except:\n" not in src, f"got {src!r}")
        check("hygiene: --fix leaves handler bodies and good handlers untouched",
              src.count("pass") == 2 and "except Exception as e:" in src)
    finally:
        shutil.rmtree(d, ignore_errors=True)


def test_hygiene_ast_dead_audit_sees_inheritance():
    mod = _load_audit(); d = _mini_repo()
    try:
        mod.REPO = d
        r = {x["file"]: x for x in mod.audit_dead(["intelligence/base.py", "intelligence/orphan.py"])}
        base = r["intelligence/base.py"]
        check("hygiene: base class used only via inheritance -> LIVE (regex version missed this)",
              base["state"] == "LIVE" and any("inherit" in kinds for _, kinds in base["used"]["ThreatIntelEngine"]),
              f"got {base}")
        check("hygiene: module nobody imports or uses -> ORPHAN",
              r["intelligence/orphan.py"]["state"] == "ORPHAN", f"got {r['intelligence/orphan.py']}")
    finally:
        shutil.rmtree(d, ignore_errors=True)


def test_hygiene_missing_file():
    mod = _load_audit(); d = _mini_repo()
    try:
        mod.REPO = d
        r = mod.audit_dead(["nope/missing.py"])[0]
        check("hygiene: missing target -> MISSING, no crash", r["state"] == "MISSING")
    finally:
        shutil.rmtree(d, ignore_errors=True)


if __name__ == "__main__":
    for name, fn in sorted(globals().items()):
        if name.startswith("test_"):
            try:
                fn()
            except Exception as e:
                check(name, False, f"EXCEPTION {e!r}")
    print("\n" + "=" * 60 + f"\nPASSED: {len(PASSED)}   FAILED: {len(FAILED)}\n" + "=" * 60)
    sys.exit(1 if FAILED else 0)
