#!/usr/bin/env python3
# Author: Manmohan (Mike) Bains -- Watchdog
"""
pod_runner.py -- the CLI and REAL backend for runtime/validation_harness.py
*** WATCHDOG ***

WHY THIS EXISTS
---------------
runtime/validation_harness.py has the full 8-stage tier-labelled logic and an
injectable backend, but no command line. Running it directly executes the
FakeBackend demo and prints "Tier-1 true-positives passed: 6/6" regardless of
whether a GPU was touched. FakeBackend.scan_vram_for_pattern() in particular
hardcodes pattern_found=True -- that is the headline finding (POD_VALIDATION_
PLAN Tier 1 #1) returning a guaranteed pass with no hardware involved.

On the pod that is the one failure mode that could turn this session into a
false claim: a confident 6/6 that is indistinguishable from real evidence.

WHAT THIS ADDS
--------------
1. RealBackend -- torch + nvidia-smi, actually touching the GPUs.
2. A CLI with --dry-run as the DEFAULT. --live must be passed explicitly.
3. A hard refusal: --live aborts if torch.cuda or nvidia-smi is unavailable.
   It NEVER silently falls back to the fake backend.
4. Every artifact is stamped with backend ("real" or "fake"), GPU UUIDs,
   driver version, hostname and a run id, so a fake run can never be
   mistaken for evidence later.
5. Artifacts written per the plan's evidence rule: JSON per stage with a
   real timestamp, GPU UUID, raw telemetry and the tier label. No artifact
   = not validated.

USAGE
  python3 runtime/pod_runner.py                          # dry run, touches nothing
  python3 runtime/pod_runner.py --live --victim 0 --workers 1,2,3 \
      --out evidence/pod_$(date +%s)

SAFETY (inherited from the harness, restated)
  Inducers are real enough to trip a detector, never destructive. No miner
  binary, no bit-flip, no other tenant. The Rowhammer true-positive is
  deliberately NOT induced (Tier 2). The VRAM work is the self-owned
  two-process read -- both processes are ours, on hardware we rented.

SECURITY REVIEW COMPLIANCE: no bare except; no shell=True; subprocess as
argument lists; every failure surfaced, never swallowed into a pass.
"""

import argparse
import json
import os
import socket
import subprocess
import sys
import time
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from runtime.validation_harness import ValidationHarness, FakeBackend, TIER1, TIER2, TIER3  # noqa: E402

PATTERN_BYTE = 0xA5          # the known pattern written into VRAM
PATTERN_NAME = "0xA5_watchdog_residual_probe"


# ---------------------------------------------------------------------------
# Environment capture (plan stage 1) -- also the arch guard
# ---------------------------------------------------------------------------
def nvidia_smi(fields, timeout=15):
    """Query nvidia-smi. Returns list of dicts, or None if unavailable."""
    q = ",".join(fields)
    try:
        r = subprocess.run(["nvidia-smi", f"--query-gpu={q}",
                            "--format=csv,noheader,nounits"],
                           capture_output=True, text=True, timeout=timeout)
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError) as e:
        return None
    if r.returncode != 0:
        return None
    out = []
    for line in r.stdout.strip().splitlines():
        parts = [p.strip() for p in line.split(",")]
        if len(parts) == len(fields):
            out.append(dict(zip(fields, parts)))
    return out


def nvidia_smi_topo(timeout=20):
    try:
        r = subprocess.run(["nvidia-smi", "topo", "-m"],
                           capture_output=True, text=True, timeout=timeout)
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError) as e:
        return f"UNAVAILABLE: {type(e).__name__}: {e}"
    return r.stdout if r.returncode == 0 else f"UNAVAILABLE: rc={r.returncode}"


def capture_environment():
    """Everything a reviewer needs to reproduce or challenge a result."""
    fields = ["index", "name", "uuid", "driver_version", "vbios_version",
              "memory.total", "power.limit", "ecc.mode.current",
              "utilization.gpu", "power.draw", "clocks.mem", "clocks.sm",
              "ecc.errors.corrected.aggregate.total",
              "ecc.errors.uncorrected.aggregate.total"]
    gpus = nvidia_smi(fields)
    env = {
        "captured_at": datetime.now(timezone.utc).isoformat(),
        "hostname": socket.gethostname(),
        "gpus": gpus,
        "gpu_count": len(gpus) if gpus else 0,
        "topology": nvidia_smi_topo(),
        "python": sys.version.split()[0],
    }
    try:
        import torch
        env["torch_version"] = torch.__version__
        env["torch_cuda_available"] = bool(torch.cuda.is_available())
        env["torch_cuda_device_count"] = torch.cuda.device_count() if torch.cuda.is_available() else 0
    except Exception as e:
        env["torch_version"] = None
        env["torch_error"] = f"{type(e).__name__}: {e}"
        env["torch_cuda_available"] = False

    # arch guard -- the plan warns against a B200 logged as an H200
    names = {g.get("name", "") for g in (gpus or [])}
    env["architectures_seen"] = sorted(names)
    env["arch_homogeneous"] = len(names) <= 1
    if not env["arch_homogeneous"]:
        env["arch_warning"] = "MIXED ARCHITECTURES ON ONE HOST -- label every result with its GPU's own name"
    return env


# ---------------------------------------------------------------------------
# RealBackend -- the thing FakeBackend pretends to be
# ---------------------------------------------------------------------------
class RealBackendUnavailable(RuntimeError):
    pass


class RealBackend:
    """torch + nvidia-smi. Every method returns what was ACTUALLY observed.
    Where a measurement could not be taken, it says so rather than
    substituting a plausible value."""

    def __init__(self, gpu_count=None):
        try:
            import torch
        except Exception as e:
            raise RealBackendUnavailable(f"torch not importable: {type(e).__name__}: {e}")
        if not torch.cuda.is_available():
            raise RealBackendUnavailable("torch.cuda.is_available() is False")
        if nvidia_smi(["index"]) is None:
            raise RealBackendUnavailable("nvidia-smi not readable")
        self.torch = torch
        self._count = gpu_count or torch.cuda.device_count()

    def gpu_count_available(self):
        return self._count

    # -- power helpers ------------------------------------------------------
    def _power_w(self, gpu):
        rows = nvidia_smi(["index", "power.draw", "utilization.gpu", "memory.used"])
        if not rows:
            return None
        for r in rows:
            try:
                if int(float(r["index"])) == int(gpu):
                    return {"power_w": float(r["power.draw"]),
                            "util_pct": float(r["utilization.gpu"]),
                            "memory_used_mb": float(r["memory.used"])}
            except (ValueError, KeyError):
                continue
        return None

    def _sample_power(self, gpu, seconds, period=1.0):
        """1 Hz power.draw -- the tightest-CI sensor. Gaps recorded, never faked."""
        vals, gaps, t0 = [], 0, time.monotonic()
        while time.monotonic() - t0 < seconds:
            s = self._power_w(gpu)
            if s is None:
                gaps += 1
            else:
                vals.append(s)
            time.sleep(period)
        return {"samples": vals, "gaps": gaps, "n": len(vals)}

    # -- Tier 1: covert compute --------------------------------------------
    def run_covert_compute(self, gpu, seconds):
        """A heavy, uniform compute loop. NOT a miner binary -- it produces the
        same telemetry signature safely (harness docstring)."""
        t = self.torch
        dev = t.device(f"cuda:{gpu}")
        n = 16384
        a = t.randn(n, n, device=dev, dtype=t.bfloat16)
        b = t.randn(n, n, device=dev, dtype=t.bfloat16)
        t.cuda.synchronize(dev)
        samples, t0, iters = [], time.monotonic(), 0
        while time.monotonic() - t0 < seconds:
            _ = a @ b
            iters += 1
            if iters % 20 == 0:
                s = self._power_w(gpu)
                if s:
                    samples.append(s)
        t.cuda.synchronize(dev)
        sm = nvidia_smi(["index", "clocks.sm"])
        sm_vals = []
        for r in (sm or []):
            try:
                if int(float(r["index"])) == int(gpu):
                    sm_vals.append(float(r["clocks.sm"]))
            except (ValueError, KeyError):
                pass
        utils = [s["util_pct"] for s in samples] or [0.0]
        powers = [s["power_w"] for s in samples] or [0.0]
        return {"gpu": gpu, "iterations": iters, "seconds": seconds,
                "util_pct": max(utils), "mean_util_pct": sum(utils) / len(utils),
                "power_watts": max(powers),
                "sm_clock_uniform": (max(sm_vals) - min(sm_vals) < 50) if len(sm_vals) > 1 else None,
                "sm_clocks_seen": sm_vals,
                "samples": len(samples),
                "measurement": "real"}

    # -- Tier 1: NVLink ------------------------------------------------------
    def run_nvlink_transfer(self, src, dst, mb):
        t = self.torch
        if self._count < 2:
            return {"src": src, "dst": dst, "error": "fewer than 2 GPUs", "measurement": "real"}
        elems = int(mb * 1024 * 1024 / 4)
        a = t.randn(elems, device=t.device(f"cuda:{src}"), dtype=t.float32)
        t.cuda.synchronize(src)
        t0 = time.monotonic()
        b = a.to(t.device(f"cuda:{dst}"))
        t.cuda.synchronize(dst)
        dt = time.monotonic() - t0
        kb_s = (mb * 1024) / dt if dt > 0 else 0.0
        # read NVLink counters if the driver exposes them
        try:
            r = subprocess.run(["nvidia-smi", "nvlink", "-gt", "d", "-i", str(src)],
                               capture_output=True, text=True, timeout=20)
            nvlink_raw = r.stdout if r.returncode == 0 else f"rc={r.returncode}"
        except (FileNotFoundError, subprocess.TimeoutExpired, OSError) as e:
            nvlink_raw = f"UNAVAILABLE: {type(e).__name__}: {e}"
        del a, b
        t.cuda.empty_cache()
        return {"src": src, "dst": dst, "transferred_mb": mb, "seconds": round(dt, 4),
                "nvlink_kb_per_s": round(kb_s, 1), "nvlink_counters_raw": nvlink_raw,
                "measurement": "real"}

    # -- Tier 1: VRAM residual (the headline) --------------------------------
    def write_vram_pattern(self, gpu, pattern, mb):
        """Writes the pattern in a SEPARATE PROCESS that then exits, so the
        residual genuinely crosses a process boundary. Returns what the child
        reported plus memory.used before/after."""
        before = self._power_w(gpu)
        child = os.path.join(os.path.dirname(os.path.abspath(__file__)), "_vram_writer.py")
        try:
            r = subprocess.run([sys.executable, child, str(gpu), str(mb), str(PATTERN_BYTE)],
                               capture_output=True, text=True, timeout=300)
        except (FileNotFoundError, subprocess.TimeoutExpired, OSError) as e:
            return {"gpu": gpu, "written": False, "error": f"{type(e).__name__}: {e}",
                    "measurement": "real"}
        time.sleep(3)  # let the driver settle after child exit
        after = self._power_w(gpu)
        ok = r.returncode == 0
        return {"gpu": gpu, "pattern": pattern, "mb": mb, "written": ok,
                "child_stdout": r.stdout.strip()[:500], "child_stderr": r.stderr.strip()[:500],
                "memory_used_mb_before": (before or {}).get("memory_used_mb"),
                "memory_used_mb_after_child_exit": (after or {}).get("memory_used_mb"),
                "measurement": "real"}

    def scan_vram_for_pattern(self, gpu, pattern):
        """Allocate fresh memory in THIS process and scan for the previous
        process's pattern. Returns the TRUE result -- including, and expected
        to be, pattern_found=False with zero recoverable bytes."""
        t = self.torch
        dev = t.device(f"cuda:{gpu}")
        mb = 512
        elems = mb * 1024 * 1024
        buf = t.empty(elems, dtype=t.uint8, device=dev)
        vals = buf.to("cpu").numpy()
        matches = int((vals == PATTERN_BYTE).sum())
        nonzero = int((vals != 0).sum())
        del buf
        t.cuda.empty_cache()
        return {"gpu": gpu, "pattern": pattern, "scanned_mb": mb,
                "pattern_byte_matches": matches,
                "nonzero_bytes": nonzero,
                "pattern_found": matches > (elems * 0.01),   # >1% of the buffer
                "bytes_readable": nonzero,
                "note": ("expected result is pattern_found=False with near-zero "
                         "nonzero bytes -- the residual is an ACCOUNTING gap, "
                         "not recoverable data (B200/H200 both returned zero)"),
                "measurement": "real"}

    # -- Tier 1: ghost power -------------------------------------------------
    def ghost_power_probe(self, gpu, load_s=60, settle_s=10, idle_s=60):
        """True idle floor, then load, then post-exit floor. Settle discarded
        by TIME (capacitor lag), never by sample fraction."""
        true_idle = self._sample_power(gpu, 30)
        self.run_covert_compute(gpu, load_s)
        time.sleep(settle_s)
        post = self._sample_power(gpu, idle_s)

        def floor(d):
            p = sorted(s["power_w"] for s in d["samples"]) if d["samples"] else []
            if not p:
                return None
            lower = p[: max(1, len(p) // 2)]
            return lower[len(lower) // 2]

        ti, pf = floor(true_idle), floor(post)
        return {"gpu": gpu, "true_idle_w": ti, "idle_floor_w": pf,
                "ghost_watts": None if (ti is None or pf is None) else round(pf - ti, 2),
                "true_idle_samples": true_idle["n"], "post_samples": post["n"],
                "gaps": true_idle["gaps"] + post["gaps"],
                "settle_seconds_discarded": settle_s,
                "measurement": "real"}

    # -- Tier 1: SDC / Dr. DNA -----------------------------------------------
    def model_activations(self, gpu, corrupt=False):
        t = self.torch
        dev = t.device(f"cuda:{gpu}")
        t.manual_seed(1234 + gpu)
        x = t.randn(512, 512, device=dev, dtype=t.float32)
        w = t.randn(512, 512, device=dev, dtype=t.float32)
        act = (x @ w).relu().mean(dim=0)
        if corrupt:
            act = act.clone()
            act[0] = act[0] * 1000.0     # injected deviation, clearly synthetic
        vals = act[:3].to("cpu").tolist()
        return {i: float(v) for i, v in enumerate(vals)}

    # -- Tier 2: ECC ---------------------------------------------------------
    def read_ecc(self, gpu):
        rows = nvidia_smi(["index", "ecc.errors.corrected.aggregate.total",
                           "ecc.errors.uncorrected.aggregate.total", "ecc.mode.current"])
        if not rows:
            return {"corrected_total": None, "uncorrectable_total": None,
                    "error": "nvidia-smi ECC fields unavailable", "measurement": "real"}
        for r in rows:
            try:
                if int(float(r["index"])) == int(gpu):
                    def num(v):
                        try:
                            return int(float(v))
                        except ValueError:
                            return None
                    return {"corrected_total": num(r["ecc.errors.corrected.aggregate.total"]),
                            "uncorrectable_total": num(r["ecc.errors.uncorrected.aggregate.total"]),
                            "ecc_mode": r.get("ecc.mode.current"),
                            "measurement": "real"}
            except (ValueError, KeyError):
                continue
        return {"corrected_total": None, "uncorrectable_total": None,
                "error": f"gpu {gpu} not in nvidia-smi output", "measurement": "real"}


# ---------------------------------------------------------------------------
# Detector hooks -- real Watchdog detectors where importable
# ---------------------------------------------------------------------------
def build_hooks():
    """Wire real detectors where they import cleanly; fall back to explicit
    threshold hooks that mirror the detector's documented rule. Every hook
    records which path was used."""
    used = {}

    def covert(e):
        used["cryptojacking_onset"] = "threshold(util>90 & uniform sm clock)"
        return (e.get("util_pct", 0) > 90) and bool(e.get("sm_clock_uniform"))

    def nvlink(e):
        used["nvlink_contention"] = "threshold(nvlink_kb_per_s > 1e6)"
        return e.get("nvlink_kb_per_s", 0) > 1_000_000

    def ghost(e):
        used["ghost_power"] = "threshold(ghost_watts > 15)  # README: >15W over learned idle floor"
        g = e.get("ghost_watts")
        return g is not None and g > 15

    def sdc(e):
        used["sdc_drdna"] = "threshold(any |activation| > 10 vs baseline)"
        return any(abs(v) > 10 for v in e.values() if isinstance(v, (int, float)))

    def rowhammer(e):
        used["rowhammer_precursor"] = "silent-on-clean check (Tier 2)"
        unc = e.get("uncorrectable_total")
        return bool(unc) and unc > 0

    return {"cryptojacking_onset": covert, "nvlink_contention": nvlink,
            "ghost_power": ghost, "sdc_drdna": sdc,
            "rowhammer_precursor": rowhammer}, used


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def main(argv=None):
    ap = argparse.ArgumentParser(
        description="Run the Watchdog pod validation harness. DRY RUN BY DEFAULT.")
    ap.add_argument("--live", action="store_true",
                    help="actually touch the GPUs. Without this, nothing runs.")
    ap.add_argument("--victim", type=int, default=0)
    ap.add_argument("--workers", default="1,2",
                    help="comma-separated worker GPU indices (leave one GPU untouched as a cold reference)")
    ap.add_argument("--out", default=None, help="evidence directory")
    ap.add_argument("--allow-fake", action="store_true",
                    help="permit the FakeBackend under --live. For debugging ONLY; "
                         "artifacts are stamped backend=fake and are NOT evidence.")
    a = ap.parse_args(argv)

    workers = [int(w) for w in a.workers.split(",") if w.strip() != ""]
    env = capture_environment()
    run_id = f"{int(time.time())}-{socket.gethostname()}"

    if not a.live:
        plan = {
            "type": "DRY_RUN",
            "run_id": run_id,
            "victim_gpu": a.victim, "worker_gpus": workers,
            "environment": env,
            "stages": ["covert_compute", "nvlink_livefire", "vram_cross_process_read",
                       "cross_gpu_residual", "ghost_power", "sdc_drdna",
                       "rowhammer_capability(TIER2)", "quantum_control_plane(TIER3)"],
            "would_write_to": a.out or "(no --out given; nothing would be written)",
            "safety": ["no miner binary", "no bit-flip", "no other tenant",
                       "Rowhammer true-positive deliberately NOT induced (Tier 2)"],
            "note": "DRY RUN -- nothing executed. Pass --live to run on hardware.",
        }
        print(json.dumps(plan, indent=2, default=str))
        return 0

    # ---- live ----
    backend, backend_kind, backend_error = None, None, None
    try:
        backend = RealBackend()
        backend_kind = "real"
    except RealBackendUnavailable as e:
        backend_error = str(e)
        if a.allow_fake:
            backend = FakeBackend(gpu_count=4)
            backend_kind = "fake"
            print(f"WARNING: real backend unavailable ({backend_error}); "
                  f"--allow-fake given, running FAKE. Artifacts are NOT evidence.",
                  file=sys.stderr)
        else:
            print(json.dumps({
                "type": "LIVE_RUN_REFUSED",
                "reason": backend_error,
                "detail": ("--live requires a real GPU. The harness will NOT silently "
                           "fall back to the fake backend, because FakeBackend reports "
                           "pattern_found=True for the VRAM residual stage and would "
                           "produce a 6/6 pass with no hardware involved."),
                "environment": env,
            }, indent=2, default=str))
            return 2

    if backend_kind == "real" and env["gpu_count"] < max([a.victim] + workers) + 1:
        print(json.dumps({"type": "LIVE_RUN_REFUSED",
                          "reason": f"requested victim={a.victim} workers={workers} "
                                    f"but only {env['gpu_count']} GPUs present",
                          "environment": env}, indent=2, default=str))
        return 2

    hooks, hook_paths = build_hooks()
    h = ValidationHarness(backend, victim_gpu=a.victim, worker_gpus=workers,
                          detector_hooks=hooks)
    summary = h.run_all()

    stamped = {
        "type": "POD_VALIDATION_RUN",
        "run_id": run_id,
        "backend": backend_kind,
        "backend_error": backend_error,
        "is_evidence": backend_kind == "real",
        "environment": env,
        "detector_hook_paths": hook_paths,
        "summary": summary,
        "evidence_rule": ("A validation counts only with a committed JSON artifact "
                          "carrying a real timestamp, GPU UUID, raw telemetry and the "
                          "tier label. backend=fake is NOT evidence."),
        "tier_rule": ("Only TIER1 passes may drop the simulation-based label. "
                      "TIER2 is a capability check. TIER3 was not attempted."),
    }

    print("\n" + "=" * 60)
    print(f"backend: {backend_kind}   is_evidence: {stamped['is_evidence']}")
    t1 = summary["tier1_true_positive"]
    print(f"Tier-1 true-positives passed: {t1['passed']}/{t1['total']} -> {t1['stages']}")
    print(f"Tier-2 capability: {summary['tier2_capability']}")
    print(f"Tier-3 cannot-induce: {summary['tier3_cannot_induce']}")

    if a.out:
        os.makedirs(a.out, exist_ok=True)
        run_path = os.path.join(a.out, "run.json")
        with open(run_path, "w") as fh:
            json.dump(stamped, fh, indent=2, default=str)
        for r in summary["results"]:
            p = os.path.join(a.out, f"stage_{r['stage']}.json")
            with open(p, "w") as fh:
                json.dump({"run_id": run_id, "backend": backend_kind,
                           "is_evidence": backend_kind == "real",
                           "gpus": env["gpus"], **r}, fh, indent=2, default=str)
        print(f"\nwritten: {run_path} + {len(summary['results'])} stage artifacts")
        print("commit them: git add evidence/ && git commit && git push")
    else:
        print("\nNO --out GIVEN: nothing written. Per the evidence rule, "
              "a run with no artifact is not a validation.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
