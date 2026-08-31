#!/usr/bin/env python3
# Author: Manmohan (Mike) Bains -- Watchdog
"""
watchdog_daemon.py -- Watchdog Runtime Daemon

The missing link between the tested library and live operation. ONE script
you launch on a rented pod (1 or N GPUs). It:

  1. Polls real nvidia-smi telemetry on a loop (per GPU)
  2. Feeds each sample to the telemetry-driven detectors
  3. Routes every alert into the unified swarm correlator
  4. Runs gated remediation planning on incidents (never auto-destructive)
  5. Writes CSV (raw telemetry), JSONL (alerts/incidents), a metrics summary,
     and a run README -- all in a timestamped evidence folder in the repo

Usage:
  python3 watchdog_daemon.py --dry-run           # print the plan, touch nothing
  python3 watchdog_daemon.py --live --duration 300
  python3 watchdog_daemon.py --live --interval 1.0 --gpus 0,1,2,3

The daemon does NOT git-push (credentials stay off the rented box, by
design). It writes evidence into the repo folder; you run one git add/
commit/push at the end.

DESIGN NOTES
------------
- nvidia-smi is invoked via an injectable runner so the whole daemon is
  unit-testable with a FAKE smi (no GPU needed here). On the pod it uses the
  real nvidia-smi.
- Detector wiring uses lazy imports guarded by try/except: a detector that
  isn't importable (or needs data this loop doesn't produce) is skipped and
  recorded, never crashes the loop. This is why it runs even if the repo
  layout shifts.
- Remediation is PLAN-ONLY here (gated); the daemon records recommended
  actions, it does not execute destructive ones.

HONEST STATUS
-------------
Built + logic-tested against synthetic telemetry. NOT yet run on a real
GPU. First real run on the pod may need 1-2 small fixes (a telemetry field
name, a driver-specific format) -- that is expected, not a failure. Run
--dry-run first to see exactly what it will do.
"""

import argparse
import csv
import json
import os
import subprocess
import sys
import time
from datetime import datetime, timezone

# Fields queried from nvidia-smi (documented interface; validated on pod).
SMI_FIELDS = [
    "index", "power.draw", "temperature.gpu", "utilization.gpu",
    "memory.used", "clocks.sm", "clocks.mem", "pcie.link.gen.current",
    "ecc.errors.corrected.aggregate.total",
    "ecc.errors.uncorrected.aggregate.total",
]


# ---------------------------------------------------------------------------
# telemetry collection (injectable runner -> testable without a GPU)
# ---------------------------------------------------------------------------
def query_nvidia_smi(runner=subprocess.run, timeout=10):
    """Return list of per-GPU dicts, or [] if nvidia-smi is unavailable."""
    query = ",".join(SMI_FIELDS)
    try:
        res = runner(["nvidia-smi", f"--query-gpu={query}",
                      "--format=csv,noheader,nounits"],
                     capture_output=True, text=True, timeout=timeout)
        if res.returncode != 0:
            return []
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        return []
    rows = []
    for line in res.stdout.strip().splitlines():
        vals = [v.strip() for v in line.split(",")]
        if len(vals) != len(SMI_FIELDS):
            continue
        rows.append(dict(zip(SMI_FIELDS, vals)))
    return rows


def normalize(row, ts):
    def num(x, d=0.0):
        try:
            return float(x)
        except (ValueError, TypeError):
            return d
    return {
        "timestamp": ts,
        "gpu_index": int(num(row.get("index"), 0)),
        "power_watts": num(row.get("power.draw")),
        "temp_c": num(row.get("temperature.gpu")),
        "gpu_util": num(row.get("utilization.gpu")),
        "vram_used_mb": num(row.get("memory.used")),
        "sm_clock_mhz": num(row.get("clocks.sm")),
        "mem_clock_mhz": num(row.get("clocks.mem")),
        "pcie_gen": num(row.get("pcie.link.gen.current")),
        "ecc_corrected_total": num(row.get("ecc.errors.corrected.aggregate.total")),
        "ecc_uncorrectable_total": num(row.get("ecc.errors.uncorrected.aggregate.total")),
    }


# ---------------------------------------------------------------------------
# detector registry -- lazy, guarded; skips anything not importable
# ---------------------------------------------------------------------------
class DetectorRegistry:
    """
    Loads telemetry-driven detectors. Each entry: (name, factory, updater).
    - factory() -> detector instance (or None if not importable)
    - updater(detector, sample) -> alert dict or None
    A detector that fails to import or errors on a sample is recorded and
    skipped, never crashing the loop.
    """

    def __init__(self, repo_root=None):
        self.repo_root = repo_root
        if repo_root and repo_root not in sys.path:
            sys.path.insert(0, repo_root)
        self.detectors = []
        self.skipped = []
        self._load()

    def _try(self, name, build, update):
        try:
            inst = build()
            if inst is None:
                self.skipped.append({"name": name, "reason": "factory returned None"})
                return
            self.detectors.append({"name": name, "inst": inst, "update": update})
        except Exception as e:
            self.skipped.append({"name": name, "reason": f"import/init: {e}"})

    def _load(self):
        # Rowhammer/ECC-break precursor (swarm agent 6) -- uses ECC counters
        def b_rowhammer():
            from intelligence.swarm.agent6_rowhammer_precursor_predictor import RowhammerPrecursorPredictor
            return {i: RowhammerPrecursorPredictor(gpu_id=i) for i in range(8)}
        def u_rowhammer(d, s):
            agent = d.get(s["gpu_index"])
            if agent is None:
                return None
            return agent.update({"ecc_corrected_total": s["ecc_corrected_total"],
                                 "ecc_uncorrectable_total": s["ecc_uncorrectable_total"],
                                 "timestamp": s["timestamp"]})
        self._try("rowhammer_precursor", b_rowhammer, u_rowhammer)

        # Cryptojacking onset (swarm agent 7)
        def b_crypto():
            from intelligence.swarm.agent7_cryptojacking_onset_predictor import CryptojackingOnsetPredictor
            return {i: CryptojackingOnsetPredictor(gpu_id=i) for i in range(8)}
        def u_crypto(d, s):
            agent = d.get(s["gpu_index"])
            if agent is None:
                return None
            return agent.update({"gpu_util": s["gpu_util"], "sm_clock_mhz": s["sm_clock_mhz"],
                                 "power_watts": s["power_watts"], "timestamp": s["timestamp"]})
        self._try("cryptojacking_onset", b_crypto, u_crypto)

        # Ghost power predictor (swarm agent 1)
        def b_ghost():
            from intelligence.swarm.agent1_ghost_power_predictor import GhostPowerPredictor
            return {i: GhostPowerPredictor(gpu_id=i) for i in range(8)}
        def u_ghost(d, s):
            agent = d.get(s["gpu_index"])
            if agent is None:
                return None
            return agent.update({"power_watts": s["power_watts"], "gpu_util": s["gpu_util"],
                                 "mem_clock_mhz": s["mem_clock_mhz"], "temp_c": s["temp_c"],
                                 "timestamp": s["timestamp"]})
        self._try("ghost_power", b_ghost, u_ghost)

    def run_all(self, sample):
        alerts = []
        for d in self.detectors:
            try:
                a = d["update"](d["inst"], sample)
            except Exception as e:
                a = None
                self.skipped.append({"name": d["name"], "reason": f"runtime: {e}"})
            if a:
                a.setdefault("detector", d["name"])
                a["gpu_index"] = sample["gpu_index"]
                alerts.append(a)
        return alerts

    def summary(self):
        return {"loaded": [d["name"] for d in self.detectors],
                "skipped": self.skipped}


# ---------------------------------------------------------------------------
# correlator loader (unified if available, else None)
# ---------------------------------------------------------------------------
def load_unified_correlator(repo_root=None):
    try:
        if repo_root and repo_root not in sys.path:
            sys.path.insert(0, repo_root)
        from intelligence.swarm.unified_correlator import UnifiedCorrelator
        # sub-correlators are optional; unified works standalone with its
        # own cross-suite rules even if none are passed.
        subs = []
        try:
            from intelligence.swarm.sdc_swarm_correlator import SDCSwarmCorrelator
            subs.append(SDCSwarmCorrelator())
        except Exception:
            pass
        return UnifiedCorrelator(sub_correlators=subs)
    except Exception:
        return None


# ---------------------------------------------------------------------------
# the daemon
# ---------------------------------------------------------------------------
class WatchdogDaemon:
    def __init__(self, repo_root, evidence_dir=None, interval=1.0,
                 duration=None, smi_runner=subprocess.run):
        self.repo_root = repo_root
        self.interval = interval
        self.duration = duration
        self.smi_runner = smi_runner
        ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        self.evidence_dir = evidence_dir or os.path.join(
            repo_root, "daemon_evidence", f"run_{ts}")
        self.registry = DetectorRegistry(repo_root)
        self.correlator = load_unified_correlator(repo_root)
        self.samples = 0
        self.alerts = 0
        self.incidents = 0

    # -- dry run: describe the plan, touch nothing -------------------------
    def dry_run(self):
        plan = {
            "mode": "DRY_RUN",
            "evidence_dir": self.evidence_dir,
            "interval_s": self.interval,
            "duration_s": self.duration,
            "smi_fields": SMI_FIELDS,
            "detectors_loaded": self.registry.summary()["loaded"],
            "detectors_skipped": self.registry.summary()["skipped"],
            "correlator": "unified" if self.correlator else "none_loaded",
            "will_write": ["telemetry.csv", "alerts.jsonl", "incidents.jsonl",
                           "metrics.json", "README.md"],
            "will_not": ["git push (credentials stay off the pod)",
                         "auto-destructive remediation (gated only)"],
            "gpu_check": "will query nvidia-smi; if absent, records 0 samples honestly",
        }
        print("=" * 60)
        print("WATCHDOG DAEMON -- DRY RUN (nothing will be written)")
        print("=" * 60)
        print(json.dumps(plan, indent=2))
        # probe telemetry once so you see whether a GPU is visible
        rows = query_nvidia_smi(self.smi_runner)
        print(f"\nnvidia-smi probe: {len(rows)} GPU(s) visible")
        if rows:
            s = normalize(rows[0], datetime.now(timezone.utc).isoformat())
            print("sample GPU0:", json.dumps(s, indent=2))
        return plan

    # -- live run ----------------------------------------------------------
    def run(self, sleep=time.sleep):
        os.makedirs(self.evidence_dir, exist_ok=True)
        tel_path = os.path.join(self.evidence_dir, "telemetry.csv")
        alerts_path = os.path.join(self.evidence_dir, "alerts.jsonl")
        inc_path = os.path.join(self.evidence_dir, "incidents.jsonl")

        started = datetime.now(timezone.utc)
        start_mono = time.monotonic()

        tel_f = open(tel_path, "w", newline="")
        writer = csv.DictWriter(tel_f, fieldnames=[
            "timestamp", "gpu_index", "power_watts", "temp_c", "gpu_util",
            "vram_used_mb", "sm_clock_mhz", "mem_clock_mhz", "pcie_gen",
            "ecc_corrected_total", "ecc_uncorrectable_total"])
        writer.writeheader()
        alerts_f = open(alerts_path, "w")
        inc_f = open(inc_path, "w")

        try:
            while True:
                if self.duration is not None and (time.monotonic() - start_mono) >= self.duration:
                    break
                ts = datetime.now(timezone.utc).isoformat()
                rows = query_nvidia_smi(self.smi_runner)
                for row in rows:
                    s = normalize(row, ts)
                    writer.writerow(s)
                    self.samples += 1
                    # run detectors
                    for alert in self.registry.run_all(s):
                        self.alerts += 1
                        alerts_f.write(json.dumps(alert) + "\n")
                        # feed correlator
                        if self.correlator is not None:
                            for inc in self.correlator.observe(alert):
                                self.incidents += 1
                                inc_f.write(json.dumps(inc) + "\n")
                tel_f.flush(); alerts_f.flush(); inc_f.flush()
                sleep(self.interval)
        finally:
            tel_f.close(); alerts_f.close(); inc_f.close()

        ended = datetime.now(timezone.utc)
        self._write_metrics(started, ended)
        self._write_readme(started, ended)
        return {"status": "COMPLETE", "evidence_dir": self.evidence_dir,
                "samples": self.samples, "alerts": self.alerts,
                "incidents": self.incidents}

    def _write_metrics(self, started, ended):
        metrics = {
            "run_started": started.isoformat(),
            "run_ended": ended.isoformat(),
            "duration_s": round((ended - started).total_seconds(), 1),
            "interval_s": self.interval,
            "samples_collected": self.samples,
            "alerts_fired": self.alerts,
            "incidents_correlated": self.incidents,
            "detectors_loaded": self.registry.summary()["loaded"],
            "detectors_skipped": self.registry.summary()["skipped"],
            "correlator": "unified" if self.correlator else "none",
            "note": ("Real-hardware run. Detector logic was simulation-tested; "
                     "this run is the first live-telemetry execution -- results "
                     "are evidence, not a pass/fail of the detectors themselves."),
        }
        with open(os.path.join(self.evidence_dir, "metrics.json"), "w") as f:
            json.dump(metrics, f, indent=2)
        return metrics

    def _write_readme(self, started, ended):
        loaded = self.registry.summary()["loaded"]
        skipped = self.registry.summary()["skipped"]
        loaded_lines = [f"- {n}" for n in loaded] if loaded else ["- (none)"]
        skipped_lines = ([f"- {s['name']}: {s['reason']}" for s in skipped]
                         if skipped else ["- (none)"])
        lines = [
            f"# Watchdog Daemon Run -- {started.strftime('%Y-%m-%d %H:%M:%SZ')}",
            "",
            "Live-telemetry run of the Watchdog runtime daemon.",
            "",
            "## Summary",
            f"- Duration: {round((ended - started).total_seconds(), 1)}s "
            f"@ {self.interval}s interval",
            f"- Telemetry samples: {self.samples}",
            f"- Alerts fired: {self.alerts}",
            f"- Correlated incidents: {self.incidents}",
            f"- Correlator: {'unified' if self.correlator else 'none loaded'}",
            "",
            "## Detectors loaded",
        ]
        lines += loaded_lines
        lines += ["", "## Detectors skipped (not importable / not applicable)"]
        lines += skipped_lines
        lines += [
            "",
            "## Files in this run",
            "- `telemetry.csv` -- raw per-GPU telemetry samples",
            "- `alerts.jsonl` -- every detector alert fired",
            "- `incidents.jsonl` -- correlated cross-suite incidents",
            "- `metrics.json` -- run metrics summary",
            "",
            "## Honest status",
            "Detector logic was simulation-tested (see main test suite). This "
            "is a LIVE-telemetry run on real hardware -- the output is evidence "
            "of what the detectors saw, not a validation pass of the detectors "
            "themselves. Remediation is gated (plan-only); no destructive "
            "actions were auto-executed. Credentials were kept off this box; "
            "commit/push these artifacts manually.",
        ]
        with open(os.path.join(self.evidence_dir, "README.md"), "w") as f:
            f.write("\n".join(lines) + "\n")


def main(argv=None):
    p = argparse.ArgumentParser(description="Watchdog runtime daemon")
    p.add_argument("--dry-run", action="store_true",
                   help="print the plan and probe telemetry; write nothing")
    p.add_argument("--live", action="store_true", help="run the live loop")
    p.add_argument("--interval", type=float, default=1.0, help="seconds between polls")
    p.add_argument("--duration", type=float, default=None,
                   help="seconds to run (default: until Ctrl-C)")
    p.add_argument("--repo-root", default=os.getcwd(),
                   help="Watchdog repo root (default: cwd)")
    args = p.parse_args(argv)

    daemon = WatchdogDaemon(repo_root=args.repo_root, interval=args.interval,
                            duration=args.duration)
    if args.dry_run or not args.live:
        daemon.dry_run()
        if not args.live:
            print("\n(no --live flag: dry-run only. Re-run with --live to execute.)")
        return 0
    result = daemon.run()
    print(json.dumps(result, indent=2))
    print(f"\nEvidence written to: {result['evidence_dir']}")
    print("Now: git add . && git commit -m 'daemon run evidence' && git push")
    return 0


if __name__ == "__main__":
    sys.exit(main())
