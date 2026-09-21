#!/usr/bin/env python3
"""
Watchdog Swarm — Derived Telemetry Fields
Author: Manmohan (Mike) Bains / GPU Optimizer Inc.

EUAIActComplianceForecaster needs four fields that nvidia-smi does not report:

    cei_flops_per_joule   NOT COMPUTABLE from passive telemetry. Needs
                          intelligence/cei_benchmark.py on real hardware.
                          This module does not fabricate it.
    ghost_power_pct       computable  <- here
    crash_count           computable  <- here
    isolation_score       computable  <- here

Three of the four blockers close without a GPU. The fourth needs one pod
session. Wiring these now means that session finishes the agent rather than
starting it.

DESIGN RULE
Every field returns None when its inputs are absent. None means "not
measured". It never degrades to 0.0, because detection/_shared.py's _f()
already demonstrated where that leads: a detector checking `is None` treats
an absent field as a real zero, and a false zero contaminates a learned
baseline silently. A missing input here produces a missing output, loudly.
"""

from collections import deque


class GhostPowerPercent(object):
    """Fraction of recent samples drawing meaningfully above the idle floor
    while NVML reports zero utilization.

    Not instantaneous. Ghost power is a sustained condition, and a single
    high sample during a workload transient is not it.
    """

    def __init__(self, idle_floor_w=80.36, margin_w=15.0, window=120):
        self.idle_floor_w = float(idle_floor_w)
        self.margin_w = float(margin_w)
        self.window = int(window)
        self.samples = deque(maxlen=self.window)

    def update(self, row):
        power = row.get("power_watts", row.get("power.draw"))
        util = row.get("gpu_util", row.get("utilization.gpu"))
        if power is None or util is None:
            return None                       # not measured, not zero
        try:
            power, util = float(power), float(util)
        except (TypeError, ValueError):
            return None
        ghost = (util <= 1.0) and (power > self.idle_floor_w + self.margin_w)
        self.samples.append(1 if ghost else 0)
        if len(self.samples) < min(30, self.window):
            return None                       # not enough history to mean anything
        return 100.0 * sum(self.samples) / float(len(self.samples))

    def reset(self):
        self.samples.clear()


class CrashCounter(object):
    """Count of hard faults observed this session.

    Counts what telemetry can actually see: XID errors, uncorrectable ECC
    events, and a GPU dropping out of the query set entirely. It does NOT
    infer a crash from a process disappearing — a process exiting normally
    looks identical from here, and that ambiguity is exactly the kind this
    project documents rather than papers over.
    """

    def __init__(self):
        self.count = 0
        self._last_xid = None
        self._last_uncorrectable = None
        self._seen_gpus = set()
        self.events = []

    def update(self, row):
        gpu_id = row.get("gpu_id")
        if gpu_id is not None:
            self._seen_gpus.add(str(gpu_id))

        xid = row.get("xid_error", row.get("xid"))
        if xid not in (None, "", "N/A", 0, "0"):
            if xid != self._last_xid:
                self.count += 1
                self.events.append({"kind": "XID", "value": xid,
                                    "timestamp": row.get("timestamp")})
                self._last_xid = xid

        unc = row.get("ecc_uncorrectable_total")
        if unc is not None:
            try:
                unc = int(float(unc))
                if self._last_uncorrectable is not None and unc > self._last_uncorrectable:
                    self.count += 1
                    self.events.append({"kind": "ECC_UNCORRECTABLE",
                                        "delta": unc - self._last_uncorrectable,
                                        "timestamp": row.get("timestamp")})
                self._last_uncorrectable = unc
            except (TypeError, ValueError):
                pass

        return self.count

    def note_gpu_disappeared(self, gpu_id):
        """Called by the collector when a previously-present GPU stops
        responding. The collector knows this; a single row does not."""
        if str(gpu_id) in self._seen_gpus:
            self.count += 1
            self.events.append({"kind": "GPU_VANISHED", "gpu_id": str(gpu_id)})

    def reset(self):
        self.__init__()


class IsolationScore(object):
    """0.0 to 1.0. Higher is better isolated.

    Built only from signals this project has actually measured. Each
    component is stated with what it can and cannot distinguish.

      per-process visibility  Can the container see which PID owns GPU
                              memory? On RunPod, --query-compute-apps
                              returns empty (driver reports PIDs in the host
                              namespace), so VRAMResidualDetector cannot
                              evaluate. That is an isolation-relevant fact.

      memory residual         Memory still allocated with no owning process
                              visible. An accounting gap, not a data leak:
                              direct recovery tests returned zero bytes on
                              B200 and H200. Scored as a capacity-integrity
                              signal, not a confidentiality one.

      cross-GPU delta         Peer GPUs moving while only one is loaded.
                              Requires a >10MB threshold: CUDA context
                              peer-mapping moves every peer by ~3MB at
                              context creation regardless of workload, and
                              an earlier check flagged that as bleed.

    Returns None until at least one component is measurable.
    """

    PEER_MAPPING_FLOOR_MB = 10.0

    def __init__(self):
        self._baseline_mem = {}

    def update(self, row, peer_rows=None):
        parts, detail = [], {}

        apps = row.get("compute_apps")
        if apps is not None:
            visible = bool(apps)
            parts.append(1.0 if visible else 0.4)
            detail["per_process_visibility"] = visible
            if not visible:
                detail["per_process_note"] = (
                    "compute_apps empty: the container cannot see PIDs owning "
                    "GPU memory. VRAMResidualDetector cannot evaluate here.")

        mem = row.get("memory_used_mb")
        if mem is not None and apps is not None:
            try:
                mem = float(mem)
                orphaned = mem > 100.0 and not apps
                parts.append(0.3 if orphaned else 1.0)
                detail["orphaned_memory_mb"] = mem if orphaned else 0.0
            except (TypeError, ValueError):
                pass

        if peer_rows:
            moved = []
            for p in peer_rows:
                pid_ = str(p.get("gpu_id"))
                try:
                    pmem = float(p.get("memory_used_mb"))
                except (TypeError, ValueError):
                    continue
                base = self._baseline_mem.get(pid_)
                if base is None:
                    self._baseline_mem[pid_] = pmem
                    continue
                delta = pmem - base
                if delta > self.PEER_MAPPING_FLOOR_MB:
                    moved.append({"gpu_id": pid_, "delta_mb": round(delta, 1)})
            if moved:
                parts.append(0.2)
                detail["peer_gpus_moved"] = moved
                detail["peer_note"] = (
                    "Above the %.0fMB peer-mapping floor. Below it, every peer "
                    "GPU moves at context creation regardless of workload."
                    % self.PEER_MAPPING_FLOOR_MB)
            else:
                parts.append(1.0)

        if not parts:
            return None
        return {"isolation_score": round(sum(parts) / float(len(parts)), 3),
                "components": len(parts), "detail": detail}

    def reset(self):
        self._baseline_mem = {}


class DerivedFieldEnricher(object):
    """Adds the three computable fields to a telemetry row.

    cei_flops_per_joule is NOT added. It cannot be derived from passive
    telemetry under any field name. Until intelligence/cei_benchmark.py runs
    on real hardware, both CEIDegradationForecaster and
    EUAIActComplianceForecaster stay structurally silent, and this module
    says so rather than supplying a plausible-looking number.
    """

    def __init__(self, idle_floor_w=80.36):
        self.ghost = GhostPowerPercent(idle_floor_w=idle_floor_w)
        self.crashes = CrashCounter()
        self.isolation = IsolationScore()

    def enrich(self, row, peer_rows=None):
        out = dict(row)

        g = self.ghost.update(row)
        if g is not None:
            out["ghost_power_pct"] = round(g, 2)

        out["crash_count"] = self.crashes.update(row)

        iso = self.isolation.update(row, peer_rows)
        if iso is not None:
            out["isolation_score"] = iso["isolation_score"]
            out["_isolation_detail"] = iso["detail"]

        out["_derived_missing"] = ["cei_flops_per_joule"]
        out["_derived_note"] = (
            "cei_flops_per_joule is not derivable from passive telemetry. "
            "Run intelligence/cei_benchmark.py on real hardware. Until then "
            "agent2 and agent5 remain structurally silent.")
        return out

    def reset(self):
        self.ghost.reset()
        self.crashes.reset()
        self.isolation.reset()


if __name__ == "__main__":
    import json
    e = DerivedFieldEnricher(idle_floor_w=78.4)
    # 40 ghost-power samples: above floor, zero utilization
    for i in range(40):
        row = {"gpu_id": 0, "power_watts": 126.0, "gpu_util": 0.0,
               "memory_used_mb": 620.0, "compute_apps": [],
               "ecc_uncorrectable_total": 0, "timestamp": "t%d" % i}
        out = e.enrich(row, peer_rows=[{"gpu_id": 1, "memory_used_mb": 4.0}])
    print(json.dumps({k: v for k, v in out.items()
                      if k.startswith(("ghost", "crash", "isolation", "_"))},
                     indent=2))
