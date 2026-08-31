#!/usr/bin/env python3
# Author: Manmohan (Mike) Bains -- Watchdog
"""
saas/agent/watchdog_agent.py -- Client-Side Telemetry Agent

The lightweight collector a CLIENT installs on each GPU host. It gathers
the nvidia-smi-accessible fields Watchdog's detectors consume, tags every
sample with the tenant_id + host, batches them, and ships to the
Watchdog ingestion endpoint in the client's region.

Design goals:
- Minimal footprint: stdlib + nvidia-smi only; no heavy deps on the host.
- Fail-safe: if nvidia-smi is missing or the endpoint is unreachable, it
  buffers locally and never crashes the host.
- Region-aware: the agent ships to its configured regional endpoint so
  data-residency is honored (EU data to eu-west, etc.).
- Auth: every batch carries the tenant's agent key (checked server-side).

The actual network send is injectable so this is fully testable offline;
nvidia-smi is also injectable so it runs without a GPU in tests.

NOTE: Reference implementation. The collector is real; the transport shown
here is a simple HTTPS POST contract -- a production agent would add TLS
pinning, retry/backoff, and OpenTelemetry framing.
"""

import json
import subprocess
import time
from collections import deque
from datetime import datetime, timezone

# The nvidia-smi query fields Watchdog detectors use (matches the telemetry
# the swarm/detectors expect).
NVIDIA_SMI_FIELDS = [
    "index", "power.draw", "temperature.gpu", "utilization.gpu",
    "memory.used", "clocks.sm", "clocks.mem", "pcie.link.gen.current",
    "ecc.errors.corrected.aggregate.total",
    "ecc.errors.uncorrected.aggregate.total",
]


def _run_nvidia_smi(runner=subprocess.run):
    """Query nvidia-smi. Returns list of per-GPU dicts, or [] if unavailable."""
    query = ",".join(NVIDIA_SMI_FIELDS)
    try:
        res = runner(
            ["nvidia-smi", f"--query-gpu={query}",
             "--format=csv,noheader,nounits"],
            capture_output=True, text=True, timeout=10)
        if res.returncode != 0:
            return []
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        return []

    rows = []
    for line in res.stdout.strip().splitlines():
        vals = [v.strip() for v in line.split(",")]
        if len(vals) != len(NVIDIA_SMI_FIELDS):
            continue
        row = {}
        for field, val in zip(NVIDIA_SMI_FIELDS, vals):
            row[field] = val
        rows.append(row)
    return rows


def _normalize(row: dict, tenant_id: str, host: str) -> dict:
    """Map raw nvidia-smi fields to the telemetry schema the detectors use."""
    def num(x, default=0.0):
        try:
            return float(x)
        except (ValueError, TypeError):
            return default

    return {
        "tenant_id": tenant_id,
        "host": host,
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
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


class WatchdogAgent:
    def __init__(self, tenant_id: str, host: str, region: str,
                 agent_key: str, endpoint_url: str,
                 nvidia_smi_runner=subprocess.run,
                 sender=None, buffer_max=10000):
        self.tenant_id = tenant_id
        self.host = host
        self.region = region
        self.agent_key = agent_key
        self.endpoint_url = endpoint_url
        self._runner = nvidia_smi_runner
        self._sender = sender or self._default_sender
        self._buffer = deque(maxlen=buffer_max)
        self.samples_collected = 0
        self.batches_sent = 0
        self.send_failures = 0

    def collect_once(self) -> list:
        """Collect one sample per GPU, normalize, buffer them."""
        rows = _run_nvidia_smi(self._runner)
        batch = [_normalize(r, self.tenant_id, self.host) for r in rows]
        for s in batch:
            self._buffer.append(s)
            self.samples_collected += 1
        return batch

    def flush(self) -> dict:
        """Ship buffered samples to the endpoint. On failure, keep them
        buffered (fail-safe) and report."""
        if not self._buffer:
            return {"status": "NOTHING_TO_FLUSH"}
        payload = {
            "tenant_id": self.tenant_id,
            "region": self.region,
            "agent_key": self.agent_key,
            "samples": list(self._buffer),
        }
        try:
            ok = self._sender(self.endpoint_url, payload)
        except Exception as e:
            self.send_failures += 1
            return {"status": "SEND_FAILED", "buffered": len(self._buffer),
                    "error": str(e)}
        if ok:
            n = len(self._buffer)
            self._buffer.clear()
            self.batches_sent += 1
            return {"status": "FLUSHED", "sent": n}
        self.send_failures += 1
        return {"status": "SEND_REJECTED", "buffered": len(self._buffer)}

    def _default_sender(self, url: str, payload: dict) -> bool:
        # Reference transport. A production agent adds TLS pinning + backoff.
        import urllib.request
        data = json.dumps(payload).encode()
        req = urllib.request.Request(url, data=data,
                                     headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=15) as resp:
            return resp.status == 200

    def run_loop(self, interval_s: float = 1.0, iterations: int = None,
                 flush_every: int = 10, sleep=time.sleep):
        """Collect on an interval, flush periodically. iterations=None runs
        forever; tests pass a finite count + a fake sleep."""
        i = 0
        while iterations is None or i < iterations:
            self.collect_once()
            if (i + 1) % flush_every == 0:
                self.flush()
            i += 1
            if iterations is None or i < iterations:
                sleep(interval_s)
        self.flush()

    def get_stats(self) -> dict:
        return {
            "component": "WatchdogAgent",
            "tenant_id": self.tenant_id,
            "host": self.host,
            "region": self.region,
            "samples_collected": self.samples_collected,
            "batches_sent": self.batches_sent,
            "send_failures": self.send_failures,
            "buffered": len(self._buffer),
        }


if __name__ == "__main__":
    # Offline demo: fake nvidia-smi + fake sender.
    from types import SimpleNamespace

    def fake_smi(cmd, **kw):
        return SimpleNamespace(returncode=0,
            stdout="0, 194.0, 65, 0, 629, 1800, 1593, 5, 12, 0\n")

    sent = []
    def fake_send(url, payload):
        sent.append(payload)
        return True

    agent = WatchdogAgent("acme-pharma", "gpu-host-1", "eu-west",
                          "agent-key-xyz", "https://eu-west.watchdog.io/ingest",
                          nvidia_smi_runner=fake_smi, sender=fake_send)
    agent.run_loop(interval_s=0, iterations=25, flush_every=10, sleep=lambda s: None)
    print("[AGENT]", agent.get_stats())
    print("[AGENT] batches captured by sender:", len(sent))
