#!/usr/bin/env python3
# Author: Manmohan (Mike) Bains -- Watchdog
"""
egress_anomaly_detector.py -- Egress Anomaly Detection
Part of Watchdog AI-Attack Detection Suite.

Runs on the EgressCollector's connection feed. Detects the named network
failure modes from the 2026 agent-escape research ("hidden egress paths",
"the agent will try to connect outward", reverse SSH tunnels -- the ROME
network half):

1. UNEXPECTED_EGRESS -- an outbound connection to a destination NOT on the
   allowlist. For a sandboxed agent that should reach nothing (or only an
   approved API), any other outbound is a flag.
2. EGRESS_BEACON -- repeated outbound connections to the same destination at
   a regular interval (C2 / model-exfil beaconing signature).
3. REVERSE_TUNNEL -- the signature of a reverse shell / tunnel: a process
   that received an inbound connection then established an outbound one to
   the same or a related remote, or a long-lived outbound on an unusual
   high port paired with shell-like local activity. (Connection-level
   heuristic; not payload inspection.)

HONEST SCOPE
------------
Operates on connection metadata (IPs, ports, timing, state) -- not packet
payload. It catches the SHAPE of malicious egress, which is exactly what the
research says matters ("prove the agent cannot connect outward"). It does
NOT decrypt or inspect traffic content.

Feeds the swarm: emits swarm signals UNEXPECTED_EGRESS / EGRESS_BEACON /
REVERSE_TUNNEL that fuse with the agent-sandbox-escape detector -- an
escaped agent's GPU-grab + its outbound tunnel = the COMPLETE ROME incident.

Pure logic over collector output. Fully testable with fixture connections.

NOTE: Simulation/logic-tested. Real validation on a pod.
"""

import collections
from datetime import datetime, timezone


class EgressAnomalyDetector:
    """
    Stateful across polls (to detect beacons and tunnels over time).

    allowlist: set of remote IPs (or 'ip:port') a sandbox/agent is permitted
    to reach. Empty allowlist + strict=True means ANY outbound is unexpected
    (appropriate for a fully-sandboxed agent that should reach nothing).
    """

    def __init__(self, allowlist=None, strict=False,
                 beacon_min_hits=4, beacon_interval_tolerance=0.25,
                 tunnel_high_port=1024):
        self.allowlist = set(allowlist or [])
        self.strict = strict
        self.beacon_min_hits = beacon_min_hits
        self.beacon_interval_tolerance = beacon_interval_tolerance
        self.tunnel_high_port = tunnel_high_port
        # history: remote_key -> list of timestamps (epoch-ish floats)
        self._dest_history = collections.defaultdict(list)
        # track inbound-then-outbound per pid for reverse-tunnel heuristic
        self._pid_had_inbound = set()
        self.checks = 0
        self.flags = 0

    def _allowed(self, conn) -> bool:
        rip = conn.get("remote_ip", "")
        key = f"{rip}:{conn.get('remote_port')}"
        return rip in self.allowlist or key in self.allowlist

    def _remote_key(self, conn):
        return f"{conn.get('remote_ip')}:{conn.get('remote_port')}"

    def check(self, outbound_connections: list, inbound_connections: list = None,
              now: float = None) -> dict:
        """
        outbound_connections: from EgressCollector.outbound_only(...)
        inbound_connections: optional list of inbound (LISTEN->ESTABLISHED
            from a remote) connections, for the reverse-tunnel heuristic.
        now: float timestamp (injectable for deterministic beacon tests).
        """
        self.checks += 1
        now = now if now is not None else _epoch()
        findings = []

        # record inbound PIDs (for reverse-tunnel pairing)
        for c in (inbound_connections or []):
            pid = c.get("pid")
            if pid is not None:
                self._pid_had_inbound.add(pid)

        for conn in outbound_connections:
            key = self._remote_key(conn)
            self._dest_history[key].append(now)

            # 1. unexpected egress
            if self.strict and not self._allowed(conn):
                findings.append({"type": "UNEXPECTED_EGRESS",
                                 "remote": key, "pid": conn.get("pid"),
                                 "detail": "outbound to a non-allowlisted destination"})
            elif self.allowlist and not self._allowed(conn):
                findings.append({"type": "UNEXPECTED_EGRESS",
                                 "remote": key, "pid": conn.get("pid"),
                                 "detail": "outbound to a destination outside the allowlist"})

            # 3. reverse-tunnel heuristic: a PID that had an inbound connection
            #    now establishing outbound on a high port
            pid = conn.get("pid")
            if (pid is not None and pid in self._pid_had_inbound
                    and conn.get("remote_port", 0) >= self.tunnel_high_port
                    and conn.get("state") == "ESTABLISHED"):
                findings.append({"type": "REVERSE_TUNNEL",
                                 "remote": key, "pid": pid,
                                 "detail": "process with prior inbound now holding an "
                                           "outbound high-port connection (reverse-tunnel signature)"})

        # 2. beacon detection: a destination hit at regular intervals
        for key, times in self._dest_history.items():
            if len(times) >= self.beacon_min_hits:
                intervals = [times[i] - times[i - 1] for i in range(1, len(times))]
                recent = intervals[-(self.beacon_min_hits - 1):]
                if recent and all(i > 0 for i in recent):
                    mean_i = sum(recent) / len(recent)
                    if mean_i > 0 and all(abs(i - mean_i) <= self.beacon_interval_tolerance * mean_i
                                          for i in recent):
                        findings.append({"type": "EGRESS_BEACON",
                                         "remote": key, "interval_s": round(mean_i, 2),
                                         "hits": len(times),
                                         "detail": "regular-interval outbound (C2/exfil beacon signature)"})

        # de-dupe findings by (type, remote)
        seen = set()
        unique = []
        for f in findings:
            k = (f["type"], f.get("remote"))
            if k not in seen:
                seen.add(k)
                unique.append(f)

        status = "EGRESS_ANOMALY_DETECTED" if unique else "EGRESS_CLEAN"
        if unique:
            self.flags += 1

        result = {
            "type": status,
            "substrate": "network",
            "outbound_count": len(outbound_connections),
            "findings": unique,
            "finding_types": sorted({f["type"] for f in unique}),
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "agent": "EgressAnomalyDetector",
            "cite": ("AI agent sandbox escape research 2026 (hidden egress / "
                     "reverse-tunnel failure mode); ROME incident network half"),
            "note": ("connection-level egress monitoring -- catches the SHAPE of "
                     "malicious egress (destination/timing/state), not payload "
                     "content. Simulation-based."),
        }
        if unique:
            # strongest signal for the swarm
            for sig in ("REVERSE_TUNNEL", "EGRESS_BEACON", "UNEXPECTED_EGRESS"):
                if any(f["type"] == sig for f in unique):
                    result["swarm_signal"] = sig
                    break
            result["severity"] = ("CRITICAL" if any(f["type"] == "REVERSE_TUNNEL"
                                                    for f in unique) else "WARNING")
            result["recommended_action"] = {
                "action": "block_egress_endpoint_gated",
                "detail": "block the specific outbound destination (reversible firewall "
                          "rule) and raise; gated for a sandboxed agent",
                "risk": "gated"}
        else:
            result["severity"] = "INFO"
        return result

    def get_stats(self):
        return {"component": "EgressAnomalyDetector",
                "checks": self.checks, "flags": self.flags,
                "tracked_destinations": len(self._dest_history)}


def _epoch():
    import time
    return time.time()


if __name__ == "__main__":
    # Demo: an agent that should reach nothing (strict) beaconing out + a tunnel
    det = EgressAnomalyDetector(allowlist=set(), strict=True, beacon_min_hits=4)
    tunnel_pid = 4242
    # simulate 5 polls, same destination at 10s intervals = beacon
    for i in range(5):
        out = [{"remote_ip": "203.0.113.9", "remote_port": 4444, "pid": tunnel_pid,
                "state": "ESTABLISHED"}]
        inbound = [{"pid": tunnel_pid}] if i == 0 else []
        r = det.check(out, inbound_connections=inbound, now=1000.0 + i * 10)
    print("[EGRESS-ANOMALY]", r["type"], "severity:", r.get("severity"))
    print("  types:", r["finding_types"])
    print("  swarm signal:", r.get("swarm_signal"))
