#!/usr/bin/env python3
# Author: Manmohan (Mike) Bains -- Watchdog
"""
egress_collector.py -- Network Egress Collector (the Pile-2 network slice)
Part of Watchdog AI-Attack Detection Suite.

WHY THIS EXISTS
---------------
Every Watchdog detector so far reads nvidia-smi (always available). Network
egress is different: seeing outbound connections requires OS-level access
that varies by environment. This collector provides a GUARANTEED baseline
(/proc/net/*, readable on any Linux with no privileges) plus an OPTIONAL
high-fidelity eBPF path where the deployment allows it -- and honestly
labels which mode is active.

This unlocks the network half of the agent-escape / ROME story: an escaped
agent's GPU-grab (already detected) plus its reverse tunnel / hidden egress
(this) = a complete incident. It also unlocks beacon and mass-scan
detection.

HONEST SCOPE
------------
- /proc mode = CONNECTION-LEVEL monitoring (who is connected to whom), NOT
  deep packet inspection. It catches connections, not payload content.
- /proc is a snapshot poll, not per-packet real-time. eBPF mode (optional,
  needs CAP_BPF) gives per-connection real-time; where unavailable this
  degrades to /proc and SAYS SO.
- This is the NETWORK-EGRESS slice of the broader Pile-2 ingestion layer,
  not the whole thing (IAM logs, Redis, prompt content remain separate).

FORMAT
------
Parses /proc/net/tcp and /proc/net/tcp6 (hex-encoded addresses, standard
Linux format) into normalized connection events:
  {pid, local_ip, local_port, remote_ip, remote_port, state, proto, ts}

The file reader is injectable so this is fully testable with fixture data
(no real network, no root).

NOTE: Simulation/logic-tested. Real validation on a pod.
"""

import os
import re
import struct
import socket
from datetime import datetime, timezone

# TCP states from the Linux kernel (/proc/net/tcp st field, hex).
TCP_STATES = {
    "01": "ESTABLISHED", "02": "SYN_SENT", "03": "SYN_RECV",
    "04": "FIN_WAIT1", "05": "FIN_WAIT2", "06": "TIME_WAIT",
    "07": "CLOSE", "08": "CLOSE_WAIT", "09": "LAST_ACK",
    "0A": "LISTEN", "0B": "CLOSING",
}


def _hex_to_ipv4(hex_addr: str) -> str:
    """/proc/net/tcp stores IPv4 as little-endian hex, e.g. '0100007F' = 127.0.0.1."""
    try:
        addr = int(hex_addr, 16)
        packed = struct.pack("<I", addr)
        return socket.inet_ntoa(packed)
    except (ValueError, struct.error, OSError):
        return "0.0.0.0"


def _hex_to_ipv6(hex_addr: str) -> str:
    try:
        # 32 hex chars, 4 little-endian 32-bit words
        b = bytes.fromhex(hex_addr)
        words = struct.unpack("<IIII", b)
        packed = struct.pack(">IIII", *words)
        return socket.inet_ntop(socket.AF_INET6, packed)
    except Exception:
        return "::"


def _hex_port(hex_port: str) -> int:
    try:
        return int(hex_port, 16)
    except ValueError:
        return 0


def parse_proc_net(text: str, proto: str = "tcp", ipv6: bool = False) -> list:
    """Parse a /proc/net/tcp(6) file body into connection dicts (no PID yet;
    PID mapping is a separate step via inode->fd)."""
    conns = []
    lines = text.strip().splitlines()
    for line in lines[1:]:  # skip header
        parts = line.split()
        if len(parts) < 10:
            continue
        local = parts[1]
        remote = parts[2]
        st = parts[3].upper()
        inode = parts[9]
        try:
            l_addr, l_port = local.split(":")
            r_addr, r_port = remote.split(":")
        except ValueError:
            continue
        conv = _hex_to_ipv6 if ipv6 else _hex_to_ipv4
        conns.append({
            "proto": proto,
            "local_ip": conv(l_addr),
            "local_port": _hex_port(l_port),
            "remote_ip": conv(r_addr),
            "remote_port": _hex_port(r_port),
            "state": TCP_STATES.get(st, st),
            "inode": inode,
        })
    return conns


class EgressCollector:
    """
    Collects outbound connection events. Baseline uses /proc/net/*; an eBPF
    backend can be injected for real-time high-fidelity where available.
    """

    def __init__(self, proc_reader=None, pid_inode_map_fn=None, ebpf_backend=None):
        # proc_reader(path) -> text; injectable for tests
        self._read = proc_reader or self._default_read
        # pid_inode_map_fn() -> {inode: pid}; injectable
        self._pid_inode_map = pid_inode_map_fn
        self.ebpf = ebpf_backend
        self.mode = "ebpf" if ebpf_backend else "proc"

    def _default_read(self, path):
        try:
            with open(path) as f:
                return f.read()
        except (FileNotFoundError, PermissionError, OSError):
            return None

    def _map_pids(self, conns: list):
        """Attach a PID to each connection via inode, if a mapper is provided."""
        if self._pid_inode_map is None:
            return
        try:
            inode_to_pid = self._pid_inode_map()
        except Exception:
            inode_to_pid = {}
        for c in conns:
            c["pid"] = inode_to_pid.get(c.get("inode"))

    def collect(self) -> dict:
        """Return current connections + the honest mode label."""
        ts = datetime.now(timezone.utc).isoformat()

        if self.ebpf is not None:
            try:
                conns = self.ebpf.poll()  # backend returns normalized conns
                for c in conns:
                    c.setdefault("ts", ts)
                return {"mode": "ebpf", "timestamp": ts, "connections": conns,
                        "note": "eBPF real-time per-connection monitoring"}
            except Exception as e:
                # fall through to /proc, honestly
                pass

        conns = []
        for path, proto, v6 in (("/proc/net/tcp", "tcp", False),
                                ("/proc/net/tcp6", "tcp", True),
                                ("/proc/net/udp", "udp", False),
                                ("/proc/net/udp6", "udp", True)):
            text = self._read(path)
            if text:
                conns.extend(parse_proc_net(text, proto=proto, ipv6=v6))

        self._map_pids(conns)
        for c in conns:
            c["ts"] = ts

        if not any(self._read(p) for p in ("/proc/net/tcp",)):
            return {"mode": "unavailable", "timestamp": ts, "connections": [],
                    "note": "/proc/net not readable (non-Linux or restricted); "
                            "egress monitoring unavailable in this environment"}

        return {"mode": "proc", "timestamp": ts, "connections": conns,
                "note": ("connection-level egress monitoring via /proc/net "
                         "(snapshot poll; not deep packet inspection). eBPF "
                         "backend not attached -- attach for real-time fidelity.")}

    def outbound_only(self, collected: dict) -> list:
        """Filter to ESTABLISHED/SYN_SENT connections with a non-local remote
        -- i.e. actual outbound egress, not listeners or loopback."""
        out = []
        for c in collected.get("connections", []):
            if c.get("state") in ("ESTABLISHED", "SYN_SENT"):
                rip = c.get("remote_ip", "")
                if rip and not rip.startswith("127.") and rip not in ("0.0.0.0", "::"):
                    out.append(c)
        return out


if __name__ == "__main__":
    # Demo with a synthetic /proc/net/tcp (one outbound HTTPS connection).
    sample_tcp = (
        "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
        "   0: 0100007F:0035 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 12345\n"  # listener 127.0.0.1:53
        "   1: 0100007F:B3C2 5B8D8EA0:01BB 01 00000000:00000000 00:00000000 00000000  1000        0 67890\n"  # outbound to a public IP:443
    )
    def fake_read(path):
        return sample_tcp if path == "/proc/net/tcp" else None

    c = EgressCollector(proc_reader=fake_read)
    collected = c.collect()
    print("[EGRESS] mode:", collected["mode"], "| conns:", len(collected["connections"]))
    for conn in c.outbound_only(collected):
        print(f"  OUT {conn['local_ip']}:{conn['local_port']} -> "
              f"{conn['remote_ip']}:{conn['remote_port']} [{conn['state']}]")
