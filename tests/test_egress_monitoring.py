#!/usr/bin/env python3
# Author: Manmohan (Mike) Bains -- Watchdog
"""
tests/test_egress_monitoring.py

Tests the network-egress slice: the /proc-based collector (with fixture
data, no root/network), the egress anomaly detector (unexpected egress,
beacon, reverse tunnel), and the egress swarm correlator (FULL_ROME_INCIDENT
= GPU escape + network tunnel).

Run standalone: python3 tests/test_egress_monitoring.py
Or via suite:   python3 tests/run_all.py (once registered in TEST_FILES).
"""
import os
import sys

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

from detection.egress_collector import (
    EgressCollector, parse_proc_net, _hex_to_ipv4, _hex_port,
)
from detection.egress_anomaly_detector import EgressAnomalyDetector
from intelligence.swarm.egress_swarm_correlator import EgressSwarmCorrelator

PASSED = []
FAILED = []


def check(name, condition, detail=""):
    if condition:
        PASSED.append(name)
        print(f"[PASS] {name}")
    else:
        FAILED.append(name)
        print(f"[FAIL] {name} {detail}")


# a /proc/net/tcp fixture: a listener + one outbound to a public IP:443
SAMPLE_TCP = (
    "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
    "   0: 0100007F:0035 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 12345\n"
    "   1: 0100007F:B3C2 5B8D8EA0:01BB 01 00000000:00000000 00:00000000 00000000  1000        0 67890\n"
)


# --------------------------------------------------------------------------
# Collector primitives
# --------------------------------------------------------------------------
def test_hex_ipv4_conversion():
    check("egress: hex->IPv4 (0100007F = 127.0.0.1)",
          _hex_to_ipv4("0100007F") == "127.0.0.1", f"got {_hex_to_ipv4('0100007F')}")


def test_hex_port_conversion():
    check("egress: hex port (01BB = 443)", _hex_port("01BB") == 443, f"got {_hex_port('01BB')}")


def test_parse_proc_net():
    conns = parse_proc_net(SAMPLE_TCP, proto="tcp")
    check("egress: parses 2 connections from /proc/net/tcp", len(conns) == 2, f"got {len(conns)}")
    established = [c for c in conns if c["state"] == "ESTABLISHED"]
    check("egress: identifies the ESTABLISHED outbound (port 443)",
          len(established) == 1 and established[0]["remote_port"] == 443, f"got {established}")


def test_collector_proc_mode():
    def fake_read(path):
        return SAMPLE_TCP if path == "/proc/net/tcp" else None
    c = EgressCollector(proc_reader=fake_read)
    collected = c.collect()
    check("egress: collector runs in /proc mode",
          collected["mode"] == "proc", f"got {collected['mode']}")
    out = c.outbound_only(collected)
    check("egress: outbound_only filters to the real outbound connection",
          len(out) == 1 and out[0]["remote_port"] == 443, f"got {out}")


def test_collector_unavailable_is_honest():
    def no_proc(path):
        return None
    c = EgressCollector(proc_reader=no_proc)
    collected = c.collect()
    check("egress: no /proc/net -> mode 'unavailable' (honest, not fake-clean)",
          collected["mode"] == "unavailable", f"got {collected['mode']}")


def test_collector_ebpf_mode_label():
    class FakeEbpf:
        def poll(self):
            return [{"remote_ip": "8.8.8.8", "remote_port": 443, "state": "ESTABLISHED"}]
    c = EgressCollector(ebpf_backend=FakeEbpf())
    collected = c.collect()
    check("egress: eBPF backend -> mode 'ebpf'",
          collected["mode"] == "ebpf", f"got {collected['mode']}")


# --------------------------------------------------------------------------
# Anomaly detector
# --------------------------------------------------------------------------
def test_unexpected_egress_strict():
    det = EgressAnomalyDetector(allowlist=set(), strict=True)
    out = [{"remote_ip": "203.0.113.9", "remote_port": 443, "pid": 100, "state": "ESTABLISHED"}]
    r = det.check(out, now=1000.0)
    check("egress: strict sandbox + any outbound -> UNEXPECTED_EGRESS",
          any(f["type"] == "UNEXPECTED_EGRESS" for f in r["findings"]), f"got {r['findings']}")


def test_allowlisted_egress_clean():
    det = EgressAnomalyDetector(allowlist={"8.8.8.8:443"}, strict=True)
    out = [{"remote_ip": "8.8.8.8", "remote_port": 443, "pid": 100, "state": "ESTABLISHED"}]
    r = det.check(out, now=1000.0)
    check("egress: allowlisted destination -> EGRESS_CLEAN",
          r["type"] == "EGRESS_CLEAN", f"got {r['type']} findings={r['findings']}")


def test_beacon_detection():
    det = EgressAnomalyDetector(allowlist={"203.0.113.9:443"}, beacon_min_hits=4)
    # same destination every 10s -> beacon (allowlisted so only beacon flags)
    r = None
    for i in range(5):
        out = [{"remote_ip": "203.0.113.9", "remote_port": 443, "pid": 100, "state": "ESTABLISHED"}]
        r = det.check(out, now=1000.0 + i * 10)
    check("egress: regular-interval outbound -> EGRESS_BEACON",
          any(f["type"] == "EGRESS_BEACON" for f in r["findings"]), f"got {r['findings']}")


def test_reverse_tunnel_detection():
    det = EgressAnomalyDetector(allowlist=set(), strict=False)
    pid = 4242
    # first: inbound to the pid; then outbound high-port established = tunnel
    det.check([], inbound_connections=[{"pid": pid}], now=1000.0)
    out = [{"remote_ip": "203.0.113.9", "remote_port": 4444, "pid": pid, "state": "ESTABLISHED"}]
    r = det.check(out, now=1005.0)
    check("egress: inbound-then-outbound-high-port -> REVERSE_TUNNEL",
          any(f["type"] == "REVERSE_TUNNEL" for f in r["findings"]), f"got {r['findings']}")
    check("egress: reverse tunnel is CRITICAL",
          r["severity"] == "CRITICAL", f"got {r['severity']}")


def test_egress_gated_remediation():
    det = EgressAnomalyDetector(allowlist=set(), strict=True)
    out = [{"remote_ip": "203.0.113.9", "remote_port": 443, "pid": 100, "state": "ESTABLISHED"}]
    r = det.check(out, now=1000.0)
    check("egress: remediation is gated (block endpoint, not auto-kill)",
          r["recommended_action"]["risk"] == "gated", f"got {r['recommended_action']}")


def test_clean_when_no_outbound():
    det = EgressAnomalyDetector(allowlist=set(), strict=True)
    r = det.check([], now=1000.0)
    check("egress: no outbound connections -> EGRESS_CLEAN",
          r["type"] == "EGRESS_CLEAN", f"got {r['type']}")


# --------------------------------------------------------------------------
# Egress swarm correlator -- the FULL ROME incident
# --------------------------------------------------------------------------
def test_full_rome_incident():
    clock = {"t": 1000.0}
    c = EgressSwarmCorrelator(time_fn=lambda: clock["t"])
    out = c.observe({"swarm_signal": "AGENT_SANDBOX_ESCAPE"})
    check("egress-swarm: escape alone -> no full incident yet", out == [], f"got {out}")
    clock["t"] += 3
    out = c.observe({"swarm_signal": "REVERSE_TUNNEL"})
    check("egress-swarm: escape + reverse tunnel -> FULL_ROME_INCIDENT",
          any(i["incident"] == "FULL_ROME_INCIDENT" for i in out), f"got {out}")
    check("egress-swarm: full ROME incident is CRITICAL",
          any(i["severity"] == "CRITICAL" for i in out), f"got {out}")


def test_exfiltration_suspected():
    clock = {"t": 2000.0}
    c = EgressSwarmCorrelator(time_fn=lambda: clock["t"])
    c.observe({"swarm_signal": "EGRESS_BEACON"})
    clock["t"] += 3
    out = c.observe({"type": "MODEL_EXTRACTION_PRECURSOR_PREDICTED"})
    check("egress-swarm: beacon + model-extraction -> EXFILTRATION_SUSPECTED",
          any(i["incident"] == "EXFILTRATION_SUSPECTED" for i in out), f"got {out}")


def test_egress_swarm_outside_window():
    clock = {"t": 3000.0}
    c = EgressSwarmCorrelator(window_seconds=60.0, time_fn=lambda: clock["t"])
    c.observe({"swarm_signal": "AGENT_SANDBOX_ESCAPE"})
    clock["t"] += 200
    out = c.observe({"swarm_signal": "REVERSE_TUNNEL"})
    check("egress-swarm: signals outside window do not fuse",
          not any(i["incident"] == "FULL_ROME_INCIDENT" for i in out), f"got {out}")


if __name__ == "__main__":
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for t in tests:
        try:
            t()
        except Exception as e:
            check(t.__name__, False, f"EXCEPTION {e!r}")
    print("\n" + "=" * 60)
    print(f"PASSED: {len(PASSED)}   FAILED: {len(FAILED)}")
    if FAILED:
        print("\nFailures:")
        for f in FAILED:
            print(f"  - {f}")
    print("=" * 60)
    sys.exit(1 if FAILED else 0)
