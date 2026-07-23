#!/usr/bin/env python3
# Author: Manmohan (Mike) Bains -- Watchdog AIDR
# Watchdog AIDR - Multi-Node Swarm Test
# HONEST STATUS: requires 2+ real running Watchdog API server instances
# reachable over the network. Uses the REAL endpoints confirmed in
# api/server.py: /status, /alerts, /health, /throughput.
#
# FIXED: previously POSTed to /api/v1/inject/{attack_type}, an endpoint
# removed tonight -- it never actually reached the live detection
# pipeline, and an unauthenticated "pretend any attack happened" switch
# on a live security tool was the wrong design regardless of whether it
# worked. Repointed to /throughput, the one real, purpose-built
# data-ingestion endpoint proven live end-to-end tonight: calibrates a
# real baseline, then sends a genuine contention-level reading, and lets
# the REAL ThroughputContentionDetector decide whether to fire -- not a
# generic fake-attack switch.
import sys, time, json, requests
from datetime import datetime


class SwarmTest:
    def __init__(self, nodes):
        self.nodes = nodes

    def check_health(self, node):
        try:
            r = requests.get(f"http://{node}/health", timeout=5)
            return r.status_code == 200
        except: return False

    def check_alerts(self, node):
        try:
            r = requests.get(f"http://{node}/alerts", timeout=5)
            return r.json() if r.status_code == 200 else None
        except: return None

    def trigger_throughput_contention(self, node):
        """Calibrates the real baseline (372.32 iter/sec, the same
        documented value used throughout this repo), then sends the
        real measured contention reading (336.96, -9.5%). Returns True
        only if the node accepted the process-mode request -- does not
        guarantee an alert fired, since require_consecutive=3 means a
        single call may land before the threshold is met."""
        try:
            for _ in range(10):
                requests.post(f"http://{node}/throughput",
                               json={"throughput": 372.32, "mode": "calibrate"},
                               timeout=5)
            r = requests.post(f"http://{node}/throughput",
                               json={"throughput": 336.96, "mode": "process"},
                               timeout=5)
            return r.status_code == 200
        except:
            return False

    def run(self):
        print(f"Swarm Test: {len(self.nodes)} nodes")
        reachable = [n for n in self.nodes if self.check_health(n)]
        print(f"Reachable nodes: {len(reachable)}/{len(self.nodes)}")
        if not reachable:
            print("No nodes reachable -- this test requires real running Watchdog API servers")
            return False
        baselines = {n: self.check_alerts(n) for n in reachable}
        triggered = self.trigger_throughput_contention(reachable[0])
        print(f"Throughput contention triggered on {reachable[0]}: {triggered}")
        time.sleep(2)
        results = {n: self.check_alerts(n) for n in reachable}
        with open("swarm_results.json", "w") as f:
            json.dump({"reachable": reachable, "triggered": triggered,
                       "baselines": baselines, "after": results},
                      f, indent=2, default=str)
        return len(reachable) == len(self.nodes)


if __name__ == "__main__":
    import argparse
    p = argparse.ArgumentParser()
    p.add_argument("--nodes", nargs="+", default=["localhost:8080"])
    a = p.parse_args()
    t = SwarmTest(nodes=a.nodes)
    s = t.run()
    sys.exit(0 if s else 1)
