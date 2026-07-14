#!/usr/bin/env python3
# Watchdog AIDR - Multi-Node Swarm Test
# HONEST STATUS: requires 2+ real running Watchdog API server instances
# reachable over the network. Uses the REAL endpoints confirmed in
# api/server.py: /status, /alerts, /health, /api/v1/inject/{attack_type}
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
    def trigger_attack(self, node, attack_type="GHOST_POWER"):
        try:
            r = requests.post(f"http://{node}/api/v1/inject/{attack_type}", timeout=5)
            return r.status_code == 200
        except: return False
    def run(self):
        print(f"Swarm Test: {len(self.nodes)} nodes")
        reachable = [n for n in self.nodes if self.check_health(n)]
        print(f"Reachable nodes: {len(reachable)}/{len(self.nodes)}")
        if not reachable:
            print("No nodes reachable -- this test requires real running Watchdog API servers")
            return False
        baselines = {n: self.check_alerts(n) for n in reachable}
        self.trigger_attack(reachable[0])
        time.sleep(5)
        results = {n: self.check_alerts(n) for n in reachable}
        with open("swarm_results.json", "w") as f:
            json.dump({"reachable": reachable, "baselines": baselines, "after": results}, f, indent=2, default=str)
        return len(reachable) == len(self.nodes)

if __name__ == "__main__":
    import argparse
    p = argparse.ArgumentParser()
    p.add_argument("--nodes", nargs="+", default=["localhost:8080"])
    a = p.parse_args()
    t = SwarmTest(nodes=a.nodes)
    s = t.run()
    sys.exit(0 if s else 1)
