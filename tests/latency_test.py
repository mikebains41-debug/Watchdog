#!/usr/bin/env python3
# Author: Manmohan (Mike) Bains -- Watchdog
# Watchdog - Attack Detection Latency Test
# HONEST STATUS: requires real GPU hardware with nvidia-smi. Confirmed
# NOT present on this device.
import sys, os, time, json
from datetime import datetime
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from agent.telemetry import TelemetryCollector
from detection.engines import DetectionPipeline

class LatencyTest:
    def __init__(self, hz=100):
        self.hz = hz
        self.interval_s = 1.0 / hz
        self.latencies = []
        self.detected = []
    def inject_attack(self):
        pipeline = DetectionPipeline()
        collector = TelemetryCollector(hz=self.hz)
        for _ in range(35):
            row = collector.collect()
            if row:
                row['power.draw'] = 50; row['utilization.gpu'] = 0; row['memory.used'] = 100
                pipeline.process(row)
        attack_time = time.time()
        for i in range(5):
            row = collector.collect()
            if row:
                row['power.draw'] = 100; row['utilization.gpu'] = 0; row['memory.used'] = 100
                result = pipeline.process(row)
                if result:
                    latency = time.time() - attack_time
                    self.latencies.append(latency)
                    self.detected.append({"latency_s": latency})
                    print(f"[DETECTED] Latency: {latency*1000:.1f}ms")
                    return
            time.sleep(self.interval_s)
    def run(self, iterations=100):
        print(f"Running {iterations} latency tests at {self.hz}Hz")
        for i in range(iterations):
            self.inject_attack()
        if self.latencies:
            avg_ms = sum(self.latencies)/len(self.latencies)*1000
            print(f"Avg latency: {avg_ms:.1f}ms")
        results = {"detections": len(self.detected), "latencies_ms": [l*1000 for l in self.latencies]}
        with open("latency_results.json", "w") as f: json.dump(results, f, indent=2)
        return len(self.detected) > 90

if __name__ == "__main__":
    import argparse
    p = argparse.ArgumentParser(); p.add_argument("--iterations", type=int, default=100); p.add_argument("--hz", type=int, default=100)
    a = p.parse_args()
    t = LatencyTest(hz=a.hz); s = t.run(iterations=a.iterations); sys.exit(0 if s else 1)
