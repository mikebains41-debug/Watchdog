#!/usr/bin/env python3
# Author: Manmohan (Mike) Bains -- Watchdog AIDR
# Watchdog AIDR - 72-Hour Stability Test
# HONEST STATUS: requires real GPU hardware with nvidia-smi. Confirmed
# NOT present on this device.
import sys, os, time, json, psutil
from datetime import datetime
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from agent.telemetry import TelemetryCollector
from detection.engines import DetectionPipeline

class StabilityTest:
    def __init__(self, duration_hours=72, hz=100):
        self.duration_hours = duration_hours; self.hz = hz; self.interval_s = 1.0/hz
        self.alerts = []; self.samples = 0; self.errors = 0; self.memory_samples = []
    def collect_metrics(self):
        p = psutil.Process()
        return {"memory_mb": p.memory_info().rss/1024/1024}
    def run(self):
        pipeline = DetectionPipeline(); collector = TelemetryCollector(hz=self.hz)
        print(f"Starting {self.duration_hours}h stability test")
        start = time.time(); end = start + (self.duration_hours*3600)
        while time.time() < end:
            try:
                row = collector.collect()
                if row:
                    alerts = pipeline.process(row)
                    if alerts: self.alerts.append({"timestamp": datetime.now().isoformat(), "alerts": alerts})
                self.samples += 1
                self.memory_samples.append(self.collect_metrics())
                if self.samples % 10000 == 0:
                    print(f"Samples: {self.samples}, Alerts: {len(self.alerts)}")
                time.sleep(self.interval_s)
            except Exception as e:
                self.errors += 1
                print(f"[ERROR] {e}")
        mem_vals = [m['memory_mb'] for m in self.memory_samples]
        results = {"samples": self.samples, "errors": self.errors, "alerts": len(self.alerts),
                   "memory": {"min_mb": min(mem_vals) if mem_vals else 0, "max_mb": max(mem_vals) if mem_vals else 0}}
        with open("stability_results.json", "w") as f: json.dump(results, f, indent=2)
        return self.errors == 0 and len(self.alerts) < 10

if __name__ == "__main__":
    import argparse
    p = argparse.ArgumentParser(); p.add_argument("--duration", type=int, default=72); p.add_argument("--hz", type=int, default=100)
    a = p.parse_args()
    t = StabilityTest(duration_hours=a.duration, hz=a.hz); s = t.run(); sys.exit(0 if s else 1)
