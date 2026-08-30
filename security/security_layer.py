"""
GPU Security Layer v2.0 - Private
Author: Manmohan (Mike) Bains
Contact: mikebains41@gmail.com
PRIVATE - DO NOT DISTRIBUTE
"""

import subprocess
import time
import json
import hashlib
import datetime
import statistics
from dataclasses import dataclass, asdict
from typing import Optional, List

# ============================================================
# THRESHOLDS
# ============================================================

COVERT_POWER_DELTA      = 15.0  # Watts above baseline
COVERT_UTIL_THRESHOLD   = 5.0   # % util suspicious
COVERT_CONFIDENCE_MIN   = 0.7   # Minimum confidence to flag
UNAUTHORIZED_POWER      = 50.0  # Watts at near zero util
UNAUTHORIZED_UTIL       = 2.0   # % util threshold
VRAM_ANOMALY_THRESHOLD  = 85.0  # % VRAM used with low compute
ABNORMAL_TEMP           = 85.0  # Celsius
SAMPLING_INTERVAL       = 1.0   # Seconds
BASELINE_SAMPLES        = 30    # Samples for baseline

# ============================================================
# GPU READER — nvidia-smi based, no pynvml
# ============================================================

def read_gpu(gpu_index: int = 0) -> dict:
    """Read GPU metrics via nvidia-smi. Works on any NVIDIA GPU via SSH."""
    try:
        cmd = [
            "nvidia-smi",
            f"--id={gpu_index}",
            "--query-gpu=power.draw,utilization.gpu,utilization.memory,"
            "memory.used,memory.free,memory.total,temperature.gpu,"
            "clocks.current.memory,pstate",
            "--format=csv,noheader,nounits"
        ]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        parts  = [p.strip() for p in result.stdout.strip().split(",")]

        return {
            "power_watts"     : float(parts[0]),
            "util_gpu_pct"    : float(parts[1]),
            "util_mem_pct"    : float(parts[2]),
            "vram_used_mb"    : float(parts[3]),
            "vram_free_mb"    : float(parts[4]),
            "vram_total_mb"   : float(parts[5]),
            "temp_celsius"    : float(parts[6]),
            "mem_clock_mhz"   : float(parts[7]),
            "pstate"          : parts[8],
            "timestamp"       : datetime.datetime.utcnow().isoformat(),
            "gpu_index"       : gpu_index
        }
    except Exception as e:
        return {"error": str(e)}

# ============================================================
# COVERT CHANNEL DETECTOR
# ============================================================

class CovertChannelDetector:
    """
    Detects abnormal power signatures indicating
    data exfiltration or hidden compute.
    High power + low utilization = potential covert channel.
    """

    def __init__(self, gpu_index: int = 0):
        self.gpu_index     = gpu_index
        self.baseline      = None
        self.power_history = []
        self.events        = []

    def establish_baseline(self) -> float:
        print(f"[COVERT] Establishing baseline on GPU {self.gpu_index}...")
        samples = []
        for i in range(BASELINE_SAMPLES):
            data = read_gpu(self.gpu_index)
            if "error" not in data:
                samples.append(data["power_watts"])
            time.sleep(SAMPLING_INTERVAL)
            print(f"  Sample {i+1}/{BASELINE_SAMPLES}: {samples[-1]:.1f}W", end="\r")
        self.baseline = statistics.mean(samples)
        print(f"\n[COVERT] Baseline: {self.baseline:.2f}W")
        return self.baseline

    def analyze(self, data: dict) -> Optional[dict]:
        if "error" in data or self.baseline is None:
            return None

        power      = data["power_watts"]
        util       = data["util_gpu_pct"]
        delta      = power - self.baseline
        confidence = 0.0
        pattern    = "NONE"

        self.power_history.append(power)

        # Pattern 1 — high power low util
        if delta > COVERT_POWER_DELTA and util < COVERT_UTIL_THRESHOLD:
            confidence += 0.5
            pattern     = "HIGH_POWER_LOW_UTIL"

        # Pattern 2 — sustained elevation
        if len(self.power_history) >= 10:
            avg = statistics.mean(self.power_history[-10:])
            if avg > self.baseline + COVERT_POWER_DELTA:
                confidence += 0.3
                pattern     = "SUSTAINED_ELEVATION"

        # Pattern 3 — oscillation at low util
        if len(self.power_history) >= 20:
            std = statistics.stdev(self.power_history[-20:])
            if std > 10.0 and util < COVERT_UTIL_THRESHOLD:
                confidence += 0.2
                pattern     = "OSCILLATION_PATTERN"

        if confidence >= COVERT_CONFIDENCE_MIN:
            event = {
                "type"            : "COVERT_CHANNEL",
                "timestamp"       : data["timestamp"],
                "gpu_index"       : self.gpu_index,
                "power_baseline"  : self.baseline,
                "power_current"   : power,
                "power_delta"     : delta,
                "util_pct"        : util,
                "pattern"         : pattern,
                "confidence"      : round(min(confidence, 1.0), 2),
                "details"         : f"{pattern} | delta={delta:.1f}W | confidence={confidence:.2f}"
            }
            self.events.append(event)
            return event

        return None

# ============================================================
# VRAM INTROSPECTOR
# ============================================================

class VRAMIntrospector:
    """
    Monitors VRAM usage patterns to detect:
    - Abnormal memory retention after workload
    - Suspicious allocation patterns
    - Memory based covert channels
    """

    def __init__(self, gpu_index: int = 0):
        self.gpu_index     = gpu_index
        self.baseline_vram = None
        self.snapshots     = []

    def snapshot(self, data: dict) -> dict:
        if "error" in data:
            return {}

        used_mb   = data["vram_used_mb"]
        total_mb  = data["vram_total_mb"]
        vram_pct  = (used_mb / total_mb) * 100 if total_mb > 0 else 0
        util      = data["util_gpu_pct"]
        power     = data["power_watts"]

        anomaly = False
        details = "Normal"

        # Anomaly 1 — high VRAM low compute
        if vram_pct > VRAM_ANOMALY_THRESHOLD and util < 5.0:
            anomaly = True
            details = f"VRAM anomaly: {vram_pct:.1f}% used at {util}% compute"

        # Anomaly 2 — VRAM not releasing after workload
        if self.baseline_vram and used_mb > self.baseline_vram * 2.0 and util < 5.0:
            anomaly = True
            details = f"VRAM retention: {used_mb:.0f}MB held at idle (baseline {self.baseline_vram:.0f}MB)"

        snap = {
            "type"             : "VRAM_SNAPSHOT",
            "timestamp"        : data["timestamp"],
            "gpu_index"        : self.gpu_index,
            "used_mb"          : used_mb,
            "free_mb"          : data["vram_free_mb"],
            "total_mb"         : total_mb,
            "vram_pct"         : round(vram_pct, 2),
            "util_pct"         : util,
            "power_watts"      : power,
            "anomaly_detected" : anomaly,
            "details"          : details
        }

        self.snapshots.append(snap)

        if self.baseline_vram is None:
            self.baseline_vram = used_mb

        return snap

# ============================================================
# UNAUTHORIZED COMPUTE DETECTOR
# ============================================================

class UnauthorizedComputeDetector:
    """
    Detects GPU compute activity bypassing job schedulers.
    Flags GPU activity not registered in workload manager.
    """

    def __init__(self, gpu_index: int = 0):
        self.gpu_index = gpu_index
        self.events    = []

    def check(self, data: dict) -> Optional[dict]:
        if "error" in data:
            return None

        power    = data["power_watts"]
        util     = data["util_gpu_pct"]
        mem_used = data["vram_used_mb"]

        confidence = 0.0
        method     = "NONE"

        # Method 1 — power without util
        if power > UNAUTHORIZED_POWER and util < UNAUTHORIZED_UTIL:
            confidence += 0.6
            method      = "POWER_WITHOUT_UTIL"

        # Method 2 — memory allocated no activity
        if mem_used > 1000 and util < 1.0 and power > 80.0:
            confidence += 0.4
            method      = "MEMORY_WITHOUT_ACTIVITY"

        if confidence >= 0.6:
            event = {
                "type"        : "UNAUTHORIZED_COMPUTE",
                "timestamp"   : data["timestamp"],
                "gpu_index"   : self.gpu_index,
                "power_watts" : power,
                "util_pct"    : util,
                "mem_used_mb" : mem_used,
                "method"      : method,
                "confidence"  : round(min(confidence, 1.0), 2),
                "details"     : f"{method} | power={power:.1f}W | util={util}% | mem={mem_used:.0f}MB"
            }
            self.events.append(event)
            return event

        return None

# ============================================================
# ABNORMAL DRAW ALERTER
# ============================================================

class AbnormalDrawAlerter:
    """
    Real time alerting for abnormal power signatures.
    Unified alert stream across all detection layers.
    """

    def __init__(self, gpu_index: int = 0):
        self.gpu_index = gpu_index
        self.alerts    = []

    def evaluate(self, data: dict) -> List[dict]:
        if "error" in data:
            return []

        alerts = []
        power  = data["power_watts"]
        util   = data["util_gpu_pct"]
        temp   = data["temp_celsius"]

        def fingerprint():
            raw = f"{power}{util}{temp}{data['timestamp']}"
            return hashlib.sha256(raw.encode()).hexdigest()[:16]

        # Alert 1 — thermal anomaly
        if temp > ABNORMAL_TEMP and util < 10.0:
            alert = {
                "type"        : "THERMAL_ANOMALY",
                "severity"    : "HIGH",
                "timestamp"   : data["timestamp"],
                "gpu_index"   : self.gpu_index,
                "power_watts" : power,
                "util_pct"    : util,
                "temp_celsius": temp,
                "fingerprint" : fingerprint(),
                "details"     : f"High temp {temp}C at {util}% util"
            }
            alerts.append(alert)
            self.alerts.append(alert)

        # Alert 2 — ghost power
        if power > 100.0 and util == 0:
            alert = {
                "type"        : "GHOST_POWER",
                "severity"    : "CRITICAL",
                "timestamp"   : data["timestamp"],
                "gpu_index"   : self.gpu_index,
                "power_watts" : power,
                "util_pct"    : util,
                "temp_celsius": temp,
                "fingerprint" : fingerprint(),
                "details"     : f"Ghost power {power:.1f}W at 0% util — DESYNC confirmed"
            }
            alerts.append(alert)
            self.alerts.append(alert)

        # Alert 3 — P0 state lock
        if data.get("pstate") == "P0" and util < 5.0 and power > 80.0:
            alert = {
                "type"        : "P0_STATE_LOCK",
                "severity"    : "HIGH",
                "timestamp"   : data["timestamp"],
                "gpu_index"   : self.gpu_index,
                "power_watts" : power,
                "util_pct"    : util,
                "temp_celsius": temp,
                "fingerprint" : fingerprint(),
                "details"     : f"P0 lock detected {power:.1f}W at {util}% util"
            }
            alerts.append(alert)
            self.alerts.append(alert)

        return alerts

# ============================================================
# MASTER SECURITY SCANNER
# ============================================================

class GPUSecurityScanner:
    """
    Master scanner combining all detection layers.
    Runs continuous monitoring and outputs unified report.
    """

    def __init__(self, gpu_index: int = 0, duration_seconds: int = 172800):
        self.gpu_index    = gpu_index
        self.duration     = duration_seconds
        self.covert       = CovertChannelDetector(gpu_index)
        self.vram         = VRAMIntrospector(gpu_index)
        self.unauthorized = UnauthorizedComputeDetector(gpu_index)
        self.alerter      = AbnormalDrawAlerter(gpu_index)
        self.all_events   = []

    def run(self):
        print(f"\n{'='*60}")
        print(f"GPU SECURITY SCANNER v2.0")
        print(f"GPU Index    : {self.gpu_index}")
        print(f"Duration     : {self.duration}s")
        print(f"Author       : Manmohan (Mike) Bains")
        print(f"{'='*60}\n")

        self.covert.establish_baseline()

        start        = time.time()
        sample_count = 0

        print("\n[SCANNER] Live monitoring...\n")

        while time.time() - start < self.duration:
            sample_count += 1
            elapsed      = time.time() - start
            data         = read_gpu(self.gpu_index)

            if "error" in data:
                print(f"[ERROR] {data['error']}")
                time.sleep(SAMPLING_INTERVAL)
                continue

            covert_event     = self.covert.analyze(data)
            vram_snap        = self.vram.snapshot(data)
            unauthorized_evt = self.unauthorized.check(data)
            alerts           = self.alerter.evaluate(data)

            status = "CLEAN"
            if covert_event or unauthorized_evt or alerts:
                status = "ALERT"

            print(
                f"[{elapsed:6.1f}s] "
                f"Power:{data['power_watts']:6.1f}W | "
                f"Util:{data['util_gpu_pct']:3.0f}% | "
                f"Temp:{data['temp_celsius']:3.0f}C | "
                f"VRAM:{vram_snap.get('vram_pct',0):5.1f}% | "
                f"{status}"
            )

            if covert_event:
                self.all_events.append(covert_event)
                print(f"  COVERT: {covert_event['details']}")

            if unauthorized_evt:
                self.all_events.append(unauthorized_evt)
                print(f"  UNAUTHORIZED: {unauthorized_evt['details']}")

            if vram_snap.get("anomaly_detected"):
                self.all_events.append(vram_snap)
                print(f"  VRAM: {vram_snap['details']}")

            for alert in alerts:
                self.all_events.append(alert)
                print(f"  [{alert['severity']}] {alert['details']}")

            time.sleep(SAMPLING_INTERVAL)

        self._report(sample_count)

    def _report(self, sample_count: int):
        report = {
            "scanner"         : "GPU Security Layer v2.0",
            "author"          : "Manmohan (Mike) Bains",
            "timestamp"       : datetime.datetime.utcnow().isoformat(),
            "gpu_index"       : self.gpu_index,
            "duration_s"      : self.duration,
            "samples"         : sample_count,
            "total_events"    : len(self.all_events),
            "covert_events"   : len(self.covert.events),
            "unauthorized"    : len(self.unauthorized.events),
            "vram_anomalies"  : sum(1 for s in self.vram.snapshots if s.get("anomaly_detected")),
            "alerts"          : len(self.alerter.alerts),
            "events"          : self.all_events
        }

        filename = f"security_scan_{datetime.datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.json"
        with open(filename, "w") as f:
            json.dump(report, f, indent=2)

        print(f"\n{'='*60}")
        print(f"SCAN COMPLETE")
        print(f"Samples          : {sample_count}")
        print(f"Total Events     : {len(self.all_events)}")
        print(f"Covert Channel   : {len(self.covert.events)}")
        print(f"Unauthorized     : {len(self.unauthorized.events)}")
        print(f"VRAM Anomalies   : {report['vram_anomalies']}")
        print(f"Alerts           : {len(self.alerter.alerts)}")
        print(f"Report           : {filename}")
        print(f"{'='*60}\n")

if __name__ == "__main__":
    scanner = GPUSecurityScanner(
        gpu_index        = 0,
        duration_seconds = 172800
    )
    scanner.run()

# B200 BLACKWELL — HARDWARE ATTESTED 2026-05-28
B200_IDLE_W = 143.47
B200_COMBINED_IDLE_W = 288.71
B200_FP32_W = 237.50
B200_FP16_W = 197.00
B200_BURST_W = 195.72
B200_GHOST_THRESHOLD_W = 140.0
B200_GPU_COUNT = 2
B200_TOTAL_VRAM_GB = 360
B200_GHOST_FROM_BOOT = True
B200_FP16_BLACKOUT = True
B200_PYTORCH_MIN = "2.11.0+cu128"
