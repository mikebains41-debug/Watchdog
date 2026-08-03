#!/usr/bin/env python3
"""
Watchdog — Module 44: Cryogenic Power Spike Detection
Monitors /sys/class/powercap (RAPL) and IPMI power readings for
sudden spikes consistent with a power rail attack on a cryogenic system.

What this detects:
  - Sudden 2x+ power spike sustained >5s on monitored power domains
  - IPMI chassis power anomalies (if ipmitool available)
  - PDU-level power rail events in dmesg

Limitation: RAPL monitors CPU/memory/GPU domains, not external PDU circuits.
Full cryogenic PDU monitoring requires hardware integration (module38).
This module provides the best available host-side power monitoring.
"""
import subprocess, time, datetime, json, os, re
from collections import deque

POWERCAP_BASE    = "/sys/class/powercap"
SPIKE_MULTIPLIER = 2.0      # 2x baseline = spike
SPIKE_DURATION_S = 5.0      # must sustain for 5 seconds
BASELINE_SAMPLES = 20       # samples to establish baseline
POLL_INTERVAL    = 1.0      # seconds between power samples
BASELINE_FILE    = "/tmp/watchdog_power_baseline.json"

def now_iso():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()

def stamp():
    return datetime.datetime.now().strftime("%Y%m%d_%H%M%S")

def read_rapl_power() -> dict:
    """Read current power consumption from RAPL powercap interface."""
    power_readings = {}
    if not os.path.isdir(POWERCAP_BASE):
        return power_readings

    try:
        for zone in os.listdir(POWERCAP_BASE):
            zone_path = os.path.join(POWERCAP_BASE, zone)
            name_file  = os.path.join(zone_path, "name")
            energy_file = os.path.join(zone_path, "energy_uj")

            if not os.path.exists(energy_file):
                continue
            try:
                with open(name_file) as f:
                    name = f.read().strip()
                with open(energy_file) as f:
                    energy_uj = int(f.read().strip())
                power_readings[name] = energy_uj
            except:
                pass
    except:
        pass
    return power_readings

def compute_power_watts(prev: dict, curr: dict, elapsed_s: float) -> dict:
    """Convert energy delta (uJ) to watts."""
    watts = {}
    for name in curr:
        if name in prev:
            delta_uj = curr[name] - prev[name]
            if delta_uj >= 0:   # Handle counter reset
                watts[name] = round(delta_uj / (elapsed_s * 1e6), 2)
    return watts

def read_ipmi_power() -> float | None:
    """Read chassis power via ipmitool if available."""
    try:
        out = subprocess.check_output(
            ["ipmitool", "dcmi", "power", "reading"],
            text=True, timeout=5, stderr=subprocess.DEVNULL)
        for line in out.splitlines():
            if "Instantaneous" in line or "Current Power" in line:
                m = re.search(r'(\d+(?:\.\d+)?)\s*Watts', line)
                if m:
                    return float(m.group(1))
    except:
        pass
    return None

def check_dmesg_power_events() -> list:
    """Check dmesg for power-related anomaly messages."""
    try:
        out = subprocess.check_output(["dmesg"], text=True, timeout=3,
                                       stderr=subprocess.DEVNULL)
        events = []
        for line in out.splitlines():
            l = line.lower()
            if any(kw in l for kw in ["power spike", "overcurrent", "undervoltage",
                                        "power fault", "psu", "power supply"]):
                events.append(line.strip())
        return events
    except:
        return []

def load_baseline() -> dict:
    try:
        with open(BASELINE_FILE) as f:
            return json.load(f)
    except:
        return {"rapl": {}, "ipmi": None, "sample_count": 0}

def save_baseline(b: dict):
    try:
        with open(BASELINE_FILE, "w") as f:
            json.dump(b, f)
    except:
        pass

def write_to_tpm(event: dict) -> bool:
    """Write power spike event hash to TPM NVRAM for immutable logging."""
    import hashlib
    try:
        if not (os.path.exists("/dev/tpm0") or os.path.exists("/dev/tpmrm0")):
            return False
        data = json.dumps(event, sort_keys=True).encode()
        h    = hashlib.sha256(data).hexdigest()
        tmp  = "/tmp/watchdog_power_spike.bin"
        with open(tmp, "w") as f:
            f.write(h)
        subprocess.check_output(["tpm2_nvwrite", "-i", "0x1500017", tmp],
                                  timeout=5, stderr=subprocess.DEVNULL)
        return True
    except:
        return False

def main():
    log = open(f"module44_{stamp()}.jsonl", "a")

    def emit(event):
        event.setdefault("ts", now_iso())
        log.write(json.dumps(event) + "\n")
        log.flush()

    emit({"event": "RUN_START", "module": "44_cryo_power_spike",
          "spike_threshold": f"{SPIKE_MULTIPLIER}x baseline for {SPIKE_DURATION_S}s",
          "note": "RAPL + IPMI power monitoring. External PDU requires module38 hardware integration."})

    baseline     = load_baseline()
    prev_energy  = read_rapl_power()
    spike_start  = {}   # domain -> time spike began
    alerts       = 0

    while True:
        time.sleep(POLL_INTERVAL)
        now = time.time()

        curr_energy = read_rapl_power()
        watts       = compute_power_watts(prev_energy, curr_energy, POLL_INTERVAL)
        ipmi_watts  = read_ipmi_power()
        prev_energy = curr_energy

        # Build/update baseline
        if baseline["sample_count"] < BASELINE_SAMPLES:
            for domain, w in watts.items():
                if domain not in baseline["rapl"]:
                    baseline["rapl"][domain] = []
                baseline["rapl"][domain].append(w)
            if ipmi_watts:
                baseline["ipmi"] = ipmi_watts if baseline["ipmi"] is None else (
                    baseline["ipmi"] * 0.9 + ipmi_watts * 0.1)
            baseline["sample_count"] += 1
            if baseline["sample_count"] == BASELINE_SAMPLES:
                # Average the baseline samples
                baseline["rapl"] = {k: sum(v)/len(v) for k, v in baseline["rapl"].items()}
                emit({"event": "BASELINE_ESTABLISHED", "rapl_w": baseline["rapl"],
                      "ipmi_w": baseline["ipmi"]})
                save_baseline(baseline)
            continue

        # Check for spikes
        for domain, w in watts.items():
            base_w = baseline["rapl"].get(domain)
            if not base_w or base_w == 0:
                continue
            if w > base_w * SPIKE_MULTIPLIER:
                if domain not in spike_start:
                    spike_start[domain] = now
                elif now - spike_start[domain] >= SPIKE_DURATION_S:
                    alerts += 1
                    spike_event = {
                        "event":      "POWER_SPIKE_DETECTED",
                        "severity":   "CRITICAL",
                        "domain":     domain,
                        "current_w":  w,
                        "baseline_w": round(base_w, 2),
                        "multiplier": round(w / base_w, 2),
                        "duration_s": round(now - spike_start[domain], 1),
                        "note":       "Sustained power spike — possible PDU attack on cryogenic system",
                        "confidence": 0.80,
                    }
                    emit(spike_event)
                    tpm_ok = write_to_tpm(spike_event)
                    emit({"event": "TPM_LOG", "written": tpm_ok,
                          "index": "0x1500017"})
                    spike_start.pop(domain, None)
            else:
                spike_start.pop(domain, None)

        # IPMI spike check
        if ipmi_watts and baseline["ipmi"]:
            if ipmi_watts > baseline["ipmi"] * SPIKE_MULTIPLIER:
                alerts += 1
                emit({"event": "IPMI_POWER_SPIKE", "severity": "CRITICAL",
                      "current_w": ipmi_watts,
                      "baseline_w": round(baseline["ipmi"], 2),
                      "multiplier": round(ipmi_watts / baseline["ipmi"], 2),
                      "confidence": 0.85})

        # dmesg power events
        for line in check_dmesg_power_events():
            alerts += 1
            emit({"event": "DMESG_POWER_EVENT", "severity": "WARN", "log": line})

if __name__ == "__main__":
    main()
