#!/usr/bin/env python3
"""
Watchdog — Module 13: NVLink Fabric Attack Detector
Monitors NVLink for unexpected state changes and bandwidth anomalies.
"""
import subprocess, time, datetime, json

DURATION_S = 120  # was fixed 300 iterations (~300s); standardized


def now_iso():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def get_nvlink_state():
    try:
        out = subprocess.check_output(["nvidia-smi", "nvlink", "-s"], text=True, timeout=5, stderr=subprocess.DEVNULL)
        return out.strip().splitlines()
    except Exception:
        return []


def get_nvlink_bandwidth():
    try:
        out = subprocess.check_output(["nvidia-smi", "nvlink", "-c"], text=True, timeout=5, stderr=subprocess.DEVNULL)
        lines = out.splitlines()
        total_bw = 0
        for l in lines:
            if "Bandwidth" in l:
                for p in l.split():
                    if p.isdigit():
                        total_bw += int(p)
        return total_bw
    except Exception:
        return None


def main():
    stamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    out = f"module13_nvlink_fabric_{stamp}.jsonl"
    log = open(out, "a")
    log.write(json.dumps({"event": "RUN_START", "module": "13_nvlink_fabric", "ts": now_iso()}) + "\n")

    alerts = 0
    prev_state = get_nvlink_state()
    prev_bw = get_nvlink_bandwidth()

    start = time.time()
    while time.time() < start + DURATION_S:
        current_state = get_nvlink_state()
        current_bw = get_nvlink_bandwidth()

        if current_state != prev_state:
            alerts += 1
            log.write(json.dumps({
                "detector": "D87_NVLINK_STATE_CHANGE",
                "severity": "WARN",
                "prev_state": prev_state,
                "current_state": current_state,
                "confidence": 0.5,
                "note": "NVLink state changed unexpectedly"
            }) + "\n")

        if prev_bw and current_bw and prev_bw > 0:
            if current_bw > prev_bw * 10:
                alerts += 1
                log.write(json.dumps({
                    "detector": "D88_NVLINK_BANDWIDTH_SPIKE",
                    "severity": "WARN",
                    "prev_bw": prev_bw,
                    "current_bw": current_bw,
                    "confidence": 0.6,
                    "note": "NVLink bandwidth spike >10x — possible cross-GPU exfiltration"
                }) + "\n")

        prev_state = current_state
        prev_bw = current_bw
        time.sleep(1.0)

    log.write(json.dumps({"event": "RUN_END", "alerts": alerts, "ts": now_iso()}) + "\n")
    log.close()
    print(f"Done. Module 13: alerts={alerts}\nLog: {out}")


if __name__ == "__main__":
    main()
