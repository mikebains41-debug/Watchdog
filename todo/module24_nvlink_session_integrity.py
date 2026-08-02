#!/usr/bin/env python3
"""
Watchdog — Module 24: NVLink Session Integrity
Prevents session hijacking across NVLink.
"""
import subprocess, time, datetime, json

def now_iso():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()

def get_compute_apps():
    try:
        out = subprocess.check_output(["nvidia-smi", "--query-compute-apps=pid", "--format=csv,noheader,nounits"], text=True, timeout=3)
        return [p.strip() for p in out.strip().splitlines()]
    except:
        return []

def get_nvlink_traffic():
    try:
        out = subprocess.check_output(["nvidia-smi", "nvlink", "-c"], text=True, timeout=3, stderr=subprocess.DEVNULL)
        total = 0
        for line in out.splitlines():
            if "Bandwidth" in line:
                for token in line.split():
                    if token.isdigit():
                        total += int(token)
        return total
    except:
        return 0

def kill_pid(pid):
    try:
        subprocess.check_output(["kill", "-9", str(pid)], text=True, timeout=3, stderr=subprocess.DEVNULL)
        return True
    except:
        return False

def reset_nvlink():
    try:
        subprocess.check_output(["nvidia-smi", "nvlink", "-e", "-i", "0"], text=True, timeout=3, stderr=subprocess.DEVNULL)
        return True
    except:
        return False

def main():
    stamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    out = f"module24_nvlink_session_integrity_{stamp}.jsonl"
    log = open(out, "a")
    log.write(json.dumps({"event":"RUN_START","module":"24_nvlink_session_integrity","ts":now_iso()}) + "\n")

    prev_traffic = get_nvlink_traffic()
    apps = get_compute_apps()

    while True:
        traffic = get_nvlink_traffic()
        current_apps = get_compute_apps()

        # If traffic spikes but no known app owns it
        if prev_traffic and traffic > prev_traffic * 10:
            for pid in current_apps:
                if pid not in apps:
                    if kill_pid(pid):
                        log.write(json.dumps({
                            "event":"NVLINK_SESSION_HIJACK_BLOCKED",
                            "pid":pid,
                            "action":"pid_killed"
                        }) + "\n")
                        if reset_nvlink():
                            log.write(json.dumps({"event":"NVLINK_RESET"}))
            apps = current_apps

        prev_traffic = traffic
        time.sleep(2)

if __name__ == "__main__":
    main()
