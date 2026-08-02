#!/usr/bin/env python3
"""
Watchdog — Module 23: GPU Model & Memory Integrity
"""
import subprocess, time, datetime, json, os, signal
from collections import deque

ECC_WINDOW = 20

def now_iso():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()

def get_ecc():
    try:
        out = subprocess.check_output(["nvidia-smi", "--query-gpu=ecc.errors.corrected.volatile.total", "--format=csv,noheader,nounits"], text=True, timeout=2)
        return float(out.strip())
    except:
        return None

def get_mem_util():
    try:
        out = subprocess.check_output(["nvidia-smi", "--query-gpu=utilization.memory", "--format=csv,noheader,nounits"], text=True, timeout=2)
        return float(out.strip())
    except:
        return None

def get_suspicious_outbound_pids():
    """Return list of (pid, port) for ESTAB connections on non-standard ports."""
    try:
        out = subprocess.check_output(["ss", "-tunp"], text=True, timeout=3, stderr=subprocess.DEVNULL)
        results = []
        for line in out.splitlines():
            if "ESTAB" not in line:
                continue
            parts = line.split()
            try:
                peer = parts[4]
                port = int(peer.rsplit(":", 1)[-1])
                if port in (80, 443, 22):
                    continue
                pid_parts = [p for p in parts if "pid=" in p]
                if pid_parts:
                    pid = int(pid_parts[0].split("pid=")[1].split(",")[0])
                    results.append((pid, port))
            except:
                pass
        return results
    except:
        return []

def reset_gpu():
    try:
        subprocess.check_output(["nvidia-smi", "--gpu-reset", "-i", "0"], text=True, timeout=5, stderr=subprocess.DEVNULL)
        return True
    except:
        return False

def main():
    stamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    out = f"module23_gpu_model_memory_integrity_{stamp}.jsonl"
    log = open(out, "a")
    log.write(json.dumps({"event":"RUN_START","module":"23_gpu_model_memory_integrity","ts":now_iso()}) + "\n")

    ecc_history = deque(maxlen=ECC_WINDOW)
    while True:
        ecc = get_ecc()
        mem_util = get_mem_util()

        if ecc is not None:
            ecc_history.append(ecc)
            if len(ecc_history) == ECC_WINDOW:
                avg = sum(ecc_history) / ECC_WINDOW
                if avg > 0 and ecc > avg * 10:
                    if reset_gpu():
                        log.write(json.dumps({
                            "event":"ECC_STORM_BLOCKED",
                            "ecc":ecc,
                            "avg":round(avg, 1),
                            "action":"gpu_reset"
                        }) + "\n")

        if mem_util and mem_util > 95:
            pids = get_suspicious_outbound_pids()
            if len(pids) > 2:
                for pid, port in pids:
                    try:
                        os.kill(pid, signal.SIGKILL)
                        log.write(json.dumps({
                            "event":"MODEL_EXFIL_BLOCKED",
                            "mem_util":mem_util,
                            "pid":pid,
                            "port":port,
                            "action":"pid_killed"
                        }) + "\n")
                    except:
                        pass

        time.sleep(2)

if __name__ == "__main__":
    main()
