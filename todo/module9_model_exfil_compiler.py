#!/usr/bin/env python3
"""
Watchdog — Module 9: Model Exfiltration & Compiler Monitor
Detects:
- Model weight exfiltration via high memory bandwidth + outbound traffic
- Malicious PyTorch/Triton compiler injection events
"""
import subprocess, time, datetime, json, os

def now_iso():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()

def get_memory_bandwidth():
    try:
        # Using nvidia-smi to sample memory throughput
        out = subprocess.check_output(["nvidia-smi", "--query-gpu=memory.used,utilization.memory", "--format=csv,noheader,nounits"], text=True, timeout=3, stderr=subprocess.DEVNULL)
        parts = out.strip().split(",")
        if len(parts) >= 2:
            return float(parts[0]), float(parts[1])
    except:
        pass
    return None, None

def get_compiler_events():
    try:
        out = subprocess.check_output(["grep", "-i", "torch.compile", "/var/log/syslog"], text=True, timeout=3, stderr=subprocess.DEVNULL)
        if out.strip():
            return out.strip().splitlines()[-5:]
        return []
    except:
        return []

def main():
    stamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    out = f"module9_model_exfil_compiler_{stamp}.jsonl"
    log = open(out, "a")
    log.write(json.dumps({"event":"RUN_START", "module":"9_exfil_compiler", "ts":now_iso()}) + "\n")

    alerts = 0

    # 1. Model Exfil (Memory Bandwidth + Outbound)
    mem_used, mem_util = get_memory_bandwidth()
    if mem_util and mem_util > 95.0:
        # Check if there are active outbound connections
        try:
            outbound = subprocess.check_output(["ss", "-tun", "|", "grep", "ESTAB"], shell=True, text=True, timeout=3, stderr=subprocess.DEVNULL)
            if outbound.strip():
                alerts += 1
                log.write(json.dumps({
                    "detector":"MODEL_EXFILTRATION",
                    "severity":"CRITICAL",
                    "mem_util_pct":mem_util,
                    "note":"High memory bandwidth + active outbound traffic — possible model theft"
                }) + "\n")
        except:
            pass

    # 2. Compiler Injection
    events = get_compiler_events()
    for e in events:
        alerts += 1
        log.write(json.dumps({
            "detector":"UNAUTHORIZED_COMPILER_INJECTION",
            "severity":"WARN",
            "log_line":e.strip(),
            "confidence":0.5,
            "note":"Unexpected torch.compile or compiler event detected"
        }) + "\n")

    log.write(json.dumps({"event":"RUN_END","alerts":alerts,"ts":now_iso()}) + "\n")
    log.close()
    print(f"Done. Module 9: alerts={alerts}\nLog: {out}")

if __name__ == "__main__":
    main()
