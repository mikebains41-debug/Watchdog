#!/usr/bin/env python3
"""
Watchdog — Module 19: GPU Driver & Context Prevention
Combines:
- gpu_context_heartbeat.py (kill unknown PID + reset CUDA context)
- gpu_driver_unload_guard.py (reload driver on unload)
"""
import subprocess, time, datetime, json, os, signal

def now_iso():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()

def get_compute_apps():
    try:
        out = subprocess.check_output(["nvidia-smi", "--query-compute-apps=pid", "--format=csv,noheader,nounits"], text=True, timeout=3)
        return [p.strip() for p in out.strip().splitlines()]
    except:
        return []

def kill_pid(pid):
    try:
        os.kill(int(pid), signal.SIGKILL)
        return True
    except:
        return False

def reset_cuda():
    try:
        subprocess.check_output(["nvidia-smi", "--gpu-reset", "-i", "0"], text=True, timeout=5, stderr=subprocess.DEVNULL)
        return True
    except:
        return False

def get_loaded_modules():
    try:
        out = subprocess.check_output(["lsmod"], text=True, timeout=2, stderr=subprocess.DEVNULL)
        return [line.split()[0] for line in out.splitlines()[1:]]
    except:
        return []

def reload_module(mod):
    try:
        subprocess.check_output(["modprobe", mod], text=True, timeout=3, stderr=subprocess.DEVNULL)
        return True
    except:
        return False

def main():
    stamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    out = f"module19_gpu_driver_context_prevent_{stamp}.jsonl"
    log = open(out, "a")
    log.write(json.dumps({"event":"RUN_START","module":"19_gpu_driver_context","ts":now_iso()}) + "\n")

    while True:
        apps = get_compute_apps()
        for pid in apps:
            try:
                with open(f'/proc/{pid}/cmdline', 'r') as f:
                    cmd = f.read().strip()
                if "unknown" in cmd or "miner" in cmd:
                    if kill_pid(pid):
                        log.write(json.dumps({
                            "event":"UNKNOWN_PID_KILLED",
                            "pid":pid,
                            "cmd":cmd
                        }) + "\n")
            except:
                pass

        # Detect empty apps but stale memory
        if not apps:
            try:
                mem = subprocess.check_output(["nvidia-smi", "--query-gpu=memory.used", "--format=csv,noheader,nounits"], text=True, timeout=2)
                if float(mem.strip()) > 1000:
                    if reset_cuda():
                        log.write(json.dumps({
                            "event":"CUDA_CONTEXT_RESET",
                            "reason":"stale_anonymous_memory"
                        }) + "\n")
            except:
                pass

        # Driver reload
        mods = get_loaded_modules()
        if "nvidia" not in mods and "nvidia_uvm" not in mods:
            if reload_module("nvidia"):
                log.write(json.dumps({
                    "event":"DRIVER_RELOADED",
                    "action":"modprobe nvidia"
                }) + "\n")
        time.sleep(2)

if __name__ == "__main__":
    main()
