#!/usr/bin/env python3
import sys
sys.exit("UNGATED: this module performs privileged destructive actions with no safety gate. See SECURITY_REVIEW_2026-09-04.md H1. Port module21 gating before running.")

"""
Watchdog — GPU Software & Context (B200)
Combines: driver/context guard (was 19) + model integrity (was 23)

Handles:
  - Unknown/miner PIDs on GPU compute → SIGKILL
  - Stale CUDA context (memory with no apps) → GPU reset
  - Driver unload → modprobe reload
  - ECC storm detection (HBM3e: window=50, wider than GDDR)
  - Model weight exfil (high mem util + suspicious outbound PIDs)
"""
import subprocess, time, datetime, json, os, signal
from collections import deque

# ── Constants ───────────────────────────────────────────────────────
ECC_WINDOW          = 50     # Wider window for HBM3e baseline
ECC_STORM_MULT      = 10     # 10x average = storm
STALE_MEM_FLOOR_MB  = 1000   # MB — memory with no apps = stale
EXFIL_MEM_UTIL      = 95     # % GPU mem util threshold for exfil check
EXFIL_CONN_MIN      = 2      # Minimum suspicious connections before kill
SAFE_PORTS          = {22, 80, 443}   # Ports to never kill

BLOCK_CMD_KEYWORDS  = ["miner", "xmrig", "cgminer", "ethminer", "unknown"]

def now_iso():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()

def stamp():
    return datetime.datetime.now().strftime("%Y%m%d_%H%M%S")

# ── GPU helpers ─────────────────────────────────────────────────────
def get_compute_apps():
    try:
        out = subprocess.check_output(
            ["nvidia-smi", "--query-compute-apps=pid",
             "--format=csv,noheader,nounits"], text=True, timeout=3)
        return [p.strip() for p in out.strip().splitlines() if p.strip()]
    except:
        return []

def get_mem_used_mb():
    try:
        out = subprocess.check_output(
            ["nvidia-smi", "--query-gpu=memory.used",
             "--format=csv,noheader,nounits"], text=True, timeout=2)
        return float(out.strip())
    except:
        return 0.0

def get_mem_util():
    try:
        out = subprocess.check_output(
            ["nvidia-smi", "--query-gpu=utilization.memory",
             "--format=csv,noheader,nounits"], text=True, timeout=2)
        return float(out.strip())
    except:
        return None

def get_ecc():
    try:
        out = subprocess.check_output(
            ["nvidia-smi", "--query-gpu=ecc.errors.corrected.volatile.total",
             "--format=csv,noheader,nounits"], text=True, timeout=2)
        return float(out.strip())
    except:
        return None

def get_loaded_modules():
    try:
        out = subprocess.check_output(
            ["lsmod"], text=True, timeout=2, stderr=subprocess.DEVNULL)
        return [line.split()[0] for line in out.splitlines()[1:]]
    except:
        return []

def kill_pid(pid):
    try:
        os.kill(int(pid), signal.SIGKILL)
        return True
    except:
        return False

def reset_gpu():
    try:
        subprocess.check_output(
            ["nvidia-smi", "--gpu-reset", "-i", "0"],
            text=True, timeout=5, stderr=subprocess.DEVNULL)
        return True
    except:
        return False

def reload_nvidia():
    try:
        subprocess.check_output(
            ["modprobe", "nvidia"],
            text=True, timeout=5, stderr=subprocess.DEVNULL)
        return True
    except:
        return False

def cmdline(pid) -> str:
    """Read /proc/pid/cmdline safely, replacing null bytes."""
    try:
        with open(f"/proc/{pid}/cmdline", "rb") as f:
            return f.read().replace(b"\x00", b" ").decode("utf-8", errors="replace").strip()
    except:
        return ""

# ── Outbound connection helpers ─────────────────────────────────────
def get_suspicious_outbound_pids():
    """Return (pid, port) pairs for ESTAB connections on non-standard ports."""
    try:
        out = subprocess.check_output(
            ["ss", "-tunp"], text=True, timeout=3, stderr=subprocess.DEVNULL)
        results = []
        for line in out.splitlines():
            if "ESTAB" not in line:
                continue
            parts = line.split()
            try:
                port = int(parts[4].rsplit(":", 1)[-1])
                if port in SAFE_PORTS:
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

# ── main ────────────────────────────────────────────────────────────
def main():
    log = open(f"watchdog_gpu_software_{stamp()}.jsonl", "a")

    def emit(event: dict):
        event.setdefault("ts", now_iso())
        log.write(json.dumps(event) + "\n")
        log.flush()

    emit({"event": "RUN_START", "module": "gpu_software", "gpu": "B200",
          "ecc_window": ECC_WINDOW, "memory": "HBM3e"})

    ecc_history = deque(maxlen=ECC_WINDOW)

    while True:
        # ── Unknown / miner PIDs ──
        apps = get_compute_apps()
        for pid in apps:
            cmd = cmdline(pid)
            if any(kw in cmd.lower() for kw in BLOCK_CMD_KEYWORDS):
                if kill_pid(pid):
                    emit({"event": "UNKNOWN_PID_KILLED",
                          "pid": pid, "cmd": cmd[:200]})

        # ── Stale CUDA context ──
        if not apps:
            mem = get_mem_used_mb()
            if mem > STALE_MEM_FLOOR_MB:
                if reset_gpu():
                    emit({"event": "CUDA_CONTEXT_RESET",
                          "reason": "stale_memory_no_apps",
                          "mem_mb": mem})

        # ── Driver unload guard ──
        mods = get_loaded_modules()
        if "nvidia" not in mods and "nvidia_uvm" not in mods:
            if reload_nvidia():
                emit({"event": "DRIVER_RELOADED",
                      "action": "modprobe nvidia"})

        # ── ECC storm (HBM3e: window=50) ──
        ecc = get_ecc()
        if ecc is not None:
            ecc_history.append(ecc)
            if len(ecc_history) == ECC_WINDOW:
                avg = sum(ecc_history) / ECC_WINDOW
                if avg > 0 and ecc > avg * ECC_STORM_MULT:
                    if reset_gpu():
                        emit({"event": "ECC_STORM_BLOCKED",
                              "ecc": ecc, "avg": round(avg, 1),
                              "action": "gpu_reset"})

        # ── Model exfil detection ──
        mem_util = get_mem_util()
        if mem_util and mem_util > EXFIL_MEM_UTIL:
            pids = get_suspicious_outbound_pids()
            if len(pids) > EXFIL_CONN_MIN:
                for pid, port in pids:
                    try:
                        os.kill(pid, signal.SIGKILL)
                        emit({"event": "MODEL_EXFIL_BLOCKED",
                              "mem_util": mem_util,
                              "pid": pid, "port": port,
                              "action": "pid_killed"})
                    except:
                        pass

        time.sleep(2)

if __name__ == "__main__":
    main()
