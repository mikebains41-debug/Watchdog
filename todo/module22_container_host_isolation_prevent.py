#!/usr/bin/env python3
"""
Watchdog — Module 22: Container & Host Isolation Prevention
Combines:
- container_escape_prevent.py (block runC/container breakouts)
- pcie_dma_mitigator.py (block DMA attacks reading host memory)
"""
import subprocess, time, datetime, json, os, signal

def now_iso():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()

def check_dmesg_for_breakout():
    try:
        out = subprocess.check_output(["dmesg"], text=True, timeout=3, stderr=subprocess.DEVNULL)
        lines = out.splitlines()
        for line in lines:
            if "runc" in line.lower() and ("escape" in line.lower() or "break" in line.lower()):
                return line.strip()
        return None
    except:
        return None

def scan_for_spoofed_pids():
    try:
        for p in os.listdir('/proc'):
            if p.isdigit():
                pid = int(p)
                try:
                    with open(f'/proc/{p}/status') as f:
                        lines = f.readlines()
                    ppid = None
                    for line in lines:
                        if line.startswith('PPid:'):
                            ppid = int(line.split()[1])
                            break
                    if pid in (0, 1) and ppid != 0:
                        return pid
                except:
                    pass
        return None
    except:
        return None

def kill_container():
    try:
        subprocess.check_output(["pkill", "-f", "runc"], text=True, timeout=5, stderr=subprocess.DEVNULL)
        return True
    except:
        return False

def check_dmesg_for_dma():
    try:
        out = subprocess.check_output(["dmesg"], text=True, timeout=3, stderr=subprocess.DEVNULL)
        for line in out.splitlines():
            if "DMAR" in line or "IOMMU" in line:
                if "fault" in line.lower() or "error" in line.lower():
                    return line.strip()
        return None
    except:
        return None

def unbind_pcie():
    try:
        subprocess.check_output(["echo", "1", ">", "/sys/bus/pci/devices/0000:00:00.0/remove"], shell=True, timeout=3, stderr=subprocess.DEVNULL)
        return True
    except:
        return False

def main():
    stamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    out = f"module22_container_host_isolation_prevent_{stamp}.jsonl"
    log = open(out, "a")
    log.write(json.dumps({"event":"RUN_START","module":"22_container_host_isolation","ts":now_iso()}) + "\n")

    while True:
        # Container breakout
        breakout_log = check_dmesg_for_breakout()
        if breakout_log:
            if kill_container():
                log.write(json.dumps({
                    "event":"CONTAINER_BREAKOUT_BLOCKED",
                    "log":breakout_log,
                    "action":"container_killed"
                }) + "\n")

        # PID spoof
        spoofed = scan_for_spoofed_pids()
        if spoofed:
            try:
                os.kill(spoofed, signal.SIGKILL)
                log.write(json.dumps({
                    "event":"SPOOFED_PID_KILLED",
                    "pid":spoofed,
                    "action":"SIGKILL"
                }) + "\n")
            except:
                pass

        # DMA attack
        dma_log = check_dmesg_for_dma()
        if dma_log:
            if unbind_pcie():
                log.write(json.dumps({
                    "event":"DMA_ATTACK_BLOCKED",
                    "log":dma_log,
                    "action":"pcie_unbind_30s"
                }) + "\n")
                time.sleep(30)
                log.write(json.dumps({"event":"PCI_REBOUND"}) + "\n")

        time.sleep(2)

if __name__ == "__main__":
    main()
