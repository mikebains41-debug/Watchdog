#!/usr/bin/env python3
"""
Watchdog — Module 22: Container & Host Isolation Prevention
"""
import subprocess, time, datetime, json, os, signal

def now_iso():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()

def acquire_lock(event):
    try:
        fd = os.open(f"/tmp/watchdog_{event}.lock", os.O_CREAT | os.O_EXCL | os.O_WRONLY)
        os.close(fd)
        return True
    except FileExistsError:
        return False

def release_lock(event):
    try:
        os.unlink(f"/tmp/watchdog_{event}.lock")
    except:
        pass

def check_dmesg_for_breakout():
    try:
        out = subprocess.check_output(["dmesg"], text=True, timeout=3, stderr=subprocess.DEVNULL)
        for line in out.splitlines():
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
        # Resolve current container ID from cgroup rather than using $(hostname)
        with open("/proc/self/cgroup") as f:
            for line in f:
                if "docker" in line:
                    cid = line.strip().split("/")[-1][:12]
                    subprocess.check_output(["docker", "kill", cid], timeout=5, stderr=subprocess.DEVNULL)
                    return True
        return False
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
        with open("/sys/bus/pci/devices/0000:00:00.0/remove", "w") as f:
            f.write("1")
        return True
    except:
        return False

def main():
    stamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    out = f"module22_container_host_isolation_prevent_{stamp}.jsonl"
    log = open(out, "a")
    log.write(json.dumps({"event":"RUN_START","module":"22_container_host_isolation","ts":now_iso()}) + "\n")

    while True:
        breakout_log = check_dmesg_for_breakout()
        if breakout_log:
            if kill_container():
                log.write(json.dumps({
                    "event":"CONTAINER_BREAKOUT_BLOCKED",
                    "log":breakout_log,
                    "action":"container_killed"
                }) + "\n")

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

        dma_log = check_dmesg_for_dma()
        if dma_log:
            # Dedup with module18 — only one module handles iommu unbind at a time
            if acquire_lock("iommu"):
                if unbind_pcie():
                    log.write(json.dumps({
                        "event":"DMA_ATTACK_BLOCKED",
                        "log":dma_log,
                        "action":"pcie_unbind_30s"
                    }) + "\n")
                    time.sleep(30)
                    log.write(json.dumps({"event":"PCI_REBOUND"}) + "\n")
                release_lock("iommu")

        time.sleep(2)

if __name__ == "__main__":
    main()
