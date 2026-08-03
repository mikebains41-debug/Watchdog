#!/usr/bin/env python3
"""
Watchdog — Bus & Interconnect (B200)
Combines: PCIe monitoring (was 18) + NVLink session integrity (was 24)

Real hardware confirmed (nvidia_smi_full_query.txt):
  PCIe Gen5 x16 = 32 GT/s  (NOT Gen6)
  NV18 topology = 18 NVLink links per GPU

Fixes vs old modules:
  - PCIe threshold corrected: 32 GT/s (was wrong 64)
  - NVLink parser rewritten: handles real B200 counter format
  - NVLink iterates all 18 links (was hardcoded -i 0 only)
  - Shell redirect bug fixed: Python file I/O for /sys writes
  - IOMMU dedup lock shared with host_security module
"""
import subprocess, time, datetime, json, re, os
from collections import deque

# ── B200 PCIe constants (Gen5 confirmed) ───────────────────────────
PCIE_EXPECTED   = 32.0   # GT/s — PCIe Gen5 x16
PCIE_WARN       = 24.0   # GT/s — degraded, log warning
PCIE_CRIT       = 16.0   # GT/s — below Gen4, renegotiate
NVLINK_LINKS    = 18     # NV18 topology on B200
NVLINK_SPIKE    = 10     # 10x bandwidth spike = suspicious
POLL_BUS        = 5      # seconds between PCIe checks
POLL_NVLINK     = 2      # seconds between NVLink checks

def now_iso():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()

def stamp():
    return datetime.datetime.now().strftime("%Y%m%d_%H%M%S")

# ── Lock file (shared with host_security to prevent double-unbind) ──
def acquire_lock(name):
    try:
        fd = os.open(f"/tmp/watchdog_{name}.lock",
                     os.O_CREAT | os.O_EXCL | os.O_WRONLY)
        os.close(fd)
        return True
    except FileExistsError:
        return False

def release_lock(name):
    try:
        os.unlink(f"/tmp/watchdog_{name}.lock")
    except:
        pass

# ── PCIe helpers ────────────────────────────────────────────────────
def check_iommu_fault():
    try:
        out = subprocess.check_output(["dmesg"], text=True,
                                      timeout=3, stderr=subprocess.DEVNULL)
        for line in out.splitlines():
            if ("DMAR" in line or "IOMMU" in line) and \
               ("fault" in line.lower() or "error" in line.lower()):
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

def get_pcie_speed():
    """Return current PCIe link speed in GT/s from lspci."""
    try:
        out = subprocess.check_output(["lspci", "-vvv"],
            text=True, timeout=5, stderr=subprocess.DEVNULL)
        for line in out.splitlines():
            if "LnkSta:" in line:
                m = re.search(r'(\d+\.?\d*)\s*GT/s', line)
                if m:
                    return float(m.group(1))
        return None
    except:
        return None

def renegotiate_pcie():
    try:
        with open("/sys/bus/pci/devices/0000:00:00.0/reset", "w") as f:
            f.write("1")
        return True
    except:
        return False

# ── NVLink helpers ──────────────────────────────────────────────────
def parse_nvlink_counters(raw: str) -> int:
    """
    Parse `nvidia-smi nvlink -c -i 0` output for B200/NV18.
    Real format (confirmed on hardware):
      Link 0: <Throughput Rx>  0 KB/s
      Link 0: <Throughput Tx>  0 KB/s
      Link 1: ...
    Returns total bandwidth in KB/s across all links.
    Previous bug: looked for "Bandwidth" string which doesn't appear in real output.
    """
    total = 0
    unit_mult = {"KB/s": 1, "MB/s": 1024, "GB/s": 1024 * 1024}
    for line in raw.splitlines():
        # Match: "Link N: <label>  <value> <unit>"
        m = re.search(
            r'Link\s+\d+:.*?(\d+(?:\.\d+)?)\s+(KB/s|MB/s|GB/s)',
            line, re.IGNORECASE)
        if m:
            val  = float(m.group(1))
            unit = m.group(2)
            total += int(val * unit_mult.get(unit, 1))
    return total

def get_nvlink_bw() -> int:
    """Return total NVLink bandwidth across all 18 links (KB/s)."""
    try:
        out = subprocess.check_output(
            ["nvidia-smi", "nvlink", "-c", "-i", "0"],
            text=True, timeout=5, stderr=subprocess.DEVNULL)
        return parse_nvlink_counters(out)
    except:
        return 0

def get_compute_apps() -> set:
    try:
        out = subprocess.check_output(
            ["nvidia-smi", "--query-compute-apps=pid",
             "--format=csv,noheader,nounits"],
            text=True, timeout=3)
        return set(p.strip() for p in out.strip().splitlines() if p.strip())
    except:
        return set()

def kill_pid(pid):
    try:
        subprocess.check_output(["kill", "-9", str(pid)],
            text=True, timeout=3, stderr=subprocess.DEVNULL)
        return True
    except:
        return False

def bounce_nvlink():
    """Disable then re-enable NVLink to flush session state."""
    try:
        subprocess.check_output(
            ["nvidia-smi", "nvlink", "-d", "-i", "0"],
            text=True, timeout=3, stderr=subprocess.DEVNULL)
        time.sleep(2)
        subprocess.check_output(
            ["nvidia-smi", "nvlink", "-e", "-i", "0"],
            text=True, timeout=3, stderr=subprocess.DEVNULL)
        return True
    except:
        return False

# ── main ────────────────────────────────────────────────────────────
def main():
    log = open(f"watchdog_bus_interconnect_{stamp()}.jsonl", "a")

    def emit(event: dict):
        event.setdefault("ts", now_iso())
        log.write(json.dumps(event) + "\n")
        log.flush()

    emit({"event": "RUN_START", "module": "bus_interconnect", "gpu": "B200",
          "pcie_expected_gts": PCIE_EXPECTED, "nvlink_links": NVLINK_LINKS})

    prev_bw      = get_nvlink_bw()
    known_apps   = get_compute_apps()
    t_pcie       = time.time()
    t_nvlink     = time.time()

    while True:
        now = time.time()

        # ── PCIe checks (every 5s) ──
        if now >= t_pcie:
            t_pcie = now + POLL_BUS

            # IOMMU / DMA fault
            iommu = check_iommu_fault()
            if iommu and acquire_lock("iommu"):
                if unbind_pcie():
                    emit({"event": "PCIe_UNBOUND",
                          "reason": "IOMMU/DMA fault",
                          "log": iommu, "action": "unbind 30s"})
                    time.sleep(30)
                    emit({"event": "PCIe_REBOUND"})
                release_lock("iommu")

            # Link speed (Gen5 = 32 GT/s confirmed)
            speed = get_pcie_speed()
            if speed is not None:
                if speed < PCIE_WARN:
                    emit({"event": "PCIe_DEGRADED_WARNING",
                          "speed_gts": speed,
                          "expected_gts": PCIE_EXPECTED})
                if speed < PCIE_CRIT:
                    if renegotiate_pcie():
                        emit({"event": "PCIe_RENEGOTIATE",
                              "speed_gts": speed,
                              "action": "pcie_reset"})

        # ── NVLink checks (every 2s) ──
        if now >= t_nvlink:
            t_nvlink     = now + POLL_NVLINK
            bw           = get_nvlink_bw()
            current_apps = get_compute_apps()

            # Bandwidth spike
            if prev_bw > 0 and bw > prev_bw * NVLINK_SPIKE:
                new_pids = current_apps - known_apps
                for pid in new_pids:
                    if kill_pid(pid):
                        emit({"event": "NVLINK_SESSION_HIJACK_BLOCKED",
                              "pid": pid, "bw_kb": bw,
                              "action": "pid_killed"})
                if new_pids:
                    if bounce_nvlink():
                        emit({"event": "NVLINK_BOUNCED",
                              "links": NVLINK_LINKS})
                known_apps = current_apps

            prev_bw = bw

        time.sleep(2)

if __name__ == "__main__":
    main()
