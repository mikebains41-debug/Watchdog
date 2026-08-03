#!/usr/bin/env python3
"""
Watchdog — PCIe Link Guard (B200)
Attack: Malformed TLP packets cause PCIe link to drop generations rapidly.
        B200 confirmed Gen5 x16 (32 GT/s). Drop >2 generations in <1s = attack.

Prevention:
  - Monitors LnkSta speed via lspci every 500ms
  - If drop >2 PCIe generations detected in <1s window: force link retrain
  - Link retrain uses setpci to set Retrain Link bit in Link Control register
    (more correct than /reset which does a function-level reset, not link retrain)
  - Falls back to /reset if setpci unavailable

PCIe generation speeds:
  Gen1 = 2.5 GT/s
  Gen2 = 5.0 GT/s
  Gen3 = 8.0 GT/s
  Gen4 = 16.0 GT/s
  Gen5 = 32.0 GT/s  ← B200 confirmed
  Gen6 = 64.0 GT/s
"""
import subprocess, time, datetime, json, re, os

PCIE_EXPECTED    = 32.0   # GT/s — B200 Gen5
GEN_SPEEDS       = [2.5, 5.0, 8.0, 16.0, 32.0, 64.0]
DROP_LIMIT       = 2      # generations — max allowed drop before retrain
DROP_WINDOW      = 1.0    # seconds — drop must happen within this window
POLL_INTERVAL    = 0.5    # seconds between speed checks
RETRAIN_COOLDOWN = 10     # seconds before allowing another retrain

# PCIe device address — update for your B200 slot (check with lspci)
PCIE_ADDR = "0000:00:00.0"

def now_iso():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()

def stamp():
    return datetime.datetime.now().strftime("%Y%m%d_%H%M%S")

def speed_to_gen(speed: float) -> int:
    """Convert GT/s to PCIe generation number."""
    for gen, s in enumerate(GEN_SPEEDS, 1):
        if abs(speed - s) < 0.5:
            return gen
    return 0

def get_pcie_speed() -> float | None:
    """Read current PCIe link speed from lspci LnkSta."""
    try:
        out = subprocess.check_output(
            ["lspci", "-vvv"], text=True, timeout=5, stderr=subprocess.DEVNULL)
        for line in out.splitlines():
            if "LnkSta:" in line:
                m = re.search(r'(\d+\.?\d*)\s*GT/s', line)
                if m:
                    return float(m.group(1))
        return None
    except:
        return None

def get_pcie_addr() -> str | None:
    """Auto-detect GPU PCIe address from nvidia-smi."""
    try:
        out = subprocess.check_output(
            ["nvidia-smi", "--query-gpu=pci.bus_id",
             "--format=csv,noheader,nounits"],
            text=True, timeout=3)
        addr = out.strip().lower().replace("00000000:", "0000:")
        return addr if addr else PCIE_ADDR
    except:
        return PCIE_ADDR

def retrain_link(addr: str) -> bool:
    """
    Force PCIe link retrain by setting Retrain Link bit (bit 5) in
    Link Control register (offset CAP_EXP+10).
    This triggers hardware link speed renegotiation back to max supported.
    """
    try:
        # Read current Link Control register value
        out = subprocess.check_output(
            ["setpci", "-s", addr, "CAP_EXP+10.w"],
            text=True, timeout=3, stderr=subprocess.DEVNULL)
        current = int(out.strip(), 16)
        # Set bit 5 (Retrain Link) — hardware clears it after retrain
        new_val = current | 0x0020
        subprocess.check_output(
            ["setpci", "-s", addr, f"CAP_EXP+10.w={new_val:04x}"],
            timeout=3, stderr=subprocess.DEVNULL)
        return True
    except:
        # Fallback: function-level reset
        try:
            with open(f"/sys/bus/pci/devices/{addr}/reset", "w") as f:
                f.write("1")
            return True
        except:
            return False

def main():
    addr = get_pcie_addr()
    log  = open(f"watchdog_pcie_link_{stamp()}.jsonl", "a")

    def emit(event: dict):
        event.setdefault("ts", now_iso())
        log.write(json.dumps(event) + "\n")
        log.flush()

    emit({"event": "RUN_START", "module": "pcie_link_guard", "gpu": "B200",
          "pcie_addr": addr, "pcie_expected_gts": PCIE_EXPECTED,
          "drop_limit_gens": DROP_LIMIT, "drop_window_s": DROP_WINDOW})

    prev_speed    = get_pcie_speed()
    prev_time     = time.time()
    last_retrain  = 0.0

    while True:
        time.sleep(POLL_INTERVAL)
        now   = time.time()
        speed = get_pcie_speed()

        if speed is None or prev_speed is None:
            prev_speed = speed
            prev_time  = now
            continue

        prev_gen = speed_to_gen(prev_speed)
        curr_gen = speed_to_gen(speed)
        gen_drop = prev_gen - curr_gen
        elapsed  = now - prev_time

        if gen_drop >= DROP_LIMIT and elapsed <= DROP_WINDOW:
            emit({"event": "PCIe_LINK_ATTACK_DETECTED",
                  "from_gts": prev_speed, "to_gts": speed,
                  "from_gen": prev_gen, "to_gen": curr_gen,
                  "drop_gens": gen_drop, "elapsed_s": round(elapsed, 3)})

            if now - last_retrain > RETRAIN_COOLDOWN:
                if retrain_link(addr):
                    emit({"event": "PCIe_LINK_RETRAIN_FORCED",
                          "addr": addr,
                          "method": "setpci_retrain_bit"})
                    last_retrain = now

        elif speed < PCIE_EXPECTED:
            # Warn on sustained degradation even without rapid drop
            emit({"event": "PCIe_SPEED_DEGRADED",
                  "speed_gts": speed,
                  "expected_gts": PCIE_EXPECTED,
                  "gen": curr_gen})

        prev_speed = speed
        prev_time  = now

if __name__ == "__main__":
    main()
