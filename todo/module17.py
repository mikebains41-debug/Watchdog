#!/usr/bin/env python3
import sys
sys.exit("UNGATED: this module performs privileged destructive actions with no safety gate. See SECURITY_REVIEW_2026-09-04.md H1. Port module21 gating before running.")

"""
Watchdog — GPU Hardware (B200)
Combines: thermal/power throttle, VRAM rowhammer, clock glitch prevention.

B200 constants (confirmed from live hardware):
  TDP          = 1000W
  TJ max       ~83°C (alert at 85)
  Emergency PL = 800W (80%)
  SM clock     = 2400 MHz
  HBM3e mem    = 8000 MHz (effective)
  Ghost power  = >80W at <5% util (confirmed +56W live)
"""
import subprocess, time, datetime, json
from collections import deque

# ── B200 constants ─────────────────────────────────────────────────
TEMP_THRESHOLD      = 85      # °C — alert before TJ max
POWER_EMERGENCY     = 800     # W — 80% of 1000W TDP
GHOST_POWER_FLOOR   = 80      # W — threshold for ghost power at idle
UTIL_IDLE           = 5       # % — "idle" definition
PSTATE_JUMP_LIMIT   = 2       # P-state levels before locking
B200_MEM_CLOCK      = 8000    # HBM3e MHz  (nvidia-smi -ac: MEM first)
B200_SM_CLOCK       = 2400    # SM MHz     (nvidia-smi -ac: GPU second)
ECC_WINDOW          = 10      # Samples for rowhammer window
ECC_SPIKE           = 10      # 10x relative multiplier
ECC_ABSOLUTE_FLOOR  = 50      # errors/s minimum — prevents HBM3e false positives
CLOCK_DROP_RATIO    = 0.5     # >50% drop in <100ms = glitch
CLOCK_GLITCH_MS     = 100     # ms

def now_iso():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()

def stamp():
    return datetime.datetime.now().strftime("%Y%m%d_%H%M%S")

# ── nvidia-smi helpers ──────────────────────────────────────────────
def _smi(fields: str):
    try:
        out = subprocess.check_output(
            ["nvidia-smi", f"--query-gpu={fields}",
             "--format=csv,noheader,nounits"],
            text=True, timeout=3)
        return [x.strip() for x in out.strip().split(",")]
    except:
        return []

def get_gpu_stats():
    """Returns (util%, temp°C, power_w) or (None, None, None)."""
    vals = _smi("utilization.gpu,temperature.gpu,power.draw")
    if len(vals) == 3:
        try:
            return float(vals[0]), float(vals[1]), float(vals[2])
        except:
            pass
    return None, None, None

def get_pstate():
    try:
        out = subprocess.check_output(
            ["nvidia-smi", "-q", "-d", "CLOCK"],
            text=True, timeout=3, stderr=subprocess.DEVNULL)
        for line in out.splitlines():
            if "Performance State" in line:
                return line.split(":")[-1].strip().replace("P", "")
        return None
    except:
        return None

def get_sm_clock():
    vals = _smi("clocks.sm")
    try:
        return float(vals[0])
    except:
        return None

def get_ecc():
    vals = _smi("ecc.errors.corrected.volatile.total")
    try:
        return float(vals[0])
    except:
        return None

def set_power_limit(w):
    try:
        subprocess.check_output(["nvidia-smi", "-pl", str(w)],
            text=True, timeout=3, stderr=subprocess.DEVNULL)
        return True
    except:
        return False

def set_fan(pct):
    try:
        subprocess.check_output(["nvidia-smi", "--fan-speed", str(pct)],
            text=True, timeout=3, stderr=subprocess.DEVNULL)
        return True
    except:
        return False

def lock_clocks():
    """Lock to B200 max clocks. nvidia-smi -ac format: MEM_CLOCK,GPU_CLOCK"""
    try:
        subprocess.check_output(
            ["nvidia-smi", "-ac", f"{B200_MEM_CLOCK},{B200_SM_CLOCK}"],
            text=True, timeout=3, stderr=subprocess.DEVNULL)
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

# ── main ────────────────────────────────────────────────────────────
def main():
    log = open(f"watchdog_gpu_hardware_{stamp()}.jsonl", "a")

    def emit(event: dict):
        event.setdefault("ts", now_iso())
        log.write(json.dumps(event) + "\n")
        log.flush()

    emit({"event": "RUN_START", "module": "gpu_hardware", "gpu": "B200",
          "constants": {"power_emergency_w": POWER_EMERGENCY,
                        "sm_mhz": B200_SM_CLOCK, "mem_mhz": B200_MEM_CLOCK,
                        "ghost_power_floor_w": GHOST_POWER_FLOOR}})

    ecc_history   = deque(maxlen=ECC_WINDOW)
    prev_ecc      = get_ecc()
    prev_ecc_time = time.time()
    prev_pstate   = get_pstate()
    prev_clock    = get_sm_clock()
    prev_clk_time = time.time()

    t_clock = time.time()   # next clock check (0.5s)
    t_ecc   = time.time()   # next ECC check   (1s)

    while True:
        now = time.time()

        # ── Thermal / power (every 2s) ──
        util, temp, power = get_gpu_stats()
        pstate = get_pstate()

        if util is not None and temp is not None and power is not None:
            # Ghost power: significant watts at near-zero util
            if power > GHOST_POWER_FLOOR and util < UTIL_IDLE:
                set_power_limit(POWER_EMERGENCY)
                emit({"event": "GHOST_POWER_DETECTED",
                      "power_w": power, "util_pct": util,
                      "action": f"power_limit={POWER_EMERGENCY}W"})

            # Thermal stress at idle — possible covert compute
            if temp > TEMP_THRESHOLD and util < UTIL_IDLE:
                set_fan(100)
                set_power_limit(POWER_EMERGENCY)
                emit({"event": "GPU_THERMAL_PREVENT",
                      "temp_c": temp, "util_pct": util, "power_w": power,
                      "action": f"fan=100% power_limit={POWER_EMERGENCY}W"})

        # P-state jump at idle
        if prev_pstate and pstate and util is not None:
            try:
                jump = abs(int(pstate) - int(prev_pstate))
                if jump > PSTATE_JUMP_LIMIT and util < UTIL_IDLE:
                    if lock_clocks():
                        emit({"event": "GPU_PSTATE_LOCK",
                              "from": f"P{prev_pstate}", "to": f"P{pstate}",
                              "action": f"-ac {B200_MEM_CLOCK},{B200_SM_CLOCK}"})
            except:
                pass

        prev_pstate = pstate

        # ── ECC / Rowhammer (every 1s) ──
        if now >= t_ecc:
            t_ecc = now + 1.0
            ecc = get_ecc()
            if ecc is not None and prev_ecc is not None:
                dt   = now - prev_ecc_time
                rate = (ecc - prev_ecc) / dt if dt > 0 else 0
                ecc_history.append(ecc)

                if len(ecc_history) == ECC_WINDOW:
                    baseline = sum(list(ecc_history)[:-1]) / (ECC_WINDOW - 1)
                    relative = baseline > 0 and ecc > baseline * ECC_SPIKE
                    absolute = rate > ECC_ABSOLUTE_FLOOR

                    if relative and absolute:
                        if reset_gpu():
                            emit({"event": "VRAM_ROWHAMMER_PREVENT",
                                  "ecc": ecc, "baseline": round(baseline, 1),
                                  "rate_per_s": round(rate, 1),
                                  "action": "gpu_reset"})

            prev_ecc      = ecc
            prev_ecc_time = now

        # ── Clock glitch (every 0.5s) ──
        if now >= t_clock:
            t_clock = now + 0.5
            clock = get_sm_clock()
            if prev_clock and clock:
                if clock < prev_clock * CLOCK_DROP_RATIO:
                    delta_ms = (now - prev_clk_time) * 1000
                    if delta_ms < CLOCK_GLITCH_MS:
                        if lock_clocks():
                            emit({"event": "GPU_CLOCK_GLITCH_BLOCKED",
                                  "old_mhz": prev_clock, "new_mhz": clock,
                                  "delta_ms": round(delta_ms, 1),
                                  "action": f"-ac {B200_MEM_CLOCK},{B200_SM_CLOCK}"})
            prev_clock    = clock
            prev_clk_time = now

        time.sleep(2)

if __name__ == "__main__":
    main()
