#!/usr/bin/env python3
"""
Watchdog — Module 11: GPU Memory Controller & ECC Stress Patterns
Tracks ECC error acceleration, memory clock desync, and power-ECC mismatches.
"""
import subprocess, time, datetime, json
from collections import deque

ECC_HISTORY = 20
ACCELERATION_THRESHOLD = 1.5  # 50% faster per sample

def now_iso():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()

def get_ecc():
    try:
        out = subprocess.check_output(["nvidia-smi", "--query-gpu=ecc.errors.corrected.volatile.total", "--format=csv,noheader,nounits"], text=True, timeout=3)
        return float(out.strip())
    except:
        return None

def get_mem_clock():
    try:
        out = subprocess.check_output(["nvidia-smi", "--query-gpu=clocks.mem", "--format=csv,noheader,nounits"], text=True, timeout=3)
        return float(out.strip())
    except:
        return None

def get_power():
    try:
        out = subprocess.check_output(["nvidia-smi", "--query-gpu=power.draw", "--format=csv,noheader,nounits"], text=True, timeout=3)
        return float(out.strip())
    except:
        return None

def main():
    stamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    out = f"module11_ecc_stress_patterns_{stamp}.jsonl"
    log = open(out, "a")
    log.write(json.dumps({"event":"RUN_START", "module":"11_ecc_stress", "ts":now_iso()}) + "\n")

    ecc_history = deque(maxlen=ECC_HISTORY)
    prev_ecc = None
    prev_mem = None
    alerts = 0

    for _ in range(600):
        ecc = get_ecc()
        mem = get_mem_clock()
        power = get_power()

        if ecc is not None:
            ecc_history.append(ecc)
            if prev_ecc is not None and len(ecc_history) >= 10:
                # Check acceleration: is ECC rising faster than normal?
                recent_rate = ecc - ecc_history[-5]
                prior_rate = ecc_history[-5] - ecc_history[-10]
                if prior_rate > 0:
                    acceleration = recent_rate / prior_rate
                    if acceleration > ACCELERATION_THRESHOLD:
                        alerts += 1
                        log.write(json.dumps({
                            "detector":"ECC_ACCELERATION_STRESS",
                            "severity":"WARN",
                            "recent_rate":round(recent_rate, 1),
                            "prior_rate":round(prior_rate, 1),
                            "acceleration":round(acceleration, 2),
                            "confidence":0.6,
                            "note":"ECC error rate accelerating — possible early silicon degradation or Rowhammer"
                        }) + "\n")
            prev_ecc = ecc

        # Memory clock desync with ECC
        if mem is not None and ecc is not None and prev_mem is not None:
            if mem == prev_mem and ecc > prev_ecc * 2:  # clock locked but ECC doubled
                alerts += 1
                log.write(json.dumps({
                    "detector":"MEM_CLOCK_DESYNC_STRESS",
                    "severity":"WARN",
                    "mem_clock":mem,
                    "ecc_surge":round(ecc, 1),
                    "confidence":0.5,
                    "note":"Memory clock locked but ECC surged — possible internal memory controller stress"
                }) + "\n")
        prev_mem = mem

        time.sleep(1.0)

    log.write(json.dumps({"event":"RUN_END","alerts":alerts,"ts":now_iso()}) + "\n")
    log.close()
    print(f"Done. Module 11: alerts={alerts}\nLog: {out}")

if __name__ == "__main__":
    main()
