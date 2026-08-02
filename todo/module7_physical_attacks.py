#!/usr/bin/env python3
"""
Watchdog — Module 7: Physical Attack Vectors
Detects rapid clock glitches and extreme power transients.
"""
import subprocess, time, datetime, json

def get_clocks():
    try:
        out = subprocess.check_output(["nvidia-smi", "--query-gpu=clocks.sm,clocks.mem", "--format=csv,noheader,nounits"], text=True, timeout=3)
        parts = out.strip().split(",")
        if len(parts) >= 2:
            return float(parts[0]), float(parts[1])
    except:
        pass
    return None, None

def get_power():
    try:
        out = subprocess.check_output(["nvidia-smi", "--query-gpu=power.draw", "--format=csv,noheader,nounits"], text=True, timeout=3)
        return float(out.strip())
    except:
        return None

def main():
    stamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    out = f"module7_physical_attacks_{stamp}.jsonl"
    log = open(out, "a")
    log.write(json.dumps({"event":"RUN_START", "module":"7_physical"}) + "\n")

    prev_sm = None
    prev_power = None
    prev_time = time.time()
    alerts = 0

    for _ in range(300):
        sm, mem = get_clocks()
        power = get_power()
        now = time.time()

        # D7: Clock Glitch
        if prev_sm and sm:
            if sm < (prev_sm * 0.5):
                delta = now - prev_time
                if delta < 0.5:
                    alerts += 1
                    log.write(json.dumps({
                        "detector":"D7_CLOCK_GLITCH",
                        "severity":"WARN",
                        "old_mhz":prev_sm,
                        "new_mhz":sm,
                        "recovery_ms":round(delta*1000,1),
                        "confidence":0.4,
                        "note":"Rapid SM clock drop <500ms — possible glitch or thermal throttle"
                    }) + "\n")
        prev_sm = sm

        # D8: Power Brake
        if prev_power and power:
            if prev_power - power > 200:
                delta = now - prev_time
                if delta < 0.025:
                    alerts += 1
                    log.write(json.dumps({
                        "detector":"D8_POWER_BRAKE",
                        "severity":"WARN",
                        "drop_w":round(prev_power - power,1),
                        "recovery_ms":round(delta*1000,1),
                        "confidence":0.4,
                        "note":"Rapid deep power transient <25ms — cause unconfirmed"
                    }) + "\n")
        prev_power = power
        prev_time = now
        time.sleep(1.0)

    log.write(json.dumps({"event":"RUN_END","alerts":alerts}) + "\n")
    log.close()
    print(f"Done. Module 7: alerts={alerts}\nLog: {out}")

if __name__ == "__main__":
    main()
