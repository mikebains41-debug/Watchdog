#!/usr/bin/env python3
"""
Watchdog — Module 16: CPU Cache Monitoring (LLC/L3 + TLB)
Uses perf to monitor cache misses and TLB flushes that deviate from baseline.
"""
import subprocess, time, datetime, json

def now_iso():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()

def run_perf_stat():
    try:
        out = subprocess.check_output(["perf", "stat", "-e", "LLC-load-misses,LLC-store-misses,dTLB-load-misses,iTLB-load-misses", "-x", ",", "sleep", "1"], text=True, timeout=3, stderr=subprocess.DEVNULL)
        lines = out.splitlines()
        stats = {}
        for l in lines:
            parts = l.split(",")
            if len(parts) >= 2:
                stats[parts[1]] = float(parts[0])
        return stats
    except:
        return {}

def main():
    stamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    out = f"module16_cpu_cache_monitor_{stamp}.jsonl"
    log = open(out, "a")
    log.write(json.dumps({"event":"RUN_START", "module":"16_cpu_cache_monitor", "ts":now_iso()}) + "\n")

    alerts = 0
    baseline = run_perf_stat()
    if not baseline:
        log.write(json.dumps({"event":"WARNING","message":"perf not available or missing permissions"}) + "\n")
        log.write(json.dumps({"event":"RUN_END","alerts":0}) + "\n")
        log.close()
        print("Module 16: perf not available. Aborting.")
        return

    for _ in range(300):
        stats = run_perf_stat()
        for key in stats:
            if key in baseline and baseline[key] > 0:
                delta = abs(stats[key] - baseline[key]) / baseline[key]
                if delta > 0.5:  # 50% delta
                    alerts += 1
                    log.write(json.dumps({
                        "detector":"CACHE_MISS_SPIKE",
                        "severity":"INFO",
                        "metric":key,
                        "delta_pct":round(delta*100, 1),
                        "confidence":0.3,
                        "note":"Cache miss or TLB flush rate deviated >50% from baseline"
                    }) + "\n")
        time.sleep(1.0)

    log.write(json.dumps({"event":"RUN_END","alerts":alerts,"ts":now_iso()}) + "\n")
    log.close()
    print(f"Done. Module 16: alerts={alerts}\nLog: {out}")

if __name__ == "__main__":
    main()
