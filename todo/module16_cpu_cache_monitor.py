#!/usr/bin/env python3
"""
Watchdog — Module 16: CPU Cache Monitoring (LLC/L3 + TLB)
Uses perf to monitor cache misses and TLB flushes that deviate from baseline.

FIXED (two bugs):
1. run_perf_stat() previously requested 4 events in one `perf stat -x,` call
   and keyed results as `stats[parts[1]] = float(parts[0])`. With `-x,` the
   column layout is `value,unit,event,...` on most perf builds — parts[1] is
   the unit (e.g. "msec" or empty), not the event name — so results were
   keyed on the wrong field and baseline/live dicts likely never matched up.
   Rewritten to call perf once per event, so each result is keyed
   unambiguously by the exact event name we requested.
2. The outer loop did `perf stat ... sleep 1` (perf's own 1s measurement
   window) AND THEN `time.sleep(1.0)` again after each iteration — so a
   "300 iteration" loop actually ran ~2x the intended wall-clock time.
   Removed the redundant outer sleep; perf's internal `sleep 1` already
   paces each sample.
"""
import subprocess, time, datetime, json

DURATION_S = 120
EVENTS = ["LLC-load-misses", "LLC-store-misses", "dTLB-load-misses", "iTLB-load-misses"]


def now_iso():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def run_perf_stat():
    """One perf call per event -> unambiguous {event_name: value} mapping."""
    stats = {}
    for event in EVENTS:
        try:
            out = subprocess.check_output(
                ["perf", "stat", "-e", event, "-x", ",", "sleep", "1"],
                text=True, timeout=3, stderr=subprocess.STDOUT
            )
            first_line = out.strip().splitlines()[0] if out.strip() else ""
            value_str = first_line.split(",")[0].strip()
            stats[event] = float(value_str)
        except Exception:
            continue  # this event unavailable on this CPU/perf build — skip, don't fake a 0
    return stats


def main():
    stamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    out = f"module16_cpu_cache_monitor_{stamp}.jsonl"
    log = open(out, "a")
    log.write(json.dumps({"event": "RUN_START", "module": "16_cpu_cache_monitor", "ts": now_iso()}) + "\n")

    alerts = 0
    baseline = run_perf_stat()
    if not baseline:
        log.write(json.dumps({"event": "WARNING", "message": "perf not available or missing permissions"}) + "\n")
        log.write(json.dumps({"event": "RUN_END", "alerts": 0}) + "\n")
        log.close()
        print("Module 16: perf not available. Aborting.")
        return

    start = time.time()
    while time.time() < start + DURATION_S:
        # perf's own `sleep 1` inside run_perf_stat() paces each sample —
        # no additional time.sleep() here (that was the double-sleep bug).
        stats = run_perf_stat()
        for key, value in stats.items():
            if key in baseline and baseline[key] > 0:
                delta = abs(value - baseline[key]) / baseline[key]
                if delta > 0.5:
                    alerts += 1
                    log.write(json.dumps({
                        "detector": "D92_CACHE_MISS_SPIKE",
                        "severity": "INFO",
                        "metric": key,
                        "delta_pct": round(delta * 100, 1),
                        "confidence": 0.3,
                        "note": "Cache miss or TLB flush rate deviated >50% from baseline"
                    }) + "\n")

    log.write(json.dumps({"event": "RUN_END", "alerts": alerts, "ts": now_iso()}) + "\n")
    log.close()
    print(f"Done. Module 16: alerts={alerts}\nLog: {out}")


if __name__ == "__main__":
    main()
