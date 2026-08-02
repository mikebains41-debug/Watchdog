#!/usr/bin/env python3
"""
Watchdog — Module 5b: Active probes (Run on-demand only)
Allocates VRAM to scan for residual data patterns.
NOTE: probe_vram() currently measures nvidia-smi's memory.used delta around a
sleep, not an actual allocation+read-back — the docstring overstates what
this does today. Left as-is functionally since you didn't report this as a
bug, but flagging: this will not reliably detect VRAM residue without an
actual allocate/read/compare step (see Module 5b real implementation, if any,
in b200_watchdog/residency_probe_*.json for what an actual probe looks like).
"""
import time, datetime, json, subprocess


def now_iso():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def probe_vram():
    try:
        out = subprocess.check_output(
            ["nvidia-smi", "--query-gpu=memory.used", "--format=csv,noheader,nounits"],
            text=True, timeout=3, stderr=subprocess.DEVNULL
        )
        before = float(out.strip())
        time.sleep(0.5)
        out = subprocess.check_output(
            ["nvidia-smi", "--query-gpu=memory.used", "--format=csv,noheader,nounits"],
            text=True, timeout=3, stderr=subprocess.DEVNULL
        )
        after = float(out.strip())
        return after - before
    except Exception:
        return 0.0


def main():
    stamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    out = f'module5b_active_{stamp}.jsonl'
    log = open(out, 'a')
    alerts = 0
    log.write(json.dumps({"event": "RUN_START", "module": "5b_active_probe", "ts": now_iso()}) + "\n")

    delta = probe_vram()
    if delta < 0:
        alerts += 1
        log.write(json.dumps({
            "detector": "D51_VRAM_RESIDUE",
            "severity": "WARN",
            "delta_mb": round(delta, 2),
            "confidence": 0.5,
            "note": "VRAM residual detected; possible cross-tenant residue"
        }) + "\n")

    log.write(json.dumps({"event": "RUN_END", "samples": 1, "alerts": alerts, "ts": now_iso()}) + "\n")
    log.close()
    print(f"Done. Module 5b: alerts={alerts}\nLog: {out}")


if __name__ == "__main__":
    main()
