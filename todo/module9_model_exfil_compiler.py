#!/usr/bin/env python3
"""
Watchdog — Module 9: Model Exfiltration & Compiler Monitor
Detects:
- Model weight exfiltration via high memory bandwidth + outbound traffic
- Malicious PyTorch/Triton compiler injection events

FIXED: the outbound-connection check previously called
  subprocess.check_output(["ss","-tun","|","grep","ESTAB"], shell=True, ...)
Passing a list with shell=True does NOT run a pipeline — only args[0] ("ss")
is treated as the shell command; "-tun", "|", "grep", "ESTAB" are passed to
that command as literal arguments, not interpreted as a pipe. The grep never
executed, so this check silently never fired. Rewritten as a single shell
string (still shell=True, but now correct) — or equivalently, two separate
subprocess calls without shell=True, which is what's used here to avoid
shell=True entirely.
"""
import subprocess, datetime, json

DURATION_S = 120  # documented for consistency; this module runs a single pass, not a loop


def now_iso():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def get_memory_bandwidth():
    try:
        out = subprocess.check_output(
            ["nvidia-smi", "--query-gpu=memory.used,utilization.memory", "--format=csv,noheader,nounits"],
            text=True, timeout=3, stderr=subprocess.DEVNULL
        )
        parts = out.strip().split(",")
        if len(parts) >= 2:
            return float(parts[0]), float(parts[1])
    except Exception:
        pass
    return None, None


def has_established_outbound():
    """No shell=True, no pipeline — filter in Python instead."""
    try:
        out = subprocess.check_output(["ss", "-tun"], text=True, timeout=3, stderr=subprocess.DEVNULL)
        return any("ESTAB" in line for line in out.splitlines())
    except Exception:
        return False


def get_compiler_events():
    try:
        out = subprocess.check_output(["grep", "-i", "torch.compile", "/var/log/syslog"],
                                       text=True, timeout=3, stderr=subprocess.DEVNULL)
        if out.strip():
            return out.strip().splitlines()[-5:]
        return []
    except Exception:
        return []


def main():
    stamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    out = f"module9_model_exfil_compiler_{stamp}.jsonl"
    log = open(out, "a")
    log.write(json.dumps({"event": "RUN_START", "module": "9_exfil_compiler", "ts": now_iso()}) + "\n")

    alerts = 0

    # D80: Model Exfil (Memory Bandwidth + Outbound)
    mem_used, mem_util = get_memory_bandwidth()
    if mem_util and mem_util > 95.0:
        if has_established_outbound():
            alerts += 1
            log.write(json.dumps({
                "detector": "D80_MODEL_EXFILTRATION",
                "severity": "CRITICAL",
                "mem_util_pct": mem_util,
                "note": "High memory bandwidth + active outbound traffic — possible model theft"
            }) + "\n")

    # D81: Compiler Injection
    events = get_compiler_events()
    for e in events:
        alerts += 1
        log.write(json.dumps({
            "detector": "D81_COMPILER_INJECTION",
            "severity": "WARN",
            "log_line": e.strip(),
            "confidence": 0.5,
            "note": "Unexpected torch.compile or compiler event detected"
        }) + "\n")

    log.write(json.dumps({"event": "RUN_END", "alerts": alerts, "ts": now_iso()}) + "\n")
    log.close()
    print(f"Done. Module 9: alerts={alerts}\nLog: {out}")


if __name__ == "__main__":
    main()
