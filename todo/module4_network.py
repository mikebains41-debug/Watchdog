#!/usr/bin/env python3
"""
Watchdog — Module 4: Network source
Outbound monitoring for C2, miners, and registry pulls.

FIXED: check_pulls() previously grepped only /var/log/containerd/audit.log,
a path that generally does not exist by default (containerd doesn't ship an
audit log there) — the check silently always returned empty. Now checks a
list of plausible log locations and emits a WARNING event if none exist,
so the absence is visible instead of silently swallowed.
"""
import subprocess, time, datetime, json

KNOWN_MINER_DOMAINS = ['pool.mine', 'stratum', 'ethpool', 'nicehash', 'minergate']
KNOWN_MINER_PORTS = [3333, 4444, 5555, 6666, 8443, 13333]
CONTAINERD_LOG_CANDIDATES = [
    "/var/log/containerd/audit.log",
    "/var/log/containerd.log",
    "/var/log/syslog",
]
DURATION_S = 120


def now_iso():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def get_connections():
    try:
        out = subprocess.check_output(["netstat", "-ntup"], text=True, timeout=5, stderr=subprocess.DEVNULL)
        return out.strip().splitlines()
    except Exception:
        return []


def check_pulls():
    import os
    for path in CONTAINERD_LOG_CANDIDATES:
        if not os.path.exists(path):
            continue
        try:
            out = subprocess.check_output(["grep", "pulling", path], text=True, timeout=2, stderr=subprocess.DEVNULL)
            lines = out.strip().splitlines()
            if lines:
                return lines[:5], None
        except subprocess.CalledProcessError:
            continue  # grep found nothing in this file — not an error
        except Exception:
            continue
    return [], "no containerd/registry log found in known locations"


def main():
    stamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    out = f'module4_network_{stamp}.jsonl'
    log = open(out, 'a')
    alerts = 0
    samples = 0
    log.write(json.dumps({"event": "RUN_START", "module": "4_network", "ts": now_iso()}) + "\n")

    warned_missing_log = False

    start = time.time()
    while time.time() < start + DURATION_S:
        samples += 1
        lines = get_connections()
        for l in lines:
            for d in KNOWN_MINER_DOMAINS:
                if d in l.lower():
                    alerts += 1
                    log.write(json.dumps({
                        "detector": "D74_OUTBOUND_C2",
                        "severity": "CRITICAL",
                        "connection": l.strip(),
                        "confidence": 0.85,
                        "note": "Outbound connection to known miner/pool domain"
                    }) + "\n")
                    break
            for p in KNOWN_MINER_PORTS:
                if f":{p}" in l:
                    alerts += 1
                    log.write(json.dumps({
                        "detector": "D75_OUTBOUND_PORT",
                        "severity": "WARN",
                        "port": p,
                        "connection": l.strip(),
                        "confidence": 0.6,
                        "note": "Connection to suspicious mining/stratum port"
                    }) + "\n")
                    break

        pulls, missing_reason = check_pulls()
        if pulls:
            for p in pulls:
                log.write(json.dumps({
                    "detector": "D50_REGISTRY_PULL",
                    "severity": "INFO",
                    "log": p.strip(),
                    "confidence": 0.4,
                    "note": "Container image pull detected"
                }) + "\n")
        elif missing_reason and not warned_missing_log:
            warned_missing_log = True
            log.write(json.dumps({
                "event": "WARNING",
                "message": missing_reason,
                "note": "D50_REGISTRY_PULL cannot fire without a readable log source"
            }) + "\n")

        time.sleep(1)

    log.write(json.dumps({"event": "RUN_END", "samples": samples, "alerts": alerts, "ts": now_iso()}) + "\n")
    log.close()
    print(f"Done. Module 4: samples={samples}, alerts={alerts}\nLog: {out}")


if __name__ == "__main__":
    main()
