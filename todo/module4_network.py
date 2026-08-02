#!/usr/bin/env python3
"""
Watchdog — Module 4: Network source
Outbound monitoring for C2, miners, and registry pulls.
"""
import subprocess, time, datetime, json, os
from collections import defaultdict

KNOWN_MINER_DOMAINS = ['pool.mine', 'stratum', 'ethpool', 'nicehash', 'minergate']
KNOWN_MINER_PORTS = [3333, 4444, 5555, 6666, 8443, 13333]

def now_iso():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()

def get_connections():
    try:
        out = subprocess.check_output(["netstat", "-ntup"], text=True, timeout=5, stderr=subprocess.DEVNULL)
        return out.strip().splitlines()
    except:
        return []

def resolve_dns_target(host):
    try:
        ip = subprocess.check_output(["dig", "+short", host], text=True, timeout=3, stderr=subprocess.DEVNULL).strip()
        return ip if ip else None
    except:
        return None

def check_pulls():
    try:
        out = subprocess.check_output(["grep", "pulling", "/var/log/containerd/audit.log"], text=True, timeout=2, stderr=subprocess.DEVNULL)
        return out.strip().splitlines()[:5]
    except:
        return []

def main():
    stamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    out = f'module4_network_{stamp}.jsonl'
    log = open(out, 'a')
    alerts = 0
    samples = 0
    log.write(json.dumps({"event":"RUN_START","module":"4_network","ts":now_iso()}) + "\n")

    start = time.time()
    while time.time() < start + 120:
        samples += 1
        lines = get_connections()
        for l in lines:
            for d in KNOWN_MINER_DOMAINS:
                if d in l.lower():
                    alerts += 1
                    log.write(json.dumps({
                        "detector":"D12_OUTBOUND_C2",
                        "severity":"CRITICAL",
                        "connection":l.strip(),
                        "confidence":0.85,
                        "note":"Outbound connection to known miner/pool domain"
                    }) + "\n")
                    break
            for p in KNOWN_MINER_PORTS:
                if f":{p}" in l:
                    alerts += 1
                    log.write(json.dumps({
                        "detector":"D12_OUTBOUND_PORT",
                        "severity":"WARN",
                        "port":p,
                        "connection":l.strip(),
                        "confidence":0.6,
                        "note":"Connection to suspicious mining/stratum port"
                    }) + "\n")
                    break

        pulls = check_pulls()
        if pulls:
            for p in pulls:
                log.write(json.dumps({
                    "detector":"D50_REGISTRY_PULL",
                    "severity":"INFO",
                    "log":p.strip(),
                    "confidence":0.4,
                    "note":"Container image pull detected"
                }) + "\n")
        time.sleep(1)

    log.write(json.dumps({"event":"RUN_END","samples":samples,"alerts":alerts,"ts":now_iso()}) + "\n")
    log.close()
    print(f"Done. Module 4: samples={samples}, alerts={alerts}\nLog: {out}")

if __name__ == "__main__":
    main()
