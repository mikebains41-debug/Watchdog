#!/usr/bin/env python3
"""
Watchdog — Module 6: sysfs / integrity checks
Monitors RAPL powercap, library hashes, ASLR state.
"""
import os, json, datetime, time, subprocess, hashlib

def now_iso():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()

def rapl_enabled():
    try:
        with open("/sys/class/powercap/intel-rapl/intel-rapl:0/enabled", "r") as f:
            return f.read().strip() == "1"
    except:
        return None

def hash_lib(path):
    if not os.path.exists(path):
        return None
    try:
        hasher = hashlib.sha256()
        with open(path, "rb") as f:
            hasher.update(f.read())
        return hasher.hexdigest()
    except:
        return None

def aslr_state():
    try:
        with open("/proc/sys/kernel/randomize_va_space", "r") as f:
            return int(f.read().strip())
    except:
        return None

def main():
    stamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    out = f'module6_sysfs_{stamp}.jsonl'
    log = open(out, 'a')
    alerts = 0
    log.write(json.dumps({"event":"RUN_START","module":"6_sysfs","ts":now_iso()}) + "\n")

    rapl = rapl_enabled()
    if rapl is False:
        alerts += 1
        log.write(json.dumps({
            "detector":"D48_RAPL_DISABLED",
            "severity":"WARN",
            "rapl_enabled":rapl,
            "confidence":0.7,
            "note":"RAPL powercap disabled — possible CPU-mining concealment"
        }) + "\n")

    libcuda = hash_lib("/usr/lib/x86_64-linux-gnu/libcuda.so")
    if libcuda:
        log.write(json.dumps({
            "detector":"D45_LIBRARY_HASH",
            "severity":"INFO",
            "sha256":libcuda,
            "note":"libcuda.so hash captured"
        }) + "\n")

    aslr = aslr_state()
    if aslr == 0:
        alerts += 1
        log.write(json.dumps({
            "detector":"D38_ASLR_DISABLED",
            "severity":"WARN",
            "aslr_value":aslr,
            "confidence":0.5,
            "note":"ASLR disabled on host — possible memory exploit precursor"
        }) + "\n")

    log.write(json.dumps({"event":"RUN_END","alerts":alerts,"ts":now_iso()}) + "\n")
    log.close()
    print(f"Done. Module 6: alerts={alerts}\nLog: {out}")

if __name__ == "__main__":
    main()
