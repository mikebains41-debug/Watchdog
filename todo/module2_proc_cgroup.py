#!/usr/bin/env python3
"""
Watchdog — Module 2: /proc + cgroup source
One pass over /proc, /sys, and cgroup metrics. Detection-only. Safe on shared hardware.

Merged detections:
  D10 Host-memory sprawl (VmRSS vs cgroup limit)
  D11 Process-lineage anomalies (parent/child chains)
  D12 Container resource limits (CPU/mem/IO beyond cgroup)
  D13 High cgroup block I/O burst
  D14 Cron/systemd persistence (unexpected scheduled tasks)
  D15 Credential-store access (T1552/T1003)
See DETECTOR_REGISTRY.md for the full, collision-free ID list.
"""
import os, sys, time, datetime, json, subprocess

SAMPLE_HZ = 0.5
MEM_LIMIT_WARN_PCT = 95.0
CRED_PATHS = ['/.aws', '/.ssh', '/.config/gcloud', '/.azure', '/.kube']
DURATION_S = 120


def now_iso():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def read_file(p):
    try:
        with open(p, 'r') as f:
            return f.read().strip()
    except Exception:
        return None


def get_cgroup_mem():
    s = read_file('/sys/fs/cgroup/memory/memory.limit_in_bytes')
    u = read_file('/sys/fs/cgroup/memory/memory.usage_in_bytes')
    if s and u:
        try:
            return float(s), float(u)
        except Exception:
            pass
    return None, None


def get_proc_stats():
    pids = []
    try:
        for p in os.listdir('/proc'):
            if p.isdigit():
                pids.append(p)
    except Exception:
        return []
    out = []
    for pid in pids:
        try:
            with open(f'/proc/{pid}/status') as f:
                lines = f.readlines()
            stat = {}
            for l in lines:
                if l.startswith('VmRSS:'):
                    stat['vmrss'] = float(l.split()[1])
                if l.startswith('PPid:'):
                    stat['ppid'] = l.split()[1]
            if stat.get('vmrss') and stat.get('ppid'):
                stat['pid'] = pid
                out.append(stat)
        except Exception:
            pass
    return out


def get_cgroup_cpu():
    try:
        with open('/sys/fs/cgroup/cpu/cpu.cfs_quota_us') as f:
            q = float(f.read().strip())
        with open('/sys/fs/cgroup/cpu/cpu.cfs_period_us') as f:
            p = float(f.read().strip())
        if q > 0:
            return q / p
        return -1.0  # unlimited
    except Exception:
        return None


def get_cgroup_io():
    try:
        with open('/sys/fs/cgroup/blkio/blkio.throttle.io_service_bytes') as f:
            lines = f.readlines()
        r, w = 0.0, 0.0
        for l in lines:
            if 'Read' in l:
                r = float(l.split()[1])
            if 'Write' in l:
                w = float(l.split()[1])
        return r, w
    except Exception:
        return None, None


def check_cron():
    out = []
    for loc in ['/etc/crontab', '/etc/cron.d/', '/var/spool/cron']:
        if os.path.exists(loc):
            out.append(loc)
    try:
        subprocess.check_output(['crontab', '-l'], stderr=subprocess.DEVNULL, text=True)
        out.append('user crontab present')
    except Exception:
        pass
    return out


def check_cred_files():
    found = []
    for p in CRED_PATHS:
        if os.path.exists(os.path.expanduser(p)):
            found.append(p)
    return found


def main():
    stamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    out = f'module2_proc_{stamp}.jsonl'
    log = open(out, 'a')
    alerts = 0
    samples = 0

    if get_cgroup_mem() == (None, None) and get_cgroup_cpu() is None:
        log.write(json.dumps({"event": "WARNING",
                               "message": "cgroup v1 paths not found — host may use cgroup v2 or lack cgroups"}) + "\n")

    log.write(json.dumps({"event": "RUN_START", "module": "2_proc", "ts": now_iso()}) + "\n")

    start = time.time()
    while time.time() < start + DURATION_S:
        samples += 1
        limit, usage = get_cgroup_mem()
        if limit and usage:
            pct = (usage / limit) * 100
            if pct >= MEM_LIMIT_WARN_PCT:
                alerts += 1
                log.write(json.dumps({
                    "detector": "D10_HOST_MEMORY_SPRAWL",
                    "severity": "WARN",
                    "usage_mb": usage / 1024 / 1024,
                    "limit_mb": limit / 1024 / 1024,
                    "pct": round(pct, 1),
                    "confidence": 0.75,
                    "note": "Process memory approaching cgroup limit"
                }) + "\n")

        procs = get_proc_stats()
        for p in procs:
            if p['ppid'] == '1' and p['vmrss'] > 500 * 1024:  # 500MB+
                alerts += 1
                log.write(json.dumps({
                    "detector": "D11_PROCESS_LINEAGE",
                    "severity": "INFO",
                    "pid": p['pid'],
                    "ppid": p['ppid'],
                    "vmrss_mb": round(p['vmrss'] / 1024, 1),
                    "confidence": 0.4,
                    "note": "Large process directly under init — suspicious launch"
                }) + "\n")

        cpu_shares = get_cgroup_cpu()
        if cpu_shares is not None and 0 < cpu_shares < 0.01:
            alerts += 1
            log.write(json.dumps({
                "detector": "D12_CONTAINER_RESOURCE_LIMIT",
                "severity": "WARN",
                "cpu_shares": cpu_shares,
                "confidence": 0.7,
                "note": "Cgroup cpu.shares suspiciously low — possible throttling"
            }) + "\n")

        io_r, io_w = get_cgroup_io()
        if io_r and io_w and io_r + io_w > 100 * 1024 * 1024 * 1024:  # 100GB+
            alerts += 1
            log.write(json.dumps({
                "detector": "D13_IO_BURST",
                "severity": "INFO",
                "read_bytes": io_r,
                "write_bytes": io_w,
                "confidence": 0.5,
                "note": "High cgroup block I/O activity"
            }) + "\n")

        cron = check_cron()
        if len(cron) > 1:
            log.write(json.dumps({
                "detector": "D14_CRON_PERSISTENCE",
                "severity": "INFO",
                "sources": cron,
                "confidence": 0.4,
                "note": "Multiple cron locations — possible persistence"
            }) + "\n")

        creds = check_cred_files()
        if creds:
            alerts += 1
            log.write(json.dumps({
                "detector": "D15_CREDENTIAL_STORE_ACCESS",
                "severity": "WARN",
                "paths": creds,
                "confidence": 0.6,
                "note": "Cloud/API credential files exposed on filesystem"
            }) + "\n")

        time.sleep(1.0 / SAMPLE_HZ)

    log.write(json.dumps({"event": "RUN_END", "samples": samples, "alerts": alerts, "ts": now_iso()}) + "\n")
    log.close()
    print(f"Done. Module 2: samples={samples}, alerts={alerts}\nLog: {out}")


if __name__ == "__main__":
    main()
