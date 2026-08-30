"""Module 120 — Cron Job Audit
Checks all crontabs and /etc/cron.d/ for scripts, flags world-writable
ones. A finding means any user could hijack a task that runs
automatically as another (possibly privileged) user."""
import subprocess, json, datetime, os, glob, stat

def now_iso(): return datetime.datetime.now(datetime.timezone.utc).isoformat()

def is_world_writable(path):
    try:
        mode = os.stat(path).st_mode
        return bool(mode & stat.S_IWOTH)
    except Exception:
        return None

def scan_cron():
    findings = []
    cron_paths = ["/etc/crontab"] + glob.glob("/etc/cron.d/*") + \
                 glob.glob("/var/spool/cron/crontabs/*")
    for path in cron_paths:
        if not os.path.isfile(path):
            continue
        ww = is_world_writable(path)
        entry = {"cron_file": path, "world_writable": ww}
        if ww:
            entry["risk"] = "World-writable cron file — any user could inject a command that runs on schedule"
        findings.append(entry)

        try:
            with open(path) as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        parts = line.split(None, 6)
                        if len(parts) >= 7:
                            script_path = parts[6].split()[0] if parts[6] else None
                            if script_path and os.path.isfile(script_path):
                                sww = is_world_writable(script_path)
                                if sww:
                                    findings.append({"cron_file": path, "invoked_script": script_path,
                                                       "world_writable": True,
                                                       "risk": "World-writable script invoked by cron"})
        except (PermissionError, Exception):
            pass
    return findings

if __name__ == "__main__":
    print("--- Cron Job Audit ---\n")
    findings = scan_cron()
    risky = [f for f in findings if "risk" in f]
    print(f"Cron files/scripts checked: {len(findings)}, flagged risky: {len(risky)}")
    for f in risky:
        print(f"  {f}")

    finding_summary = (
        f"Checked {len(findings)} cron file(s)/invoked script(s). Found "
        f"{len(risky)} world-writable — a real risk since anything "
        f"scheduled runs automatically, often as a privileged user, and "
        f"a world-writable script or crontab means any local user could "
        f"inject commands into that schedule."
    )
    print(f"\nFINDING: {finding_summary}")

    result = {"findings": findings, "finding_summary": finding_summary, "timestamp": now_iso()}
    OUTPUT_DIR = "/data/data/com.termux/files/home/Watchdog/todo"
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    with open(os.path.join(OUTPUT_DIR, "module120_cron_audit_result.json"), "w") as f:
        json.dump(result, f, indent=2)
    print("Saved.")
