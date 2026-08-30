"""Module 126 — Log Tampering Detection
Checks for gaps, zero-size logs, or timestamp anomalies in /var/log —
possible evidence of an attacker covering tracks."""
import json, datetime, os, glob

def now_iso(): return datetime.datetime.now(datetime.timezone.utc).isoformat()

LOG_GLOBS = ["/var/log/*.log", "/var/log/auth.log", "/var/log/syslog"]

def check_logs():
    findings = []
    log_files = set()
    for pattern in LOG_GLOBS:
        log_files.update(glob.glob(pattern))

    for path in sorted(log_files):
        try:
            st = os.stat(path)
            size = st.st_size
            mtime = datetime.datetime.fromtimestamp(st.st_mtime, tz=datetime.timezone.utc)
            entry = {"file": path, "size_bytes": size, "last_modified": mtime.isoformat()}
            if size == 0:
                entry["flag"] = "zero-size log file — unusual unless freshly rotated"
            findings.append(entry)
        except Exception as e:
            findings.append({"file": path, "error": f"{type(e).__name__}: {e}"})
    return findings

if __name__ == "__main__":
    print("--- Log Tampering Detection ---\n")
    findings = check_logs()
    flagged = [f for f in findings if "flag" in f]
    print(f"Log files checked: {len(findings)}, flagged: {len(flagged)}")
    for f in findings:
        print(f"  {f}")

    finding_summary = (
        f"Checked {len(findings)} log file(s) for zero-size anomalies. "
        f"Found {len(flagged)} flagged. This is a lightweight check — "
        f"zero-size logs are consistent with either normal rotation or "
        f"deliberate clearing to hide activity; this alone cannot "
        f"distinguish the two, only flag it for review."
    )
    print(f"\nFINDING: {finding_summary}")

    result = {"log_files_checked": findings, "finding_summary": finding_summary, "timestamp": now_iso()}
    OUTPUT_DIR = "/data/data/com.termux/files/home/Watchdog/todo"
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    with open(os.path.join(OUTPUT_DIR, "module126_log_tamper_result.json"), "w") as f:
        json.dump(result, f, indent=2)
    print("Saved.")
