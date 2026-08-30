"""Module 117 — Running Process Secret Leak Scan
Reads /proc/*/environ for live processes, checking for credentials
sitting in environment variables right now. A finding means any
process on the box could read another's secrets via /proc."""
import json, datetime, os, re

def now_iso(): return datetime.datetime.now(datetime.timezone.utc).isoformat()

SECRET_PATTERNS = re.compile(
    r'(SECRET|TOKEN|PASSWORD|API_KEY|CLIENT_ID|CLIENT_SECRET|PRIVATE_KEY)', re.IGNORECASE)

def redact(value):
    if len(value) <= 8:
        return "*" * len(value)
    return f"{value[:4]}...{value[-2:]} ({len(value)} chars)"

def scan_proc_environ():
    findings = []
    accessible = 0
    denied = 0
    for pid_dir in os.listdir("/proc"):
        if not pid_dir.isdigit():
            continue
        environ_path = f"/proc/{pid_dir}/environ"
        try:
            with open(environ_path, "rb") as f:
                raw = f.read()
            accessible += 1
            entries = raw.split(b"\x00")
            for entry in entries:
                try:
                    text = entry.decode("utf-8", errors="ignore")
                except Exception:
                    continue
                if "=" not in text:
                    continue
                key, _, value = text.partition("=")
                if SECRET_PATTERNS.search(key) and value:
                    findings.append({"pid": pid_dir, "var_name": key, "redacted_value": redact(value)})
        except PermissionError:
            denied += 1
        except FileNotFoundError:
            pass
        except Exception:
            pass
    return findings, accessible, denied

if __name__ == "__main__":
    print("--- Running Process Secret Leak Scan ---\n")
    findings, accessible, denied = scan_proc_environ()
    print(f"Processes with readable environ: {accessible}")
    print(f"Processes with permission-denied environ: {denied}")
    print(f"Potential secret-like env vars found: {len(findings)}")
    for f in findings[:15]:
        print(f"  PID {f['pid']}: {f['var_name']} = {f['redacted_value']}")

    finding_summary = (
        f"Scanned /proc/*/environ across {accessible} accessible "
        f"processes ({denied} denied by permissions). Found "
        f"{len(findings)} environment variable(s) matching secret-like "
        f"naming patterns, with values redacted in this output. "
        f"If /proc/*/environ is readable across UID boundaries on this "
        f"system, that's a real cross-process secret exposure risk."
    )
    print(f"\nFINDING: {finding_summary}")

    result = {"processes_readable": accessible, "processes_denied": denied,
               "findings": findings, "finding_summary": finding_summary, "timestamp": now_iso()}
    OUTPUT_DIR = "/data/data/com.termux/files/home/Watchdog/todo"
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    with open(os.path.join(OUTPUT_DIR, "module117_process_secret_scan_result.json"), "w") as f:
        json.dump(result, f, indent=2)
    print("Saved. (all values redacted — safe to commit)")
