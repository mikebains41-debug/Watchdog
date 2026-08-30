"""Module 114 — Sudo/Root Privilege Audit
Checks /etc/sudoers and /etc/sudoers.d/ for NOPASSWD entries — a real
finding means compromising that user account grants instant root."""
import subprocess, json, datetime, os, glob

def now_iso(): return datetime.datetime.now(datetime.timezone.utc).isoformat()

def scan_sudoers():
    findings = []
    paths = ["/etc/sudoers"] + glob.glob("/etc/sudoers.d/*")
    for path in paths:
        try:
            with open(path) as f:
                for lineno, line in enumerate(f, 1):
                    line = line.strip()
                    if line.startswith("#") or not line:
                        continue
                    if "NOPASSWD" in line:
                        findings.append({"file": path, "line": lineno, "content": line})
        except PermissionError:
            findings.append({"file": path, "error": "permission denied reading file"})
        except FileNotFoundError:
            pass
        except Exception as e:
            findings.append({"file": path, "error": f"{type(e).__name__}: {e}"})
    return findings

if __name__ == "__main__":
    print("--- Sudo/Root Privilege Audit ---\n")
    findings = scan_sudoers()
    print(f"NOPASSWD entries found: {len([f for f in findings if 'content' in f])}")
    for f in findings:
        if "content" in f:
            print(f"  {f['file']}:{f['line']}  {f['content']}")
        elif "error" in f:
            print(f"  {f['file']}: {f['error']}")

    finding_summary = (
        f"Scanned sudoers config for NOPASSWD entries. Found "
        f"{len([f for f in findings if 'content' in f])} such entries — "
        f"each represents an account where privilege escalation to root "
        f"requires no password, a real risk if that account is ever "
        f"compromised via any other vector (weak SSH key, leaked "
        f"credential, etc.)."
    )
    print(f"\nFINDING: {finding_summary}")

    result = {"findings": findings, "finding_summary": finding_summary, "timestamp": now_iso()}
    OUTPUT_DIR = "/data/data/com.termux/files/home/Watchdog/todo"
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    with open(os.path.join(OUTPUT_DIR, "module114_sudo_audit_result.json"), "w") as f:
        json.dump(result, f, indent=2)
    print("Saved.")
