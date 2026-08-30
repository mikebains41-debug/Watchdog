"""Module 115 — World-Writable File Scan
Finds files in key system directories that any user can modify — a
classic tampering entry point if a privileged process later reads or
executes that file."""
import subprocess, json, datetime, os

def now_iso(): return datetime.datetime.now(datetime.timezone.utc).isoformat()

SCAN_DIRS = ["/etc", "/usr/bin", "/usr/sbin", "/usr/local/bin"]

def find_world_writable():
    findings = []
    for d in SCAN_DIRS:
        if not os.path.isdir(d):
            continue
        try:
            out = subprocess.run(
                ["find", d, "-xdev", "-type", "f", "-perm", "-o+w"],
                capture_output=True, text=True, timeout=30
            )
            for line in out.stdout.splitlines():
                if line.strip():
                    findings.append(line.strip())
        except Exception as e:
            findings.append(f"ERROR scanning {d}: {type(e).__name__}: {e}")
    return findings

if __name__ == "__main__":
    print("--- World-Writable File Scan ---\n")
    findings = find_world_writable()
    print(f"World-writable files found: {len(findings)}")
    for f in findings[:20]:
        print(f"  {f}")
    if len(findings) > 20:
        print(f"  ... and {len(findings)-20} more")

    finding_summary = (
        f"Scanned {SCAN_DIRS} for world-writable files. Found "
        f"{len(findings)}. Any file here can be modified by ANY user on "
        f"the system — if a privileged process later reads or executes "
        f"one of these, that's a real tampering vector."
    )
    print(f"\nFINDING: {finding_summary}")

    result = {"scanned_dirs": SCAN_DIRS, "world_writable_files": findings,
               "finding_summary": finding_summary, "timestamp": now_iso()}
    OUTPUT_DIR = "/data/data/com.termux/files/home/Watchdog/todo"
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    with open(os.path.join(OUTPUT_DIR, "module115_world_writable_result.json"), "w") as f:
        json.dump(result, f, indent=2)
    print("Saved.")
