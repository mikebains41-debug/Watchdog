"""Module 125 — Package Integrity Drift Check
Compares installed files against apt's original checksums (dpkg -V).
A finding means a package binary was modified after install — a
classic backdoor signature."""
import subprocess, json, datetime, os

def now_iso(): return datetime.datetime.now(datetime.timezone.utc).isoformat()

def run_dpkg_verify():
    try:
        out = subprocess.run(["dpkg", "-V"], capture_output=True, text=True, timeout=120)
        return out.stdout, None
    except FileNotFoundError:
        return None, "dpkg not available"
    except subprocess.TimeoutExpired:
        return None, "dpkg -V timed out after 120s"
    except Exception as e:
        return None, f"{type(e).__name__}: {e}"

def check_debsums():
    try:
        out = subprocess.run(["which", "debsums"], capture_output=True, text=True, timeout=5)
        return out.returncode == 0
    except Exception:
        return False

if __name__ == "__main__":
    print("--- Package Integrity Drift Check ---\n")
    has_debsums = check_debsums()
    print(f"debsums available (more thorough tool): {has_debsums}")

    output, error = run_dpkg_verify()
    if error:
        print(f"Could not run dpkg -V: {error}")
        drift_lines = []
    else:
        drift_lines = [l for l in output.splitlines() if l.strip()]
        print(f"Files with detected drift from package checksums: {len(drift_lines)}")
        for line in drift_lines[:20]:
            print(f"  {line}")
        if len(drift_lines) > 20:
            print(f"  ... and {len(drift_lines)-20} more")

    finding_summary = (
        f"Ran dpkg -V to compare installed files against original package "
        f"checksums. Found {len(drift_lines)} file(s) with drift. Each one "
        f"is either a legitimate local config change, OR a real integrity "
        f"concern if it's a binary that was never meant to be edited "
        f"post-install — worth reviewing each entry individually. "
        + ("(debsums not installed — dpkg -V alone only checks metadata "
           "like permissions/ownership for many packages, not full file "
           "content hashes; consider installing debsums for a stronger check)"
           if not has_debsums else "")
    )
    print(f"\nFINDING: {finding_summary}")

    result = {"debsums_available": has_debsums, "drift_lines": drift_lines,
               "error": error, "finding_summary": finding_summary, "timestamp": now_iso()}
    OUTPUT_DIR = "/data/data/com.termux/files/home/Watchdog/todo"
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    with open(os.path.join(OUTPUT_DIR, "module125_package_drift_result.json"), "w") as f:
        json.dump(result, f, indent=2)
    print("Saved.")
