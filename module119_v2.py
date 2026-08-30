"""Module 119 v2 — Open Network Port Audit (installs missing tool first)
v1 couldn't run at all — neither ss nor netstat was available. v2
installs iproute2 (provides ss) before attempting the real scan."""
import subprocess, json, datetime, os

def now_iso(): return datetime.datetime.now(datetime.timezone.utc).isoformat()

def ensure_tool():
    try:
        check = subprocess.run(["which", "ss"], capture_output=True, text=True, timeout=10)
        if check.returncode == 0:
            return True, "ss already available"
        install = subprocess.run(
            ["apt-get", "install", "-y", "iproute2"],
            capture_output=True, text=True, timeout=120
        )
        if install.returncode == 0:
            return True, "iproute2 installed successfully"
        return False, f"install failed: {install.stderr.strip()[-300:]}"
    except Exception as e:
        return False, f"{type(e).__name__}: {e}"

def scan_ports():
    try:
        out = subprocess.run(["ss", "-tulnp"], capture_output=True, text=True, timeout=15)
        return out.stdout if out.returncode == 0 else None
    except Exception:
        return None

if __name__ == "__main__":
    print("--- Open Network Port Audit v2 (installs tool first) ---\n")
    ready, install_msg = ensure_tool()
    print(f"Tool setup: {install_msg}\n")

    output = scan_ports() if ready else None
    if output:
        print(output)
        listening = [l for l in output.splitlines() if "LISTEN" in l]
    else:
        listening = []

    finding_summary = (
        f"v1 could not scan at all (no tool available). v2 installed the "
        f"missing tool ({install_msg}) and " +
        (f"successfully scanned — found {len(listening)} listening socket(s), "
         f"each a real currently-reachable network service worth verifying "
         f"is intentional." if output else
         "the scan still could not run — genuinely unavailable in this environment.")
    )
    print(f"\nFINDING: {finding_summary}")

    result = {"tool_ready": ready, "install_message": install_msg, "raw_output": output,
               "listening_count": len(listening), "finding_summary": finding_summary,
               "timestamp": now_iso()}
    OUTPUT_DIR = "/data/data/com.termux/files/home/Watchdog/todo"
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    with open(os.path.join(OUTPUT_DIR, "module119_v2_port_audit_result.json"), "w") as f:
        json.dump(result, f, indent=2)
    print("Saved.")
