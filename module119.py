"""Module 119 — Open Network Port Audit
Real scan of what's actually listening on this device right now."""
import subprocess, json, datetime, os

def now_iso(): return datetime.datetime.now(datetime.timezone.utc).isoformat()

def scan_ports():
    for cmd in (["ss", "-tulnp"], ["netstat", "-tulnp"]):
        try:
            out = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
            if out.returncode == 0:
                return out.stdout, cmd[0]
        except FileNotFoundError:
            continue
        except Exception:
            continue
    return None, None

if __name__ == "__main__":
    print("--- Open Network Port Audit ---\n")
    output, tool_used = scan_ports()

    if output is None:
        print("Neither 'ss' nor 'netstat' available — cannot scan.")
        listening = []
    else:
        print(f"Using: {tool_used}\n{output}")
        listening = [l for l in output.splitlines() if "LISTEN" in l]

    finding_summary = (
        f"Scanned open/listening network ports using '{tool_used}'. "
        f"Found {len(listening)} listening socket(s). Each represents a "
        f"real, currently-reachable network service — worth verifying "
        f"every one is intentional and necessary."
        if output else
        "Could not scan ports — no scanning tool available on this system."
    )
    print(f"\nFINDING: {finding_summary}")

    result = {"tool_used": tool_used, "raw_output": output, "listening_count": len(listening) if output else 0,
               "finding_summary": finding_summary, "timestamp": now_iso()}
    OUTPUT_DIR = "/data/data/com.termux/files/home/Watchdog/todo"
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    with open(os.path.join(OUTPUT_DIR, "module119_port_audit_result.json"), "w") as f:
        json.dump(result, f, indent=2)
    print("Saved.")
