"""Module 123 — Firewall Rule Audit
Checks iptables/ufw status. A finding means there's effectively no
network filtering active."""
import subprocess, json, datetime, os

def now_iso(): return datetime.datetime.now(datetime.timezone.utc).isoformat()

def check_iptables():
    try:
        out = subprocess.run(["iptables", "-L", "-n"], capture_output=True, text=True, timeout=10)
        return out.stdout, out.returncode
    except FileNotFoundError:
        return None, None
    except Exception as e:
        return f"error: {type(e).__name__}: {e}", -1

def check_ufw():
    try:
        out = subprocess.run(["ufw", "status"], capture_output=True, text=True, timeout=10)
        return out.stdout
    except FileNotFoundError:
        return None
    except Exception as e:
        return f"error: {type(e).__name__}: {e}"

if __name__ == "__main__":
    print("--- Firewall Rule Audit ---\n")
    iptables_out, iptables_rc = check_iptables()
    ufw_out = check_ufw()

    print("iptables -L -n:")
    print(iptables_out if iptables_out else "(not available / not accessible in this environment)")
    print("\nufw status:")
    print(ufw_out if ufw_out else "(ufw not installed)")

    no_rules = iptables_out and "Chain INPUT" in iptables_out and \
               iptables_out.count("\n") <= 6  # rough heuristic: default chains only, no real rules

    finding_summary = (
        f"Checked iptables and ufw status. "
        + ("iptables shows only default empty chains — no active filtering rules found. "
           if no_rules else
           "iptables output captured for review. ")
        + ("ufw is not installed. " if ufw_out is None else "")
        + "Note: this environment (proot/Termux) may not have real kernel-level "
          "netfilter access even if commands run — treat 'not accessible' results "
          "as inconclusive, not as 'firewall confirmed absent'."
    )
    print(f"\nFINDING: {finding_summary}")

    result = {"iptables_output": iptables_out, "ufw_output": ufw_out,
               "finding_summary": finding_summary, "timestamp": now_iso()}
    OUTPUT_DIR = "/data/data/com.termux/files/home/Watchdog/todo"
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    with open(os.path.join(OUTPUT_DIR, "module123_firewall_audit_result.json"), "w") as f:
        json.dump(result, f, indent=2)
    print("Saved.")
