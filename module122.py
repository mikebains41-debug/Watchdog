"""Module 122 — DNS/Hosts File Integrity Check
Checks /etc/hosts and /etc/resolv.conf for suspicious entries. A
finding means traffic to a trusted domain could be silently rerouted."""
import json, datetime, os, re

def now_iso(): return datetime.datetime.now(datetime.timezone.utc).isoformat()

COMMON_DOMAINS = ["google.com", "github.com", "cloudflare.com",
                    "openquantum.com", "gpu-optimizer.com"]

def check_hosts():
    findings = []
    try:
        with open("/etc/hosts") as f:
            content = f.read()
        for domain in COMMON_DOMAINS:
            if domain in content:
                for lineno, line in enumerate(content.splitlines(), 1):
                    if domain in line and not line.strip().startswith("#"):
                        findings.append({"file": "/etc/hosts", "line": lineno,
                                           "content": line.strip(),
                                           "note": f"Explicit override for {domain} found in hosts file"})
    except Exception as e:
        return None, f"{type(e).__name__}: {e}"
    return findings, None

def check_resolv_conf():
    try:
        with open("/etc/resolv.conf") as f:
            return f.read().strip()
    except Exception as e:
        return f"could not read: {type(e).__name__}: {e}"

if __name__ == "__main__":
    print("--- DNS/Hosts File Integrity Check ---\n")
    hosts_findings, error = check_hosts()
    resolv_content = check_resolv_conf()

    print("Current /etc/resolv.conf:")
    print(resolv_content)
    print()

    if error:
        print(f"Could not check hosts file: {error}")
        hosts_findings = []
    else:
        print(f"Suspicious hosts file overrides for known domains: {len(hosts_findings)}")
        for f in hosts_findings:
            print(f"  {f}")

    finding_summary = (
        f"Checked /etc/hosts for explicit overrides of {len(COMMON_DOMAINS)} "
        f"commonly-trusted domains — found {len(hosts_findings)}. Any "
        f"override here would silently redirect traffic for that domain "
        f"without any TLS certificate warning being triggered, since the "
        f"redirect happens before DNS resolution ever occurs."
    )
    print(f"\nFINDING: {finding_summary}")

    result = {"hosts_findings": hosts_findings, "resolv_conf": resolv_content,
               "finding_summary": finding_summary, "timestamp": now_iso()}
    OUTPUT_DIR = "/data/data/com.termux/files/home/Watchdog/todo"
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    with open(os.path.join(OUTPUT_DIR, "module122_dns_integrity_result.json"), "w") as f:
        json.dump(result, f, indent=2)
    print("Saved.")
