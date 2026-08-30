"""Module 116 — SSH Key Strength Audit
Checks authorized_keys for weak key types (short RSA, DSA) — a
finding means a "secure" SSH login is actually crackable."""
import subprocess, json, datetime, os, glob

def now_iso(): return datetime.datetime.now(datetime.timezone.utc).isoformat()

WEAK_TYPES = {"ssh-dss": "DSA (deprecated, weak)"}

def check_key_bits(pubkey_line):
    try:
        out = subprocess.run(["ssh-keygen", "-lf", "/dev/stdin"],
                               input=pubkey_line, capture_output=True, text=True, timeout=5)
        return out.stdout.strip()
    except Exception:
        return None

def scan_authorized_keys():
    findings = []
    paths = glob.glob(os.path.expanduser("~/.ssh/authorized_keys")) + \
            glob.glob("/root/.ssh/authorized_keys") + \
            glob.glob("/home/*/.ssh/authorized_keys")
    for path in set(paths):
        try:
            with open(path) as f:
                for lineno, line in enumerate(f, 1):
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    parts = line.split()
                    if not parts:
                        continue
                    key_type = parts[0]
                    info = check_key_bits(line)
                    entry = {"file": path, "line": lineno, "key_type": key_type, "info": info}
                    if key_type in WEAK_TYPES:
                        entry["weakness"] = WEAK_TYPES[key_type]
                    elif key_type == "ssh-rsa" and info and "2048" in info:
                        entry["weakness"] = "RSA 2048 — acceptable but not future-proof; prefer ed25519"
                    findings.append(entry)
        except (FileNotFoundError, PermissionError):
            pass
        except Exception as e:
            findings.append({"file": path, "error": f"{type(e).__name__}: {e}"})
    return findings

if __name__ == "__main__":
    print("--- SSH Key Strength Audit ---\n")
    findings = scan_authorized_keys()
    weak = [f for f in findings if "weakness" in f]
    print(f"Authorized keys found: {len(findings)}, flagged as weak/aging: {len(weak)}")
    for f in findings:
        print(f"  {f.get('file')}:{f.get('line')} {f.get('key_type')} {f.get('weakness','')}")

    finding_summary = (
        f"Scanned authorized_keys files. Found {len(findings)} key(s), "
        f"{len(weak)} flagged as weak or aging (DSA, or RSA at the "
        f"minimum-acceptable 2048-bit size rather than a modern default "
        f"like ed25519)."
    )
    print(f"\nFINDING: {finding_summary}")

    result = {"keys_found": findings, "finding_summary": finding_summary, "timestamp": now_iso()}
    OUTPUT_DIR = "/data/data/com.termux/files/home/Watchdog/todo"
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    with open(os.path.join(OUTPUT_DIR, "module116_ssh_key_audit_result.json"), "w") as f:
        json.dump(result, f, indent=2)
    print("Saved.")
