"""Module 117 v2 — Process Secret Leak Scan (with context)
v1 found 6 secret-like variables but gave no way to tell if they're
expected (your own exported credentials) vs genuinely concerning
(another process's secrets readable across UID boundaries)."""
import json, datetime, os, re, subprocess

def now_iso(): return datetime.datetime.now(datetime.timezone.utc).isoformat()

SECRET_PATTERNS = re.compile(
    r'(SECRET|TOKEN|PASSWORD|API_KEY|CLIENT_ID|CLIENT_SECRET|PRIVATE_KEY)', re.IGNORECASE)

def redact(value):
    if len(value) <= 8: return "*" * len(value)
    return f"{value[:4]}...{value[-2:]} ({len(value)} chars)"

def get_process_owner(pid):
    try:
        st = os.stat(f"/proc/{pid}")
        return st.st_uid
    except Exception:
        return None

def get_process_name(pid):
    try:
        with open(f"/proc/{pid}/comm") as f:
            return f.read().strip()
    except Exception:
        return None

if __name__ == "__main__":
    print("--- Process Secret Leak Scan v2 (with context) ---\n")
    my_uid = os.getuid()
    print(f"This script's own UID: {my_uid}\n")

    findings = []
    accessible, denied = 0, 0
    for pid_dir in os.listdir("/proc"):
        if not pid_dir.isdigit():
            continue
        try:
            with open(f"/proc/{pid_dir}/environ", "rb") as f:
                raw = f.read()
            accessible += 1
            owner_uid = get_process_owner(pid_dir)
            proc_name = get_process_name(pid_dir)
            for entry in raw.split(b"\x00"):
                try:
                    text = entry.decode("utf-8", errors="ignore")
                except Exception:
                    continue
                if "=" not in text:
                    continue
                key, _, value = text.partition("=")
                if SECRET_PATTERNS.search(key) and value:
                    same_owner = (owner_uid == my_uid)
                    findings.append({
                        "pid": pid_dir, "process_name": proc_name,
                        "owner_uid": owner_uid, "same_owner_as_scanner": same_owner,
                        "var_name": key, "redacted_value": redact(value),
                        "classification": "expected (own process)" if same_owner
                                            else "CROSS-PROCESS — different UID, worth reviewing"
                    })
        except PermissionError:
            denied += 1
        except Exception:
            pass

    own = [f for f in findings if f["same_owner_as_scanner"]]
    cross = [f for f in findings if not f["same_owner_as_scanner"]]

    print(f"Total secret-like vars found: {len(findings)}")
    print(f"  Owned by this scanner's own UID (expected, e.g. your own exported credentials): {len(own)}")
    print(f"  Owned by a DIFFERENT UID (real cross-process exposure concern): {len(cross)}\n")

    for f in findings:
        print(f"  PID {f['pid']} ({f['process_name']}, uid={f['owner_uid']}): "
              f"{f['var_name']} = {f['redacted_value']}  [{f['classification']}]")

    finding_summary = (
        f"v1 found 6 secret-like variables with no context. v2 adds process "
        f"ownership: {len(findings)} total found, {len(own)} belong to this "
        f"scanner's own UID ({my_uid}) — almost certainly your own exported "
        f"OPENQUANTUM_CLIENT_ID/SECRET from this session, expected and not a "
        f"real finding. {len(cross)} belong to a DIFFERENT UID — those are "
        f"the ones that would represent genuine cross-process secret exposure, "
        f"if any exist."
    )
    print(f"\nFINDING: {finding_summary}")

    result = {"my_uid": my_uid, "findings": findings, "own_process_count": len(own),
               "cross_process_count": len(cross), "finding_summary": finding_summary,
               "timestamp": now_iso()}
    OUTPUT_DIR = "/data/data/com.termux/files/home/Watchdog/todo"
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    with open(os.path.join(OUTPUT_DIR, "module117_v2_process_secret_result.json"), "w") as f:
        json.dump(result, f, indent=2)
    print("Saved. (all values redacted)")
