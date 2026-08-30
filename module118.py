"""Module 118 — Git History Secret Scan
Unlike module102 (current files only), scans FULL commit history via
git log -p. A finding means a secret was "deleted" but is still
permanently recoverable from history."""
import subprocess, json, datetime, os, re

def now_iso(): return datetime.datetime.now(datetime.timezone.utc).isoformat()

PATTERNS = {
    "generic_secret_assignment": re.compile(
        r'(?:secret|SECRET|token|TOKEN|password|PASSWORD)["\']?\s*[:=]\s*["\']([A-Za-z0-9_\-\.]{16,})["\']'),
    "aws_access_key_id": re.compile(r'\b((?:AKIA|ASIA)[A-Z0-9]{16})\b'),
}

def redact(value):
    if len(value) <= 8: return "*" * len(value)
    return f"{value[:4]}...{value[-2:]} ({len(value)} chars)"

def scan_git_history(repo_dir):
    if not os.path.isdir(os.path.join(repo_dir, ".git")):
        return None, "not a git repository"
    try:
        out = subprocess.run(
            ["git", "-C", repo_dir, "log", "-p", "--all"],
            capture_output=True, text=True, timeout=60
        )
    except Exception as e:
        return None, f"{type(e).__name__}: {e}"

    findings = []
    for lineno, line in enumerate(out.stdout.splitlines(), 1):
        if not line.startswith("+"):
            continue
        for pattern_name, pattern in PATTERNS.items():
            for m in pattern.finditer(line):
                findings.append({"line_in_diff": lineno, "pattern": pattern_name,
                                   "redacted_value": redact(m.group(1))})
    return findings, None

if __name__ == "__main__":
    print("--- Git History Secret Scan ---\n")
    REPO_DIR = "/data/data/com.termux/files/home/Watchdog"
    findings, error = scan_git_history(REPO_DIR)

    if error:
        print(f"Could not scan: {error}")
        findings = []
    else:
        print(f"Potential secrets found across full git history: {len(findings)}")
        for f in findings[:15]:
            print(f"  [{f['pattern']}] {f['redacted_value']}")

    finding_summary = (
        f"Scanned full commit history (git log -p --all) of {REPO_DIR}, "
        f"not just current files. Found {len(findings)} potential secret "
        f"pattern(s) in historical diffs. Secrets removed from current "
        f"files but present in past commits remain permanently "
        f"recoverable by anyone with repo access — this is the gap "
        f"module102's current-files-only scan cannot see."
    )
    print(f"\nFINDING: {finding_summary}")

    result = {"repo_scanned": REPO_DIR, "error": error, "findings": findings,
               "finding_summary": finding_summary, "timestamp": now_iso()}
    OUTPUT_DIR = "/data/data/com.termux/files/home/Watchdog/todo"
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    with open(os.path.join(OUTPUT_DIR, "module118_git_history_scan_result.json"), "w") as f:
        json.dump(result, f, indent=2)
    print("Saved. (all values redacted)")
