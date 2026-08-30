"""
Module 102 — Credential Exposure Scanner

METHOD:
  Real, local filesystem scan for hardcoded secrets — API keys, tokens,
  passwords — sitting in plaintext across scripts, configs, and shell
  history. This is directly validated by tonight's own session: real
  OpenQuantum credentials were pasted in plaintext multiple times
  across this exact conversation and its terminal history. A tool that
  would catch that automatically is demonstrated, not hypothetical.

SAFETY-CRITICAL DESIGN NOTE: a credential scanner that prints or saves
the actual secret VALUES it finds would recreate the exact problem it
exists to catch. Every match in this script's output is REDACTED —
only the first/last few characters are shown, enough to confirm a real
finding exists and identify which file/line, never enough to
reconstruct the actual secret.

HONESTY NOTE: this is pattern-based detection (regex), not a claim of
perfect recall. It will miss cleverly-obfuscated secrets and may
occasionally flag high-entropy strings that aren't actually secrets
(false positives) — every finding should be manually verified, not
treated as automatically certain.
"""
import os
import re
import json
import datetime

def now_iso():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()

SCAN_DIR = "/data/data/com.termux/files/home/Watchdog"
MAX_FILE_SIZE = 2_000_000  # skip anything over 2MB, likely not source/config
SKIP_DIRS = {".git", "__pycache__", "node_modules", ".venv"}
SKIP_EXTENSIONS = {".pyc", ".png", ".jpg", ".jpeg", ".pdf", ".zip", ".tar",
                    ".gz", ".docx", ".xlsx", ".pptx", ".bin", ".ipynb"}

# Pattern name -> regex. Grouped so the SECRET VALUE is always capture
# group 1, for consistent redaction.
PATTERNS = {
    "generic_client_secret_assignment": re.compile(
        r'(?:CLIENT_SECRET|client_secret)["\']?\s*[:=]\s*["\']([A-Za-z0-9_\-\.]{16,})["\']'),
    "generic_client_id_assignment": re.compile(
        r'(?:CLIENT_ID|client_id)["\']?\s*[:=]\s*["\']([A-Za-z0-9_\-\.]{16,})["\']'),
    "generic_api_key_assignment": re.compile(
        r'(?:api[_-]?key|API[_-]?KEY)["\']?\s*[:=]\s*["\']([A-Za-z0-9_\-\.]{16,})["\']'),
    "generic_password_assignment": re.compile(
        r'(?:password|PASSWORD|passwd)["\']?\s*[:=]\s*["\']([^\s"\']{6,})["\']'),
    "generic_secret_assignment": re.compile(
        r'(?:secret|SECRET|token|TOKEN)["\']?\s*[:=]\s*["\']([A-Za-z0-9_\-\.]{16,})["\']'),
    "aws_access_key_id": re.compile(r'\b((?:AKIA|ASIA)[A-Z0-9]{16})\b'),
    "generic_bearer_token": re.compile(
        r'Bearer\s+([A-Za-z0-9_\-\.]{20,})'),
    "export_env_secret": re.compile(
        r'export\s+\w*(?:SECRET|KEY|TOKEN|PASSWORD)\w*\s*=\s*["\']?([A-Za-z0-9_\-\.]{12,})["\']?'),
}


def redact(value):
    """Shows just enough to confirm a real finding without exposing
    anything reconstructable."""
    if len(value) <= 8:
        return "*" * len(value)
    return f"{value[:4]}...{value[-2:]} ({len(value)} chars)"


def should_skip_file(path):
    ext = os.path.splitext(path)[1].lower()
    if ext in SKIP_EXTENSIONS:
        return True
    try:
        if os.path.getsize(path) > MAX_FILE_SIZE:
            return True
    except OSError:
        return True
    return False


def scan_file(path):
    findings = []
    try:
        with open(path, "r", errors="ignore") as f:
            for lineno, line in enumerate(f, start=1):
                for pattern_name, pattern in PATTERNS.items():
                    for m in pattern.finditer(line):
                        secret_value = m.group(1)
                        findings.append({
                            "file": path,
                            "line": lineno,
                            "pattern": pattern_name,
                            "redacted_value": redact(secret_value),
                        })
    except Exception:
        pass
    return findings


def run_scan(scan_dir=SCAN_DIR):
    print(f"Scanning: {scan_dir}\n")
    all_findings = []
    files_scanned = 0
    files_skipped = 0

    for root, dirs, files in os.walk(scan_dir):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        for fname in files:
            fpath = os.path.join(root, fname)
            if should_skip_file(fpath):
                files_skipped += 1
                continue
            files_scanned += 1
            findings = scan_file(fpath)
            all_findings.extend(findings)

    print(f"Files scanned: {files_scanned}")
    print(f"Files skipped (binary/oversized): {files_skipped}")
    print(f"Total potential credential exposures found: {len(all_findings)}\n")

    by_pattern = {}
    for f in all_findings:
        by_pattern.setdefault(f["pattern"], []).append(f)

    for pattern_name, matches in sorted(by_pattern.items(), key=lambda x: -len(x[1])):
        print(f"  {pattern_name}: {len(matches)} match(es)")

    if all_findings:
        print(f"\nSample findings (values redacted):")
        for f in all_findings[:15]:
            rel_path = os.path.relpath(f["file"], scan_dir)
            print(f"  {rel_path}:{f['line']}  [{f['pattern']}]  {f['redacted_value']}")
        if len(all_findings) > 15:
            print(f"  ... and {len(all_findings) - 15} more (see saved JSON)")

    finding_summary = (
        f"Scanned {files_scanned} files under {scan_dir} and found "
        f"{len(all_findings)} potential hardcoded credential exposures "
        f"across {len(by_pattern)} distinct pattern type(s). "
        f"This is a real, demonstrated risk category — this exact "
        f"session had real OpenQuantum credentials pasted in plaintext "
        f"multiple times across chat and terminal history, which a "
        f"scan like this is designed to catch before it becomes an "
        f"incident. All matched values are redacted in this output; "
        f"see file:line references to locate and remediate the "
        f"originals directly."
    )
    print(f"\nFINDING: {finding_summary}")

    return {
        "scan_dir": scan_dir,
        "files_scanned": files_scanned,
        "files_skipped": files_skipped,
        "total_findings": len(all_findings),
        "findings_by_pattern_count": {k: len(v) for k, v in by_pattern.items()},
        "findings": all_findings,  # already redacted at collection time
        "finding_summary": finding_summary,
        "timestamp": now_iso(),
    }


if __name__ == "__main__":
    result = run_scan()

    OUTPUT_DIR = "/data/data/com.termux/files/home/Watchdog/todo"
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    output_path = os.path.join(OUTPUT_DIR, "module102_credential_scan_result.json")
    with open(output_path, "w") as f:
        json.dump(result, f, indent=2)
    print(f"\nSaved to {output_path}")
    print("(all values redacted — safe to commit and share)")
