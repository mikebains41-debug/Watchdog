"""Module 125 v2 — Package Integrity Drift Check (torture-tested)

REPAIR NOTE: v1 reported a raw count of 9,095 "drift" entries from
dpkg -V with no breakdown — that number alone is meaningless, since
dpkg -V's status codes mix trivial metadata drift (permissions,
ownership — extremely common and expected, especially in
Termux/proot where UID mapping is nonstandard) with genuine content
hash mismatches (a real integrity concern).

v2 does two things v1 didn't:
  1. Installs and runs debsums — the tool that actually re-computes
     MD5 hashes of installed files and compares against what apt
     originally shipped. This is real content verification, not
     just metadata.
  2. Parses dpkg -V's status codes properly: the 3rd character of
     each status code is '5' specifically when the MD5 content hash
     doesn't match. Everything else (M=mode, U=user, G=group,
     T=mtime) is metadata-only and expected to drift constantly in
     a proot environment.

This separates "real concern" from "noise" instead of reporting one
scary-looking undifferentiated number.
"""
import subprocess, json, datetime, os

def now_iso(): return datetime.datetime.now(datetime.timezone.utc).isoformat()

def try_install_debsums():
    try:
        check = subprocess.run(["which", "debsums"], capture_output=True, text=True, timeout=10)
        if check.returncode == 0:
            return True, "already installed"
        install = subprocess.run(
            ["apt-get", "install", "-y", "debsums"],
            capture_output=True, text=True, timeout=120
        )
        if install.returncode == 0:
            return True, "installed successfully"
        return False, f"install failed: {install.stderr.strip()[-300:]}"
    except Exception as e:
        return False, f"{type(e).__name__}: {e}"

def run_debsums():
    """Real content-hash verification — the actual torture test."""
    try:
        out = subprocess.run(
            ["debsums", "-c"],  # -c: only show files that fail
            capture_output=True, text=True, timeout=300
        )
        failed_files = [l.strip() for l in out.stdout.splitlines() if l.strip()]
        return failed_files, None
    except FileNotFoundError:
        return None, "debsums not available"
    except subprocess.TimeoutExpired:
        return None, "debsums timed out after 300s (large file count — genuinely thorough, just slow)"
    except Exception as e:
        return None, f"{type(e).__name__}: {e}"

def parse_dpkg_verify():
    """Parse dpkg -V status codes: 3rd char == '5' means real MD5
    content mismatch. Everything else is metadata-only drift."""
    try:
        out = subprocess.run(["dpkg", "-V"], capture_output=True, text=True, timeout=180)
    except Exception as e:
        return None, f"{type(e).__name__}: {e}"

    content_mismatches = []
    metadata_only = []
    binary_paths = ("/bin/", "/sbin/", "/usr/bin/", "/usr/sbin/", "/lib/", "/usr/lib/")

    for line in out.stdout.splitlines():
        if not line.strip() or len(line) < 4:
            continue
        code = line[:9]
        path = line[10:].strip() if len(line) > 10 else line.strip()
        is_content_mismatch = len(code) > 2 and code[2] == "5"
        entry = {"code": code, "path": path}
        if is_content_mismatch:
            entry["in_binary_path"] = path.startswith(binary_paths)
            content_mismatches.append(entry)
        else:
            metadata_only.append(entry)

    return {"content_mismatches": content_mismatches, "metadata_only": metadata_only}, None

if __name__ == "__main__":
    print("--- Package Integrity Drift Check v2 (torture-tested) ---\n")

    print("Step 1: Installing debsums for real content-hash verification...")
    installed, install_msg = try_install_debsums()
    print(f"  {install_msg}\n")

    debsums_failed = None
    debsums_error = None
    if installed:
        print("Step 2: Running debsums (real MD5 content verification, may take a while)...")
        debsums_failed, debsums_error = run_debsums()
        if debsums_error:
            print(f"  {debsums_error}")
        else:
            print(f"  debsums found {len(debsums_failed)} file(s) with REAL content hash mismatches")
            for f in debsums_failed[:20]:
                print(f"    {f}")
            if len(debsums_failed) > 20:
                print(f"    ... and {len(debsums_failed)-20} more")
    else:
        print("Step 2: SKIPPED (debsums unavailable)\n")

    print("\nStep 3: Parsing dpkg -V for comparison (breaks down the v1 raw count)...")
    dpkg_parsed, dpkg_error = parse_dpkg_verify()
    if dpkg_error:
        print(f"  {dpkg_error}")
        content_mismatches, metadata_only = [], []
    else:
        content_mismatches = dpkg_parsed["content_mismatches"]
        metadata_only = dpkg_parsed["metadata_only"]
        in_binary = [f for f in content_mismatches if f.get("in_binary_path")]
        print(f"  Total dpkg -V entries: {len(content_mismatches) + len(metadata_only)}")
        print(f"  Metadata-only drift (permissions/owner/mtime — expected in proot, low concern): {len(metadata_only)}")
        print(f"  REAL content hash mismatches (dpkg's own MD5 check): {len(content_mismatches)}")
        print(f"  Of those, in binary/executable paths (highest concern): {len(in_binary)}")
        for f in content_mismatches[:10]:
            flag = " [BINARY PATH]" if f.get("in_binary_path") else ""
            print(f"    {f['path']}{flag}")

    finding_summary = (
        f"v1 reported 9,095 undifferentiated 'drift' entries — that number alone was "
        f"noise, not signal. v2 breaks it down: dpkg -V shows "
        f"{len(metadata_only)} metadata-only changes (permissions/ownership — expected "
        f"and common in a proot/Termux environment, NOT a real concern) versus "
        f"{len(content_mismatches)} genuine MD5 content hash mismatches "
        f"({len([f for f in content_mismatches if f.get('in_binary_path')])} of those in "
        f"binary/executable paths, the highest-priority category). "
        + (f"debsums (a stronger, independent tool) confirms {len(debsums_failed)} file(s) "
           f"with real content drift." if debsums_failed is not None else
           f"debsums could not be run for independent confirmation ({debsums_error or install_msg}).")
    )
    print(f"\nFINDING: {finding_summary}")

    result = {
        "debsums_installed": installed, "debsums_install_message": install_msg,
        "debsums_failed_files": debsums_failed, "debsums_error": debsums_error,
        "dpkg_content_mismatches": content_mismatches,
        "dpkg_metadata_only_count": len(metadata_only),
        "finding_summary": finding_summary, "timestamp": now_iso(),
    }
    OUTPUT_DIR = "/data/data/com.termux/files/home/Watchdog/todo"
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    with open(os.path.join(OUTPUT_DIR, "module125_v2_package_drift_result.json"), "w") as f:
        json.dump(result, f, indent=2)
    print("\nSaved.")
