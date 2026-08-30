"""Module 121 — Watchdog Self-Tamper-Detection
Hashes Watchdog's own core scripts. First run establishes a baseline;
subsequent runs flag any file that changed. A finding means someone
modified the security tool itself — using Watchdog to protect Watchdog."""
import json, datetime, os, hashlib, glob

def now_iso(): return datetime.datetime.now(datetime.timezone.utc).isoformat()

WATCHDOG_DIR = "/data/data/com.termux/files/home/Watchdog"
BASELINE_FILE = os.path.join(WATCHDOG_DIR, "todo", "module121_baseline.json")

def hash_file(path):
    h = hashlib.sha256()
    try:
        with open(path, "rb") as f:
            h.update(f.read())
        return h.hexdigest()
    except Exception:
        return None

def get_core_scripts():
    patterns = [os.path.join(WATCHDOG_DIR, "module9*.py"),
                os.path.join(WATCHDOG_DIR, "module1[0-2]*.py"),
                os.path.join(WATCHDOG_DIR, "modules", "module*.py")]
    files = []
    for p in patterns:
        files.extend(glob.glob(p))
    return sorted(set(files))

if __name__ == "__main__":
    print("--- Watchdog Self-Tamper-Detection ---\n")
    scripts = get_core_scripts()
    current_hashes = {path: hash_file(path) for path in scripts}
    print(f"Core scripts checked: {len(scripts)}")

    if os.path.isfile(BASELINE_FILE):
        with open(BASELINE_FILE) as f:
            baseline = json.load(f)
        changed = []
        new_files = []
        for path, h in current_hashes.items():
            if path not in baseline:
                new_files.append(path)
            elif baseline[path] != h:
                changed.append(path)
        missing = [p for p in baseline if p not in current_hashes]

        print(f"Changed since baseline: {len(changed)}")
        print(f"New files since baseline: {len(new_files)}")
        print(f"Missing since baseline: {len(missing)}")
        for c in changed:
            print(f"  CHANGED: {c}")
        for m in missing:
            print(f"  MISSING: {m}")

        finding_summary = (
            f"Compared {len(scripts)} core script hashes against prior "
            f"baseline. {len(changed)} changed, {len(new_files)} new, "
            f"{len(missing)} missing since last baseline. Any CHANGED or "
            f"MISSING entry on a script you did not intentionally edit "
            f"is a real tamper signal on Watchdog's own codebase."
        )
    else:
        print("No prior baseline found — establishing one now.")
        finding_summary = (
            f"No prior baseline existed. Established a new baseline "
            f"hashing {len(scripts)} core scripts. Re-run this module "
            f"later to detect any unauthorized changes since this point."
        )
        changed, new_files, missing = [], [], []

    with open(BASELINE_FILE, "w") as f:
        json.dump(current_hashes, f, indent=2)

    print(f"\nFINDING: {finding_summary}")

    result = {"scripts_checked": len(scripts), "changed": changed, "new_files": new_files,
               "missing": missing, "finding_summary": finding_summary, "timestamp": now_iso()}
    OUTPUT_DIR = "/data/data/com.termux/files/home/Watchdog/todo"
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    with open(os.path.join(OUTPUT_DIR, "module121_self_tamper_result.json"), "w") as f:
        json.dump(result, f, indent=2)
    print("Saved. Baseline updated for next run.")
