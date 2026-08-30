"""
run_replaced_modules.py — runs all 24 newly-replaced real modules in
sequence, each with a hard per-module timeout, and prints ONE clean
summary at the end instead of scrolling walls of text.

This is separate from run_all.py — it specifically targets the 24
modules that were just swapped from stubs to their real todo/ versions,
so you can verify the batch works before relying on run_all.py to pick
them up correctly.
"""
import subprocess
import time
import os

MODULE_IDS = [32, 33, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47,
              48, 49, 50, 55, 56, 57, 58, 59, 60]
PER_MODULE_TIMEOUT_S = 60
MODULES_DIR = "modules"

def run_all():
    results = []
    print(f"Running {len(MODULE_IDS)} modules, {PER_MODULE_TIMEOUT_S}s timeout each...\n")

    for i in MODULE_IDS:
        path = os.path.join(MODULES_DIR, f"module{i}.py")
        if not os.path.isfile(path):
            print(f"module{i}: SKIPPED (file not found)")
            results.append((i, "SKIPPED", None))
            continue

        print(f"module{i}: running...", end=" ", flush=True)
        start = time.time()
        try:
            proc = subprocess.run(
                ["python3", path],
                capture_output=True, text=True,
                timeout=PER_MODULE_TIMEOUT_S
            )
            elapsed = round(time.time() - start, 1)
            if proc.returncode == 0:
                print(f"OK ({elapsed}s)")
                results.append((i, "OK", elapsed))
            else:
                print(f"FAILED exit={proc.returncode} ({elapsed}s)")
                if proc.stderr.strip():
                    print(f"    stderr (last 300 chars): ...{proc.stderr.strip()[-300:]}")
                results.append((i, f"FAILED exit={proc.returncode}", elapsed))
        except subprocess.TimeoutExpired:
            elapsed = PER_MODULE_TIMEOUT_S
            print(f"TIMEOUT after {elapsed}s")
            results.append((i, "TIMEOUT", elapsed))
        except Exception as e:
            print(f"ERROR: {type(e).__name__}: {e}")
            results.append((i, f"ERROR: {type(e).__name__}", None))

    print(f"\n{'='*60}")
    print("SUMMARY")
    print(f"{'='*60}")
    ok = [r for r in results if r[1] == "OK"]
    failed = [r for r in results if r[1] not in ("OK", "SKIPPED")]
    skipped = [r for r in results if r[1] == "SKIPPED"]

    print(f"OK: {len(ok)}/{len(MODULE_IDS)}")
    print(f"Failed/Timeout: {len(failed)}")
    print(f"Skipped: {len(skipped)}")

    if failed:
        print(f"\nModules needing attention:")
        for i, status, elapsed in failed:
            print(f"  module{i}: {status}")

    return results


if __name__ == "__main__":
    run_all()
