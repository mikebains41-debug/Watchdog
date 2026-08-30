"""
run_batch15.py — runs all 15 new local security modules (114-128) in
sequence, each with a per-module timeout so nothing can hang the
batch, then prints one clean summary.

Run this from /data/data/com.termux/files/home/Watchdog after all 15
module1XX.py files have been copied into that directory.
"""
import subprocess
import time
import os

MODULE_IDS = list(range(114, 129))  # 114 through 128
PER_MODULE_TIMEOUT_S = 60

def run_all():
    results = []
    print(f"Running {len(MODULE_IDS)} modules, {PER_MODULE_TIMEOUT_S}s timeout each...\n")

    for i in MODULE_IDS:
        path = f"module{i}.py"
        if not os.path.isfile(path):
            print(f"module{i}: SKIPPED (file not found — did you copy it from Downloads?)")
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
            print(f"TIMEOUT after {PER_MODULE_TIMEOUT_S}s")
            results.append((i, "TIMEOUT", PER_MODULE_TIMEOUT_S))
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
    print(f"Skipped (file not found): {len(skipped)}")

    if failed:
        print(f"\nModules needing attention:")
        for i, status, elapsed in failed:
            print(f"  module{i}: {status}")
    if skipped:
        print(f"\nModules never downloaded/copied:")
        for i, status, elapsed in skipped:
            print(f"  module{i}")

    return results


if __name__ == "__main__":
    run_all()
