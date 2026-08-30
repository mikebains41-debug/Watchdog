"""
verify_patched_daemons.py — runs the 11 just-patched daemon modules
with a short timeout to confirm the break patch worked across all of
them, not just module55.
"""
import subprocess
import time

MODULE_IDS = [43, 44, 47, 48, 49, 55, 56, 57, 58, 59, 60]
TIMEOUT_S = 20

results = []
print(f"Verifying {len(MODULE_IDS)} patched modules, {TIMEOUT_S}s timeout each...\n")

for i in MODULE_IDS:
    path = f"modules/module{i}.py"
    print(f"module{i}: running...", end=" ", flush=True)
    start = time.time()
    try:
        proc = subprocess.run(["python3", path], capture_output=True,
                                text=True, timeout=TIMEOUT_S)
        elapsed = round(time.time() - start, 1)
        if proc.returncode == 0:
            print(f"OK ({elapsed}s)")
            results.append((i, "OK"))
        else:
            print(f"FAILED exit={proc.returncode} ({elapsed}s)")
            if proc.stderr.strip():
                print(f"    stderr: ...{proc.stderr.strip()[-200:]}")
            results.append((i, f"FAILED exit={proc.returncode}"))
    except subprocess.TimeoutExpired:
        print(f"STILL TIMES OUT after {TIMEOUT_S}s")
        results.append((i, "TIMEOUT"))
    except Exception as e:
        print(f"ERROR: {type(e).__name__}: {e}")
        results.append((i, f"ERROR: {type(e).__name__}"))

ok = [r for r in results if r[1] == "OK"]
print(f"\n{'='*50}")
print(f"OK: {len(ok)}/{len(MODULE_IDS)}")
if len(ok) < len(MODULE_IDS):
    print("Still needing attention:")
    for i, status in results:
        if status != "OK":
            print(f"  module{i}: {status}")
print(f"{'='*50}")
