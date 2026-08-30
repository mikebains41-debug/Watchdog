"""Module 128 — Kernel Module Audit
Lists loaded kernel modules, flags unsigned ones. A finding means
possible deep, hard-to-detect kernel-level compromise."""
import subprocess, json, datetime, os

def now_iso(): return datetime.datetime.now(datetime.timezone.utc).isoformat()

def list_modules():
    try:
        with open("/proc/modules") as f:
            lines = f.read().splitlines()
        return [line.split()[0] for line in lines if line.strip()]
    except Exception as e:
        return None, f"{type(e).__name__}: {e}"

def check_module_signature(module_name):
    try:
        out = subprocess.run(["modinfo", module_name], capture_output=True, text=True, timeout=10)
        if out.returncode != 0:
            return "unknown (modinfo failed)"
        has_sig = "signature" in out.stdout.lower() or "sig_id" in out.stdout.lower()
        return "signed" if has_sig else "no signature info found"
    except Exception:
        return "unknown (check failed)"

if __name__ == "__main__":
    print("--- Kernel Module Audit ---\n")
    modules = list_modules()

    if modules is None or isinstance(modules, tuple):
        print(f"Could not list kernel modules — likely no real kernel access in this "
              f"environment (Termux/proot containers do not expose the host kernel's "
              f"/proc/modules meaningfully).")
        modules = []
        unsigned = []
    else:
        print(f"Loaded kernel modules: {len(modules)}")
        unsigned = []
        for mod in modules[:30]:  # cap to avoid excessive modinfo calls
            sig_status = check_module_signature(mod)
            print(f"  {mod}: {sig_status}")
            if sig_status == "no signature info found":
                unsigned.append(mod)

    finding_summary = (
        f"Checked {len(modules)} loaded kernel module(s) (capped at first 30 for "
        f"signature checks). Found {len(unsigned)} without detectable signature "
        f"info. NOTE: in a Termux/proot environment, this check likely cannot see "
        f"the real host kernel's module list at all — results here should be "
        f"treated as inconclusive unless running with genuine kernel-level access."
    )
    print(f"\nFINDING: {finding_summary}")

    result = {"modules_checked": len(modules), "unsigned_modules": unsigned,
               "finding_summary": finding_summary, "timestamp": now_iso()}
    OUTPUT_DIR = "/data/data/com.termux/files/home/Watchdog/todo"
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    with open(os.path.join(OUTPUT_DIR, "module128_kernel_module_result.json"), "w") as f:
        json.dump(result, f, indent=2)
    print("Saved.")
