"""Module 127 — Memory/Swap Exposure Check
Checks whether swap is encrypted. A finding means secrets that were
only ever meant to live in RAM could be recoverable from disk."""
import subprocess, json, datetime, os

def now_iso(): return datetime.datetime.now(datetime.timezone.utc).isoformat()

def check_swap():
    try:
        with open("/proc/swaps") as f:
            content = f.read()
        return content
    except Exception as e:
        return f"could not read /proc/swaps: {type(e).__name__}: {e}"

def check_crypttab():
    try:
        with open("/etc/crypttab") as f:
            return f.read()
    except FileNotFoundError:
        return None
    except Exception as e:
        return f"error: {type(e).__name__}: {e}"

if __name__ == "__main__":
    print("--- Memory/Swap Exposure Check ---\n")
    swaps = check_swap()
    print("Active swap devices:")
    print(swaps)

    crypttab = check_crypttab()
    print("\n/etc/crypttab:")
    print(crypttab if crypttab else "(not present)")

    has_swap = "Filename" in swaps and len(swaps.strip().splitlines()) > 1
    swap_in_crypttab = crypttab and "swap" in crypttab.lower() if crypttab else False

    finding_summary = (
        f"Active swap present: {has_swap}. "
        + (f"Swap entry found in /etc/crypttab (suggests encrypted swap "
           f"is configured): {swap_in_crypttab}. "
           if has_swap else "No active swap device found on this system — "
           "this specific exposure vector doesn't apply here. ")
        + ("If swap is active and NOT encrypted, any secret that ever "
           "existed only in RAM (a decrypted key, a password held "
           "briefly in memory) could be recoverable by reading the raw "
           "swap partition." if has_swap else "")
    )
    print(f"\nFINDING: {finding_summary}")

    result = {"swap_status": swaps, "crypttab": crypttab, "has_active_swap": has_swap,
               "swap_in_crypttab": swap_in_crypttab, "finding_summary": finding_summary,
               "timestamp": now_iso()}
    OUTPUT_DIR = "/data/data/com.termux/files/home/Watchdog/todo"
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    with open(os.path.join(OUTPUT_DIR, "module127_swap_exposure_result.json"), "w") as f:
        json.dump(result, f, indent=2)
    print("Saved.")
