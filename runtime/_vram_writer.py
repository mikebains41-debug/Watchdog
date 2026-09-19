#!/usr/bin/env python3
# Author: Manmohan (Mike) Bains -- Watchdog
"""
_vram_writer.py -- Process A of the self-owned two-process residual test
*** WATCHDOG *** (invoked by runtime/pod_runner.py, not run directly)

POD_VALIDATION_PLAN Tier 1 #1 requires the pattern to be written by a process
that then EXITS, so the residual genuinely crosses a process boundary. Doing
it in-process would prove nothing -- the memory would still be ours.

This is the self-owned two-process read: both processes are ours, on hardware
we rented. It is NOT an attack on another tenant and must never be described
as one.

Writes an 0xA5 pattern into `mb` megabytes of VRAM, syncs, reports what it
did, and exits WITHOUT freeing -- exactly the condition a crashed or killed
tenant process leaves behind.

argv: <gpu_index> <megabytes> <pattern_byte>
"""
import json
import sys


def main():
    if len(sys.argv) != 4:
        print(json.dumps({"ok": False, "error": "usage: _vram_writer.py <gpu> <mb> <pattern_byte>"}))
        return 2
    try:
        gpu = int(sys.argv[1]); mb = int(sys.argv[2]); pat = int(sys.argv[3])
    except ValueError as e:
        print(json.dumps({"ok": False, "error": f"bad args: {e}"}))
        return 2

    try:
        import torch
    except Exception as e:
        print(json.dumps({"ok": False, "error": f"torch unavailable: {type(e).__name__}: {e}"}))
        return 3

    if not torch.cuda.is_available():
        print(json.dumps({"ok": False, "error": "torch.cuda.is_available() is False"}))
        return 3

    try:
        dev = torch.device(f"cuda:{gpu}")
        elems = mb * 1024 * 1024
        buf = torch.full((elems,), pat, dtype=torch.uint8, device=dev)
        torch.cuda.synchronize(dev)
        checksum = int(buf[:1024].sum().item())
        free_b, total_b = torch.cuda.mem_get_info(dev)
        print(json.dumps({
            "ok": True, "gpu": gpu, "mb_written": mb, "pattern_byte": pat,
            "first_1k_checksum": checksum,
            "expected_first_1k_checksum": pat * 1024,
            "vram_free_mb_after_write": round(free_b / 1024 / 1024, 1),
            "vram_total_mb": round(total_b / 1024 / 1024, 1),
            "note": "exiting WITHOUT freeing -- leaves the residual a killed tenant would",
        }))
        # deliberately no free / no empty_cache: os.exit leaves the driver to clean up
        return 0
    except Exception as e:
        print(json.dumps({"ok": False, "error": f"{type(e).__name__}: {e}"}))
        return 4


if __name__ == "__main__":
    sys.exit(main())
