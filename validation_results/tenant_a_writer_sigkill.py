#!/usr/bin/env python3
# Author: Manmohan (Mike) Bains -- Watchdog AIDR
# Project: GPU Optimizer
"""
Cross-Tenant PoC - Tenant A (Writer, SIGKILL variant)
Writes the same marker, then sleeps to be externally SIGKILLed
rather than exiting gracefully.
"""
import torch, time

MARKER = "NELSON_VICENTE_CROSS_TENANT_MARKER_7F3A9C2E8B1D"
print(f"MARKER={MARKER}", flush=True)

marker_bytes = (MARKER * 4).encode("utf-8")[:64]
n_repeats = 200_000_000 // 64
t = torch.frombuffer(bytearray(marker_bytes * n_repeats), dtype=torch.uint8).clone().cuda()
torch.cuda.synchronize()
print("TENANT_A_READY", flush=True)
time.sleep(600)
