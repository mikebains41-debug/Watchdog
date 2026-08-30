#!/usr/bin/env python3
# Author: Manmohan (Mike) Bains
# Project: GPU Optimizer
"""
Cross-Tenant PoC - Tenant A (Writer)
Writes a unique, high-entropy marker into a large VRAM buffer, then
exits. Run as a genuinely separate process from Tenant B.
"""
import torch, sys

MARKER = "NELSON_VICENTE_CROSS_TENANT_MARKER_7F3A9C2E8B1D"
print(f"MARKER={MARKER}", flush=True)

marker_bytes = (MARKER * 4).encode("utf-8")[:64]
n_repeats = 200_000_000 // 64
t = torch.frombuffer(bytearray(marker_bytes * n_repeats), dtype=torch.uint8).clone().cuda()
torch.cuda.synchronize()
print(f"Tenant A: wrote {t.numel()} bytes with marker pattern, exiting", flush=True)
sys.exit(0)
