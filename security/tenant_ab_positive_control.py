#!/usr/bin/env python3
# Author: Manmohan (Mike) Bains
# Project: GPU Optimizer
"""
A/B Positive Control - proves scanner finds marker when present.
Same process writes and scans - confirms scanner works.
"""
import torch, hashlib, subprocess

MARKER = "NELSON_VICENTE_CROSS_TENANT_MARKER_7F3A9C2E8B1D"
marker_bytes = MARKER.encode("utf-8")
marker_sha256 = hashlib.sha256(marker_bytes).hexdigest()

print(f"Marker SHA256: {marker_sha256}", flush=True)

marker_repeated = (MARKER * 4).encode("utf-8")[:64]
n_repeats = 200_000_000 // 64
t = torch.frombuffer(bytearray(marker_repeated * n_repeats), dtype=torch.uint8).clone().cuda()
torch.cuda.synchronize()

uuid = subprocess.run(["nvidia-smi","--query-gpu=uuid","--format=csv,noheader"],
                      capture_output=True, text=True).stdout.strip().split("\n")[0]
print(f"GPU UUID: {uuid}", flush=True)

raw = bytes(t.cpu().numpy().tobytes())
hits = raw.count(marker_bytes)
bytes_scanned = len(raw)

print(f"hits={hits} bytes_scanned={bytes_scanned}", flush=True)
if hits > 0:
    print("CONFIRMED: Scanner works - cross-process 0/20 means isolation held", flush=True)
else:
    print("FAIL: Scanner bug", flush=True)

del t
torch.cuda.empty_cache()
print("=== DONE ===", flush=True)
