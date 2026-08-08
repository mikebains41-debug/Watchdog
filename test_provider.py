#!/usr/bin/env python3
import os
import sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from quantum_providers import get_provider

provider = get_provider()
print(f"Provider: {provider.provider_name}")
print(f"Devices: {provider.list_devices()}")

# Test calibration
device = os.getenv("QUANTUM_DEVICE", "mock_device")
cal = provider.get_calibration_data(device)
print(f"Calibration keys: {list(cal.keys())[:5]}...")

# Test queue
queue = provider.get_queue_depth(device)
print(f"Queue: {queue.pending_jobs} pending, status={queue.status}")

# Test job history
jobs = provider.get_job_history(limit=5)
print(f"Job history count: {len(jobs)}")

print("\nAll provider methods OK")
