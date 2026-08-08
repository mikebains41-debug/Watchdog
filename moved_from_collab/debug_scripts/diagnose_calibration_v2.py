"""
Diagnostic v2 — calls get_calibration_data() and get_queue_depth() DIRECTLY,
so it tests the real patched method instead of reimplementing the logic.
"""
from quantum_providers import get_provider

provider = get_provider()
device_id = "iqm:garnet"

print(f"Provider: {provider.provider_name}")
print(f"Testing device: {device_id}")
print()

print("--- get_calibration_data(device_id) ---")
cal = provider.get_calibration_data(device_id)
print(f"Result: {cal}")
print()

print("--- get_queue_depth(device_id) ---")
q = provider.get_queue_depth(device_id)
print(f"Result: {q}")
print()

print("--- get_job_history(limit=10) ---")
hist = provider.get_job_history(limit=10)
print(f"Result: {hist}")
print()

print("--- get_job_timing(job_id) for the one known job ---")
timing = provider.get_job_timing("65d67897-faa9-45cf-b0e5-548cde68fbb2")
print(f"Result: {timing}")
