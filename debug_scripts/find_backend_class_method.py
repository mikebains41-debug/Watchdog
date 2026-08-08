"""Find how to resolve 'iqm:garnet' -> its backend_class UUID. Run in qiskit-env."""
from openquantum_sdk.clients import SchedulerClient
import inspect

sig = inspect.signature(SchedulerClient.get_backend_class)
print(f"get_backend_class{sig}")
doc = inspect.getdoc(SchedulerClient.get_backend_class)
print(f"\n{doc}")

print("\n--- Testing live ---")
from quantum_providers import get_provider
provider = get_provider()

try:
    result = provider._scheduler.get_backend_class("iqm:garnet")
    print(f"Result: {result}")
    print(f"Type: {type(result)}")
    if hasattr(result, "__dict__"):
        print(f"Attrs: {vars(result)}")
except Exception as e:
    print(f"FAILED with device_id string: {e}")

    # Try list_devices to see what device_id actually looks like
    print("\n--- Checking list_devices() output ---")
    devices = provider.list_devices()
    print(f"list_devices() returned: {devices}")
