"""Check JobRecord's real fields, and debug why calibration still returns {}."""
import inspect

print("=== JobRecord real fields ===")
try:
    from quantum_providers.base import JobRecord
    if hasattr(JobRecord, "__dataclass_fields__"):
        for name, f in JobRecord.__dataclass_fields__.items():
            print(f"  {name}: {f.type}")
    elif hasattr(JobRecord, "model_fields"):
        for name, f in JobRecord.model_fields.items():
            print(f"  {name}: {f.annotation}")
    else:
        sig = inspect.signature(JobRecord.__init__)
        print(f"  __init__{sig}")
except Exception as e:
    print(f"  Error: {e}")

print()
print("=== Debug calibration match ===")
from quantum_providers import get_provider
provider = get_provider()
device_id = "iqm:garnet"

bc = provider._scheduler.get_backend_class(device_id)
resolved_uuid = bc.get("id") if isinstance(bc, dict) else None
print(f"resolved_uuid = {resolved_uuid}")

result = provider._scheduler.list_jobs(limit=50)
jobs = getattr(result, "jobs", []) or []
for j in jobs:
    backend = (getattr(j, "backend_class_id", None)
               or getattr(j, "backend", None)
               or getattr(j, "device_id", None))
    match = (backend == device_id) or (resolved_uuid and backend == resolved_uuid)
    print(f"  job={j.id}  backend_field={backend!r}  MATCH={match}")

    if match:
        full_job = provider._scheduler.get_job(j.id)
        cal_url = getattr(full_job, "calibration_data_url", None)
        print(f"    calibration_data_url = {cal_url!r}")
