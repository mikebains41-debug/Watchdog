"""
Diagnoses exactly why get_calibration_data() returns {} —
real absence of data vs a bug in the fix. Run in qiskit-env.
"""
import sys
sys.path.insert(0, ".")
from quantum_providers import get_provider

provider = get_provider()
device_id = "iqm:garnet"

print(f"Provider: {provider.provider_name}")
print(f"Testing device: {device_id}")
print()

# Step 1: list jobs directly
print("--- Step 1: list_jobs(limit=50) ---")
try:
    result = provider._scheduler.list_jobs(limit=50)
    jobs = getattr(result, "jobs", []) or []
    print(f"Jobs returned: {len(jobs)}")
    for j in jobs[:10]:
        backend = (getattr(j, "backend_class_id", None)
                   or getattr(j, "backend", None)
                   or getattr(j, "device_id", None))
        print(f"  id={getattr(j,'id',None)}  status={getattr(j,'status',None)}  "
              f"backend_field_value={backend!r}")
except Exception as e:
    print(f"list_jobs FAILED: {e}")
print()

# Step 2: find a job matching our device_id
print(f"--- Step 2: matching against device_id={device_id!r} ---")
matching_job = None
for j in jobs:
    backend = (getattr(j, "backend_class_id", None)
               or getattr(j, "backend", None)
               or getattr(j, "device_id", None))
    if backend == device_id:
        matching_job = j
        break
if matching_job:
    print(f"MATCH FOUND: job id={matching_job.id}")
else:
    print("NO MATCH — this is why get_calibration_data returns {}")
    print("The backend field name/value on JobList objects doesn't match "
          "the device_id string used elsewhere. Printing all distinct "
          "backend field values seen:")
    seen = set()
    for j in jobs:
        b = (getattr(j, "backend_class_id", None)
             or getattr(j, "backend", None)
             or getattr(j, "device_id", None))
        seen.add(repr(b))
    print(f"  Distinct values: {seen}")
print()

# Step 3: if we found a job, check calibration_data_url
if matching_job:
    print("--- Step 3: get_job(matching_job.id) ---")
    full_job = provider._scheduler.get_job(matching_job.id)
    cal_url = getattr(full_job, "calibration_data_url", None)
    print(f"calibration_data_url = {cal_url!r}")
    if cal_url:
        print()
        print("--- Step 4: download_job_calibration ---")
        try:
            raw = provider._scheduler.download_job_calibration(full_job)
            print(f"Raw calibration payload: {raw}")
        except Exception as e:
            print(f"download_job_calibration FAILED: {e}")
    else:
        print("This job has no calibration_data_url — real absence of data,")
        print("not a bug. The API only attaches calibration when reported,")
        print("and this job simply doesn't have any.")
