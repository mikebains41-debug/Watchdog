"""
Fixes the UUID mismatch: job.backend_class_id is a UUID, device_id like
'iqm:garnet' is a short_code. get_backend_class(device_id)['id'] resolves
short_code -> UUID. Patches get_calibration_data and get_queue_depth to
resolve first, then match.
"""
import re

TARGET = "quantum_providers/openquantum_provider.py"

with open(TARGET) as f:
    src = f.read()

old_calib_match = '''        result = self._scheduler.list_jobs(limit=50)
        jobs = getattr(result, "jobs", []) or []

        matching_job = None
        for j in jobs:
            backend = (getattr(j, "backend_class_id", None)
                       or getattr(j, "backend", None)
                       or getattr(j, "device_id", None))
            if backend == device_id:
                matching_job = j
                break'''

new_calib_match = '''        try:
            backend_class = self._scheduler.get_backend_class(device_id)
            resolved_uuid = backend_class.get("id") if isinstance(backend_class, dict) else None
        except Exception:
            resolved_uuid = None

        result = self._scheduler.list_jobs(limit=50)
        jobs = getattr(result, "jobs", []) or []

        matching_job = None
        for j in jobs:
            backend = (getattr(j, "backend_class_id", None)
                       or getattr(j, "backend", None)
                       or getattr(j, "device_id", None))
            if backend == device_id or (resolved_uuid and backend == resolved_uuid):
                matching_job = j
                break'''

if old_calib_match in src:
    src = src.replace(old_calib_match, new_calib_match)
    print("Patched get_calibration_data matching logic")
else:
    print("WARNING: get_calibration_data pattern not found — check manually")

old_queue_match = '''        result = self._scheduler.list_jobs(limit=200, status="Queued")
        jobs = getattr(result, "jobs", []) or []

        matching = [j for j in jobs if (
            getattr(j, "backend_class_id", None) == device_id or
            getattr(j, "backend", None) == device_id or
            getattr(j, "device_id", None) == device_id
        )]'''

new_queue_match = '''        try:
            backend_class = self._scheduler.get_backend_class(device_id)
            resolved_uuid = backend_class.get("id") if isinstance(backend_class, dict) else None
        except Exception:
            resolved_uuid = None

        result = self._scheduler.list_jobs(limit=200, status="Queued")
        jobs = getattr(result, "jobs", []) or []

        matching = [j for j in jobs if (
            getattr(j, "backend_class_id", None) == device_id or
            getattr(j, "backend", None) == device_id or
            getattr(j, "device_id", None) == device_id or
            (resolved_uuid and (
                getattr(j, "backend_class_id", None) == resolved_uuid or
                getattr(j, "backend", None) == resolved_uuid or
                getattr(j, "device_id", None) == resolved_uuid
            ))
        )]'''

if old_queue_match in src:
    src = src.replace(old_queue_match, new_queue_match)
    print("Patched get_queue_depth matching logic")
else:
    print("WARNING: get_queue_depth pattern not found — check manually")

with open(TARGET, "w") as f:
    f.write(src)

print("Done writing file")
