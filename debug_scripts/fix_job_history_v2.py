"""
Replaces the ENTIRE get_job_history function body with a known-correct
version, rather than patching lines in place (which broke last time).
Finds the function by its 'def get_job_history' line and the next
top-level 'def ' line, and swaps everything between them.
"""
TARGET = "quantum_providers/openquantum_provider.py"

with open(TARGET) as f:
    lines = f.readlines()

start_idx = None
end_idx = None

for i, line in enumerate(lines):
    if "def get_job_history" in line:
        start_idx = i
    elif start_idx is not None and end_idx is None:
        # Look for the next top-level method def (4-space indent + def)
        if line.startswith("    def ") and "get_job_history" not in line:
            end_idx = i
            break

if start_idx is None:
    print("ERROR: could not find get_job_history")
    exit(1)
if end_idx is None:
    print("ERROR: could not find end of get_job_history")
    exit(1)

new_function = '''    def get_job_history(self, limit: int = 200) -> "List[JobRecord]":
        """
        Real implementation against list_jobs(). SDK default limit is 20;
        caller-specified limit is passed through directly.
        """
        try:
            result = self._scheduler.list_jobs(limit=limit)
            jobs = getattr(result, "jobs", []) or []

            records = []
            for j in jobs:
                backend = (getattr(j, "backend_class_id", None)
                           or getattr(j, "backend", None)
                           or getattr(j, "device_id", None)
                           or "")
                records.append(JobRecord(
                    job_id=getattr(j, "id", None) or "",
                    device_id=backend,
                    shots=getattr(j, "shots", None) or 0,
                    circuit_count=getattr(j, "circuit_count", None) or 0,
                    status=getattr(j, "status", None) or "unknown",
                    created_at=(getattr(j, "created_at", None)
                                or getattr(j, "submitted_at", None)),
                    queue_seconds=getattr(j, "queue_seconds", None),
                    exec_seconds=getattr(j, "exec_seconds", None),
                ))
            return records
        except Exception as e:
            print(f"[OpenQuantum] get_job_history failed: {e}")
            return []

'''

new_lines = lines[:start_idx] + [new_function] + lines[end_idx:]

with open(TARGET, "w") as f:
    f.writelines(new_lines)

print(f"Replaced lines {start_idx+1} to {end_idx} with clean function")
