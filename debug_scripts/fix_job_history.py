"""
Fixes get_job_history to use JobRecord's REAL required fields:
  job_id: str, device_id: str, shots: int, circuit_count: int, status: str
  (required, non-optional — must have safe defaults, not None)
  created_at, queue_seconds, exec_seconds: optional
"""
TARGET = "quantum_providers/openquantum_provider.py"

with open(TARGET) as f:
    src = f.read()

old = '''        records = []
        for j in jobs:
            records.append(JobRecord(
                job_id=getattr(j, "id", None),
                status=getattr(j, "status", None),
                submitted_at=getattr(j, "submitted_at", None),
                message=getattr(j, "message", None),
            ))
        return records'''

new = '''        records = []
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
                created_at=getattr(j, "created_at", None) or getattr(j, "submitted_at", None),
                queue_seconds=getattr(j, "queue_seconds", None),
                exec_seconds=getattr(j, "exec_seconds", None),
            ))
        return records'''

if old in src:
    src = src.replace(old, new)
    print("Patched get_job_history with real JobRecord fields")
else:
    print("WARNING: exact block not found — trying line-based patch")
    lines = src.split("\n")
    out = []
    in_history = False
    for line in lines:
        if "def get_job_history" in line:
            in_history = True
        elif line.strip().startswith("def ") and in_history and "get_job_history" not in line:
            in_history = False
        if in_history and "job_id=getattr" in line:
            indent = line[:len(line) - len(line.lstrip())]
            out.append(f'{indent}backend = (getattr(j, "backend_class_id", None)\n')
            out.append(f'{indent}           or getattr(j, "backend", None)\n')
            out.append(f'{indent}           or getattr(j, "device_id", None)\n')
            out.append(f'{indent}           or "")\n')
            out.append(f'{indent}job_id=getattr(j, "id", None) or "",\n')
            out.append(f'{indent}device_id=backend,\n')
            out.append(f'{indent}shots=getattr(j, "shots", None) or 0,\n')
            out.append(f'{indent}circuit_count=getattr(j, "circuit_count", None) or 0,\n')
            out.append(f'{indent}status=getattr(j, "status", None) or "unknown",\n')
            out.append(f'{indent}created_at=getattr(j, "created_at", None) or getattr(j, "submitted_at", None),\n')
            out.append(f'{indent}queue_seconds=getattr(j, "queue_seconds", None),\n')
            out.append(f'{indent}exec_seconds=getattr(j, "exec_seconds", None),\n')
            continue
        if in_history and ('status=getattr(j, "status", None),' in line
                            or 'submitted_at=getattr' in line
                            or 'message=getattr' in line):
            continue
        out.append(line + "\n" if not line.endswith("\n") else line)
    src = "".join(out)
    print("Line-based patch applied")

with open(TARGET, "w") as f:
    f.write(src)
print("Done")
