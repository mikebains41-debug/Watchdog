"""
Robust patch v2 — targets short unique anchor lines instead of exact
multi-line blocks, which broke on whitespace mismatch.
"""
TARGET = "quantum_providers/openquantum_provider.py"

with open(TARGET) as f:
    lines = f.readlines()

out = []
in_calib = False
in_queue = False
patched_calib = False
patched_queue = False

for i, line in enumerate(lines):
    if "def get_calibration_data" in line:
        in_calib = True
    elif "def get_queue_depth" in line:
        in_queue = True
    elif line.strip().startswith("def ") and (in_calib or in_queue):
        in_calib = False
        in_queue = False

    # Inject resolution right before "matching_job = None" in calibration fn
    if in_calib and "matching_job = None" in line and not patched_calib:
        indent = line[:len(line) - len(line.lstrip())]
        out.append(f"{indent}try:\n")
        out.append(f"{indent}    _bc = self._scheduler.get_backend_class(device_id)\n")
        out.append(f"{indent}    _resolved_uuid = _bc.get('id') if isinstance(_bc, dict) else None\n")
        out.append(f"{indent}except Exception:\n")
        out.append(f"{indent}    _resolved_uuid = None\n")
        out.append("\n")
        patched_calib = True

    # Inject resolution right before "matching = [j for j in jobs" in queue fn
    if in_queue and "matching = [j for j in jobs" in line and not patched_queue:
        indent = line[:len(line) - len(line.lstrip())]
        out.append(f"{indent}try:\n")
        out.append(f"{indent}    _bc = self._scheduler.get_backend_class(device_id)\n")
        out.append(f"{indent}    _resolved_uuid = _bc.get('id') if isinstance(_bc, dict) else None\n")
        out.append(f"{indent}except Exception:\n")
        out.append(f"{indent}    _resolved_uuid = None\n")
        out.append("\n")
        patched_queue = True

    # Widen the calibration match condition
    if in_calib and "if backend == device_id:" in line:
        indent = line[:len(line) - len(line.lstrip())]
        line = f"{indent}if backend == device_id or (_resolved_uuid and backend == _resolved_uuid):\n"

    out.append(line)

# Widen the queue_depth list comprehension condition (multi-line, do as string op)
content = "".join(out)
content = content.replace(
    'getattr(j, "device_id", None) == device_id\n        )]',
    'getattr(j, "device_id", None) == device_id or\n'
    '            (_resolved_uuid and (\n'
    '                getattr(j, "backend_class_id", None) == _resolved_uuid or\n'
    '                getattr(j, "backend", None) == _resolved_uuid or\n'
    '                getattr(j, "device_id", None) == _resolved_uuid\n'
    '            ))\n        )]'
)

with open(TARGET, "w") as f:
    f.write(content)

print(f"patched_calib={patched_calib}  patched_queue={patched_queue}")
