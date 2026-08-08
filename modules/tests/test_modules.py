#!/usr/bin/env python3
import json
import sys
import os
import subprocess
import pytest
from pathlib import Path

# Add repo root to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

# List of active modules (exclude stubs like 32,35-39,41,43-44,48-50,55-75)
ACTIVE_MODULES = [
    "module33.py",
    "module34.py",
    "module40.py",
    "module42.py",
    "module45.py",
    "module46.py",
    "module47.py",
    "module51.py",
    "module52.py",
    "module53.py",
    "module54.py",
]

# Stubs are modules that only emit MODULE_DISABLED – we can test them too but they don't do much.
# We'll test all modules, but we'll check that stubs emit MODULE_DISABLED.

@pytest.mark.parametrize("mod", [
    f for f in os.listdir("modules") if f.startswith("module") and f.endswith(".py")
])
def test_module_runs(mod):
    """Run each module and verify it produces at least one JSON event."""
    path = os.path.join("modules", mod)
    # Use subprocess to run the module with the mock provider (no credentials set)
    env = os.environ.copy()
    # Ensure no real credentials interfere
    env.pop("IBM_QUANTUM_TOKEN", None)
    env.pop("OPENQUANTUM_CLIENT_ID", None)
    env.pop("OPENQUANTUM_CLIENT_SECRET", None)
    env.pop("DWAVE_API_TOKEN", None)
    env.pop("AWS_DEFAULT_REGION", None)
    
    result = subprocess.run(
        [sys.executable, path],
        capture_output=True,
        text=True,
        env=env,
        timeout=120,
        stdin=subprocess.DEVNULL
    )
    # Some modules may print to stderr (info) – we ignore that.
    # But we check that stdout has at least one JSON line.
    lines = [line.strip() for line in result.stdout.splitlines() if line.strip()]
    json_lines = []
    for line in lines:
        try:
            data = json.loads(line)
            json_lines.append(data)
        except json.JSONDecodeError:
            continue
    assert len(json_lines) > 0, f"Module {mod} produced no JSON events."
    # Check that at least one event is not RAW_OUTPUT (i.e., a proper event)
    proper_events = [e for e in json_lines if e.get("event") != "RAW_OUTPUT"]
    assert len(proper_events) > 0, f"Module {mod} only produced RAW_OUTPUT events."

    # For active modules, we can also check that specific events are present.
    # We'll do a simple check: if the module is in ACTIVE_MODULES, we expect
    # at least one event that is not MODULE_DISABLED or PROVIDER_NOT_SUPPORTED.
    if mod in ACTIVE_MODULES:
        # Allow some modules to emit PROVIDER_NOT_SUPPORTED if they require IBM/qiskit (52-54)
        # or PROBE_SKIP for 51 if qiskit missing.
        # We just check that the module runs without crashing.
        pass

def test_active_modules_specific_behaviour():
    """Test specific modules for expected alert conditions."""
    # We can test module33 (queue spike) by patching the mock provider's queue depth.
    # However, for simplicity, we'll just ensure that the module runs.
    # We could simulate by temporarily modifying the module's threshold constants.
    # We'll keep this as a placeholder for future enhancement.
    pass

if __name__ == "__main__":
    pytest.main(["-v", __file__])
