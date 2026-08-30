#!/usr/bin/env python3
"""
Watchdog — Module 47: QaaS Supply Chain Integrity
Finds: Poisoned pip package in the quantum SDK stack injecting a backdoor.

Refactored: standardized JSON output, deterministic hashing.
"""
import hashlib, json, os, subprocess, sys
from datetime import datetime, timezone
from typing import Dict, List, Any

PACKAGES = [
    "qiskit", "qiskit-ibm-runtime", "qiskit-aer",
    "amazon-braket-sdk", "cirq", "cirq-core",
    "dwave-ocean-sdk", "pennylane",
]

STATE_PATH = os.path.expanduser("~/watchdog_qc_pkg_hashes.json")


def emit(event_type: str, details: Dict[str, Any]) -> None:
    print(json.dumps({
        "event": event_type,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        **details
    }))


def pip_show(pkg: str) -> str:
    try:
        r = subprocess.run(["pip", "show", pkg], capture_output=True, text=True, timeout=10)
        return r.stdout if r.returncode == 0 else ""
    except Exception:
        return ""


def get_pkg_location(show_output: str) -> str:
    for line in show_output.splitlines():
        if line.startswith("Location:"):
            return line.split(":", 1)[1].strip()
    return ""


def get_pkg_version(show_output: str) -> str:
    for line in show_output.splitlines():
        if line.startswith("Version:"):
            return line.split(":", 1)[1].strip()
    return "unknown"


def hash_directory(path: str) -> str:
    h = hashlib.sha256()
    for root, _, files in os.walk(path):
        for f in sorted(files):
            if f.endswith(".py"):
                fp = os.path.join(root, f)
                try:
                    with open(fp, "rb") as file:
                        h.update(file.read())
                except Exception:
                    pass
    return h.hexdigest()


def load_state() -> Dict[str, Any]:
    if not os.path.exists(STATE_PATH):
        return {}
    try:
        with open(STATE_PATH, "r") as f:
            return json.load(f)
    except Exception:
        return {}


def save_state(state: Dict[str, Any]) -> None:
    with open(STATE_PATH, "w") as f:
        json.dump(state, f, default=str)


def main():
    state = load_state()
    tampered = []
    clean = []
    errors = []

    for pkg in PACKAGES:
        show = pip_show(pkg)
        if not show:
            errors.append({"package": pkg, "reason": "not_installed"})
            continue

        loc = get_pkg_location(show)
        ver = get_pkg_version(show)
        key = f"{pkg}=={ver}"

        if not loc or not os.path.exists(loc):
            errors.append({"package": pkg, "reason": "location_not_found"})
            continue

        current_hash = hash_directory(loc)
        baseline = state.get(key)

        if baseline is None:
            state[key] = current_hash
            clean.append({"package": pkg, "version": ver, "status": "baseline_stored"})
        elif baseline != current_hash:
            tampered.append({
                "package": pkg,
                "version": ver,
                "expected_prefix": baseline[:16],
                "actual_prefix": current_hash[:16],
                "remediation": f"pip install --force-reinstall {key}",
            })
        else:
            clean.append({"package": pkg, "version": ver, "status": "hash_match"})

    if tampered:
        emit("QUANTUM_LIBRARY_TAMPER", {
            "severity": "CRITICAL",
            "confidence": 0.95,
            "packages": tampered,
        })
    else:
        emit("SUPPLY_CHAIN_CLEAN", {
            "packages_checked": len(PACKAGES),
            "clean_count": len(clean),
            "error_count": len(errors),
        })

    for e in errors:
        emit("PACKAGE_STATUS", {
            "package": e["package"],
            "status": "error",
            "reason": e["reason"],
        })

    save_state(state)


if __name__ == "__main__":
    main()
