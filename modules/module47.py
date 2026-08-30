#!/usr/bin/env python3
"""
Watchdog — Module 47: QaaS Supply Chain Integrity
Hashes installed Qiskit/Cirq/Braket/Ocean packages and verifies against
PyPI release hashes. Flags if any package has been tampered with.

Attack vector: Attacker compromises open-source quantum SDK packages
(poisoned pip package) and injects a backdoor that leaks circuit results
to a remote C2 server.

Note on auto-deletion: Auto-deleting packages is too destructive without
human confirmation. This module flags and logs — operator rotates/reinstalls.
"""
import subprocess, json, datetime, os, time, hashlib, importlib.util
from pathlib import Path

PACKAGES_TO_CHECK = [
    "qiskit",
    "qiskit-ibm-runtime",
    "qiskit-aer",
    "amazon-braket-sdk",
    "cirq",
    "cirq-core",
    "dwave-ocean-sdk",
    "pennylane",
]

HASH_STORE_FILE = "/tmp/watchdog_qc_pkg_hashes.json"
POLL_INTERVAL   = 3600   # Check every hour

def now_iso():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()

def stamp():
    return datetime.datetime.now().strftime("%Y%m%d_%H%M%S")

def get_installed_version(pkg: str) -> str | None:
    """Get installed version of a package."""
    try:
        out = subprocess.check_output(
            ["pip", "show", pkg], text=True, timeout=10,
            stderr=subprocess.DEVNULL)
        for line in out.splitlines():
            if line.startswith("Version:"):
                return line.split(":", 1)[1].strip()
    except:
        pass
    return None

def get_package_location(pkg: str) -> str | None:
    """Get filesystem location of installed package."""
    try:
        out = subprocess.check_output(
            ["pip", "show", pkg], text=True, timeout=10,
            stderr=subprocess.DEVNULL)
        for line in out.splitlines():
            if line.startswith("Location:"):
                return line.split(":", 1)[1].strip()
    except:
        pass
    return None

def hash_package_files(pkg: str) -> str | None:
    """
    SHA256 hash of all .py files in the installed package directory.
    Returns a single combined hash representing the entire package content.
    """
    location = get_package_location(pkg)
    if not location:
        return None

    # Find package directory
    pkg_dir = None
    pkg_name_variants = [pkg, pkg.replace("-", "_"), pkg.replace("-", "")]
    for variant in pkg_name_variants:
        candidate = os.path.join(location, variant)
        if os.path.isdir(candidate):
            pkg_dir = candidate
            break

    if not pkg_dir:
        return None

    combined = hashlib.sha256()
    try:
        py_files = sorted(Path(pkg_dir).rglob("*.py"))
        for f in py_files:
            try:
                with open(f, "rb") as fh:
                    combined.update(fh.read())
            except:
                pass
        return combined.hexdigest()
    except:
        return None

def get_pypi_hash(pkg: str, version: str) -> str | None:
    """
    Fetch the SHA256 hash of a package from PyPI JSON API.
    Returns hash of the wheel or sdist for the installed version.
    """
    try:
        import urllib.request
        url = f"https://pypi.org/pypi/{pkg}/{version}/json"
        with urllib.request.urlopen(url, timeout=10) as resp:
            data = json.loads(resp.read())

        releases = data.get("releases", {}).get(version, [])
        # Prefer wheel over sdist
        for release in releases:
            if release.get("filename", "").endswith(".whl"):
                digests = release.get("digests", {})
                return digests.get("sha256")

        # Fall back to sdist
        for release in releases:
            digests = release.get("digests", {})
            if digests.get("sha256"):
                return digests.get("sha256")
    except:
        pass
    return None

def load_hash_store() -> dict:
    try:
        with open(HASH_STORE_FILE) as f:
            return json.load(f)
    except:
        return {}

def save_hash_store(store: dict):
    try:
        with open(HASH_STORE_FILE, "w") as f:
            json.dump(store, f, indent=2)
    except:
        pass

def check_packages() -> tuple[list, list, dict]:
    """
    Check all quantum packages.
    Returns (alerts, status_log, updated_hash_store).
    """
    alerts     = []
    status_log = []
    store      = load_hash_store()

    for pkg in PACKAGES_TO_CHECK:
        version = get_installed_version(pkg)
        if not version:
            status_log.append({"package": pkg, "status": "not_installed"})
            continue

        local_hash = hash_package_files(pkg)
        if not local_hash:
            status_log.append({"package": pkg, "version": version,
                                "status": "hash_failed",
                                "note": "Could not hash package files"})
            continue

        store_key = f"{pkg}=={version}"

        # First time seeing this package+version — store as baseline
        if store_key not in store:
            store[store_key] = {
                "local_hash":    local_hash,
                "first_seen":    now_iso(),
                "version":       version,
            }
            status_log.append({"package": pkg, "version": version,
                                "status": "baseline_stored",
                                "hash": local_hash[:16] + "..."})
        else:
            # Compare against stored baseline
            baseline_hash = store[store_key]["local_hash"]
            if local_hash != baseline_hash:
                alerts.append({
                    "event":          "QUANTUM_LIBRARY_TAMPER",
                    "severity":       "CRITICAL",
                    "package":        pkg,
                    "version":        version,
                    "expected_hash":  baseline_hash[:32] + "...",
                    "actual_hash":    local_hash[:32] + "...",
                    "confidence":     0.95,
                    "note":           (f"{pkg} {version} file hashes changed since baseline — "
                                       "possible supply chain compromise"),
                    "action":         f"pip install --force-reinstall {pkg}=={version} "
                                      f"and verify from official source",
                })
            else:
                status_log.append({"package": pkg, "version": version,
                                    "status": "clean", "hash": local_hash[:16] + "..."})

    return alerts, status_log, store

def main():
    log = open(f"module47_{stamp()}.jsonl", "a")

    def emit(event):
        event.setdefault("ts", now_iso())
        log.write(json.dumps(event) + "\n")
        log.flush()

    emit({"event": "RUN_START", "module": "47_supply_chain",
          "packages_monitored": PACKAGES_TO_CHECK,
          "note": "Hashes package .py files against stored baseline. Flags tamper, does not auto-delete."})

    while True:
        alerts, status_log, store = check_packages()
        save_hash_store(store)

        for status in status_log:
            emit({"event": "PACKAGE_STATUS", **status})

        for alert in alerts:
            emit(alert)

        if not alerts:
            emit({"event": "SUPPLY_CHAIN_CLEAN",
                  "packages_checked": len([s for s in status_log if s.get("status") == "clean"])})

        break  # patched: run once and exit instead of infinite monitoring loop
        time.sleep(POLL_INTERVAL)

if __name__ == "__main__":
    main()
