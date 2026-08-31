#!/usr/bin/env python3
# Author: Manmohan (Mike) Bains -- Watchdog
"""
aibom_vuln_crossref.py -- AIBOM Vulnerability Cross-Reference
Part of Watchdog AI-Attack Detection Suite.

Takes a Watchdog AIBOM (from aibom_generator) and cross-references each
component + the environment's installed Python packages against a local
list of known-vulnerable AI-supply-chain components. This is the
"vulnerability match" half of AIBOM operationalisation (see the CSAF-VEX
AIBOM framework, arXiv:2606.19390; CISA "SBOM for AI").

The KNOWN-VULN list is LOCAL and explicit -- no network calls, no
third-party feed. It seeds from the real AI-supply-chain CVEs already
researched for Watchdog. Extend it as new advisories land. Matching is a
name+version-range lookup, so it is deterministic and testable.

Emits, per matched component:
    VULNERABLE_COMPONENT with the advisory id, severity, and fixed version.

Citations for the seeded entries:
- ShaiWorm: malicious pytorch-lightning 2.6.2 / 2.6.3 (April 2026)
- PickleScan bypass: CVE-2025-10155/10156/10157 (CVSS 9.3), CVE-2025-46417
- CVE-2024-2952: litellm Jinja SSTI (chat_template)
- CVE-2024-41130: ggml gguf parse null-ptr deref
- lmdeploy torch.load RCE: GHSA-9pf3-7rrr-x5jh
- CVE-2025-1716: picklescan pip-install RCE

REMEDIATION
-----------
Detection + reporting only. Fix = upgrade/replace the component to the
fixed version, a process action, not a runtime one.
"""

import json
import subprocess
from pathlib import Path

# Local known-vulnerable AI-supply-chain components.
# Each: package/component name -> list of advisories.
# affected: list of exact versions OR ("<", "x") / ("range", lo, hi) tuples.
KNOWN_VULNERABLE = {
    "pytorch-lightning": [
        {"id": "ShaiWorm-2026", "severity": "CRITICAL",
         "affected_exact": ["2.6.2", "2.6.3"], "fixed": "2.6.4",
         "detail": "ShaiWorm supply-chain compromise (malicious release)"},
    ],
    "lightning": [
        {"id": "ShaiWorm-2026", "severity": "CRITICAL",
         "affected_exact": ["2.6.2", "2.6.3"], "fixed": "2.6.4",
         "detail": "ShaiWorm supply-chain compromise (malicious release)"},
    ],
    "picklescan": [
        {"id": "CVE-2025-10155", "severity": "CRITICAL",
         "affected_lt": "0.0.30", "fixed": "0.0.30",
         "detail": "scanner bypass (extension spoof / ZIP CRC / blocklist evasion)"},
        {"id": "CVE-2025-1716", "severity": "HIGH",
         "affected_lt": "0.0.23", "fixed": "0.0.23",
         "detail": "pip-install RCE via crafted package"},
    ],
    "litellm": [
        {"id": "CVE-2024-2952", "severity": "HIGH",
         "affected_lt": "1.35.0", "fixed": "1.35.0",
         "detail": "Jinja SSTI via chat_template (code execution)"},
    ],
    "ggml": [
        {"id": "CVE-2024-41130", "severity": "MEDIUM",
         "affected_lt": "0.0.0", "fixed": "unknown",
         "detail": "null-ptr deref in gguf_init_from_file (parse crash)"},
    ],
    "lmdeploy": [
        {"id": "GHSA-9pf3-7rrr-x5jh", "severity": "HIGH",
         "affected_lt": "0.7.0", "fixed": "0.7.0",
         "detail": "torch.load without weights_only=True (RCE on malicious ckpt)"},
    ],
}


def _ver_tuple(v: str):
    parts = []
    for p in str(v).split("."):
        num = "".join(ch for ch in p if ch.isdigit())
        parts.append(int(num) if num else 0)
    return tuple(parts)


def _match_advisory(version: str, adv: dict) -> bool:
    if version in (None, "", "UNPINNED"):
        # unpinned -> cannot rule out; flag conservatively as possibly-affected
        return True
    if "affected_exact" in adv and version in adv["affected_exact"]:
        return True
    if "affected_lt" in adv:
        try:
            return _ver_tuple(version) < _ver_tuple(adv["affected_lt"])
        except Exception:
            return False
    return False


def get_installed_packages(runner=subprocess.run) -> dict:
    """Return {name_lower: version} from pip. Empty dict on failure."""
    try:
        res = runner(["pip", "list", "--format=json"],
                     capture_output=True, text=True, timeout=30)
        if res.returncode != 0:
            return {}
        pkgs = json.loads(res.stdout)
        return {p["name"].lower(): p.get("version", "") for p in pkgs}
    except (FileNotFoundError, subprocess.TimeoutExpired, json.JSONDecodeError, OSError):
        return {}


def crossref(aibom_components: list = None,
             installed_packages: dict = None,
             runner=subprocess.run) -> dict:
    """
    aibom_components: the 'components' list from build_aibom's result (optional).
    installed_packages: {name_lower: version}; if None, queried from pip.
    Returns matched vulnerabilities.
    """
    if installed_packages is None:
        installed_packages = get_installed_packages(runner=runner)

    findings = []

    # 1. Check installed Python packages.
    for name, version in installed_packages.items():
        for adv in KNOWN_VULNERABLE.get(name, []):
            if _match_advisory(version, adv):
                findings.append({
                    "component": name,
                    "installed_version": version or "UNKNOWN",
                    "advisory": adv["id"],
                    "severity": adv["severity"],
                    "fixed_version": adv["fixed"],
                    "detail": adv["detail"],
                    "source": "installed_package",
                    "unpinned": version in (None, "", "UNPINNED"),
                })

    # 2. Check AIBOM components (by name stem, e.g. a bundled lib).
    for comp in (aibom_components or []):
        name = comp.get("name", "").lower()
        version = comp.get("version", "")
        stem = name.split("-")[0].split(".")[0]
        for key in (name, stem):
            for adv in KNOWN_VULNERABLE.get(key, []):
                if _match_advisory(version, adv):
                    findings.append({
                        "component": comp.get("name"),
                        "installed_version": version,
                        "advisory": adv["id"],
                        "severity": adv["severity"],
                        "fixed_version": adv["fixed"],
                        "detail": adv["detail"],
                        "source": "aibom_component",
                        "unpinned": version == "UNPINNED",
                    })

    # de-dupe
    seen = set()
    unique = []
    for f in findings:
        key = (f["component"], f["advisory"], f["source"])
        if key not in seen:
            seen.add(key)
            unique.append(f)

    status = "VULNERABLE_COMPONENTS_FOUND" if unique else "NO_KNOWN_VULNERABILITIES"
    return {
        "status": status,
        "finding_count": len(unique),
        "findings": unique,
        "note": ("Matched against a LOCAL known-vuln list (no network). "
                 "Absence of a finding means not in the local list, not "
                 "proof of safety. Simulation-based; extend the list as "
                 "advisories land."),
    }


if __name__ == "__main__":
    # Demo with a synthetic installed set.
    demo = {"pytorch-lightning": "2.6.2", "litellm": "1.30.0", "numpy": "1.26.0"}
    r = crossref(installed_packages=demo)
    print(f"[AIBOM-VULN] {r['status']} ({r['finding_count']} findings)")
    for f in r["findings"]:
        print(f"  {f['component']} {f['installed_version']} -> {f['advisory']} "
              f"({f['severity']}), fix: {f['fixed_version']}")
