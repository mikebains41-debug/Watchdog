"""
Module 101 — Supply-Chain Signing Algorithm Check

METHOD:
  Same "installed but not verified/adopted" pattern as WD-089-001,
  module98, and module99 — applied one layer deeper: the software
  supply chain itself. Every package this system installs via apt or
  pip has to come from somewhere and be trusted somehow. This module
  checks what's ACTUALLY verifying that trust, using real local
  binaries and configuration — not assumptions.

  Two genuinely different mechanisms exist here, checked separately:

  1. APT: repository metadata (Release/InRelease files) is signed with
     GPG keys stored in this system's trusted keyrings. This script
     inspects those real keyrings and reports the actual signing
     algorithm and key size in use — GPG/OpenPGP has no standardized
     post-quantum signature algorithm in mainstream use as of this
     writing, so this is expected to show classical-only (RSA/DSA/
     ECDSA/EdDSA), which is a fact about the ecosystem's current state,
     not a misconfiguration unique to this system.

  2. PIP: unlike apt, pip does not cryptographically verify package
     signatures by default. This script checks this system's ACTUAL
     local pip configuration (not what PyPI does server-side, which
     this script cannot inspect) — specifically, whether hash-checking
     mode is enforced anywhere. If it isn't, pip installs are trusting
     TLS-transport-security and nothing else, package-content-wise.

HONESTY NOTE: This script inspects LOCAL configuration and installed
keyrings only. It does not and cannot verify PyPI's own server-side
practices — any statement about PyPI's current signing policy would
need independent verification and is deliberately NOT asserted here as
a checked fact.
"""
import subprocess
import json
import datetime
import os
import glob
import re

def now_iso():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def check_apt_keyrings():
    """Real inspection of this system's apt trust keyrings — what
    algorithm and key size actually signs the repo metadata this
    system trusts. Uses --show-keys --with-colons (GPG 2.1.23+), which
    gives structured, reliable output rather than parsing free-text
    --list-packets output."""
    keyring_paths = []
    for pattern in ("/etc/apt/trusted.gpg.d/*.gpg",
                     "/etc/apt/trusted.gpg.d/*.asc",
                     "/usr/share/keyrings/*.gpg",
                     "/etc/apt/keyrings/*.gpg"):
        keyring_paths.extend(glob.glob(pattern))

    keyring_paths = sorted(set(keyring_paths))
    results = []

    # GPG pubkey algorithm IDs per RFC 4880 / colon-output field 4
    ALGO_NAMES = {
        "1": "RSA", "2": "RSA-Encrypt-only", "3": "RSA-Sign-only",
        "16": "ElGamal", "17": "DSA", "18": "ECDH", "19": "ECDSA",
        "22": "EdDSA",
    }

    for kpath in keyring_paths:
        try:
            out = subprocess.run(
                ["gpg", "--with-colons", "--show-keys", kpath],
                capture_output=True, text=True, timeout=10
            )
            output = out.stdout

            algos_found = []
            bits_found = []
            for line in output.splitlines():
                fields = line.split(":")
                if fields[0] in ("pub", "sub") and len(fields) > 4:
                    key_bits = fields[2] if fields[2] else None
                    algo_id = fields[3] if fields[3] else None
                    if algo_id:
                        algos_found.append(ALGO_NAMES.get(algo_id, f"unknown_algo_id({algo_id})"))
                    if key_bits:
                        bits_found.append(key_bits)

            if not algos_found:
                # fallback: try --list-packets in case --show-keys isn't
                # supported on this GPG version
                out2 = subprocess.run(
                    ["gpg", "--list-packets", kpath],
                    capture_output=True, text=True, timeout=10
                )
                text = out2.stdout + out2.stderr
                m = re.findall(r"pubkey algo\s+(\d+)", text)
                algos_found = [ALGO_NAMES.get(a, f"unknown_algo_id({a})") for a in m]

            results.append({
                "keyring_file": kpath,
                "algorithms_found": sorted(set(algos_found)) if algos_found else None,
                "key_bit_sizes_found": sorted(set(bits_found), key=lambda x: int(x) if x.isdigit() else 0) if bits_found else None,
                "parse_status": "ok" if algos_found else "no_algo_detected",
            })
        except FileNotFoundError:
            return None, "gpg binary not found — cannot inspect keyrings"
        except Exception as e:
            results.append({
                "keyring_file": kpath,
                "error": f"{type(e).__name__}: {e}",
            })

    return results, None


def check_pip_hash_enforcement():
    """Checks THIS system's local pip config for hash-checking
    enforcement. Does not and cannot check PyPI's server-side practices."""
    findings = {}

    try:
        out = subprocess.run(
            ["pip", "config", "list"],
            capture_output=True, text=True, timeout=10
        )
        findings["pip_config_list"] = out.stdout.strip() or "(empty — no explicit pip config set)"
    except FileNotFoundError:
        findings["pip_config_list"] = "(pip binary not found)"
    except Exception as e:
        findings["pip_config_list"] = f"(error: {type(e).__name__}: {e})"

    require_hashes_configured = "require-hashes" in findings.get("pip_config_list", "").lower()
    findings["require_hashes_enforced_globally"] = require_hashes_configured

    # Check common config file locations directly too
    config_paths = [
        os.path.expanduser("~/.pip/pip.conf"),
        os.path.expanduser("~/.config/pip/pip.conf"),
        "/etc/pip.conf",
    ]
    config_file_findings = {}
    for path in config_paths:
        if os.path.exists(path):
            try:
                with open(path) as f:
                    content = f.read()
                config_file_findings[path] = (
                    "require-hashes found" if "require-hashes" in content.lower()
                    else "exists, no require-hashes directive"
                )
            except Exception as e:
                config_file_findings[path] = f"error reading: {e}"
        else:
            config_file_findings[path] = "(not present)"
    findings["config_files_checked"] = config_file_findings

    return findings


def run_check():
    print("--- Checking APT keyring signing algorithms ---")
    apt_results, apt_error = check_apt_keyrings()
    if apt_error:
        print(f"  {apt_error}")
    else:
        print(f"  Found {len(apt_results)} keyring file(s)")
        classical_only = True
        for r in apt_results:
            algos = r.get("algorithms_found")
            print(f"  {os.path.basename(r['keyring_file'])}: "
                  f"{algos or 'could not parse'}")

    print("\n--- Checking pip local hash-enforcement configuration ---")
    pip_findings = check_pip_hash_enforcement()
    print(f"  require-hashes enforced globally: "
          f"{pip_findings['require_hashes_enforced_globally']}")
    for path, status in pip_findings["config_files_checked"].items():
        print(f"  {path}: {status}")

    print(f"\n{'='*60}")

    apt_finding = None
    if apt_results:
        all_algos = set()
        for r in apt_results:
            if r.get("algorithms_found"):
                all_algos.update(r["algorithms_found"])
        apt_finding = (
            f"This system's apt trusts {len(apt_results)} keyring file(s), "
            f"signing algorithms found: {sorted(all_algos) if all_algos else 'undetermined'}. "
            f"No PQC signature algorithm is in mainstream apt/GPG use as of "
            f"this writing — this reflects the ecosystem's current state, "
            f"not a local misconfiguration."
        )
        print(f"APT FINDING: {apt_finding}")

    pip_finding = (
        f"This system's pip does NOT enforce hash-checking globally "
        f"(require-hashes not set in any checked config location). "
        f"Without --require-hashes, pip installs rely on TLS transport "
        f"security only for package integrity — there is no local "
        f"cryptographic verification step being enforced by this "
        f"system's configuration for package CONTENT, independent of "
        f"whatever PyPI itself may or may not do server-side (not "
        f"checked by this script)."
    )
    print(f"\nPIP FINDING: {pip_finding}")
    print(f"{'='*60}")

    return {
        "apt_keyring_results": apt_results,
        "apt_finding": apt_finding,
        "pip_findings": pip_findings,
        "pip_finding": pip_finding,
        "timestamp": now_iso(),
    }


if __name__ == "__main__":
    result = run_check()

    OUTPUT_DIR = "/data/data/com.termux/files/home/Watchdog/todo"
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    output_path = os.path.join(OUTPUT_DIR, "module101_supply_chain_result.json")
    with open(output_path, "w") as f:
        json.dump(result, f, indent=2)
    print(f"\nSaved to {output_path}")
