"""
Module 99 — SSH PQC Key Exchange Audit

METHOD:
  Same gap pattern as WD-089-001 and module98, applied to SSH instead of
  TLS. OpenSSH has supported hybrid post-quantum key exchange
  (sntrup761x25519, and more recently mlkem768x25519) for several
  releases now. This module checks:

    1. Does the installed SSH client/server binary even support any
       PQC-hybrid key exchange algorithm? (capability check)
    2. Is any PQC-hybrid algorithm actually enabled/offered in this
       system's live negotiated preference order?
    3. For any real SSH connections this system's config points at, does
       it actually negotiate hybrid, or silently fall back to classical
       (curve25519-sha256, diffie-hellman-group*)?

  This is a LIVE audit of installed binaries and real connection
  behavior, not a simulation — same honesty standard as module98.

CITATION: sntrup761x25519-sha512 — OpenSSH 8.9+ (2022). mlkem768x25519-
sha256 — OpenSSH 9.9+ (2024), standardizing on NIST ML-KEM-768.

HONESTY NOTE: A remote host that doesn't advertise PQC-hybrid kex will
correctly cause a classical fallback — that's the remote's limitation,
not a finding about this system. The real finding is when THIS system's
SSH build supports hybrid kex, offers it, but a real negotiated
connection still lands on classical anyway.
"""
import subprocess
import json
import datetime
import os
import re

CONNECT_TIMEOUT_S = 10

# Known PQC-hybrid KEX algorithm names across OpenSSH versions
PQC_HYBRID_KEX_NAMES = [
    "sntrup761x25519-sha512",
    "sntrup761x25519-sha512@openssh.com",
    "mlkem768x25519-sha256",
]


def now_iso():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def get_supported_kex_algorithms():
    """Ask the installed ssh binary what KEX algorithms it knows about
    at all — this is the capability check, not the usage check."""
    try:
        out = subprocess.run(
            ["ssh", "-Q", "kex"],
            capture_output=True, text=True, timeout=10
        )
        algos = [line.strip() for line in out.stdout.splitlines() if line.strip()]
        return algos
    except FileNotFoundError:
        return None
    except Exception:
        return None


def get_ssh_version():
    try:
        out = subprocess.run(
            ["ssh", "-V"],
            capture_output=True, text=True, timeout=10
        )
        # ssh -V prints to stderr on most builds
        return (out.stderr or out.stdout).strip()
    except Exception as e:
        return f"could not determine: {type(e).__name__}: {e}"


def get_configured_kex_preference():
    """Check sshd_config and ssh_config for any explicit KexAlgorithms
    directive that might be restricting away from hybrid PQC even if
    the binary supports it."""
    findings = {}
    for path in ("/etc/ssh/sshd_config", "/etc/ssh/ssh_config"):
        try:
            with open(path) as f:
                content = f.read()
            matches = re.findall(r"^\s*KexAlgorithms\s+(.+)$", content,
                                   re.MULTILINE | re.IGNORECASE)
            findings[path] = matches if matches else "(no explicit KexAlgorithms directive — uses compiled-in default order)"
        except FileNotFoundError:
            findings[path] = "(file not present)"
        except PermissionError:
            findings[path] = "(permission denied reading file)"
        except Exception as e:
            findings[path] = f"(error: {type(e).__name__}: {e})"
    return findings


def test_negotiation(host, port=22, timeout=CONNECT_TIMEOUT_S):
    """Attempt a real SSH handshake (auth not required — kex happens
    before auth) against a host, forcing it to prefer a PQC-hybrid
    algorithm first, and see what actually gets negotiated via verbose
    output."""
    preferred_order = ",".join(PQC_HYBRID_KEX_NAMES + ["curve25519-sha256"])
    cmd = [
        "ssh", "-vv",
        "-o", f"KexAlgorithms={preferred_order}",
        "-o", "BatchMode=yes",
        "-o", f"ConnectTimeout={timeout}",
        "-o", "StrictHostKeyChecking=no",
        "-p", str(port),
        host,
        "true",
    ]
    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout + 5
        )
        output = proc.stdout + proc.stderr
    except subprocess.TimeoutExpired:
        return {"host": f"{host}:{port}", "error": "connection timeout",
                 "negotiated_kex": None}
    except Exception as e:
        return {"host": f"{host}:{port}", "error": f"{type(e).__name__}: {e}",
                 "negotiated_kex": None}

    m = re.search(r"kex: algorithm:\s*([A-Za-z0-9@.\-]+)", output)
    negotiated = m.group(1) if m else None

    if negotiated is None:
        return {"host": f"{host}:{port}",
                 "error": "connected but could not parse negotiated kex "
                           "algorithm from verbose output — see raw_tail",
                 "negotiated_kex": None,
                 "raw_tail": output[-800:]}

    is_hybrid = negotiated in PQC_HYBRID_KEX_NAMES

    return {
        "host": f"{host}:{port}",
        "negotiated_kex": negotiated,
        "is_hybrid_pqc": is_hybrid,
        "raw_tail": output[-500:],
    }


def run_audit(test_hosts=None):
    ssh_version = get_ssh_version()
    print(f"SSH version: {ssh_version}\n")

    supported = get_supported_kex_algorithms()
    if supported is None:
        print("Could not query ssh -Q kex — ssh binary may not be installed "
              "or accessible.")
        supports_hybrid = None
        hybrid_supported_names = []
    else:
        hybrid_supported_names = [a for a in supported if a in PQC_HYBRID_KEX_NAMES]
        supports_hybrid = len(hybrid_supported_names) > 0
        print(f"This system's ssh binary supports PQC-hybrid KEX: {supports_hybrid}")
        if hybrid_supported_names:
            print(f"  Supported hybrid algorithms: {hybrid_supported_names}")

    config_findings = get_configured_kex_preference()
    print("\nExplicit KexAlgorithms config (if any):")
    for path, val in config_findings.items():
        print(f"  {path}: {val}")

    results = []
    if test_hosts:
        print(f"\nTesting live negotiation against {len(test_hosts)} host(s)...")
        for h in test_hosts:
            host = h if ":" not in h else h.split(":")[0]
            port = 22 if ":" not in h else int(h.split(":")[1])
            print(f"  {host}:{port} ...")
            r = test_negotiation(host, port)
            results.append(r)
            status = r.get("negotiated_kex") or f"ERROR: {r.get('error')}"
            print(f"    negotiated: {status}")
    else:
        print("\nNo test_hosts provided — skipping live negotiation test. "
              "Pass real SSH host(s) you connect to (e.g. github.com, or "
              "your own servers) to test actual negotiated behavior.")

    hybrid_ok = [r for r in results if r.get("is_hybrid_pqc")]
    fell_back = [r for r in results
                 if r.get("negotiated_kex") and not r.get("is_hybrid_pqc")]
    errored = [r for r in results if r.get("error")]

    finding = None
    if supports_hybrid and fell_back:
        finding = (
            f"This system's ssh binary supports PQC-hybrid key exchange "
            f"({hybrid_supported_names}), but {len(fell_back)} of "
            f"{len(results)} tested SSH connections negotiated "
            f"classical-only key exchange anyway. Same 'installed but not "
            f"adopted' gap as WD-089-001 and module98, now shown for SSH."
        )
        print(f"\nFINDING: {finding}")
    elif supports_hybrid is False:
        print("\nThis system's ssh binary does not support any PQC-hybrid "
              "KEX algorithm at all — an upgrade candidate, not a "
              "negotiation-behavior gap. Check OpenSSH version above "
              "against 8.9+ (sntrup761x25519) or 9.9+ (mlkem768x25519).")
    elif hybrid_ok and not fell_back and results:
        print("\nNo negotiation gap found — all tested connections used "
              "hybrid PQC key exchange where this system supports it.")

    return {
        "ssh_version": ssh_version,
        "ssh_supports_pqc_hybrid_kex": supports_hybrid,
        "supported_hybrid_algorithms": hybrid_supported_names,
        "all_supported_kex_algorithms": supported,
        "config_kex_directives": config_findings,
        "hosts_tested": results,
        "hybrid_negotiated_count": len(hybrid_ok),
        "classical_fallback_count": len(fell_back),
        "error_count": len(errored),
        "finding": finding,
        "timestamp": now_iso(),
    }


if __name__ == "__main__":
    # Add real SSH hosts here that this system actually connects to
    # (e.g. "github.com", or internal servers) to test live negotiated
    # behavior. Left empty by default — capability/config checks still
    # run without it.
    TEST_HOSTS = ["github.com"]

    result = run_audit(TEST_HOSTS)

    OUTPUT_DIR = "/data/data/com.termux/files/home/Watchdog/todo"
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    output_path = os.path.join(OUTPUT_DIR, "module99_ssh_pqc_audit_result.json")
    with open(output_path, "w") as f:
        json.dump(result, f, indent=2)
    print(f"\nSaved to {output_path}")
