"""Module 140 — TLS Protocol Downgrade Attack Test
Attack tested: a MITM or malicious proxy tricking the connection into
using an OLD, weak TLS version instead of modern TLS 1.3 — even if
the server SUPPORTS strong TLS (confirmed by module98/139), if it
ALSO still accepts deprecated protocols, that's a real downgrade
attack surface.

METHOD: explicitly forces openssl to attempt TLS 1.0, TLS 1.1, and
TLS 1.2 handshakes against OpenQuantum's real auth server — a properly
hardened server should REFUSE the two oldest ones outright.

COST: $0 — pure TLS handshake attempts, no API calls, no credits.
"""
import subprocess, json, datetime, os

def now_iso(): return datetime.datetime.now(datetime.timezone.utc).isoformat()

ENDPOINT = "id.openquantum.com:443"
PROTOCOLS = [
    ("-tls1", "TLS 1.0 (deprecated since 2020, should be REFUSED)"),
    ("-tls1_1", "TLS 1.1 (deprecated since 2020, should be REFUSED)"),
    ("-tls1_2", "TLS 1.2 (still acceptable, commonly still supported)"),
    ("-tls1_3", "TLS 1.3 (modern, should be the negotiated default)"),
]

def try_protocol(flag):
    try:
        proc = subprocess.run(
            ["openssl", "s_client", "-connect", ENDPOINT, flag,
             "-servername", ENDPOINT.split(":")[0]],
            input="", capture_output=True, text=True, timeout=12
        )
        output = proc.stdout + proc.stderr
        # A real successful handshake shows "Protocol :" with the ACTUAL
        # requested version, and no "no protocols available" style error.
        # Checking for the error condition first is more reliable than
        # just checking for boilerplate text that can appear regardless.
        real_error = ("no protocols available" in output.lower()
                       or "handshake failure" in output.lower()
                       or "unsupported protocol" in output.lower())
        connected = ("CONNECTED" in output and "Cipher is" in output
                     and not real_error)
        return connected, output[-400:]
    except Exception as e:
        return None, f"{type(e).__name__}: {e}"

if __name__ == "__main__":
    print(f"--- TLS Protocol Downgrade Test on {ENDPOINT} ---\n")
    findings = []
    for flag, desc in PROTOCOLS:
        print(f"Trying {desc}...")
        connected, detail = try_protocol(flag)
        print(f"  Connection succeeded: {connected}")
        findings.append({"protocol_flag": flag, "description": desc,
                           "connection_succeeded": connected})

    weak_accepted = [f for f in findings if f["protocol_flag"] in ("-tls1", "-tls1_1")
                      and f["connection_succeeded"]]

    print(f"\n{'='*60}")
    print(f"Deprecated TLS 1.0/1.1 accepted: {len(weak_accepted)}/2")
    print(f"{'='*60}")

    finding_summary = (
        f"Tested TLS 1.0, 1.1, 1.2, 1.3 against {ENDPOINT}. "
        + (f"{len(weak_accepted)} deprecated protocol(s) were still ACCEPTED — "
           f"a real downgrade-attack surface, worth reporting." if weak_accepted else
           "Deprecated TLS 1.0/1.1 were correctly refused — no downgrade attack "
           "surface found on this endpoint.")
    )
    print(f"\nFINDING: {finding_summary}")

    result = {"endpoint": ENDPOINT, "findings": findings,
               "weak_protocols_accepted": len(weak_accepted),
               "finding_summary": finding_summary, "timestamp": now_iso()}
    OUTPUT_DIR = "/data/data/com.termux/files/home/Watchdog-quantum-collab/open_quantum_results"
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    with open(os.path.join(OUTPUT_DIR, "module140_tls_downgrade_result.json"), "w") as f:
        json.dump(result, f, indent=2)
    print("\nSaved.")
