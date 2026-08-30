"""
Module 103 — Live TLS PQC Negotiation Check (own domain)

METHOD: identical technique to module98, but targeted at your OWN
production domain instead of third-party sites (Google/Cloudflare/
GitHub). Module98 told you whether THIS SYSTEM's outbound client
negotiates hybrid PQC correctly. This tells you whether YOUR OWN
server-side infrastructure supports and negotiates it — a materially
different and more directly relevant question if this feeds into any
customer-facing claim about Watchdog's own security posture.

HONESTY NOTE: if the domain below is unreachable, misconfigured, or
doesn't exist yet, this script will report that plainly rather than
silently failing or fabricating a result. Edit TARGET_DOMAIN below to
whatever your actual live production endpoint is.
"""
import subprocess
import json
import datetime
import os
import re

TARGET_DOMAIN = "gpu-optimizer.com:443"  # EDIT to your real live domain if different

HYBRID_GROUP = "X25519MLKEM768"
OFFERED_GROUPS = f"{HYBRID_GROUP}:X25519:prime256v1:secp384r1"
CONNECT_TIMEOUT_S = 12


def now_iso():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def negotiate(endpoint, timeout=CONNECT_TIMEOUT_S):
    cmd = [
        "openssl", "s_client",
        "-connect", endpoint,
        "-groups", OFFERED_GROUPS,
        "-tls1_3",
        "-brief",
    ]
    try:
        proc = subprocess.run(
            cmd, input="", capture_output=True, text=True, timeout=timeout
        )
        output = proc.stdout + proc.stderr
    except subprocess.TimeoutExpired:
        return {"endpoint": endpoint, "error": "connection timeout",
                 "negotiated_group": None}
    except FileNotFoundError:
        return {"endpoint": endpoint, "error": "openssl binary not found",
                 "negotiated_group": None}
    except Exception as e:
        return {"endpoint": endpoint, "error": f"{type(e).__name__}: {e}",
                 "negotiated_group": None}

    negotiated_group = None
    m = re.search(r"Server Temp Key:\s*([A-Za-z0-9]+)", output)
    if m:
        negotiated_group = m.group(1)
    else:
        m2 = re.search(r"group:\s*([A-Za-z0-9]+)", output, re.IGNORECASE)
        if m2:
            negotiated_group = m2.group(1)

    if negotiated_group is None:
        return {
            "endpoint": endpoint,
            "error": "connected but could not parse negotiated group "
                      "from openssl output — see raw_tail",
            "negotiated_group": None,
            "is_hybrid_pqc": False,
            "raw_tail": output[-800:],
        }

    is_hybrid = "MLKEM" in negotiated_group.upper()

    return {
        "endpoint": endpoint,
        "negotiated_group": negotiated_group,
        "is_hybrid_pqc": is_hybrid,
        "raw_tail": output[-500:],
    }


def run_check():
    print(f"Testing {TARGET_DOMAIN} (your production domain)...\n")
    result = negotiate(TARGET_DOMAIN)

    if result.get("error"):
        print(f"RESULT: {result['error']}")
        if "timeout" in result.get("error", "") or "not found" in result.get("error", ""):
            print("This may mean the domain isn't live, isn't reachable from "
                  "this network, or doesn't accept TLS 1.3 connections. "
                  "Verify TARGET_DOMAIN is correct and the endpoint is live "
                  "before treating this as a security finding either way.")
    else:
        print(f"Negotiated group: {result['negotiated_group']}")
        print(f"Hybrid PQC in use: {result['is_hybrid_pqc']}")
        if result["is_hybrid_pqc"]:
            print("\nFINDING: your own production domain correctly negotiates "
                  "hybrid post-quantum key exchange. This is a positive, "
                  "verifiable claim about your own infrastructure's current "
                  "security posture.")
        else:
            print(f"\nFINDING: your own production domain negotiated "
                  f"classical-only key exchange ({result['negotiated_group']}), "
                  f"not hybrid PQC. This may be your server's own "
                  f"configuration, your CDN/load balancer's TLS termination, "
                  f"or simply not yet supported by your current stack — worth "
                  f"investigating which, since it's directly checkable and "
                  f"directly fixable.")

    return {
        "target_domain": TARGET_DOMAIN,
        "result": result,
        "timestamp": now_iso(),
    }


if __name__ == "__main__":
    result = run_check()

    OUTPUT_DIR = "/data/data/com.termux/files/home/Watchdog/todo"
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    output_path = os.path.join(OUTPUT_DIR, "module103_own_domain_tls_result.json")
    with open(output_path, "w") as f:
        json.dump(result, f, indent=2)
    print(f"\nSaved to {output_path}")
