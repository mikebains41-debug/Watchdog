"""
Module 100 — Harvest-Now-Decrypt-Later Exposure Window

METHOD:
  WD-089-001 (module89) found a static count: 144/144 certs are
  quantum-vulnerable. That's a snapshot, not a timeline. This module
  turns it into a time-bounded risk by cross-referencing each real
  cert's actual validity period against a CRQC (cryptographically-
  relevant quantum computer) threshold year.

  Two distinct exposure mechanisms, both real, both worth separating:

  1. HARVEST-NOW RISK (applies to ALL non-PQC-protected traffic,
     regardless of cert expiry): any data encrypted today under one of
     these certs' keys can be captured and stored now, then decrypted
     the moment a CRQC exists — even years from now. This risk exists
     from TODAY, for every cert, full stop.

  2. ONGOING-EXPOSURE WINDOW (specific to certs with long remaining
     validity): a cert that stays valid and in active use for years
     keeps generating NEW harvestable traffic right up until it
     expires or is replaced. The longer a vulnerable cert stays in
     service, the more harvestable data accumulates before any
     transition to PQC actually happens.

CITATION: The "harvest now, decrypt later" threat model is a
well-established, uncontested concept in post-quantum cryptography
discourse (see NIST IR 8547, and the broad expert consensus reflected
in NIST's PQC migration guidance) — the exact TIMING of when a CRQC
will exist is genuinely disputed among experts (estimates in public
discourse commonly range from the early 2030s to considerably later).

HONESTY NOTE: CRQC_THRESHOLD_YEAR below is NOT a fact — it's a
configurable, illustrative scenario marker, defaulting to 10 years
from today as a commonly-cited rough midpoint in public discourse.
Change it to reflect whatever source/estimate you trust; the script's
output is only as meaningful as that input, and this is stated
explicitly rather than presented as a proven timeline.
"""
import subprocess
import json
import datetime
import os
import glob

CERT_DIR = "/etc/ssl/certs"
CRQC_THRESHOLD_YEAR = datetime.datetime.now().year + 10  # illustrative — see HONESTY NOTE above


def now_iso():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def get_cert_expiry(cert_path):
    """Real openssl call — returns the cert's actual notAfter date, or
    None if it can't be read/parsed."""
    try:
        out = subprocess.run(
            ["openssl", "x509", "-enddate", "-noout", "-in", cert_path],
            capture_output=True, text=True, timeout=10
        )
        if out.returncode != 0:
            return None
        # Format: "notAfter=Jan  1 00:00:00 2035 GMT"
        line = out.stdout.strip()
        date_str = line.split("=", 1)[1].strip()
        # Parse OpenSSL's date format
        dt = datetime.datetime.strptime(date_str, "%b %d %H:%M:%S %Y %Z")
        return dt
    except Exception:
        return None


def get_cert_subject(cert_path):
    try:
        out = subprocess.run(
            ["openssl", "x509", "-subject", "-noout", "-in", cert_path],
            capture_output=True, text=True, timeout=10
        )
        return out.stdout.strip() if out.returncode == 0 else None
    except Exception:
        return None


def run_analysis():
    if not os.path.isdir(CERT_DIR):
        print(f"Cert directory not found: {CERT_DIR}")
        return None

    cert_files = sorted(glob.glob(os.path.join(CERT_DIR, "*.pem")))
    print(f"Found {len(cert_files)} cert files in {CERT_DIR}")
    print(f"CRQC threshold year (illustrative, see HONESTY NOTE): {CRQC_THRESHOLD_YEAR}\n")

    today = datetime.datetime.now()
    results = []
    unparseable = 0

    for cert_path in cert_files:
        expiry = get_cert_expiry(cert_path)
        if expiry is None:
            unparseable += 1
            continue

        subject = get_cert_subject(cert_path)
        days_until_expiry = (expiry - today).days
        expires_after_threshold = expiry.year > CRQC_THRESHOLD_YEAR

        results.append({
            "cert_file": os.path.basename(cert_path),
            "subject": subject,
            "expiry_date": expiry.strftime("%Y-%m-%d"),
            "days_until_expiry": days_until_expiry,
            "still_valid_past_crqc_threshold": expires_after_threshold,
        })

    already_expired = [r for r in results if r["days_until_expiry"] < 0]
    still_valid = [r for r in results if r["days_until_expiry"] >= 0]
    past_threshold = [r for r in still_valid if r["still_valid_past_crqc_threshold"]]

    print(f"{'='*60}")
    print(f"Certs parsed successfully: {len(results)}")
    print(f"Certs unparseable/skipped: {unparseable}")
    print(f"Currently valid certs: {len(still_valid)}")
    print(f"Already-expired certs found: {len(already_expired)}")
    print(f"Valid certs whose expiry extends PAST the {CRQC_THRESHOLD_YEAR} "
          f"threshold: {len(past_threshold)}")
    print(f"{'='*60}")

    if past_threshold:
        print(f"\nCerts remaining in active service past the illustrative "
              f"threshold year:")
        for r in past_threshold[:10]:
            print(f"  {r['cert_file']}  expires {r['expiry_date']}  "
                  f"({r['days_until_expiry']} days from now)")
        if len(past_threshold) > 10:
            print(f"  ... and {len(past_threshold) - 10} more")

    finding = (
        f"All {len(still_valid)} currently-valid, non-PQC certs on this "
        f"system are harvest-now-decrypt-later exposed starting today — "
        f"any traffic they protect can be captured now and decrypted "
        f"whenever a CRQC exists, independent of cert expiry. "
        f"{len(past_threshold)} of those certs remain in active service "
        f"past the illustrative {CRQC_THRESHOLD_YEAR} threshold used here, "
        f"meaning they will keep generating NEW harvestable traffic for "
        f"years into the window during which a CRQC is plausibly "
        f"expected by at least some public estimates. This turns "
        f"WD-089-001's static count into a time-bounded risk rather than "
        f"a single snapshot."
    )
    print(f"\nFINDING: {finding}")

    return {
        "cert_dir": CERT_DIR,
        "crqc_threshold_year": CRQC_THRESHOLD_YEAR,
        "crqc_threshold_is_illustrative_not_authoritative": True,
        "total_certs_found": len(cert_files),
        "certs_parsed": len(results),
        "certs_unparseable": unparseable,
        "currently_valid_certs": len(still_valid),
        "already_expired_certs": len(already_expired),
        "certs_valid_past_threshold": len(past_threshold),
        "certs_valid_past_threshold_detail": past_threshold,
        "all_results": results,
        "finding": finding,
        "timestamp": now_iso(),
    }


if __name__ == "__main__":
    result = run_analysis()
    if result is None:
        exit(1)

    OUTPUT_DIR = "/data/data/com.termux/files/home/Watchdog/todo"
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    output_path = os.path.join(OUTPUT_DIR, "module100_harvest_now_result.json")
    with open(output_path, "w") as f:
        json.dump(result, f, indent=2)
    print(f"\nSaved to {output_path}")
