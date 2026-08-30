"""Module 137 — Auth Timing Side-Channel Probe

METHOD: measures response time for THREE auth scenarios using the
real token endpoint directly:
  1. Our own real, valid client_id + a wrong secret
  2. A clearly-fake, made-up client_id + a wrong secret
  3. Our own real, valid client_id + correct secret (baseline)

If scenario 1 consistently takes measurably longer/shorter than
scenario 2, that's a timing side-channel — it would let an attacker
determine whether a given client_id EXISTS in the system at all,
without ever needing the correct secret. This is a well-known, real
vulnerability class (user/account enumeration via timing).

SCOPE: only tests OUR OWN real client_id against fabricated ones —
never attempts to test or guess at any other real customer's
credentials.
"""
import time, json, datetime, os, statistics
import requests

REAL_CLIENT_ID = os.environ.get("OPENQUANTUM_CLIENT_ID", "")
REAL_SECRET = os.environ.get("OPENQUANTUM_CLIENT_SECRET", "")
TOKEN_URL = "https://id.openquantum.com/realms/platform/protocol/openid-connect/token"
ROUNDS = 8

def now_iso(): return datetime.datetime.now(datetime.timezone.utc).isoformat()

def timed_auth_attempt(client_id, client_secret):
    start = time.time()
    try:
        resp = requests.post(TOKEN_URL, data={
            "grant_type": "client_credentials",
            "client_id": client_id, "client_secret": client_secret,
        }, timeout=15)
        elapsed = time.time() - start
        return elapsed, resp.status_code
    except Exception:
        return time.time() - start, None

if __name__ == "__main__":
    if not REAL_CLIENT_ID or not REAL_SECRET:
        print("Real credentials not found in environment — cannot run this test.")
        exit(1)

    print(f"Running {ROUNDS} rounds each for 3 scenarios (timing side-channel probe)\n")

    real_id_wrong_secret_times = []
    fake_id_wrong_secret_times = []
    real_id_real_secret_times = []

    for i in range(ROUNDS):
        t1, s1 = timed_auth_attempt(REAL_CLIENT_ID, "definitely_wrong_secret_0000")
        real_id_wrong_secret_times.append(t1)

        t2, s2 = timed_auth_attempt("s_totally_fake_made_up_id_zzz999", "definitely_wrong_secret_0000")
        fake_id_wrong_secret_times.append(t2)

        t3, s3 = timed_auth_attempt(REAL_CLIENT_ID, REAL_SECRET)
        real_id_real_secret_times.append(t3)

        print(f"  round {i+1}: real_id+wrong={t1:.3f}s(status={s1})  "
              f"fake_id+wrong={t2:.3f}s(status={s2})  real+real={t3:.3f}s(status={s3})")
        time.sleep(1)

    avg_real_wrong = statistics.mean(real_id_wrong_secret_times)
    avg_fake_wrong = statistics.mean(fake_id_wrong_secret_times)
    avg_real_real = statistics.mean(real_id_real_secret_times)
    diff = avg_real_wrong - avg_fake_wrong
    diff_pct = (diff / avg_fake_wrong * 100) if avg_fake_wrong else 0

    print(f"\n{'='*60}")
    print(f"Avg time — real client_id + wrong secret:  {avg_real_wrong:.4f}s")
    print(f"Avg time — fake client_id + wrong secret:  {avg_fake_wrong:.4f}s")
    print(f"Avg time — real client_id + real secret:   {avg_real_real:.4f}s")
    print(f"Difference (real_id vs fake_id, both wrong secret): {diff:.4f}s ({diff_pct:+.1f}%)")
    print(f"{'='*60}")

    # A difference under ~20% and under 50ms absolute is not a meaningfully
    # exploitable timing channel over a real network; anything larger is
    # worth flagging
    meaningful_timing_leak = abs(diff) > 0.05 and abs(diff_pct) > 20

    finding_summary = (
        f"Measured {ROUNDS} rounds comparing auth response time for a real, valid "
        f"client_id vs a fabricated one (both with wrong secrets). Difference: "
        f"{diff:.4f}s ({diff_pct:+.1f}%). "
        + ("This difference is large enough to be a potential timing side-channel for "
           "client_id enumeration, worth further investigation." if meaningful_timing_leak else
           "This difference is small enough to likely be normal network jitter, not a "
           "meaningful timing side-channel.")
    )
    print(f"\nFINDING: {finding_summary}")

    result = {
        "rounds": ROUNDS,
        "avg_real_id_wrong_secret_s": round(avg_real_wrong, 4),
        "avg_fake_id_wrong_secret_s": round(avg_fake_wrong, 4),
        "avg_real_id_real_secret_s": round(avg_real_real, 4),
        "difference_s": round(diff, 4), "difference_pct": round(diff_pct, 1),
        "meaningful_timing_leak": meaningful_timing_leak,
        "finding_summary": finding_summary, "timestamp": now_iso(),
    }
    OUTPUT_DIR = "/data/data/com.termux/files/home/Watchdog-quantum-collab/open_quantum_results"
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    with open(os.path.join(OUTPUT_DIR, "module137_timing_result.json"), "w") as f:
        json.dump(result, f, indent=2)
    print("\nSaved.")
