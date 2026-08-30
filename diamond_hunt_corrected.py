"""
Corrected version — the first attempt wrongly compared Bell-state
jobs against CHSH/QAOA/VQE jobs under one Bell-state-specific metric.
Those circuit types were NEVER supposed to concentrate on 00/11 —
comparing them that way looks like a dramatic "fidelity drop" that
is actually just a wrong metric applied to the wrong circuit type.

This version identifies ONLY genuine, comparable Bell-state jobs by
job name, and checks for real time-drift among those alone.
"""
import json
import datetime
import os
from quantum_providers import get_provider

# Known real Bell-state job IDs from tonight, by their actual purpose
# (identified from session log, not guessed from output shape)
BELL_STATE_JOB_IDS = {
    "29770bf5": "module105 cross-vendor Bell (early)",
    "be2f53ce": "stability run",
    "bede52b5": "stability run",
    "99c9e787": "stability run",
    "f85374d7": "stability run",
    "511ee10c": "stability run",
    "bf428e6b": "stability run",
    "33369a45": "stability run",
    "9d148293": "stability run",
    "dff3dd54": "isolation probe Bell state",
    "5dd9563d": "isolation probe Bell state",
}

def correlation_fraction(counts, total):
    if not total:
        return None
    p00 = counts.get("00", 0)
    p11 = counts.get("11", 0)
    return (p00 + p11) / total

if __name__ == "__main__":
    provider = get_provider()
    print(f"Provider: {provider.provider_name}\n")
    print("Comparing ONLY genuine Bell-state circuits (same circuit type, "
          "same expected ideal outcome) across time.\n")

    history = provider.get_job_history(limit=50)
    data_points = []

    for h in history:
        short_id = h.job_id[:8]
        if short_id not in BELL_STATE_JOB_IDS:
            continue
        if h.status not in ("Completed", "Done"):
            continue
        try:
            result = provider.get_job_results(h.job_id)
            counts = result.get("raw", {})
            total = sum(counts.values())
            # Only include if it's genuinely a 2-character-key (2-qubit) result
            if any(len(k) != 2 for k in counts.keys()):
                print(f"{short_id}: SKIPPED — not actually 2-qubit output, "
                      f"despite being in the known Bell-state list (verify manually)")
                continue
            fidelity = correlation_fraction(counts, total)
            created = getattr(h, "created_at", None)
            data_points.append({"job_id": short_id, "created": created,
                                  "fidelity": round(fidelity, 4),
                                  "label": BELL_STATE_JOB_IDS[short_id]})
            print(f"{short_id}  ({BELL_STATE_JOB_IDS[short_id]})  "
                  f"created={created}  fidelity={fidelity:.4f}")
        except Exception as e:
            print(f"{short_id}: error — {type(e).__name__}: {e}")

    data_points.sort(key=lambda d: d["created"])

    print(f"\n{'='*60}")
    print(f"Genuine, comparable Bell-state data points: {len(data_points)}")
    print(f"{'='*60}")

    if len(data_points) >= 4:
        fidelities = [d["fidelity"] for d in data_points]
        first_half = fidelities[:len(fidelities)//2]
        second_half = fidelities[len(fidelities)//2:]
        avg_first = sum(first_half)/len(first_half)
        avg_second = sum(second_half)/len(second_half)
        drift = avg_second - avg_first
        print(f"\nEarlier avg: {avg_first:.4f}")
        print(f"Later avg: {avg_second:.4f}")
        print(f"Real drift (like-for-like circuits only): {drift:+.4f}")

        meaningful = abs(drift) > 0.03
        finding = (
            f"Corrected analysis: comparing ONLY genuinely equivalent Bell-state "
            f"circuits ({len(data_points)} data points) across the session. "
            f"Earlier avg fidelity: {avg_first:.4f}, later avg: {avg_second:.4f}, "
            f"real drift: {drift:+.4f}. "
            + (f"This IS a meaningful drift worth investigating." if meaningful else
               f"This is within normal run-to-run variation — NO meaningful "
               f"time-correlated hardware drift found. The earlier apparent "
               f"'40% drift' was a methodology error (comparing incompatible "
               f"circuit types under one metric), not a real finding.")
        )
    else:
        finding = "Not enough genuine like-for-like data points for a valid comparison."

    print(f"\nFINDING: {finding}")

    result = {"data_points": data_points, "finding": finding,
               "correction_note": ("Original analysis wrongly compared Bell-state "
                                     "jobs against CHSH/QAOA/VQE jobs using a Bell-"
                                     "state-specific metric those circuit types were "
                                     "never designed to satisfy. This version compares "
                                     "only genuinely equivalent circuits."),
               "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat()}

    OUTPUT_DIR = "/data/data/com.termux/files/home/Watchdog-quantum-collab/open_quantum_results"
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    with open(os.path.join(OUTPUT_DIR, "diamond_hunt_queue_correlation_CORRECTED_result.json"), "w") as f:
        json.dump(result, f, indent=2)
    print("\nSaved.")
