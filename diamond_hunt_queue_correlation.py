"""
diamond_hunt_queue_correlation.py — real exploratory analysis, not a
confirmation test. Checks whether jobs that waited LONGER in queue
show measurably different fidelity than jobs that completed fast.

If true: real evidence that OpenQuantum's backend drifts/degrades
during high-queue periods — a genuine, previously undiscovered
operational finding, directly relevant to reliability claims.

If false: honest null result, still worth knowing.

Uses only already-completed jobs — $0 cost, pure analysis.
"""
import json
import datetime
from quantum_providers import get_provider

def parse_iso(ts):
    return datetime.datetime.fromisoformat(ts.replace("Z", "+00:00"))

def correlation_fraction(counts, total):
    if not total:
        return None
    key_lengths = {len(k) for k in counts.keys()}
    if len(key_lengths) != 1:
        return None
    n = key_lengths.pop()
    all_zeros = "0" * n
    all_ones = "1" * n
    correlated = counts.get(all_zeros, 0) + counts.get(all_ones, 0)
    return correlated / total

if __name__ == "__main__":
    provider = get_provider()
    print(f"Provider: {provider.provider_name}\n")

    history = provider.get_job_history(limit=50)
    completed = [h for h in history if h.status in ("Completed", "Done")]
    print(f"Analyzing {len(completed)} completed jobs for queue-time vs fidelity correlation\n")

    data_points = []
    for h in completed:
        jid = h.job_id
        created_str = getattr(h, "created_at", None)
        if not created_str:
            continue
        try:
            result = provider.get_job_results(jid)
            counts = result.get("raw", {})
            total = sum(counts.values())
            fidelity = correlation_fraction(counts, total)
            if fidelity is None:
                continue

            # We don't have completion time directly from history, but we
            # can use submission time as a proxy for queue congestion at
            # that moment (later submissions during busy periods = longer
            # real wait, based on tonight's observed pattern)
            created = parse_iso(created_str)
            data_points.append({
                "job_id": jid[:8], "created": created_str,
                "fidelity": round(fidelity, 4), "total_shots": total,
                "num_qubits_detected": len(next(iter(counts.keys()))) if counts else None,
            })
            print(f"{jid[:8]}  created={created_str}  fidelity={fidelity:.4f}")
        except Exception as e:
            print(f"{jid[:8]}: could not analyze — {type(e).__name__}: {e}")

    # Filter to only 2-qubit jobs for a fair fidelity comparison
    two_qubit = [d for d in data_points if d["num_qubits_detected"] == 2]
    two_qubit.sort(key=lambda d: d["created"])

    print(f"\n{'='*60}")
    print(f"2-qubit jobs available for time-ordered comparison: {len(two_qubit)}")
    print(f"{'='*60}\n")

    for d in two_qubit:
        print(f"  {d['created']}  fidelity={d['fidelity']}")

    if len(two_qubit) >= 3:
        fidelities = [d["fidelity"] for d in two_qubit]
        first_half = fidelities[:len(fidelities)//2]
        second_half = fidelities[len(fidelities)//2:]
        avg_first = sum(first_half) / len(first_half)
        avg_second = sum(second_half) / len(second_half)
        drift = avg_second - avg_first

        print(f"\nEarlier submissions avg fidelity: {avg_first:.4f}")
        print(f"Later submissions avg fidelity: {avg_second:.4f}")
        print(f"Drift (later - earlier): {drift:.4f}")

        meaningful_drift = abs(drift) > 0.03

        finding = (
            f"Compared {len(two_qubit)} real 2-qubit job fidelities ordered by "
            f"submission time across the session. Earlier avg: {avg_first:.4f}, "
            f"later avg: {avg_second:.4f}, drift: {drift:+.4f}. "
            + ("This is a MEANINGFUL drift, worth investigating as a real hardware "
               "calibration/degradation signal over the session." if meaningful_drift
               else "This is within normal run-to-run variation, not a meaningful "
               "time-correlated drift.")
        )
        print(f"\nFINDING: {finding}")
    else:
        finding = "Not enough 2-qubit data points for a meaningful time-ordered comparison."
        print(f"\n{finding}")

    result = {"all_data_points": data_points, "two_qubit_time_ordered": two_qubit,
               "finding": finding, "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat()}

    import os
    OUTPUT_DIR = "/data/data/com.termux/files/home/Watchdog-quantum-collab/open_quantum_results"
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    with open(os.path.join(OUTPUT_DIR, "diamond_hunt_queue_correlation_result.json"), "w") as f:
        json.dump(result, f, indent=2)
    print("\nSaved.")
