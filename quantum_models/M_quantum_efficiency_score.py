#!/usr/bin/env python3
"""M_quantum_efficiency_score.py - CEI-equivalent for cryo/quantum.
STATUS: AWAITING_HARDWARE_TEST. Inputs modeled, not measured.
Ref: ~6.25 W/qubit (arXiv:2304.14344); coldest ~15mK."""

PUBLISHED_W_PER_QUBIT = 6.25
ROOM_TEMP_K = 300.0
MIXING_K = 0.015

def carnot_amp(t=MIXING_K): return (ROOM_TEMP_K - t) / t

def score(qubits, wall_w, cold_load_w):
    wpq = wall_w / qubits
    ideal = cold_load_w * carnot_amp()
    carnot_pct = (ideal / wall_w * 100) if wall_w else 0
    r = wpq / PUBLISHED_W_PER_QUBIT
    wq_comp = max(0, min(100, 100 / r)) if r > 0 else 0
    s = int(round(0.6 * wq_comp + 0.4 * min(100, carnot_pct)))
    rating = "EFFICIENT" if s>=75 else "ACCEPTABLE" if s>=45 else "WASTEFUL" if s>=20 else "CRITICAL WASTE"
    return wpq, ideal, carnot_pct, s, rating

if __name__ == "__main__":
    qubits, wall_w, cold_load_w = 1000, 26000.0, 1.0
    wpq, ideal, cpct, s, rating = score(qubits, wall_w, cold_load_w)
    print("="*74)
    print("QUANTUM EFFICIENCY SCORE (CEI-equivalent for cryo infrastructure)")
    print("STATUS: AWAITING_HARDWARE_TEST (inputs modeled, not measured)")
    print("="*74)
    print("Qubits: {}   Wall: {:.0f} W ({:.1f} kW)".format(qubits, wall_w, wall_w/1000))
    print("W/qubit: {:.2f} (ref {:.2f})   Carnot amp: {:.0f}x at 15mK".format(wpq, PUBLISHED_W_PER_QUBIT, carnot_amp()))
    print("Carnot-floor ideal: {:.0f} W   Carnot efficiency: {:.2f}%".format(ideal, cpct))
    print("-"*74)
    print(">> SCORE: {} / 100   [{}]".format(s, rating))
    print("-"*74)
    print("Blends W/qubit-vs-published (60%) + closeness-to-Carnot (40%).")
    print("Relative index like GPU CEI. Feed real wall power to make it real.")
