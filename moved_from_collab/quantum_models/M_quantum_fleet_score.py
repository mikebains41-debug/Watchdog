#!/usr/bin/env python3
"""M_quantum_fleet_score.py - fleet roll-up, scores multiple fridges.
STATUS: AWAITING_HARDWARE_TEST. Per-unit inputs modeled, not measured.
Ref: ~6.25 W/qubit (arXiv:2304.14344)."""

PUBLISHED_W_PER_QUBIT = 6.25
ROOM_TEMP_K = 300.0
MIXING_K = 0.015

def carnot_amp(t=MIXING_K): return (ROOM_TEMP_K - t) / t

def unit_score(qubits, wall_w, cold_w):
    wpq = wall_w / qubits
    ideal = cold_w * carnot_amp()
    carnot_pct = (ideal / wall_w * 100) if wall_w else 0
    r = wpq / PUBLISHED_W_PER_QUBIT
    wq = max(0, min(100, 100 / r)) if r > 0 else 0
    s = int(round(0.6 * wq + 0.4 * min(100, carnot_pct)))
    rating = "EFFICIENT" if s>=75 else "ACCEPTABLE" if s>=45 else "WASTEFUL" if s>=20 else "CRITICAL"
    return wpq, s, rating

if __name__ == "__main__":
    fleet = [
        ("FRIDGE-01", 4158, 26000.0, 1.0),
        ("FRIDGE-02", 4158, 28000.0, 1.0),
        ("FRIDGE-03", 4158, 45000.0, 0.8),
    ]
    tq = sum(f[1] for f in fleet)
    tw = sum(f[2] for f in fleet)
    print("="*88)
    print("QUANTUM FLEET EFFICIENCY ROLL-UP ({} fridges, {} qubits)".format(len(fleet), tq))
    print("STATUS: AWAITING_HARDWARE_TEST (per-unit inputs modeled, not measured)")
    print("="*88)
    print("{:<12}{:>10}{:>12}{:>12}{:>8}{:>14}".format("Unit","Qubits","Wall(kW)","W/qubit","Score","Rating"))
    print("-"*88)
    weighted = 0
    worst = None
    for uid, q, w, c in fleet:
        wpq, s, rating = unit_score(q, w, c)
        weighted += s * q
        if worst is None or s < worst[1]: worst = (uid, s, rating)
        print("{:<12}{:>10}{:>12.1f}{:>12.2f}{:>8}{:>14}".format(uid, q, w/1000, wpq, s, rating))
    print("-"*88)
    fs = int(round(weighted / tq))
    fr = "EFFICIENT" if fs>=75 else "ACCEPTABLE" if fs>=45 else "WASTEFUL" if fs>=20 else "CRITICAL"
    print("FLEET TOTAL  {:>10}{:>12.1f}{:>12.2f}".format(tq, tw/1000, tw/tq))
    print(">> FLEET SCORE: {} / 100  [{}]".format(fs, fr))
    print("Worst unit: {} (score {}, {}) - biggest opportunity.".format(worst[0], worst[1], worst[2]))
