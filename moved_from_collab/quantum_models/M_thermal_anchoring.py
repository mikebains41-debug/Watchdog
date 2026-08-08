#!/usr/bin/env python3
"""M_thermal_anchoring.py - adds stage anchoring, closes the 96x gap.
STATUS: AWAITING_HARDWARE_TEST. Anchor fractions are literature assumptions,
not measured. Lands near published ~6.25 W/qubit (arXiv:2304.14344)."""

ROOM_TEMP_K = 300.0
PUBLISHED_W_PER_QUBIT = 6.25

STAGES = [
    ("50K stage", 50.0, 0.90),
    ("4K stage", 4.0, 0.90),
    ("Still (~0.8K)", 0.8, 0.80),
    ("Cold plate (~0.1K)", 0.1, 0.80),
    ("Mixing chamber", 0.015, 1.00),
]

def carnot(t): return (ROOM_TEMP_K - t) / t

def distribute(total_w):
    remaining, rows, total_cost = total_w, [], 0.0
    for name, t, frac in STAGES:
        anchored = remaining * frac
        cost = anchored * carnot(t)
        total_cost += cost
        rows.append((name, t, anchored, carnot(t), cost))
        remaining -= anchored
    return rows, total_cost

if __name__ == "__main__":
    TOTAL_CONDUCTED_W, QUBITS = 30.0, 1000
    rows, total = distribute(TOTAL_CONDUCTED_W)
    print("="*84)
    print("THERMAL ANCHORING - conducted heat distributed across stages")
    print("STATUS: AWAITING_HARDWARE_TEST (anchor fractions are assumptions)")
    print("="*84)
    print("{:<22}{:>10}{:>16}{:>16}{:>14}".format("Stage","Temp(K)","Anchored(W)","CarnotAmp","Cost@300K(W)"))
    print("-"*84)
    for name, t, anch, amp, cost in rows:
        print("{:<22}{:>10.4f}{:>16.4f}{:>16.1f}{:>14.1f}".format(name, t, anch, amp, cost))
    print("-"*84)
    wpq = total / QUBITS
    ratio = wpq / PUBLISHED_W_PER_QUBIT
    v = "SAME ORDER as 6.25" if 0.1<=ratio<=10 else ("HIGH ({}x)".format(round(ratio,1)) if ratio>10 else "LOW ({}x)".format(round(ratio,3)))
    print("Total: {:.1f} W for {} qubits  ->  {:.2f} W/qubit  ->  {}".format(total, QUBITS, wpq, v))
    print("Un-anchored was ~600 W/qubit (96x high); anchoring dumps ~90% at 50K.")
    print("Next: replace assumed anchor fractions with real per-stage heat-sink data.")
