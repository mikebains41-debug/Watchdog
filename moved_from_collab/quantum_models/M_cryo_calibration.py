#!/usr/bin/env python3
"""M_cryo_calibration.py - checks cryo models vs PUBLISHED figures.
STATUS: CALIBRATION_AGAINST_PUBLISHED_DATA (not hardware-validated).
Anchors: fridge wall power ~25-50kW; ~6.25 W/qubit (arXiv:2304.14344,
IBM System Two ~4158 qubits @ ~26kW); ~2000uW at 100mK; coldest ~15mK."""

PUBLISHED_W_PER_QUBIT = 6.25
IBM_QUBITS = 4158
IBM_FRIDGE_KW = 26.0

def verdict(model, published):
    r = model / published
    if 0.1 <= r <= 10: return "SAME ORDER"
    if r > 10: return "MODEL HIGH ({}x)".format(round(r,1))
    return "MODEL LOW ({}x)".format(round(r,3))

def check(label, model, published, unit):
    print("{:<42}{:>12.3f} {:<4}{:>16}".format(label[:41], model, unit, verdict(model, published)))

if __name__ == "__main__":
    print("="*76)
    print("CRYO MODEL CALIBRATION vs PUBLISHED DATA")
    print("STATUS: CALIBRATION_AGAINST_PUBLISHED_DATA (not hardware-validated)")
    print("="*76)
    derived = IBM_FRIDGE_KW * 1000 / IBM_QUBITS
    check("IBM System Two derived W/qubit vs 6.25", derived, PUBLISHED_W_PER_QUBIT, "W/q")
    check("Scaling-curve implied W/qubit vs 6.25", 600020.0/1000, PUBLISHED_W_PER_QUBIT, "W/q")
    print("-"*76)
    print("SAME ORDER = not obviously wrong, NOT validated.")
    print("MODEL HIGH = raw model omits thermal anchoring at 50K/4K stages.")
    print("Next: add stage anchoring so model lands near 6.25 W/qubit.")
    print("Only real cryostat telemetry graduates this to VALIDATED.")
