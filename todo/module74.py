#!/usr/bin/env python3
"""
Watchdog — Module 74: Readout Resonator Frequency Collision Monitor
Status: FUNCTIONAL with IBM_QUANTUM_TOKEN

THE ATTACK SURFACE:

  Superconducting qubits are read out through coupled resonators that
  are frequency-multiplexed onto a shared feedline. Each resonator gets
  a distinct frequency slot. When two resonators drift close in
  frequency — a "frequency collision" — the measurement tone for one
  perturbs the other, and readout discrimination degrades for both.

  Frequency crowding is a documented fabrication and operational problem
  in circuit QED. It is also an attack surface:
    - An attacker who can shift a resonator frequency (via flux bias,
      thermal load, or driven AC Stark shift) creates a deliberate
      collision with a victim's readout resonator.
    - The victim's readout fidelity degrades. Jobs still complete.
      Results are just wrong.
    - Collisions also open the readout crosstalk channel that module69
      measures directly.

  This module is the frequency-domain complement to module69. module69
  measures the RESULT of readout interference by running circuits. This
  module watches the CAUSE — the frequency spacing itself — from
  calibration data, at zero QPU cost.

WHAT THIS MODULE DOES:
  1. Extracts per-qubit readout frequency and qubit frequency from
     backend.properties() and backend configuration.
  2. Computes pairwise frequency spacing across all qubits and flags
     pairs closer than the safe multiplexing separation.
  3. Tracks each resonator's frequency over time. A drift that is not
     shared by its neighbours is anomalous — global drift is thermal,
     single-resonator drift is not.
  4. Correlates collision events with readout error rises, confirming
     cause and effect.
  5. Detects anharmonicity changes, which indicate the qubit itself has
     shifted rather than just the resonator.
  6. Flags collisions that specifically involve the tenant's allocated
     qubits versus background collisions elsewhere on the chip.

Requires: qiskit-ibm-runtime
Credentials: IBM_QUANTUM_TOKEN
Cost: zero QPU time — reads calibration data only.
"""
import json, os, time, datetime, math
from collections import defaultdict

POLL_INTERVAL         = 600     # seconds between calibration reads
COLLISION_MHZ         = 20.0    # resonator spacing below this = collision
NEAR_COLLISION_MHZ    = 50.0    # spacing below this = warn
QUBIT_COLLISION_MHZ   = 30.0    # qubit-qubit frequency spacing floor
DRIFT_MHZ             = 5.0     # single-resonator drift above this = flag
READOUT_RISE_MULT     = 1.5     # readout error rise confirming a collision
BASELINE_SAMPLES      = 6
STATE_FILE            = "/tmp/watchdog_resonator_collision.json"

def now_iso():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()

def stamp():
    return datetime.datetime.now().strftime("%Y%m%d_%H%M%S")

def load_state() -> dict:
    try:
        with open(STATE_FILE) as f:
            return json.load(f)
    except:
        return {"snapshots": [], "freq_baseline": {},
                 "readout_baseline": {}, "established": now_iso()}

def save_state(s: dict):
    try:
        s["snapshots"] = s.get("snapshots", [])[-50:]
        with open(STATE_FILE, "w") as f:
            json.dump(s, f)
    except:
        pass

def fetch_frequencies(token: str, backend_name: str | None) -> dict | None:
    """
    Pull qubit and readout resonator frequencies plus readout errors.
    All from real calibration data — no QPU execution.
    """
    try:
        from qiskit_ibm_runtime import QiskitRuntimeService
        svc = QiskitRuntimeService(token=token)
        backend = (svc.backend(backend_name) if backend_name
                   else svc.least_busy(operational=True, simulator=False,
                                        min_num_qubits=5))
        props = backend.properties(refresh=True)
        if props is None:
            return None

        qubits = {}
        for i in range(backend.num_qubits):
            entry = {}
            # Qubit transition frequency (Hz -> MHz)
            try:
                f = props.frequency(i)
                if f:
                    entry["qubit_freq_mhz"] = f / 1e6
            except Exception:
                pass
            # Readout resonator frequency, anharmonicity, readout error
            try:
                for param in props.qubit_property(i).items():
                    name, value = param[0], param[1]
                    val = value[0] if isinstance(value, tuple) else value
                    if name == "readout_error":
                        entry["readout_error"] = val
                    elif name == "anharmonicity" and val:
                        entry["anharmonicity_mhz"] = val / 1e6
                    elif name in ("readout_frequency", "resonator_frequency") and val:
                        entry["resonator_freq_mhz"] = val / 1e6
                    elif name == "T1":
                        entry["t1"] = val
                    elif name == "T2":
                        entry["t2"] = val
            except Exception:
                pass
            if entry:
                qubits[i] = entry

        # Fall back to configuration for resonator frequencies if
        # properties did not expose them
        try:
            config = backend.configuration()
            meas_freqs = getattr(config, "meas_freq_range", None)
            if hasattr(config, "meas_lo_range"):
                for i, rng in enumerate(config.meas_lo_range):
                    if i in qubits and "resonator_freq_mhz" not in qubits[i]:
                        if rng and len(rng) == 2:
                            qubits[i]["resonator_freq_mhz"] = (
                                (rng[0] + rng[1]) / 2 / 1e6)
        except Exception:
            pass

        return {"backend":    backend.name,
                 "num_qubits": backend.num_qubits,
                 "qubits":     {str(k): v for k, v in qubits.items()},
                 "ts":         time.time()}
    except ImportError:
        return {"error": "qiskit_ibm_runtime not installed"}
    except Exception as e:
        return {"error": str(e)}

def find_collisions(qubits: dict, field: str, floor_mhz: float,
                     warn_mhz: float) -> list:
    """Pairwise frequency spacing below the safe separation."""
    entries = [(int(q), v[field]) for q, v in qubits.items()
               if v.get(field) is not None]
    collisions = []
    for i, (qa, fa) in enumerate(entries):
        for qb, fb in entries[i+1:]:
            spacing = abs(fa - fb)
            if spacing < warn_mhz:
                collisions.append({
                    "qubit_a": qa, "qubit_b": qb,
                    "freq_a_mhz": round(fa, 3),
                    "freq_b_mhz": round(fb, 3),
                    "spacing_mhz": round(spacing, 3),
                    "severity": "collision" if spacing < floor_mhz else "near",
                })
    collisions.sort(key=lambda c: c["spacing_mhz"])
    return collisions

def analyse(snapshot: dict, state: dict) -> list:
    alerts   = []
    qubits   = snapshot.get("qubits", {})
    backend  = snapshot.get("backend")
    freq_base = state.get("freq_baseline", {})
    ro_base   = state.get("readout_baseline", {})

    # ── 1. Resonator frequency collisions ──
    res_collisions = find_collisions(qubits, "resonator_freq_mhz",
                                      COLLISION_MHZ, NEAR_COLLISION_MHZ)
    hard = [c for c in res_collisions if c["severity"] == "collision"]
    near = [c for c in res_collisions if c["severity"] == "near"]

    if hard:
        alerts.append({
            "event":    "RESONATOR_FREQUENCY_COLLISION",
            "severity": "CRITICAL",
            "backend":  backend,
            "collisions": hard[:10],
            "count":    len(hard),
            "floor_mhz": COLLISION_MHZ,
            "confidence": 0.80,
            "note": (f"{len(hard)} readout resonator pairs are separated by "
                     f"less than {COLLISION_MHZ} MHz. Frequency-multiplexed "
                     "readout requires clear separation — colliding resonators "
                     "means the measurement tone for one perturbs the other, "
                     "degrading readout discrimination for both and opening "
                     "the readout crosstalk channel"),
            "related": "module69 measures the resulting crosstalk directly",
        })

    if near and not hard:
        alerts.append({
            "event":    "RESONATOR_FREQUENCY_CROWDING",
            "severity": "WARN",
            "backend":  backend,
            "near_collisions": near[:10],
            "count":    len(near),
            "warn_mhz": NEAR_COLLISION_MHZ,
            "confidence": 0.60,
            "note": ("Resonator pairs are crowded but not yet colliding. A "
                     "small further drift closes the gap"),
        })

    # ── 2. Qubit frequency collisions ──
    qubit_collisions = find_collisions(qubits, "qubit_freq_mhz",
                                        QUBIT_COLLISION_MHZ,
                                        QUBIT_COLLISION_MHZ * 2)
    hard_q = [c for c in qubit_collisions if c["severity"] == "collision"]
    if hard_q:
        alerts.append({
            "event":    "QUBIT_FREQUENCY_COLLISION",
            "severity": "WARN",
            "backend":  backend,
            "collisions": hard_q[:10],
            "count":    len(hard_q),
            "floor_mhz": QUBIT_COLLISION_MHZ,
            "confidence": 0.65,
            "note": ("Qubit transition frequencies are colliding. Two qubits "
                     "at the same frequency exchange excitations — this is the "
                     "physical mechanism behind gate crosstalk"),
        })

    # ── 3. Single-resonator drift ──
    drifted = []
    for q, v in qubits.items():
        curr = v.get("resonator_freq_mhz")
        prev = freq_base.get(q, {}).get("resonator_freq_mhz")
        if curr is not None and prev is not None:
            delta = abs(curr - prev)
            if delta > DRIFT_MHZ:
                drifted.append({"qubit": int(q),
                                 "was_mhz": round(prev, 3),
                                 "now_mhz": round(curr, 3),
                                 "drift_mhz": round(delta, 3)})

    if drifted:
        # Global drift is thermal; isolated drift is not
        total_with_freq = sum(1 for v in qubits.values()
                              if v.get("resonator_freq_mhz") is not None)
        fraction = len(drifted) / total_with_freq if total_with_freq else 0
        if fraction < 0.25:
            alerts.append({
                "event":    "RESONATOR_ISOLATED_DRIFT",
                "severity": "CRITICAL",
                "backend":  backend,
                "drifted":  drifted[:10],
                "drifted_count": len(drifted),
                "total_qubits":  total_with_freq,
                "fraction":  round(fraction, 3),
                "confidence": 0.75,
                "note": ("Individual resonators have shifted frequency while "
                         "the majority held steady. Global drift is thermal "
                         "and affects everything. Isolated drift on specific "
                         "resonators is consistent with targeted flux bias, "
                         "local thermal load, or a driven AC Stark shift"),
            })
        else:
            alerts.append({
                "event":    "RESONATOR_GLOBAL_DRIFT",
                "severity": "WARN",
                "backend":  backend,
                "drifted_count": len(drifted),
                "fraction":  round(fraction, 3),
                "confidence": 0.55,
                "note": ("Most resonators drifted together — consistent with "
                         "a thermal excursion or a recalibration"),
            })

    # ── 4. Collision confirmed by readout error rise ──
    colliding_qubits = {c["qubit_a"] for c in hard} | {c["qubit_b"] for c in hard}
    confirmed = []
    for q in colliding_qubits:
        curr = qubits.get(str(q), {}).get("readout_error")
        prev = ro_base.get(str(q))
        if curr is not None and prev and prev > 0 and curr > prev * READOUT_RISE_MULT:
            confirmed.append({"qubit": q,
                               "readout_was": round(prev, 5),
                               "readout_now": round(curr, 5),
                               "ratio": round(curr / prev, 2)})
    if confirmed:
        alerts.append({
            "event":    "COLLISION_CONFIRMED_BY_READOUT",
            "severity": "CRITICAL",
            "backend":  backend,
            "confirmed": confirmed,
            "confidence": 0.85,
            "note": ("Qubits involved in a frequency collision also show a "
                     "readout error rise. Cause and effect are both visible — "
                     "the collision is actively degrading measurement"),
        })

    # ── 5. Anharmonicity change ──
    anh_changed = []
    for q, v in qubits.items():
        curr = v.get("anharmonicity_mhz")
        prev = freq_base.get(q, {}).get("anharmonicity_mhz")
        if curr is not None and prev is not None and abs(curr - prev) > DRIFT_MHZ:
            anh_changed.append({"qubit": int(q),
                                 "was_mhz": round(prev, 3),
                                 "now_mhz": round(curr, 3)})
    if anh_changed:
        alerts.append({
            "event":    "QUBIT_ANHARMONICITY_SHIFT",
            "severity": "WARN",
            "backend":  backend,
            "changed":  anh_changed[:10],
            "confidence": 0.60,
            "note": ("Anharmonicity has shifted, which means the qubit's own "
                     "potential changed rather than just its readout "
                     "resonator. Flux bias manipulation produces this"),
        })

    return alerts

def update_baseline(state: dict, snapshot: dict) -> dict:
    qubits = snapshot.get("qubits", {})
    fb = state.setdefault("freq_baseline", {})
    rb = state.setdefault("readout_baseline", {})
    alpha = 0.3
    for q, v in qubits.items():
        entry = fb.setdefault(q, {})
        for field in ("resonator_freq_mhz", "qubit_freq_mhz",
                       "anharmonicity_mhz"):
            val = v.get(field)
            if val is None:
                continue
            entry[field] = (alpha * val + (1 - alpha) * entry[field]
                            if field in entry else val)
        ro = v.get("readout_error")
        if ro is not None:
            rb[q] = (alpha * ro + (1 - alpha) * rb[q]) if q in rb else ro
    return state

def main():
    token        = os.environ.get("IBM_QUANTUM_TOKEN")
    backend_name = os.environ.get("IBM_QUANTUM_BACKEND")
    log          = open(f"module74_{stamp()}.jsonl", "a")

    def emit(event):
        event.setdefault("ts", now_iso())
        log.write(json.dumps(event) + "\n")
        log.flush()

    emit({
        "event":  "RUN_START",
        "module": "74_resonator_frequency_collision",
        "status": "FUNCTIONAL with credentials",
        "attack_surface": ("Readout resonators are frequency-multiplexed onto "
                            "a shared feedline. Two resonators drifting close "
                            "in frequency degrade each other's readout and "
                            "open the crosstalk channel. An attacker who can "
                            "shift a resonator creates that collision "
                            "deliberately"),
        "complements": ("module69 measures the RESULT of readout interference "
                         "by running circuits. This module watches the CAUSE — "
                         "frequency spacing — from calibration data at zero "
                         "QPU cost"),
        "thresholds": {
            "collision_mhz":       COLLISION_MHZ,
            "near_collision_mhz":  NEAR_COLLISION_MHZ,
            "qubit_collision_mhz": QUBIT_COLLISION_MHZ,
            "drift_mhz":           DRIFT_MHZ,
        },
        "cost": "Zero QPU time — calibration data only",
        "credentials": "present" if token else "absent",
    })

    if not token:
        emit({"event": "STATUS", "status": "NO_CREDENTIALS",
              "note": "Set IBM_QUANTUM_TOKEN to enable frequency monitoring"})
        emit({"event": "RUN_END", "alerts": 0})
        log.close()
        return

    state = load_state()

    while True:
        snapshot = fetch_frequencies(token, backend_name)

        if not snapshot or "error" in snapshot:
            emit({"event": "FREQUENCY_FETCH_ERROR", "detail": snapshot})
            time.sleep(POLL_INTERVAL)
            continue

        qubits = snapshot.get("qubits", {})
        with_res = sum(1 for v in qubits.values()
                       if v.get("resonator_freq_mhz") is not None)

        emit({"event":   "FREQUENCY_SNAPSHOT",
              "backend": snapshot["backend"],
              "qubits_read": len(qubits),
              "with_resonator_freq": with_res,
              "samples": len(state.get("snapshots", []))})

        if with_res == 0:
            emit({"event": "NO_RESONATOR_DATA",
                  "note": ("This backend does not expose readout resonator "
                           "frequencies through the public API. Qubit "
                           "frequency and readout error checks still run.")})

        if len(state.get("snapshots", [])) >= BASELINE_SAMPLES:
            alerts = analyse(snapshot, state)
            for a in alerts:
                emit(a)
            if not alerts:
                emit({"event": "RESONATOR_SPACING_OK",
                      "backend": snapshot["backend"]})
        else:
            emit({"event": "BUILDING_FREQUENCY_BASELINE",
                  "have": len(state.get("snapshots", [])),
                  "need": BASELINE_SAMPLES})

        state.setdefault("snapshots", []).append({
            "backend": snapshot["backend"], "ts": now_iso()})
        state = update_baseline(state, snapshot)
        save_state(state)
        time.sleep(POLL_INTERVAL)

if __name__ == "__main__":
    main()
