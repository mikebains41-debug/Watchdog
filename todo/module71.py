#!/usr/bin/env python3
"""
Watchdog — Module 71: QKD Detector Blinding & Control Attack Guard
Status: PARTIAL — statistical detection functional, optical monitoring
        AWAITING_HARDWARE_INTEGRATION

PUBLISHED ATTACKS THIS MODULE DETECTS:

  Detector blinding / faked-state attack family
    Lydersen, L., Wiechers, C., Wittmann, C., Elser, D., Skaar, J. &
    Makarov, V. "Hacking commercial quantum cryptography systems by
    tailored bright illumination." Nature Photonics 4, 686-689 (2010).

    The mechanism: single-photon avalanche photodiodes can be blinded by
    a macroscopic light level into giving no response at all. A stronger
    pulse then forces the blinded detector to emit an output that looks
    exactly like a genuine photon detection. Eve intercepts, measures in
    a basis of her choice, and re-emits faked states. The receiver
    reports normal detections. The error-correction step does not flag
    it. The key is fully recovered without being noticed.

    Experimentally demonstrated against both avalanche photodiodes and
    superconducting nanowire detectors, and shown to allow complete key
    recovery from a real QKD implementation.

  Countermeasures that were tested and DEFEATED
    Huang, A., Sajeed, S., Chaiwongkhot, P., Soucarros, M., Legré, M. &
    Makarov, V. "Testing random-detector-efficiency countermeasure in a
    commercial system reveals a breakable unrealistic assumption."
    IEEE J. Quantum Electronics 52(11), 1-11 (2016).

    Tested the first commercial implementation of a blinding
    countermeasure in the Clavis2 system. Result: effective against the
    ORIGINAL blinding attack, but NOT against a modified version where
    the trigger pulses are time-aligned to coincide with the detector
    gates rather than following them. The modified attack fully controls
    Bob's detectors without triggering the security alarm.

  Photon number splitting
    Practical QKD approximates single photons with attenuated coherent
    pulses. Multi-photon pulses let Eve split off a copy. The decoy-state
    method is the standard defence — and its statistics are exactly what
    this module monitors.

  Detector self-testing countermeasure
    "Countering detector manipulation attacks in quantum communication
    through detector self-testing." APL Photonics 10, 016106 (2025).
    Confirms blinding remains one of the biggest concerns in the field.

WHAT RUNS NOW (no optical hardware required):
  Every one of these attacks leaves a statistical fingerprint in the QKD
  session logs that the protocol itself already produces. This module
  reads those logs and applies the published detection criteria:

  1. Detection-rate anomaly — blinding forces a detector into linear
     mode, changing the click statistics away from Poissonian.
  2. QBER-versus-detection-rate decoupling — in an intercept-resend
     attack QBER should rise toward 25%; if detection rate climbs while
     QBER stays suspiciously flat, the detectors are being controlled.
  3. Decoy-state ratio violation — the signal/decoy/vacuum yield ratios
     have protocol-mandated bounds. PNS attacks distort them.
  4. Detector efficiency mismatch between the two detectors — the
     signature of an efficiency-mismatch or time-shift attack.
  5. After-pulse rate collapse — a blinded APD in linear mode stops
     after-pulsing. Zero after-pulses is physically wrong.
  6. Sifted-key ratio drift and double-click rate anomalies.

WHAT NEEDS HARDWARE (documented, not simulated):
  - Watchdog photodiode on a high-transmission beam splitter at the
    receiver input, sampling incoming optical power. This is the
    canonical countermeasure from the literature and directly detects
    the bright illumination used for blinding.
  - APD bias current monitoring: a blinded detector draws a
    characteristic elevated current.
  - Random detector-efficiency modulation with the verification that
    Huang et al. showed the naive implementation lacked.
  - Optical power meter with ~1 MHz sampling, or an analog comparator,
    on the detector output — Automated verification of countermeasure
    against detector-control attack, EPJ Quantum Technology (2023),
    established this is sufficient to reveal pulsed blinding.

NO SIMULATED OPTICAL DATA. If no QKD session log is present, this module
says so and fires nothing.
"""
import json, os, time, datetime, math, glob, statistics
from collections import deque

POLL_INTERVAL            = 60      # seconds between log reads
DETECTION_RATE_SIGMA     = 4.0     # deviations from baseline detection rate
QBER_INTERCEPT_RESEND    = 0.25    # theoretical QBER for full intercept-resend
QBER_FLAT_TOLERANCE      = 0.02    # QBER considered "flat" within this band
DETECTION_RISE_MULT      = 1.5     # detection rate rise triggering correlation check
DECOY_RATIO_TOLERANCE    = 0.30    # fractional deviation in decoy yields
EFFICIENCY_MISMATCH_MAX  = 0.15    # max acceptable detector efficiency imbalance
AFTERPULSE_FLOOR         = 0.001   # below this after-pulse rate = suspicious
DOUBLE_CLICK_SPIKE       = 3.0     # x baseline double-click rate
BASELINE_SAMPLES         = 20
STATE_FILE               = "/tmp/watchdog_qkd_blinding.json"

# Where QKD systems commonly write session statistics
QKD_LOG_GLOBS = [
    "/var/log/qkd/*.json",
    "/var/log/qkd/*.jsonl",
    "/opt/qkd/logs/*.json",
    "/var/lib/qkd/session_*.json",
    os.path.expanduser("~/qkd_sessions/*.json"),
]

def now_iso():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()

def stamp():
    return datetime.datetime.now().strftime("%Y%m%d_%H%M%S")

def load_state() -> dict:
    try:
        with open(STATE_FILE) as f:
            return json.load(f)
    except:
        return {"sessions": [], "baseline": {}, "established": now_iso()}

def save_state(s: dict):
    try:
        s["sessions"] = s.get("sessions", [])[-200:]
        with open(STATE_FILE, "w") as f:
            json.dump(s, f)
    except:
        pass

def mean_std(values: list) -> tuple:
    if len(values) < 2:
        return None, None
    m = sum(values) / len(values)
    var = sum((v - m) ** 2 for v in values) / len(values)
    return m, math.sqrt(var)

def find_qkd_logs() -> list:
    """Locate QKD session statistic files on this host."""
    found = []
    for pattern in QKD_LOG_GLOBS:
        found.extend(glob.glob(pattern))
    return sorted(set(found))

def parse_session(path: str) -> dict | None:
    """
    Read one QKD session record. Expected fields — all standard QKD
    protocol outputs, none invented:

      detection_rate       clicks per second
      qber                 quantum bit error rate
      sifted_key_length    bits after basis sifting
      raw_key_length       bits before sifting
      double_clicks        simultaneous clicks on both detectors
      afterpulse_rate      APD after-pulse probability
      detector_0_counts    per-detector click counts
      detector_1_counts
      decoy_yield_signal   decoy-state protocol yields
      decoy_yield_decoy
      decoy_yield_vacuum
      mu_signal            mean photon numbers
      mu_decoy
    """
    try:
        with open(path) as f:
            content = f.read().strip()
        if not content:
            return None
        # Support both a single JSON object and JSONL
        if content.startswith("{") and "\n" not in content.strip():
            return json.loads(content)
        last = None
        for line in content.splitlines():
            line = line.strip()
            if line.startswith("{"):
                try:
                    last = json.loads(line)
                except:
                    pass
        return last
    except Exception:
        return None

def check_detection_rate(session: dict, baseline: dict) -> list:
    """
    Blinding pushes an APD out of Geiger mode into linear mode. The
    click statistics change character — this catches the rate shift.
    """
    alerts = []
    rate = session.get("detection_rate")
    if rate is None:
        return alerts
    m = baseline.get("detection_rate_mean")
    s = baseline.get("detection_rate_std")
    if m is None or s is None or s == 0:
        return alerts
    z = abs(rate - m) / s
    if z > DETECTION_RATE_SIGMA:
        alerts.append({
            "event":    "QKD_DETECTION_RATE_ANOMALY",
            "severity": "WARN",
            "detection_rate": rate,
            "baseline_mean":  round(m, 4),
            "baseline_std":   round(s, 4),
            "z_score":        round(z, 2),
            "threshold_sigma": DETECTION_RATE_SIGMA,
            "confidence": 0.60,
            "citation": "Lydersen et al., Nature Photonics 4, 686-689 (2010)",
            "note": ("Detection rate has moved far from its own baseline. "
                     "Blinding forces the detector out of Geiger mode into "
                     "linear mode, which changes the click statistics"),
        })
    return alerts

def check_qber_decoupling(session: dict, baseline: dict) -> list:
    """
    THE PRIMARY BLINDING SIGNATURE.

    In a genuine intercept-resend attack QBER rises toward 25% because
    Eve guesses the basis wrong half the time. The entire point of a
    detector-control attack is that it does NOT raise QBER — Eve
    deterministically controls what Bob detects.

    So: detection rate climbing while QBER stays flat is the fingerprint
    of a successful detector-control attack. That combination is exactly
    what a blinding attack produces and what the error-correction step
    fails to catch.
    """
    alerts = []
    qber = session.get("qber")
    rate = session.get("detection_rate")
    if qber is None or rate is None:
        return alerts

    m_rate = baseline.get("detection_rate_mean")
    m_qber = baseline.get("qber_mean")
    if m_rate is None or m_qber is None or m_rate == 0:
        return alerts

    rate_ratio = rate / m_rate
    qber_delta = abs(qber - m_qber)

    if rate_ratio > DETECTION_RISE_MULT and qber_delta < QBER_FLAT_TOLERANCE:
        alerts.append({
            "event":    "QKD_DETECTOR_CONTROL_SUSPECTED",
            "severity": "CRITICAL",
            "detection_rate":       rate,
            "baseline_rate":        round(m_rate, 4),
            "rate_ratio":           round(rate_ratio, 2),
            "qber":                 qber,
            "baseline_qber":        round(m_qber, 5),
            "qber_delta":           round(qber_delta, 5),
            "expected_qber_if_intercept_resend": QBER_INTERCEPT_RESEND,
            "confidence": 0.85,
            "citation": ("Lydersen et al., Nature Photonics 4, 686-689 (2010); "
                          "Huang et al., IEEE J. Quantum Electron. 52(11) (2016)"),
            "note": ("Detection rate rose sharply while QBER stayed flat. A "
                     "genuine intercept-resend attack drives QBER toward 25%. "
                     "An attack that raises detections WITHOUT raising QBER is "
                     "the signature of detector control — Eve is deciding what "
                     "Bob detects. Error correction will not catch this"),
            "action": ("Discard the entire accumulated raw key and start a new "
                        "session. Do not proceed to privacy amplification"),
        })
    return alerts

def check_decoy_states(session: dict) -> list:
    """
    Decoy-state protocol yields have bounds set by the protocol itself.
    A photon-number-splitting attack distorts the relationship between
    signal, decoy and vacuum yields.
    """
    alerts = []
    y_sig = session.get("decoy_yield_signal")
    y_dec = session.get("decoy_yield_decoy")
    y_vac = session.get("decoy_yield_vacuum")
    mu_s  = session.get("mu_signal")
    mu_d  = session.get("mu_decoy")

    if None in (y_sig, y_dec, mu_s, mu_d):
        return alerts

    # Vacuum yield is the dark-count floor. It must not exceed the
    # decoy yield — that ordering is physical, not statistical.
    if y_vac is not None and y_dec is not None and y_vac > y_dec:
        alerts.append({
            "event":    "QKD_DECOY_ORDERING_VIOLATION",
            "severity": "CRITICAL",
            "yield_vacuum": y_vac,
            "yield_decoy":  y_dec,
            "confidence": 0.80,
            "note": ("Vacuum-state yield exceeds decoy-state yield. The vacuum "
                     "state contains no photons — its yield is the dark-count "
                     "floor and cannot exceed a state that does carry photons. "
                     "Something is generating detections that are not signal"),
        })

    # For a channel with transmittance eta, yields scale roughly with mu.
    # A large departure from the expected ratio indicates PNS or an
    # intensity-modulation attack.
    if mu_d > 0 and y_dec > 0:
        expected_ratio = mu_s / mu_d
        observed_ratio = y_sig / y_dec
        if expected_ratio > 0:
            deviation = abs(observed_ratio - expected_ratio) / expected_ratio
            if deviation > DECOY_RATIO_TOLERANCE:
                alerts.append({
                    "event":    "QKD_DECOY_YIELD_ANOMALY",
                    "severity": "CRITICAL",
                    "expected_ratio": round(expected_ratio, 4),
                    "observed_ratio": round(observed_ratio, 4),
                    "deviation":      round(deviation, 4),
                    "tolerance":      DECOY_RATIO_TOLERANCE,
                    "mu_signal":      mu_s,
                    "mu_decoy":       mu_d,
                    "confidence": 0.80,
                    "citation": "Decoy-state method against photon number splitting",
                    "note": ("Signal-to-decoy yield ratio departs from the "
                             "protocol expectation. A photon-number-splitting "
                             "attacker preferentially forwards multi-photon "
                             "pulses, which distorts exactly this ratio"),
                })
    return alerts

def check_detector_symmetry(session: dict) -> list:
    """
    Efficiency mismatch and time-shift attacks work by making one
    detector more sensitive than the other at a chosen moment.
    """
    alerts = []
    d0 = session.get("detector_0_counts")
    d1 = session.get("detector_1_counts")
    if d0 is None or d1 is None:
        return alerts
    total = d0 + d1
    if total == 0:
        return alerts
    imbalance = abs(d0 - d1) / total
    if imbalance > EFFICIENCY_MISMATCH_MAX:
        alerts.append({
            "event":    "QKD_DETECTOR_EFFICIENCY_MISMATCH",
            "severity": "WARN",
            "detector_0": d0,
            "detector_1": d1,
            "imbalance":  round(imbalance, 4),
            "threshold":  EFFICIENCY_MISMATCH_MAX,
            "confidence": 0.70,
            "note": ("The two detectors are reporting materially different "
                     "count rates. For a balanced basis choice they should be "
                     "close. Efficiency mismatch is the enabling condition for "
                     "time-shift and faked-state attacks"),
        })
    return alerts

def check_afterpulsing(session: dict) -> list:
    """
    A real avalanche photodiode after-pulses. A blinded APD operating in
    linear mode does not — it is no longer avalanching. An after-pulse
    rate of essentially zero is physically wrong for a working APD.
    """
    alerts = []
    ap = session.get("afterpulse_rate")
    if ap is None:
        return alerts
    if ap < AFTERPULSE_FLOOR:
        alerts.append({
            "event":    "QKD_AFTERPULSE_COLLAPSE",
            "severity": "CRITICAL",
            "afterpulse_rate": ap,
            "floor":     AFTERPULSE_FLOOR,
            "confidence": 0.80,
            "citation": "Lydersen et al., Nature Photonics 4, 686-689 (2010)",
            "note": ("After-pulse rate has collapsed to essentially zero. A "
                     "functioning avalanche photodiode always after-pulses. A "
                     "blinded APD held in linear mode does not avalanche at "
                     "all, so it stops after-pulsing. This is a direct "
                     "physical indicator of detector blinding"),
        })
    return alerts

def check_double_clicks(session: dict, baseline: dict) -> list:
    """
    Double clicks — both detectors firing at once — carry information
    about faked states. Their rate should be stable.
    """
    alerts = []
    dc = session.get("double_clicks")
    if dc is None:
        return alerts
    m = baseline.get("double_click_mean")
    if m is None or m <= 0:
        return alerts
    if dc > m * DOUBLE_CLICK_SPIKE:
        alerts.append({
            "event":    "QKD_DOUBLE_CLICK_SPIKE",
            "severity": "WARN",
            "double_clicks": dc,
            "baseline":      round(m, 4),
            "ratio":         round(dc / m, 2),
            "confidence": 0.65,
            "note": ("Double-click rate has spiked. Faked-state attacks that "
                     "are imperfectly aligned produce excess double clicks — "
                     "how these are handled in sifting affects security"),
        })
    return alerts

def update_baseline(state: dict) -> dict:
    """Rebuild statistical baselines from the session history."""
    sessions = state.get("sessions", [])
    if len(sessions) < BASELINE_SAMPLES:
        return state

    recent = sessions[-100:]
    b = state.setdefault("baseline", {})

    rates = [s["detection_rate"] for s in recent
             if s.get("detection_rate") is not None]
    if rates:
        m, sd = mean_std(rates)
        b["detection_rate_mean"] = m
        b["detection_rate_std"]  = sd

    qbers = [s["qber"] for s in recent if s.get("qber") is not None]
    if qbers:
        m, sd = mean_std(qbers)
        b["qber_mean"] = m
        b["qber_std"]  = sd

    dcs = [s["double_clicks"] for s in recent
           if s.get("double_clicks") is not None]
    if dcs:
        m, _ = mean_std(dcs)
        b["double_click_mean"] = m

    return state

def main():
    log = open(f"module71_{stamp()}.jsonl", "a")

    def emit(event):
        event.setdefault("ts", now_iso())
        log.write(json.dumps(event) + "\n")
        log.flush()

    emit({
        "event":  "RUN_START",
        "module": "71_qkd_detector_blinding",
        "status": ("PARTIAL — statistical detection functional, optical "
                    "monitoring AWAITING_HARDWARE_INTEGRATION"),
        "citations": [
            ("Lydersen, Wiechers, Wittmann, Elser, Skaar & Makarov — Hacking "
             "commercial quantum cryptography systems by tailored bright "
             "illumination. Nature Photonics 4, 686-689 (2010)"),
            ("Huang, Sajeed, Chaiwongkhot, Soucarros, Legré & Makarov — "
             "Testing random-detector-efficiency countermeasure in a "
             "commercial system reveals a breakable unrealistic assumption. "
             "IEEE J. Quantum Electron. 52(11), 1-11 (2016)"),
            ("Countering detector manipulation attacks in quantum "
             "communication through detector self-testing. APL Photonics 10, "
             "016106 (2025)"),
            ("Automated verification of countermeasure against "
             "detector-control attack in QKD. EPJ Quantum Technology (2023)"),
        ],
        "functional_now": [
            "Detection-rate anomaly against session baseline",
            "QBER-vs-detection-rate decoupling (primary blinding signature)",
            "Decoy-state yield ordering and ratio validation",
            "Detector efficiency mismatch",
            "After-pulse collapse (blinded APD stops avalanching)",
            "Double-click rate spikes",
        ],
        "awaiting_hardware": [
            ("Watchdog photodiode on a high-transmission beam splitter at the "
             "receiver input — the canonical countermeasure, directly detects "
             "the bright illumination used for blinding"),
            "APD bias current monitoring (blinded detectors draw elevated current)",
            ("Random detector-efficiency modulation with the verification "
             "Huang et al. showed the naive commercial implementation lacked"),
            ("Optical power sampling at ~1 MHz or an analog comparator on the "
             "detector output — shown sufficient to reveal pulsed blinding"),
        ],
        "known_defeated_countermeasure": (
            "Huang et al. (2016) tested the first commercial blinding "
            "countermeasure in Clavis2 and found it effective against the "
            "original attack but NOT against a modified version that "
            "time-aligns trigger pulses with the detector gates. Any "
            "countermeasure claim must specify which attack variant it stops"),
        "thresholds": {
            "detection_rate_sigma":    DETECTION_RATE_SIGMA,
            "qber_flat_tolerance":     QBER_FLAT_TOLERANCE,
            "detection_rise_mult":     DETECTION_RISE_MULT,
            "decoy_ratio_tolerance":   DECOY_RATIO_TOLERANCE,
            "efficiency_mismatch_max": EFFICIENCY_MISMATCH_MAX,
            "afterpulse_floor":        AFTERPULSE_FLOOR,
        },
    })

    state = load_state()

    while True:
        logs = find_qkd_logs()

        if not logs:
            emit({
                "event":  "NO_QKD_SESSION_LOGS",
                "status": "AWAITING_QKD_SYSTEM",
                "searched": QKD_LOG_GLOBS,
                "note": ("No QKD session logs found on this host. This module "
                         "reads statistics the QKD protocol already produces — "
                         "it does not simulate them. Point it at a real QKD "
                         "system's session output to activate."),
                "expected_fields": [
                    "detection_rate", "qber", "sifted_key_length",
                    "raw_key_length", "double_clicks", "afterpulse_rate",
                    "detector_0_counts", "detector_1_counts",
                    "decoy_yield_signal", "decoy_yield_decoy",
                    "decoy_yield_vacuum", "mu_signal", "mu_decoy",
                ],
            })
            time.sleep(POLL_INTERVAL)
            continue

        for path in logs:
            session = parse_session(path)
            if not session:
                continue

            baseline = state.get("baseline", {})
            alerts = []
            alerts.extend(check_detection_rate(session, baseline))
            alerts.extend(check_qber_decoupling(session, baseline))
            alerts.extend(check_decoy_states(session))
            alerts.extend(check_detector_symmetry(session))
            alerts.extend(check_afterpulsing(session))
            alerts.extend(check_double_clicks(session, baseline))

            emit({"event":  "QKD_SESSION_READ",
                  "source": path,
                  "detection_rate": session.get("detection_rate"),
                  "qber":           session.get("qber"),
                  "sifted_key_length": session.get("sifted_key_length"),
                  "baseline_ready": len(state.get("sessions", [])) >= BASELINE_SAMPLES})

            for a in alerts:
                a["source"] = path
                emit(a)

            if not alerts and len(state.get("sessions", [])) >= BASELINE_SAMPLES:
                emit({"event":  "QKD_SESSION_CLEAN",
                      "source": path,
                      "qber":   session.get("qber")})

            state["sessions"].append({
                "detection_rate": session.get("detection_rate"),
                "qber":           session.get("qber"),
                "double_clicks":  session.get("double_clicks"),
                "ts":             now_iso(),
            })

        state = update_baseline(state)

        if len(state.get("sessions", [])) == BASELINE_SAMPLES:
            emit({"event": "QKD_BASELINE_ESTABLISHED",
                  "samples": BASELINE_SAMPLES,
                  "baseline": state.get("baseline", {})})

        save_state(state)
        time.sleep(POLL_INTERVAL)

if __name__ == "__main__":
    main()
