#!/usr/bin/env python3
"""
Watchdog — Module 73: QEC Syndrome Decoder Timing Integrity
Status: FUNCTIONAL — decoder timing analysis works now on any host running
        a decoder; QPU-side syndrome extraction AWAITING_HARDWARE_INTEGRATION

THE ATTACK SURFACE:

  Fault-tolerant quantum computing runs a classical decoder in the loop.
  Every syndrome extraction round produces a set of parity measurements,
  and a classical algorithm — minimum-weight perfect matching, union-find,
  or a neural decoder — must identify the most likely error chain and
  emit a correction before the next round completes.

  This creates a hard real-time constraint that is not optional. If the
  decoder falls behind the syndrome extraction rate, the backlog grows
  without bound. This is the well-documented "backlog problem" in
  fault-tolerant architectures: a decoder that is slower than the
  measurement cycle causes an exponential blowup in latency.

  The attack: an adversary who can delay syndrome delivery, or slow the
  decoder, or perturb decoder timing by a few hundred nanoseconds per
  round, causes the decoder to work on stale or incomplete syndrome data.
  It then misidentifies Pauli error chains. The logical qubit is
  corrupted — silently — while every PHYSICAL error rate on the device
  still reads normal, because the physical qubits are fine. It is the
  classical decoding layer that has been compromised.

  Why it is stealthy: nothing in backend.properties() shows this. T1, T2,
  gate error, readout error all stay nominal. The only observable is the
  decoder's own timing distribution and its correction output.

  A secondary signal: a man-in-the-middle hook intercepting the syndrome
  bitstream imposes its own processing time, which shows as a SUDDEN
  TIGHTENING of the latency distribution — a natural decoder has variance
  driven by syndrome weight, an intercepting shim often does not.

WHAT RUNS NOW (no QPU required):
  Any host running a decoder produces timing data. This module reads it
  and applies real-time-systems analysis:

  1. Round-trip latency distribution — mean, standard deviation, and the
     upper percentiles that actually matter for a hard deadline.
  2. Deadline violations: rounds where decode time exceeded the syndrome
     extraction cycle time. Even a small violation rate compounds.
  3. Backlog growth: whether the queue of undecoded rounds is trending
     upward. This is the definitive failure mode.
  4. Distribution SHAPE change — variance collapse or bimodality, the
     signature of an interposed process.
  5. Syndrome weight versus decode time correlation. A genuine matching
     decoder takes longer on heavier syndromes. If that correlation
     breaks, the decoder is not doing the work it claims.
  6. Logical error rate versus physical error rate divergence: physical
     errors flat while logical errors climb is decoder failure, not
     hardware failure.
  7. Decoder process integrity: binary hash, CPU affinity, scheduling
     priority, and whether it has been reniced or migrated off its
     isolated core.

WHAT NEEDS HARDWARE:
  - Direct FPGA/control-electronics timestamps for syndrome extraction
  - Sub-microsecond round-trip measurement at the control interface
  - Real surface-code syndrome data from a fault-tolerant QPU

If no decoder telemetry is present, this module says so and fires nothing.
"""
import json, os, time, datetime, math, glob, hashlib, statistics
from collections import deque, defaultdict

POLL_INTERVAL              = 60      # seconds between telemetry reads
DEADLINE_VIOLATION_RATE    = 0.01    # >1% of rounds missing deadline = alert
BACKLOG_GROWTH_ROUNDS      = 10      # consecutive rising backlog samples
VARIANCE_COLLAPSE_RATIO    = 0.30    # std drops to this x baseline = interposed
LATENCY_RISE_MULT          = 1.5     # mean latency rise vs baseline
CORRELATION_FLOOR          = 0.30    # syndrome-weight vs time Pearson r floor
LOGICAL_DIVERGENCE_MULT    = 2.0     # logical error rise with flat physical
BASELINE_SAMPLES           = 20
STATE_FILE                 = "/tmp/watchdog_qec_decoder.json"

# Where decoder telemetry commonly lands
DECODER_LOG_GLOBS = [
    "/var/log/qec/*.jsonl",
    "/var/log/qec/decoder*.json",
    "/opt/qec/logs/*.jsonl",
    "/var/lib/qec/decoder_*.json",
    os.path.expanduser("~/qec_decoder/*.jsonl"),
]

# Process names of known decoder implementations
DECODER_PROCESS_MARKERS = [
    "pymatching", "fusion_blossom", "stim", "sinter",
    "union_find", "unionfind", "mwpm", "decoder",
    "chromobius", "tesseract",
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
        return {"samples": [], "baseline": {}, "decoder_binary": {},
                 "backlog_history": [], "established": now_iso()}

def save_state(s: dict):
    try:
        s["samples"] = s.get("samples", [])[-200:]
        s["backlog_history"] = s.get("backlog_history", [])[-50:]
        with open(STATE_FILE, "w") as f:
            json.dump(s, f)
    except:
        pass

def mean_std(values: list) -> tuple:
    if not values:
        return None, None
    if len(values) < 2:
        return values[0], 0.0
    m = sum(values) / len(values)
    var = sum((v - m) ** 2 for v in values) / len(values)
    return m, math.sqrt(var)

def percentile(values: list, p: float) -> float | None:
    if not values:
        return None
    s = sorted(values)
    k = (len(s) - 1) * p
    f = math.floor(k)
    c = math.ceil(k)
    if f == c:
        return s[int(k)]
    return s[f] * (c - k) + s[c] * (k - f)

def pearson(xs: list, ys: list) -> float | None:
    n = len(xs)
    if n < 3 or len(ys) != n:
        return None
    mx, my = sum(xs) / n, sum(ys) / n
    num = sum((x - mx) * (y - my) for x, y in zip(xs, ys))
    dx  = math.sqrt(sum((x - mx) ** 2 for x in xs))
    dy  = math.sqrt(sum((y - my) ** 2 for y in ys))
    if dx == 0 or dy == 0:
        return None
    return num / (dx * dy)

def sha256_file(path: str) -> str | None:
    try:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return None

def find_decoder_logs() -> list:
    found = []
    for pattern in DECODER_LOG_GLOBS:
        found.extend(glob.glob(pattern))
    return sorted(set(found))

def parse_decoder_telemetry(path: str, max_records: int = 500) -> list:
    """
    Read decoder round records. Expected fields — all standard outputs of
    a real-time decoder, none invented:

      decode_time_ns        wall time to decode one syndrome round
      syndrome_round        monotonically increasing round index
      syndrome_weight       number of triggered detectors this round
      cycle_time_ns         syndrome extraction cycle period (the deadline)
      backlog_rounds        rounds awaiting decode
      correction_applied    bool
      logical_error         bool, if a logical error was detected
      physical_error_rate   measured physical error rate this round
      code_distance         surface code distance
    """
    records = []
    try:
        with open(path, errors="replace") as f:
            lines = f.readlines()
        for line in lines[-max_records:]:
            line = line.strip()
            if not line.startswith("{"):
                continue
            try:
                records.append(json.loads(line))
            except Exception:
                pass
    except Exception:
        pass
    return records

def find_decoder_processes() -> list:
    """
    Locate running decoder processes and record their scheduling state.
    A decoder that has been reniced or moved off its isolated core will
    miss deadlines without any code change.
    """
    found = []
    try:
        for pid in os.listdir("/proc"):
            if not pid.isdigit():
                continue
            try:
                with open(f"/proc/{pid}/cmdline", "rb") as f:
                    cmd = (f.read().replace(b"\x00", b" ")
                             .decode("utf-8", errors="replace").strip())
            except Exception:
                continue
            if not cmd:
                continue
            low = cmd.lower()
            if not any(m in low for m in DECODER_PROCESS_MARKERS):
                continue

            entry = {"pid": int(pid), "cmd": cmd[:200]}

            # Executable path and hash
            try:
                exe = os.readlink(f"/proc/{pid}/exe")
                entry["exe"] = exe
                entry["exe_sha256"] = sha256_file(exe)
            except Exception:
                pass

            # Scheduling: nice value and policy from /proc/<pid>/stat
            try:
                with open(f"/proc/{pid}/stat") as f:
                    stat_fields = f.read().split()
                if len(stat_fields) > 18:
                    entry["nice"]     = int(stat_fields[18])
                    entry["priority"] = int(stat_fields[17])
            except Exception:
                pass

            # CPU affinity
            try:
                entry["cpu_affinity"] = sorted(os.sched_getaffinity(int(pid)))
            except Exception:
                pass

            # Scheduling policy
            try:
                policy = os.sched_getscheduler(int(pid))
                entry["sched_policy"] = {
                    0: "SCHED_OTHER", 1: "SCHED_FIFO", 2: "SCHED_RR",
                    3: "SCHED_BATCH", 5: "SCHED_IDLE",
                }.get(policy, str(policy))
            except Exception:
                pass

            found.append(entry)
    except Exception:
        pass
    return found

def analyse_timing(records: list, state: dict) -> list:
    alerts   = []
    baseline = state.get("baseline", {})

    times   = [r["decode_time_ns"] for r in records
               if isinstance(r.get("decode_time_ns"), (int, float))]
    if not times:
        return alerts

    cycles  = [r["cycle_time_ns"] for r in records
               if isinstance(r.get("cycle_time_ns"), (int, float))]
    weights = [r.get("syndrome_weight") for r in records
               if r.get("syndrome_weight") is not None
               and isinstance(r.get("decode_time_ns"), (int, float))]
    weight_times = [r["decode_time_ns"] for r in records
                    if r.get("syndrome_weight") is not None
                    and isinstance(r.get("decode_time_ns"), (int, float))]

    m, sd = mean_std(times)
    p99   = percentile(times, 0.99)
    p999  = percentile(times, 0.999)

    # ── 1. Deadline violations ──
    if cycles:
        cycle_m, _ = mean_std(cycles)
        if cycle_m and cycle_m > 0:
            violations = sum(1 for t in times if t > cycle_m)
            rate = violations / len(times)
            if rate > DEADLINE_VIOLATION_RATE:
                alerts.append({
                    "event":    "QEC_DECODER_DEADLINE_VIOLATION",
                    "severity": "CRITICAL",
                    "violation_rate": round(rate, 5),
                    "threshold":      DEADLINE_VIOLATION_RATE,
                    "violations":     violations,
                    "rounds":         len(times),
                    "cycle_time_ns":  round(cycle_m, 1),
                    "p99_decode_ns":  round(p99, 1) if p99 else None,
                    "p999_decode_ns": round(p999, 1) if p999 else None,
                    "confidence": 0.85,
                    "note": ("The decoder is missing its real-time deadline. "
                             "Syndrome extraction does not pause for a slow "
                             "decoder — every missed deadline adds to a "
                             "backlog that grows without bound. The physical "
                             "qubits remain nominal while logical qubits are "
                             "corrupted by stale corrections"),
                })

    # ── 2. Latency rise from baseline ──
    base_m = baseline.get("decode_time_mean")
    if base_m and m and m > base_m * LATENCY_RISE_MULT:
        alerts.append({
            "event":    "QEC_DECODER_LATENCY_RISE",
            "severity": "WARN",
            "current_mean_ns":  round(m, 1),
            "baseline_mean_ns": round(base_m, 1),
            "ratio":    round(m / base_m, 2),
            "confidence": 0.70,
            "note": ("Decoder round-trip latency has risen materially above "
                     "its own baseline. Even a few hundred nanoseconds per "
                     "round compounds across the extraction cycle"),
        })

    # ── 3. Variance collapse — the interposition signature ──
    base_sd = baseline.get("decode_time_std")
    if base_sd and base_sd > 0 and sd is not None:
        if sd < base_sd * VARIANCE_COLLAPSE_RATIO:
            alerts.append({
                "event":    "QEC_DECODER_TIMING_MANIPULATION",
                "severity": "CRITICAL",
                "current_std_ns":  round(sd, 2),
                "baseline_std_ns": round(base_sd, 2),
                "ratio":    round(sd / base_sd, 3),
                "threshold": VARIANCE_COLLAPSE_RATIO,
                "confidence": 0.75,
                "note": ("The decode-time distribution has SUDDENLY TIGHTENED. "
                         "A genuine matching decoder has variance driven by "
                         "syndrome weight — heavier syndromes take longer. A "
                         "distribution that collapses to near-constant "
                         "indicates an interposed process imposing its own "
                         "uniform processing time on the syndrome bitstream"),
            })

    # ── 4. Syndrome weight vs decode time correlation ──
    if len(weights) >= 20 and len(weight_times) == len(weights):
        r = pearson(weights, weight_times)
        if r is not None and r < CORRELATION_FLOOR:
            alerts.append({
                "event":    "QEC_DECODER_WORK_DECOUPLED",
                "severity": "CRITICAL",
                "pearson_r": round(r, 3),
                "floor":     CORRELATION_FLOOR,
                "samples":   len(weights),
                "confidence": 0.75,
                "note": ("Decode time no longer correlates with syndrome "
                         "weight. A real minimum-weight matching decoder does "
                         "more work on heavier syndromes — that correlation is "
                         "a property of the algorithm. If it has broken, the "
                         "decoder is not performing the matching it reports"),
            })

    return alerts

def analyse_backlog(records: list, state: dict) -> list:
    """The definitive fault-tolerant failure mode: unbounded backlog."""
    alerts = []
    backlogs = [r["backlog_rounds"] for r in records
                if isinstance(r.get("backlog_rounds"), (int, float))]
    if len(backlogs) < 5:
        return alerts

    history = state.setdefault("backlog_history", [])
    history.append(backlogs[-1])

    if len(history) >= BACKLOG_GROWTH_ROUNDS:
        recent = history[-BACKLOG_GROWTH_ROUNDS:]
        rising = all(recent[i] <= recent[i+1] for i in range(len(recent)-1))
        growth = recent[-1] - recent[0]
        if rising and growth > 0:
            alerts.append({
                "event":    "QEC_DECODER_BACKLOG_GROWTH",
                "severity": "CRITICAL",
                "backlog_start": recent[0],
                "backlog_now":   recent[-1],
                "growth":        growth,
                "samples":       BACKLOG_GROWTH_ROUNDS,
                "confidence": 0.90,
                "note": ("The undecoded syndrome backlog has grown "
                         "monotonically across every recent sample. This is "
                         "the backlog problem: once the decoder is slower than "
                         "the extraction cycle, latency blows up "
                         "exponentially and fault tolerance is lost outright"),
            })

    return alerts

def analyse_logical_divergence(records: list) -> list:
    """
    Physical error rate flat while logical error rate climbs. That
    combination cannot be explained by hardware — it is decoder failure.
    """
    alerts = []
    with_both = [r for r in records
                 if r.get("physical_error_rate") is not None
                 and r.get("logical_error") is not None]
    if len(with_both) < 40:
        return alerts

    half = len(with_both) // 2
    early, late = with_both[:half], with_both[half:]

    phys_early, _ = mean_std([r["physical_error_rate"] for r in early])
    phys_late,  _ = mean_std([r["physical_error_rate"] for r in late])
    log_early = sum(1 for r in early if r["logical_error"]) / len(early)
    log_late  = sum(1 for r in late  if r["logical_error"]) / len(late)

    if phys_early and phys_late and log_early > 0:
        phys_ratio = phys_late / phys_early if phys_early > 0 else 1.0
        log_ratio  = log_late / log_early

        # Physical roughly flat, logical climbing
        if 0.8 <= phys_ratio <= 1.2 and log_ratio > LOGICAL_DIVERGENCE_MULT:
            alerts.append({
                "event":    "QEC_LOGICAL_PHYSICAL_DIVERGENCE",
                "severity": "CRITICAL",
                "physical_error_early": round(phys_early, 6),
                "physical_error_late":  round(phys_late, 6),
                "physical_ratio":       round(phys_ratio, 3),
                "logical_error_early":  round(log_early, 5),
                "logical_error_late":   round(log_late, 5),
                "logical_ratio":        round(log_ratio, 2),
                "confidence": 0.85,
                "note": ("Logical error rate has climbed while the physical "
                         "error rate stayed flat. Error correction is supposed "
                         "to make logical errors fall as physical errors hold "
                         "steady. This divergence localises the fault to the "
                         "classical decoding layer, not the quantum hardware — "
                         "which is exactly what a decoder timing attack "
                         "produces"),
            })

    return alerts

def analyse_decoder_processes(procs: list, state: dict) -> list:
    alerts = []
    known = state.setdefault("decoder_binary", {})

    for p in procs:
        key = p.get("exe") or p.get("cmd", "")[:60]

        # Binary changed
        curr_hash = p.get("exe_sha256")
        prev_hash = known.get(key)
        if prev_hash and curr_hash and prev_hash != curr_hash:
            alerts.append({
                "event":    "QEC_DECODER_BINARY_CHANGED",
                "severity": "CRITICAL",
                "exe":      p.get("exe"),
                "pid":      p.get("pid"),
                "was_hash": prev_hash[:32] + "...",
                "now_hash": curr_hash[:32] + "...",
                "confidence": 0.90,
                "note": ("The decoder executable has changed. The program "
                         "deciding which Pauli errors occurred is not the "
                         "program that was verified"),
            })
        if curr_hash:
            known[key] = curr_hash

        # Scheduling policy — a hard real-time decoder should not be SCHED_OTHER
        policy = p.get("sched_policy")
        if policy == "SCHED_OTHER":
            alerts.append({
                "event":    "QEC_DECODER_NOT_REALTIME",
                "severity": "WARN",
                "pid":      p.get("pid"),
                "exe":      p.get("exe"),
                "sched_policy": policy,
                "nice":     p.get("nice"),
                "confidence": 0.65,
                "note": ("The decoder is running under the default scheduler "
                         "with no real-time priority. It will be preempted by "
                         "ordinary system load, and its deadline is not "
                         "enforced by the kernel"),
                "remediation": "chrt --fifo 80 -p <pid>",
            })

        # Renice — a positive nice value deprioritises the decoder
        nice = p.get("nice")
        if nice is not None and nice > 0:
            alerts.append({
                "event":    "QEC_DECODER_DEPRIORITISED",
                "severity": "CRITICAL",
                "pid":      p.get("pid"),
                "nice":     nice,
                "confidence": 0.75,
                "note": ("The decoder process has a positive nice value — it "
                         "has been deliberately deprioritised. This slows "
                         "decoding without touching a single line of code"),
            })

        # Affinity collapsed to a shared or single busy core
        aff = p.get("cpu_affinity")
        if aff is not None and len(aff) == os.cpu_count():
            alerts.append({
                "event":    "QEC_DECODER_NOT_PINNED",
                "severity": "WARN",
                "pid":      p.get("pid"),
                "cpu_affinity": aff,
                "confidence": 0.55,
                "note": ("The decoder is free to run on any CPU. A hard "
                         "real-time decoder should be pinned to an isolated "
                         "core so it is not competing with other work"),
            })

    return alerts

def update_baseline(state: dict, records: list) -> dict:
    times = [r["decode_time_ns"] for r in records
             if isinstance(r.get("decode_time_ns"), (int, float))]
    if not times:
        return state
    state.setdefault("samples", []).extend(times[-50:])
    samples = state["samples"][-500:]
    state["samples"] = samples
    if len(samples) >= BASELINE_SAMPLES:
        m, sd = mean_std(samples)
        b = state.setdefault("baseline", {})
        b["decode_time_mean"] = m
        b["decode_time_std"]  = sd
    return state

def main():
    log = open(f"module73_{stamp()}.jsonl", "a")

    def emit(event):
        event.setdefault("ts", now_iso())
        log.write(json.dumps(event) + "\n")
        log.flush()

    emit({
        "event":  "RUN_START",
        "module": "73_qec_decoder_timing",
        "status": ("FUNCTIONAL for decoder-side analysis; QPU syndrome "
                    "extraction timing AWAITING_HARDWARE_INTEGRATION"),
        "attack_surface": ("Fault-tolerant QC runs a classical decoder under a "
                            "hard real-time deadline. Delay the syndrome "
                            "stream or slow the decoder and it misidentifies "
                            "Pauli error chains — corrupting logical qubits "
                            "while every physical error rate still reads "
                            "nominal"),
        "functional_now": [
            "Decode latency distribution: mean, std, p99, p999",
            "Deadline violation rate against syndrome cycle time",
            "Backlog growth detection (the definitive FT failure mode)",
            "Variance collapse — the interposed-process signature",
            "Syndrome weight vs decode time correlation",
            "Logical vs physical error rate divergence",
            "Decoder binary hash, nice value, scheduling policy, CPU affinity",
        ],
        "awaiting_hardware": [
            "Direct FPGA/control-electronics syndrome extraction timestamps",
            "Sub-microsecond round-trip measurement at the control interface",
            "Real surface-code syndrome data from a fault-tolerant QPU",
        ],
        "thresholds": {
            "deadline_violation_rate": DEADLINE_VIOLATION_RATE,
            "backlog_growth_rounds":   BACKLOG_GROWTH_ROUNDS,
            "variance_collapse_ratio": VARIANCE_COLLAPSE_RATIO,
            "latency_rise_mult":       LATENCY_RISE_MULT,
            "correlation_floor":       CORRELATION_FLOOR,
        },
        "decoder_markers": DECODER_PROCESS_MARKERS,
    })

    state = load_state()

    while True:
        logs  = find_decoder_logs()
        procs = find_decoder_processes()

        emit({"event": "DECODER_SCAN",
              "telemetry_files":   len(logs),
              "decoder_processes": len(procs),
              "process_detail": [{"pid": p["pid"],
                                   "sched": p.get("sched_policy"),
                                   "nice":  p.get("nice")} for p in procs]})

        if not logs and not procs:
            emit({
                "event":  "NO_QEC_DECODER_PRESENT",
                "status": "AWAITING_QEC_SYSTEM",
                "searched_logs": DECODER_LOG_GLOBS,
                "note": ("No QEC decoder telemetry or decoder process found on "
                         "this host. This module reads timing a real decoder "
                         "already produces — it does not simulate syndrome "
                         "data. Point it at a fault-tolerant control host to "
                         "activate."),
                "expected_fields": [
                    "decode_time_ns", "syndrome_round", "syndrome_weight",
                    "cycle_time_ns", "backlog_rounds", "correction_applied",
                    "logical_error", "physical_error_rate", "code_distance",
                ],
            })
            time.sleep(POLL_INTERVAL)
            continue

        alerts = []

        if procs:
            alerts.extend(analyse_decoder_processes(procs, state))

        for path in logs:
            records = parse_decoder_telemetry(path)
            if not records:
                continue

            times = [r["decode_time_ns"] for r in records
                     if isinstance(r.get("decode_time_ns"), (int, float))]
            m, sd = mean_std(times) if times else (None, None)

            emit({"event":  "DECODER_TELEMETRY_READ",
                  "source": path,
                  "records": len(records),
                  "mean_decode_ns": round(m, 1) if m else None,
                  "std_decode_ns":  round(sd, 2) if sd else None,
                  "p99_decode_ns":  round(percentile(times, 0.99), 1)
                                     if times else None,
                  "code_distance": records[-1].get("code_distance")})

            file_alerts = []
            file_alerts.extend(analyse_timing(records, state))
            file_alerts.extend(analyse_backlog(records, state))
            file_alerts.extend(analyse_logical_divergence(records))
            for a in file_alerts:
                a["source"] = path
            alerts.extend(file_alerts)

            state = update_baseline(state, records)

        for a in alerts:
            emit(a)

        if not alerts and (logs or procs):
            emit({"event": "QEC_DECODER_INTEGRITY_OK",
                  "telemetry_files": len(logs),
                  "processes":       len(procs)})

        save_state(state)
        time.sleep(POLL_INTERVAL)

if __name__ == "__main__":
    main()
