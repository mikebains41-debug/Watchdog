#!/usr/bin/env python3
"""
Watchdog — Module 70: Non-Local Attack Path Analyser
Status: FUNCTIONAL — topology analysis offline, live scoring with credentials

PUBLISHED ATTACK THIS MODULE MAPS:

  "Pulse-to-Circuit Characterization of Stealthy Crosstalk Attack on
  Multi-Tenant Superconducting Quantum Hardware." arXiv:2509.11407.

  The finding that changes the threat model: even when the attacker is
  NOT a direct neighbour of the victim, the adversary can leverage an
  intermediate qubit as a conduit. By applying suitably shaped and timed
  pulses to their own qubit and to an intermediate qubit, an attacker
  induces targeted, stealthy integrity violations on a victim qubit two
  hops away. The paper names this the "attack-through-a-neighbor"
  pathway and concludes that crosstalk vulnerabilities extend beyond
  direct couplings, making device topology a critical security
  consideration.

  "Pulse-Level Simulation of Crosstalk Attacks on Superconducting Quantum
  Hardware." arXiv:2507.16181. Establishes that protocol vulnerability
  varies greatly — circuits relying on precise state preparation are most
  at risk, while others show notable resilience.

  QubitHammer — arXiv:2504.07875. Independently demonstrates qubit
  flipping when attacker and victim are far apart on the same QPU.

WHY BUFFER QUBITS ARE NOT SUFFICIENT: module68 enforces a one- or two-hop
buffer around an allocation, which is the published recommendation. This
module exists because the published recommendation has a documented
limit. A two-hop buffer stops direct crosstalk. It does not stop an
attacker who owns a qubit three hops away and drives an intermediate
qubit as a relay. The literature states this plainly: "buffer qubits
alone may not be enough to isolate quantum circuits."

WHAT THIS MODULE DOES — it is a threat-surface map, not a live detector:
  1. Builds the full device coupling graph from backend.coupling_map.
  2. For the tenant's allocated qubits, enumerates every 2-hop and 3-hop
     path that originates outside the allocation and terminates on an
     allocated qubit.
  3. Scores each path by conduit quality: a relay qubit with long T1/T2
     and low gate error carries a pulse further with less attenuation,
     making it a better attack conduit. High-quality relay qubits
     adjacent to an allocation are the real exposure.
  4. Identifies articulation points — single qubits whose isolation
     would sever the largest number of attack paths. This is the
     actionable output: which one qubit to leave idle.
  5. Ranks the allocation's overall non-local exposure and compares
     alternatives.
  6. Detects when a previously-safe path has become viable because a
     relay qubit's calibration improved.

Requires: qiskit-ibm-runtime for live topology and calibration
Credentials: IBM_QUANTUM_TOKEN
"""
import json, os, time, datetime, math
from collections import defaultdict, deque

POLL_INTERVAL       = 1800   # seconds between topology analyses
MAX_PATH_HOPS       = 3      # enumerate paths up to this length
RELAY_QUALITY_HIGH  = 0.70   # relay score above this = effective conduit
EXPOSURE_WARN       = 5      # viable non-local paths above this = flag
EXPOSURE_CRITICAL   = 15
STATE_FILE          = "/tmp/watchdog_nonlocal_paths.json"

def now_iso():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()

def stamp():
    return datetime.datetime.now().strftime("%Y%m%d_%H%M%S")

def load_state() -> dict:
    try:
        with open(STATE_FILE) as f:
            return json.load(f)
    except:
        return {"path_counts": {}, "relay_scores": {}, "established": now_iso()}

def save_state(s: dict):
    try:
        with open(STATE_FILE, "w") as f:
            json.dump(s, f)
    except:
        pass

def build_adjacency(coupling_map: list) -> dict:
    adj = defaultdict(set)
    for pair in coupling_map:
        if len(pair) == 2:
            adj[pair[0]].add(pair[1])
            adj[pair[1]].add(pair[0])
    return adj

def relay_quality(props_map: dict, q: int, cx_errors: dict,
                   adj: dict) -> float:
    """
    How good a conduit is this qubit for relaying a crosstalk pulse?

    A relay carries a driven excitation from an attacker toward a victim.
    It is effective when:
      - Its coherence is long (T1/T2) — the excitation survives transit
      - Its coupling gate errors are LOW — strong, clean coupling
      - It has multiple neighbours — more onward routes

    Score in [0, 1]. Higher means a better attack conduit, which is worse
    for the defender.
    """
    p = props_map.get(q) or props_map.get(str(q))
    if not p:
        return 0.0

    t1 = p.get("t1") or 0.0
    t2 = p.get("t2") or 0.0
    # Normalise against a 200us reference; cap at 1.0
    t1_s = min((t1 * 1e6) / 200.0, 1.0)
    t2_s = min((t2 * 1e6) / 200.0, 1.0)

    # Mean coupling error on this qubit's edges — lower error = better conduit
    errs = []
    for nxt in adj.get(q, ()):
        key = f"{min(q, nxt)}_{max(q, nxt)}"
        e = cx_errors.get(key)
        if e is not None:
            errs.append(e)
    if errs:
        mean_err = sum(errs) / len(errs)
        # A 1% two-qubit error is typical; scale so lower error scores higher
        coupling_s = max(0.0, 1.0 - min(mean_err / 0.02, 1.0))
    else:
        coupling_s = 0.5

    degree_s = min(len(adj.get(q, ())) / 4.0, 1.0)

    return round(0.35 * t1_s + 0.25 * t2_s +
                 0.30 * coupling_s + 0.10 * degree_s, 4)

def enumerate_attack_paths(allocated: set, adj: dict,
                            max_hops: int = MAX_PATH_HOPS) -> list:
    """
    Every simple path of length 2..max_hops that starts on a qubit
    OUTSIDE the allocation and ends on a qubit INSIDE it, with all
    intermediate qubits also outside.

    A length-1 path is direct coupling — that is module68's job.
    Length 2+ is the attack-through-a-neighbor pathway.
    """
    paths = []
    outside = [q for q in adj if q not in allocated]

    for start in outside:
        # DFS from each outside qubit
        stack = [(start, [start])]
        while stack:
            node, path = stack.pop()
            if len(path) > max_hops + 1:
                continue
            for nxt in adj.get(node, ()):
                if nxt in path:
                    continue
                new_path = path + [nxt]
                hops = len(new_path) - 1
                if hops > max_hops:
                    continue
                if nxt in allocated:
                    # Terminates on the victim. Only record if there was
                    # at least one intermediate relay (hops >= 2).
                    if hops >= 2:
                        paths.append({
                            "attacker": start,
                            "relays":   new_path[1:-1],
                            "victim":   nxt,
                            "hops":     hops,
                        })
                    # Do not continue through an allocated qubit
                    continue
                stack.append((nxt, new_path))
    return paths

def score_paths(paths: list, props_map: dict, cx_errors: dict,
                 adj: dict) -> list:
    """Attach a conduit-quality score to each path."""
    scored = []
    for p in paths:
        relays = p["relays"]
        if not relays:
            continue
        scores = [relay_quality(props_map, r, cx_errors, adj) for r in relays]
        # A chain is only as good as its weakest relay
        chain_score = min(scores) if scores else 0.0
        # Longer chains attenuate further
        attenuated = chain_score * (0.7 ** (p["hops"] - 2))
        scored.append({**p,
                        "relay_scores":  [round(s, 4) for s in scores],
                        "chain_score":   round(chain_score, 4),
                        "viability":     round(attenuated, 4)})
    scored.sort(key=lambda x: -x["viability"])
    return scored

def find_articulation_relays(paths: list) -> list:
    """
    Which single relay qubit appears in the most viable attack paths?
    Isolating that one qubit severs the most routes — the highest-value
    defensive move available.
    """
    counts = defaultdict(lambda: {"paths": 0, "total_viability": 0.0})
    for p in paths:
        for r in p["relays"]:
            counts[r]["paths"] += 1
            counts[r]["total_viability"] += p.get("viability", 0)

    ranked = [{"relay": r,
                "paths_severed": v["paths"],
                "viability_removed": round(v["total_viability"], 4)}
               for r, v in counts.items()]
    ranked.sort(key=lambda x: -x["viability_removed"])
    return ranked[:5]

def fetch_topology(token: str, backend_name: str | None) -> dict | None:
    try:
        from qiskit_ibm_runtime import QiskitRuntimeService
        svc = QiskitRuntimeService(token=token)
        backend = (svc.backend(backend_name) if backend_name
                   else svc.least_busy(operational=True, simulator=False,
                                        min_num_qubits=5))
        props = backend.properties(refresh=True)

        coupling = []
        try:
            cm = backend.coupling_map
            if cm is not None:
                coupling = [list(e) for e in cm]
        except Exception:
            pass

        props_map = {}
        cx_errors = {}
        if props is not None:
            for i in range(backend.num_qubits):
                try:
                    props_map[i] = {"t1": props.t1(i), "t2": props.t2(i),
                                     "readout": props.readout_error(i)}
                except Exception:
                    pass
            try:
                for gate in props.gates:
                    if len(gate.qubits) == 2:
                        key = f"{min(gate.qubits)}_{max(gate.qubits)}"
                        for param in gate.parameters:
                            if param.name == "gate_error":
                                prev = cx_errors.get(key)
                                cx_errors[key] = (max(prev, param.value)
                                                   if prev is not None
                                                   else param.value)
            except Exception:
                pass

        return {"backend":      backend.name,
                 "num_qubits":   backend.num_qubits,
                 "coupling_map": coupling,
                 "props_map":    props_map,
                 "cx_errors":    cx_errors,
                 "_backend_obj": backend}
    except ImportError:
        return {"error": "qiskit_ibm_runtime not installed"}
    except Exception as e:
        return {"error": str(e)}

def get_allocation(backend, n_qubits: int = 4) -> list:
    try:
        from qiskit import QuantumCircuit, transpile
        qc = QuantumCircuit(n_qubits)
        qc.h(0)
        for i in range(n_qubits - 1):
            qc.cx(i, i + 1)
        qc.measure_all()
        t = transpile(qc, backend=backend, optimization_level=1,
                      seed_transpiler=42)
        try:
            layout = t.layout
            if layout is not None:
                return list(layout.initial_index_layout(filter_ancillas=True))
        except Exception:
            pass
        seen = set()
        for inst in t.data:
            for q in inst.qubits:
                seen.add(t.find_bit(q).index)
        return sorted(seen)[:n_qubits]
    except Exception:
        return []

def analyse(topology: dict, allocated: list, state: dict) -> tuple:
    alerts = []
    if not allocated:
        return alerts, state

    adj = build_adjacency(topology.get("coupling_map", []))
    if not adj:
        return alerts, state

    alloc_set = set(allocated)
    props_map = topology.get("props_map", {})
    cx_errors = topology.get("cx_errors", {})
    backend   = topology.get("backend")

    raw_paths = enumerate_attack_paths(alloc_set, adj)
    scored    = score_paths(raw_paths, props_map, cx_errors, adj)

    viable = [p for p in scored if p["viability"] >= RELAY_QUALITY_HIGH * 0.5]
    high   = [p for p in scored if p["viability"] >= RELAY_QUALITY_HIGH]

    # ── 1. Overall non-local exposure ──
    if len(viable) >= EXPOSURE_CRITICAL:
        sev = "CRITICAL"
        conf = 0.75
    elif len(viable) >= EXPOSURE_WARN:
        sev = "WARN"
        conf = 0.60
    else:
        sev = None
        conf = 0.0

    if sev:
        alerts.append({
            "event":    "NONLOCAL_ATTACK_SURFACE",
            "severity": sev,
            "backend":  backend,
            "allocation": sorted(alloc_set),
            "viable_path_count": len(viable),
            "high_viability_count": len(high),
            "total_paths_enumerated": len(raw_paths),
            "max_hops_analysed": MAX_PATH_HOPS,
            "top_paths": viable[:5],
            "confidence": conf,
            "citation": "arXiv:2509.11407 (attack-through-a-neighbor)",
            "note": (f"{len(viable)} viable non-local attack paths reach this "
                     "allocation through intermediate relay qubits. A buffer "
                     "qubit stops direct crosstalk but does not stop an "
                     "attacker driving a relay two or three hops away. The "
                     "published literature states buffer qubits alone may not "
                     "be enough to isolate quantum circuits"),
        })

    # ── 2. High-quality relay conduits ──
    if high:
        relay_set = sorted({r for p in high for r in p["relays"]})
        alerts.append({
            "event":    "HIGH_QUALITY_RELAY_ADJACENT",
            "severity": "WARN",
            "backend":  backend,
            "relay_qubits": relay_set,
            "path_count": len(high),
            "example_path": high[0],
            "confidence": 0.65,
            "citation": "arXiv:2509.11407; arXiv:2504.07875",
            "note": ("Relay qubits with long coherence and low coupling error "
                     "sit adjacent to this allocation. A well-calibrated relay "
                     "carries a driven excitation further with less "
                     "attenuation, making it a more effective attack conduit "
                     "than a noisy one. Good hardware is worse for isolation"),
        })

    # ── 3. Articulation points — the actionable output ──
    articulations = find_articulation_relays(viable)
    if articulations and articulations[0]["paths_severed"] >= 3:
        top = articulations[0]
        alerts.append({
            "event":    "RELAY_ARTICULATION_POINT",
            "severity": "INFO",
            "backend":  backend,
            "recommended_isolate": top["relay"],
            "paths_severed":       top["paths_severed"],
            "viability_removed":   top["viability_removed"],
            "alternatives":        articulations[1:4],
            "confidence": 0.60,
            "note": (f"Leaving qubit {top['relay']} idle would sever "
                     f"{top['paths_severed']} non-local attack paths — the "
                     "single highest-value isolation available for this "
                     "allocation"),
            "remediation": (f"Extend the buffer to include qubit {top['relay']}, "
                            "or move the allocation away from it"),
        })

    # ── 4. Relay quality improved since baseline ──
    prev_relays = state.get("relay_scores", {})
    newly_viable = []
    for p in high:
        for r in p["relays"]:
            score = relay_quality(props_map, r, cx_errors, adj)
            prev  = prev_relays.get(str(r))
            if prev is not None and score > prev * 1.3 and score >= RELAY_QUALITY_HIGH:
                newly_viable.append({"relay": r,
                                      "was": round(prev, 4),
                                      "now": round(score, 4)})
    if newly_viable:
        alerts.append({
            "event":    "RELAY_PATH_NEWLY_VIABLE",
            "severity": "WARN",
            "backend":  backend,
            "relays":   newly_viable[:5],
            "confidence": 0.55,
            "note": ("A relay qubit's calibration improved enough to make a "
                     "previously-attenuated attack path viable. Recalibration "
                     "changes the threat surface, not just the fidelity"),
        })

    # Persist relay scores
    state["relay_scores"] = {
        str(q): relay_quality(props_map, q, cx_errors, adj)
        for q in adj if q not in alloc_set
    }
    state["path_counts"] = {"viable": len(viable), "high": len(high),
                             "total": len(raw_paths)}

    return alerts, state

def main():
    token        = os.environ.get("IBM_QUANTUM_TOKEN")
    backend_name = os.environ.get("IBM_QUANTUM_BACKEND")
    log          = open(f"module70_{stamp()}.jsonl", "a")

    def emit(event):
        event.setdefault("ts", now_iso())
        log.write(json.dumps(event) + "\n")
        log.flush()

    emit({
        "event":  "RUN_START",
        "module": "70_nonlocal_attack_paths",
        "status": "FUNCTIONAL with credentials",
        "citations": [
            ("Pulse-to-Circuit Characterization of Stealthy Crosstalk Attack "
             "on Multi-Tenant Superconducting Quantum Hardware — arXiv:2509.11407"),
            ("Pulse-Level Simulation of Crosstalk Attacks on Superconducting "
             "Quantum Hardware — arXiv:2507.16181"),
            "QubitHammer — arXiv:2504.07875",
        ],
        "why_module68_is_not_enough": ("module68 enforces the published "
                                        "buffer-qubit defence. The literature "
                                        "states buffer qubits alone may not be "
                                        "enough — an attacker three hops away "
                                        "can drive an intermediate qubit as a "
                                        "relay. This module maps that surface"),
        "thresholds": {
            "max_path_hops":       MAX_PATH_HOPS,
            "relay_quality_high":  RELAY_QUALITY_HIGH,
            "exposure_warn":       EXPOSURE_WARN,
            "exposure_critical":   EXPOSURE_CRITICAL,
        },
        "output_type": ("Threat-surface map with a concrete recommendation, "
                         "not a live intrusion detector"),
        "credentials": "present" if token else "absent",
    })

    if not token:
        emit({"event": "STATUS", "status": "NO_CREDENTIALS",
              "note": ("Set IBM_QUANTUM_TOKEN to enable topology and "
                       "calibration-weighted path analysis")})
        emit({"event": "RUN_END", "alerts": 0})
        log.close()
        return

    state = load_state()

    while True:
        topology = fetch_topology(token, backend_name)

        if not topology or "error" in topology:
            emit({"event": "TOPOLOGY_FETCH_ERROR", "detail": topology})
            time.sleep(POLL_INTERVAL)
            continue

        allocated = get_allocation(topology["_backend_obj"])

        adj = build_adjacency(topology.get("coupling_map", []))
        emit({"event":          "TOPOLOGY_SNAPSHOT",
              "backend":        topology["backend"],
              "num_qubits":     topology["num_qubits"],
              "coupling_edges": len(topology.get("coupling_map", [])),
              "allocation":     sorted(allocated),
              "mean_degree":    round(
                  sum(len(v) for v in adj.values()) / len(adj), 2)
                  if adj else 0})

        alerts, state = analyse(topology, allocated, state)
        for a in alerts:
            emit(a)

        if not alerts:
            emit({"event":   "NONLOCAL_SURFACE_ACCEPTABLE",
                  "backend": topology["backend"],
                  "allocation": sorted(allocated),
                  "path_counts": state.get("path_counts", {})})

        save_state(state)
        time.sleep(POLL_INTERVAL)

if __name__ == "__main__":
    main()
