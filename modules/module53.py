#!/usr/bin/env python3
"""
Watchdog — Module 53: Qubit Mapping Attack Detection (Refactored)
"""
import json, os, sys, statistics
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from quantum_providers import get_provider, IBMQuantumProvider

BAD_PERCENTILE      = 0.25
CRITICAL_PERCENTILE = 0.10
MIN_QUBITS_TO_JUDGE = 2
HISTORY_PATH        = os.path.expanduser("~/watchdog_qubit_mapping.json")

def emit(event_type, details):
    print(json.dumps({
        "event": event_type,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        **details
    }))

def load_history():
    if not os.path.exists(HISTORY_PATH):
        return {"mappings": []}
    try:
        with open(HISTORY_PATH) as f:
            return json.load(f)
    except:
        return {"mappings": []}

def save_history(h):
    h["mappings"] = h.get("mappings", [])[-100:]
    with open(HISTORY_PATH, "w") as f:
        json.dump(h, f)

def percentile_rank(value, population, higher_is_better):
    if not population:
        return 0.5
    if higher_is_better:
        below = sum(1 for p in population if p < value)
    else:
        below = sum(1 for p in population if p > value)
    return below / len(population)

def get_backend_stats(backend):
    props = backend.properties(refresh=True)
    if props is None:
        return None
    qubit_stats = {}
    for i in range(backend.num_qubits):
        try:
            qubit_stats[i] = {
                "t1": props.t1(i),
                "t2": props.t2(i),
                "readout": props.readout_error(i),
            }
        except:
            pass
    coupling_errors = {}
    try:
        for gate in props.gates:
            if len(gate.qubits) == 2:
                key = tuple(sorted(gate.qubits))
                for param in gate.parameters:
                    if param.name == "gate_error":
                        prev = coupling_errors.get(key)
                        coupling_errors[key] = max(prev, param.value) if prev is not None else param.value
    except:
        pass
    return {
        "backend": backend.name,
        "num_qubits": backend.num_qubits,
        "qubit_stats": qubit_stats,
        "coupling_errors": coupling_errors,
        "_backend_obj": backend,
    }

def get_assigned_layout(backend):
    try:
        from qiskit import QuantumCircuit, transpile
        qc = QuantumCircuit(4)
        qc.h(0); qc.cx(0,1); qc.cx(1,2); qc.cx(2,3); qc.measure_all()
        t = transpile(qc, backend=backend, optimization_level=1, seed_transpiler=42)
        physical = []
        try:
            layout = t.layout
            if layout is not None:
                physical = list(layout.initial_index_layout(filter_ancillas=True))
        except:
            try:
                seen = set()
                for inst in t.data:
                    for q in inst.qubits:
                        seen.add(t.find_bit(q).index)
                physical = sorted(seen)[:4]
            except:
                pass
        pairs = set()
        try:
            for inst in t.data:
                if len(inst.qubits) == 2:
                    a = t.find_bit(inst.qubits[0]).index
                    b = t.find_bit(inst.qubits[1]).index
                    pairs.add(tuple(sorted((a, b))))
        except:
            pass
        return {"physical_qubits": physical, "coupling_pairs": sorted(pairs), "depth": t.depth()}
    except Exception as e:
        return {"error": str(e)}

def analyse_mapping(stats, layout):
    alerts = []
    assigned = layout.get("physical_qubits", [])
    if len(assigned) < MIN_QUBITS_TO_JUDGE:
        return alerts
    qubit_stats = stats.get("qubit_stats", {})
    if not qubit_stats:
        return alerts

    all_t1 = [v["t1"] for v in qubit_stats.values() if v.get("t1")]
    all_t2 = [v["t2"] for v in qubit_stats.values() if v.get("t2")]
    all_readout = [v["readout"] for v in qubit_stats.values() if v.get("readout") is not None]

    t1_ranks, t2_ranks, ro_ranks = [], [], []
    for q in assigned:
        s = qubit_stats.get(q) or qubit_stats.get(str(q))
        if not s:
            continue
        if s.get("t1") and all_t1:
            t1_ranks.append(percentile_rank(s["t1"], all_t1, True))
        if s.get("t2") and all_t2:
            t2_ranks.append(percentile_rank(s["t2"], all_t2, True))
        if s.get("readout") is not None and all_readout:
            ro_ranks.append(percentile_rank(s["readout"], all_readout, False))

    def flag_ranks(ranks, label, metric):
        if not ranks:
            return
        mean_rank = sum(ranks) / len(ranks)
        if mean_rank < CRITICAL_PERCENTILE:
            alerts.append({
                "event": "QUBIT_MAPPING_WORST_TAIL",
                "severity": "CRITICAL",
                "metric": metric,
                "mean_percentile": round(mean_rank, 3),
                "assigned_qubits": assigned,
                "backend": stats.get("backend"),
                "confidence": 0.80,
                "note": f"Qubits in worst {int(CRITICAL_PERCENTILE*100)}% by {label}",
            })
        elif mean_rank < BAD_PERCENTILE:
            alerts.append({
                "event": "QUBIT_MAPPING_POOR",
                "severity": "INFO",
                "metric": metric,
                "mean_percentile": round(mean_rank, 3),
                "assigned_qubits": assigned,
                "backend": stats.get("backend"),
                "confidence": 0.65,
                "note": f"Qubits in worst {int(BAD_PERCENTILE*100)}% by {label}",
            })

    flag_ranks(t1_ranks, "T1 coherence", "t1")
    flag_ranks(t2_ranks, "T2 coherence", "t2")
    flag_ranks(ro_ranks, "readout fidelity", "readout_error")

    # Coupling check
    coupling_errors = stats.get("coupling_errors", {})
    used_pairs = [tuple(p) for p in layout.get("coupling_pairs", [])]
    if coupling_errors and used_pairs:
        all_errors = list(coupling_errors.values())
        used_errors = [coupling_errors[p] for p in used_pairs if p in coupling_errors]
        if used_errors and all_errors:
            ranks = [percentile_rank(e, all_errors, False) for e in used_errors]
            mean_rank = sum(ranks) / len(ranks)
            if mean_rank < CRITICAL_PERCENTILE:
                alerts.append({
                    "event": "COUPLING_MAPPING_WORST_TAIL",
                    "severity": "CRITICAL",
                    "mean_percentile": round(mean_rank, 3),
                    "used_pairs": used_pairs,
                    "mean_error": round(sum(used_errors)/len(used_errors), 6),
                    "backend_median": round(statistics.median(all_errors), 6) if all_errors else None,
                    "backend": stats.get("backend"),
                    "confidence": 0.85,
                    "note": "Two-qubit gates routed onto worst couplings",
                })
            elif mean_rank < BAD_PERCENTILE:
                alerts.append({
                    "event": "COUPLING_MAPPING_POOR",
                    "severity": "INFO",
                    "mean_percentile": round(mean_rank, 3),
                    "used_pairs": used_pairs,
                    "confidence": 0.60,
                })

    return alerts

def main():
    provider = get_provider()
    if not isinstance(provider, IBMQuantumProvider):
        emit("PROVIDER_NOT_SUPPORTED", {"provider": provider.provider_name,
                                        "note": "Module53 requires IBM Quantum"})
        return

    backend_name = os.getenv("IBM_QUANTUM_BACKEND")
    try:
        backend = provider.get_backend(backend_name)
    except Exception as e:
        emit("BACKEND_FETCH_ERROR", {"error": str(e)})
        return

    emit("RUN_START", {"module": "53_qubit_mapping",
                       "backend": backend.name,
                       "bad_percentile": BAD_PERCENTILE,
                       "critical_percentile": CRITICAL_PERCENTILE})

    stats = get_backend_stats(backend)
    if not stats:
        emit("STATS_FETCH_ERROR", {"detail": "Failed to get backend properties"})
        return

    layout = get_assigned_layout(backend)
    if "error" in layout:
        emit("LAYOUT_ERROR", {"detail": layout["error"]})
        return

    emit("MAPPING_SNAPSHOT", {
        "backend": stats["backend"],
        "backend_qubits": stats["num_qubits"],
        "assigned_qubits": layout["physical_qubits"],
        "coupling_pairs": layout["coupling_pairs"],
        "transpiled_depth": layout["depth"],
    })

    alerts = analyse_mapping(stats, layout)
    for a in alerts:
        emit(a["event"], a)

    history = load_history()
    history["mappings"].append({
        "backend": stats["backend"],
        "assigned": layout["physical_qubits"],
        "ts": datetime.now(timezone.utc).isoformat(),
    })
    save_history(history)

    alert_count = sum(1 for a in alerts if a.get("severity") in ("CRITICAL","WARN"))
    emit("RUN_END", {"alerts": alert_count})

if __name__ == "__main__":
    main()
