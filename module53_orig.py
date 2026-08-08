#!/usr/bin/env python3
"""
Watchdog — Module 53: Qubit Mapping Attack Detection

Attack vector: when a logical circuit is submitted, the layout pass assigns
each logical qubit to a physical qubit on the chip. Physical qubits are not
equal — on any real QPU some have T1 five times better than others, and some
two-qubit couplings have error rates an order of magnitude apart.

An attacker who influences layout selection — via a compromised transpiler
plugin, a manipulated scheduler, or a malicious provider-side default — can
route a tenant's circuit onto the worst physical qubits on the chip. The job
completes. No error is raised. The results are simply wrong, and the tenant
has no way to know why. This is a denial-of-quality attack: invisible,
deniable, and it consumes the tenant's paid allocation.

Method: after transpilation, extract the physical qubits actually assigned,
then compare their real error characteristics against the backend-wide
distribution from backend.properties().

Three checks:
  1. Percentile rank of assigned qubits' T1/T2 vs all qubits on the backend
  2. Percentile rank of assigned two-qubit couplings' gate error
  3. Whether a materially better layout was available and not chosen

Requires: qiskit, qiskit-ibm-runtime
Credentials: IBM_QUANTUM_TOKEN env var
"""
import json, datetime, os, time, statistics
from collections import deque

BAD_PERCENTILE       = 0.25   # assigned qubits in worst 25% = flag
CRITICAL_PERCENTILE  = 0.10   # worst 10% = critical
MIN_QUBITS_TO_JUDGE  = 2      # need at least this many assigned to judge
BETTER_LAYOUT_MARGIN = 1.50   # available layout 1.5x better = flag
POLL_INTERVAL        = 1800   # seconds between checks
HISTORY_FILE         = "/tmp/watchdog_qubit_mapping.json"

def now_iso():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()

def stamp():
    return datetime.datetime.now().strftime("%Y%m%d_%H%M%S")

def load_history() -> dict:
    try:
        with open(HISTORY_FILE) as f:
            return json.load(f)
    except:
        return {"mappings": []}

def save_history(h: dict):
    try:
        h["mappings"] = h.get("mappings", [])[-100:]
        with open(HISTORY_FILE, "w") as f:
            json.dump(h, f)
    except:
        pass

def percentile_rank(value: float, population: list, higher_is_better: bool) -> float:
    """
    Where does `value` sit in `population`? Returns 0.0 (worst) to 1.0 (best).
    higher_is_better=True for T1/T2, False for error rates.
    """
    if not population:
        return 0.5
    if higher_is_better:
        below = sum(1 for p in population if p < value)
    else:
        below = sum(1 for p in population if p > value)
    return below / len(population)

def get_backend_qubit_stats(token: str, backend_name: str | None) -> dict | None:
    """
    Pull per-qubit T1/T2/readout_error and per-coupling gate_error
    for the whole backend. This is the population we rank against.
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

        qubit_stats = {}
        for i in range(backend.num_qubits):
            try:
                qubit_stats[i] = {
                    "t1":      props.t1(i),
                    "t2":      props.t2(i),
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
                            # Keep the worst value if multiple gates on a pair
                            prev = coupling_errors.get(key)
                            coupling_errors[key] = (max(prev, param.value)
                                                     if prev is not None
                                                     else param.value)
        except:
            pass

        return {
            "backend":         backend.name,
            "num_qubits":      backend.num_qubits,
            "qubit_stats":     qubit_stats,
            "coupling_errors": coupling_errors,
            "_backend_obj":    backend,
        }
    except ImportError:
        return {"error": "qiskit_ibm_runtime not installed"}
    except Exception as e:
        return {"error": str(e)}

def get_assigned_layout(backend, optimization_level: int = 1) -> dict | None:
    """
    Transpile a reference circuit and extract which physical qubits the
    layout pass assigned.
    """
    try:
        from qiskit import QuantumCircuit, transpile

        qc = QuantumCircuit(4)
        qc.h(0)
        qc.cx(0, 1)
        qc.cx(1, 2)
        qc.cx(2, 3)
        qc.measure_all()

        t = transpile(qc, backend=backend,
                      optimization_level=optimization_level,
                      seed_transpiler=42)

        physical = []
        try:
            layout = t.layout
            if layout is not None:
                initial = layout.initial_index_layout(filter_ancillas=True)
                physical = list(initial)
        except Exception:
            # Fall back to reading qubit indices off the transpiled ops
            try:
                seen = set()
                for inst in t.data:
                    for q in inst.qubits:
                        seen.add(t.find_bit(q).index)
                physical = sorted(seen)[:4]
            except Exception:
                pass

        # Coupling pairs actually used by two-qubit gates
        pairs = set()
        try:
            for inst in t.data:
                if len(inst.qubits) == 2:
                    a = t.find_bit(inst.qubits[0]).index
                    b = t.find_bit(inst.qubits[1]).index
                    pairs.add(tuple(sorted((a, b))))
        except Exception:
            pass

        return {
            "physical_qubits": physical,
            "coupling_pairs":  sorted(pairs),
            "depth":           t.depth(),
        }
    except Exception as e:
        return {"error": str(e)}

def analyse_mapping(stats: dict, layout: dict) -> list:
    """Rank the assigned qubits against the backend population."""
    alerts = []

    assigned = layout.get("physical_qubits", [])
    if len(assigned) < MIN_QUBITS_TO_JUDGE:
        return alerts

    qubit_stats = stats.get("qubit_stats", {})
    if not qubit_stats:
        return alerts

    # Population distributions across the whole backend
    all_t1      = [v["t1"] for v in qubit_stats.values() if v.get("t1")]
    all_t2      = [v["t2"] for v in qubit_stats.values() if v.get("t2")]
    all_readout = [v["readout"] for v in qubit_stats.values()
                   if v.get("readout") is not None]

    # ── 1. Are the assigned qubits in the bad tail for coherence? ──
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
                "event":    "QUBIT_MAPPING_WORST_TAIL",
                "severity": "CRITICAL",
                "metric":   metric,
                "mean_percentile": round(mean_rank, 3),
                "assigned_qubits": assigned,
                "backend":  stats.get("backend"),
                "confidence": 0.80,
                "note": (f"Circuit mapped onto qubits in the worst "
                         f"{int(CRITICAL_PERCENTILE*100)}% of the backend by "
                         f"{label}. Results will be degraded with no error "
                         f"raised — consistent with a denial-of-quality attack"),
            })
        elif mean_rank < BAD_PERCENTILE:
            alerts.append({
                "event":    "QUBIT_MAPPING_POOR",
                "severity": "WARN",
                "metric":   metric,
                "mean_percentile": round(mean_rank, 3),
                "assigned_qubits": assigned,
                "backend":  stats.get("backend"),
                "confidence": 0.65,
                "note": (f"Assigned qubits sit in the worst "
                         f"{int(BAD_PERCENTILE*100)}% by {label}"),
            })

    flag_ranks(t1_ranks, "T1 coherence",     "t1")
    flag_ranks(t2_ranks, "T2 coherence",     "t2")
    flag_ranks(ro_ranks, "readout fidelity", "readout_error")

    # ── 2. Are the assigned couplings among the worst on the chip? ──
    coupling_errors = stats.get("coupling_errors", {})
    used_pairs      = [tuple(p) for p in layout.get("coupling_pairs", [])]

    if coupling_errors and used_pairs:
        all_errors = list(coupling_errors.values())
        used_errors = [coupling_errors[p] for p in used_pairs
                       if p in coupling_errors]

        if used_errors and all_errors:
            ranks = [percentile_rank(e, all_errors, False) for e in used_errors]
            mean_rank = sum(ranks) / len(ranks)

            if mean_rank < CRITICAL_PERCENTILE:
                alerts.append({
                    "event":    "COUPLING_MAPPING_WORST_TAIL",
                    "severity": "CRITICAL",
                    "mean_percentile": round(mean_rank, 3),
                    "used_pairs":      used_pairs,
                    "mean_error":      round(sum(used_errors)/len(used_errors), 6),
                    "backend_median":  round(statistics.median(all_errors), 6),
                    "backend":  stats.get("backend"),
                    "confidence": 0.85,
                    "note": ("Two-qubit gates routed onto the worst couplings "
                             "on the chip. Entangling operations will fail at "
                             "far above the backend's typical rate"),
                })
            elif mean_rank < BAD_PERCENTILE:
                alerts.append({
                    "event":    "COUPLING_MAPPING_POOR",
                    "severity": "WARN",
                    "mean_percentile": round(mean_rank, 3),
                    "used_pairs":      used_pairs,
                    "confidence": 0.60,
                })

    # ── 3. Was a materially better layout available? ──
    if all_t1 and t1_ranks:
        assigned_mean_t1 = statistics.mean(
            [qubit_stats[q]["t1"] for q in assigned
             if (qubit_stats.get(q) or {}).get("t1")] or [0])
        best_available = sorted(all_t1, reverse=True)[:len(assigned)]
        if best_available and assigned_mean_t1 > 0:
            best_mean = statistics.mean(best_available)
            if best_mean / assigned_mean_t1 > BETTER_LAYOUT_MARGIN:
                alerts.append({
                    "event":    "BETTER_LAYOUT_AVAILABLE",
                    "severity": "WARN",
                    "assigned_mean_t1_us": round(assigned_mean_t1 * 1e6, 2),
                    "best_available_t1_us": round(best_mean * 1e6, 2),
                    "improvement_factor":  round(best_mean / assigned_mean_t1, 2),
                    "backend":  stats.get("backend"),
                    "confidence": 0.55,
                    "note": ("A materially better set of physical qubits was "
                             "available and not selected"),
                })

    return alerts

def main():
    token   = os.environ.get("IBM_QUANTUM_TOKEN")
    backend_name = os.environ.get("IBM_QUANTUM_BACKEND")
    log     = open(f"module53_{stamp()}.jsonl", "a")

    def emit(event):
        event.setdefault("ts", now_iso())
        log.write(json.dumps(event) + "\n")
        log.flush()

    emit({"event": "RUN_START", "module": "53_qubit_mapping",
          "bad_percentile": BAD_PERCENTILE,
          "critical_percentile": CRITICAL_PERCENTILE,
          "credentials": "present" if token else "absent"})

    if not token:
        emit({"event": "STATUS", "status": "NO_CREDENTIALS",
              "note": "Set IBM_QUANTUM_TOKEN to enable qubit mapping analysis"})
        emit({"event": "RUN_END", "alerts": 0})
        log.close()
        return

    history = load_history()
    alerts  = 0

    while True:
        stats = get_backend_qubit_stats(token, backend_name)

        if not stats or "error" in stats:
            emit({"event": "STATS_FETCH_ERROR", "detail": stats})
        else:
            layout = get_assigned_layout(stats["_backend_obj"])

            if not layout or "error" in layout:
                emit({"event": "LAYOUT_ERROR", "detail": layout})
            else:
                emit({"event":   "MAPPING_SNAPSHOT",
                      "backend": stats["backend"],
                      "backend_qubits":   stats["num_qubits"],
                      "assigned_qubits":  layout["physical_qubits"],
                      "coupling_pairs":   layout["coupling_pairs"],
                      "transpiled_depth": layout["depth"]})

                for a in analyse_mapping(stats, layout):
                    alerts += 1
                    emit(a)

                history["mappings"].append({
                    "backend":  stats["backend"],
                    "assigned": layout["physical_qubits"],
                    "ts":       now_iso(),
                })
                save_history(history)

        time.sleep(POLL_INTERVAL)

if __name__ == "__main__":
    main()
