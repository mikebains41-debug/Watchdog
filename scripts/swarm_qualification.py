#!/usr/bin/env python3
"""
Watchdog Swarm — Agent Qualification Harness
Author: Manmohan (Mike) Bains / GPU Optimizer Inc.

Answers four questions before any agent joins a voting pool:

  1. DISCOVERY     Which agents import, construct, and actually fire?
                   An agent that never fires on any input is structurally
                   silent, not merely inaccurate. That distinction decides
                   whether you fix telemetry or fix the agent.

  2. TPR / FPR     Per-agent accuracy on randomized synthetic trials.
                   Fresh noise per trial, severity varied per trial. Not a
                   replayed fixture: an agent must not be able to pass by
                   matching a known input.

  3. PAIRWISE      Agreement matrix across agents. Two agents agreeing
                   above the threshold are functionally one agent wearing
                   two hats, and both will carry weight in a vote they
                   should share.

  4. ENSEMBLE      Weighted consensus vs. the single best agent, on the
                   same corpus. THIS IS THE PASS/FAIL TEST FOR THE WHOLE
                   SWARM. If the ensemble does not beat the best single
                   agent, the coordination layer is adding noise and more
                   agents will add more noise.

WHAT THIS DOES NOT DO
  It does not prove any precursor pattern precedes a real event on real
  hardware. Synthetic trials test whether the scoring logic generalizes
  across randomized severity. Real, timestamped hardware data is a
  separate and still-missing requirement.

USAGE
  python3 swarm_qualification.py                       # full run
  python3 swarm_qualification.py --n-clean 500 --n-event 500
  python3 swarm_qualification.py --discover-only       # no scoring
  python3 swarm_qualification.py --json out.json
"""

import argparse
import importlib
import os
import json
import math
import random
import zlib
import sys
from datetime import datetime, timezone

# Run from anywhere: put the repository root on sys.path so
# intelligence.swarm.* resolves whether this is invoked from scripts/,
# the repo root, or an absolute path.
_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)
for _p in (_ROOT, _HERE):
    if _p not in sys.path:
        sys.path.insert(0, _p)

# --------------------------------------------------------------------------
# Agent registry. Import path, class name, constructor kwargs.
# Sourced from intelligence/swarm/swarm_orchestrator.py, not assumed.
# --------------------------------------------------------------------------

AGENT_SPECS = [
    ("agent1", "intelligence.swarm.agent1_ghost_power_predictor",
     "GhostPowerPredictor", {"gpu_id": 0, "idle_floor_w": 80.36}),
    ("agent2", "intelligence.swarm.agent2_cei_degradation_forecaster",
     "CEIDegradationForecaster", {"gpu_id": 0}),
    ("agent3", "intelligence.swarm.agent3_thermal_event_predictor",
     "ThermalEventPredictor", {"gpu_id": 0, "gpu_arch": "H200"}),
    ("agent4", "intelligence.swarm.agent4_tenant_isolation_risk_scorer",
     "TenantIsolationRiskScorer", {"gpu_id": 0, "gpu_arch": "H200"}),
    ("agent5", "intelligence.swarm.agent5_eu_ai_act_compliance_forecaster",
     "EUAIActComplianceForecaster", {"gpu_id": 0}),
    ("agent6", "intelligence.swarm.agent6_rowhammer_precursor_predictor",
     "RowhammerPrecursorPredictor", {"gpu_id": 0}),
    ("agent7", "intelligence.swarm.agent7_cryptojacking_onset_predictor",
     "CryptojackingOnsetPredictor", {"gpu_id": 0}),
    ("agent8", "intelligence.swarm.agent8_model_extraction_precursor_predictor",
     "ModelExtractionPrecursorPredictor", {"gpu_id": 0}),
]

# H200 baseline, measured 2026-09-19 on 4x H200 SXM (RunPod, driver 570.124.06).
SUSTAIN = 30   # trajectory length; must exceed the largest agent window (20)

BASE = {
    "idle_floor_w": 78.4,
    "ctx_alive_w": 126.0,
    "active_w": 692.0,
    "sm_clock_idle": 345.0,
    "sm_clock_active": 1980.0,
    "mem_clock": 3201.0,
    "temp_idle": 34.0,
    "temp_active": 57.0,
    "temp_throttle": 83.0,
}


# --------------------------------------------------------------------------
# Telemetry generation
# --------------------------------------------------------------------------

def clean_row(rng, t_index=0, state=None):
    """One CLEAN telemetry row with realistic jitter.

    "Clean" is two different states and conflating them is the single
    biggest source of false positives in this system:

      cold        no CUDA context.        ~78W at 345MHz.
      ctx_alive   context held, no work.  ~126W at 345MHz.

    Both are clean. Neither is an attack. But a ghost-power detector
    configured with the COLD floor (78.4W) sees every ctx_alive sample as
    ~47W above floor at 0% utilization, which is its exact firing
    condition. No real Watchdog agent has shown this yet; the check is
    kept because a cold-only corpus would hide it if one did.

    Any negative-control corpus that contains only cold-idle rows will
    score a broken detector as perfect. This one carries both, in a 50/50
    mix, because a GPU serving an idle model is the commonest state in
    production and a detector that alarms on it is unusable.
    """
    if state is None:
        state = "cold" if rng.random() < 0.5 else "ctx_alive"
    watts = BASE["idle_floor_w"] if state == "cold" else BASE["ctx_alive_w"]
    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "gpu_id": 0,
        "sample_index": t_index,
        "idle_state": state,
        "power_watts": watts + rng.gauss(0, 1.2),
        "gpu_util": max(0.0, rng.gauss(0.4, 0.5)),
        "mem_util": max(0.0, rng.gauss(1.0, 0.8)),
        "sm_clock_mhz": BASE["sm_clock_idle"] + rng.gauss(0, 3),
        "mem_clock_mhz": BASE["mem_clock"],
        "temp_c": BASE["temp_idle"] + rng.gauss(0, 0.6),
        "memory_used_mb": 620.0 + rng.gauss(0, 2),
        "vram_used_mb": 620.0 + rng.gauss(0, 2),
        "inference_req_per_s": max(0.0, rng.gauss(2.0, 0.5)),
        "avg_req_compute_ms": max(1.0, rng.gauss(40.0, 5.0)),
        "ecc_corrected_total": 0,
        "ecc_uncorrectable_total": 0,
        "mem_bw_util_pct": max(0.0, rng.gauss(2.0, 1.0)),
        "pcie_rx_mb_s": max(0.0, rng.gauss(3.0, 2.0)),
        "pcie_tx_mb_s": max(0.0, rng.gauss(3.0, 2.0)),
        "power_limit_w": 700.0,
        "fan_pct": 30.0 + rng.gauss(0, 1),
    }


def inject(row, agent_key, severity, rng, progress=1.0, phantom=True):
    """Apply an agent-appropriate PRECURSOR TRAJECTORY.

    These agents are PREDICTORS, not detectors. They score a transition
    toward an event, not the event itself. GhostPowerPredictor weights
    "power dropping more than 50W across the window" at 0.30 and
    "utilization falling toward zero" at 0.20 — half its total weight is on
    movement. Feeding it a flat, already-ghosted GPU scores 0.50 against an
    0.82 threshold and fires nothing, which is exactly what a steady-state
    injection produced.

    progress runs 0.0 -> 1.0 across the sustained window, so each row is a
    point on a trajectory rather than a repeat of the same state.

    severity in [0,1] scales how pronounced the trajectory is. Low severity
    is deliberately included: an agent that only fires at 1.0 is not useful.

    phantom=False withholds fields that production telemetry does not
    actually supply (currently memory_access_timing_ms). Use it to measure
    what an agent does in deployment rather than in a harness that feeds it
    a field it will never receive.

    Returns (row, injected_bool).
    """
    r = dict(row)
    s = max(0.0, min(1.0, severity))
    g = max(0.0, min(1.0, progress))

    if agent_key == "agent1":
        # Ghost power: workload winding down. Power and utilization fall
        # together; the memory clock does NOT, which is the signature.
        util_start, util_end = 95.0, 0.0
        pw_start = BASE["active_w"] * (0.55 + 0.45 * s)
        pw_end = BASE["idle_floor_w"] + 15.0 + (110.0 * s)
        r["gpu_util"] = max(0.0, util_start + (util_end - util_start) * g)
        r["power_watts"] = pw_start + (pw_end - pw_start) * g
        r["sm_clock_mhz"] = BASE["sm_clock_active"] + (BASE["sm_clock_idle"] - BASE["sm_clock_active"]) * g
        r["mem_clock_mhz"] = BASE["mem_clock"]          # locked: the tell
        r["temp_c"] = BASE["temp_active"] - 10.0 * g
        return r, True

    if agent_key == "agent3":
        # Thermal: temperature climbing toward the throttle point.
        t_start = BASE["temp_active"]
        t_end = BASE["temp_throttle"] - 1.0 + (1.0 * s)
        r["temp_c"] = t_start + (t_end - t_start) * g + rng.gauss(0, 0.25)
        r["power_watts"] = BASE["active_w"] * (0.70 + 0.28 * g)
        r["gpu_util"] = 80.0 + 19.0 * g
        r["sm_clock_mhz"] = BASE["sm_clock_active"]
        r["fan_pct"] = 55.0 + 44.0 * g
        return r, True

    if agent_key == "agent6":
        # ECC counters are cumulative, so this one needs accumulation rather
        # than a ramp. It qualified at 100% under the flat model for exactly
        # that reason.
        r["ecc_corrected_total"] = int(1 + 60 * s * g)
        r["ecc_uncorrectable_total"] = 1 if (s > 0.85 and g > 0.8) else 0
        r["mem_bw_util_pct"] = 35.0 + 60.0 * s * g
        return r, True

    if agent_key == "agent7":
        # Cryptojacking onset: utilization ramping UP to a sustained plateau,
        # memory bandwidth staying low. Compute-heavy, memory-light.
        r["gpu_util"] = 4.0 + (93.0 + 5.0 * s) * g
        r["sm_clock_mhz"] = BASE["sm_clock_idle"] + (BASE["sm_clock_active"] - BASE["sm_clock_idle"]) * g
        r["power_watts"] = BASE["ctx_alive_w"] + (BASE["active_w"] * (0.78 + 0.2 * s) - BASE["ctx_alive_w"]) * g
        r["mem_bw_util_pct"] = max(0.5, 12.0 - 9.0 * s * g)
        r["temp_c"] = BASE["temp_idle"] + (BASE["temp_active"] - BASE["temp_idle"]) * g
        return r, True

    if agent_key == "agent8":
        # Model extraction: request rate climbing while per-request compute
        # collapses. Many trivial queries is the extraction signature.
        r["inference_req_per_s"] = 2.0 + (280.0 * s) * g
        r["avg_req_compute_ms"] = max(1.0, 40.0 - (36.0 * s) * g)
        r["vram_used_mb"] = 620.0 + (30000.0 * s) * g
        r["memory_used_mb"] = r["vram_used_mb"]
        r["pcie_tx_mb_s"] = 5.0 + (5000.0 * s) * g
        r["power_watts"] = BASE["ctx_alive_w"] + (70.0 * s) * g
        r["mem_bw_util_pct"] = 20.0 + 70.0 * s * g
        return r, True

    if agent_key == "agent4":
        # Tenant isolation: VRAM residual climbing.
        r["vram_used_mb"] = 629.0 + (9000.0 * s) * g
        r["memory_used_mb"] = r["vram_used_mb"]
        r["mem_bw_util_pct"] = 25.0 + 55.0 * s * g
        r["power_watts"] = BASE["ctx_alive_w"] + 40.0 * s * g
        r["gpu_util"] = max(0.0, 3.0 - 2.0 * g)
        if phantom:
            # memory_access_timing_ms is the agent's dominant weighted signal
            # and NOTHING in agent/telemetry.py collects it. Supplying it
            # here measures the agent in a condition that cannot occur in
            # deployment. Run with --no-phantom to see the real figure.
            r["memory_access_timing_ms"] = 0.30 + 3.2 * s * g
        return r, True

    if agent_key == "agent2":
        # Requires cei_flops_per_joule, which no passive nvidia-smi field
        # provides under any name. intelligence/cei_benchmark.py exists to
        # produce it and has never been run on hardware.
        if phantom:
            r["cei_flops_per_joule"] = 9.70e11 * (1.0 - 0.65 * s * g)
        r["power_watts"] = BASE["active_w"]
        r["gpu_util"] = 95.0
        return r, True

    if agent_key == "agent5":
        if phantom:
            r["cei_flops_per_joule"] = 9.70e11 * (1.0 - 0.55 * s * g)
        r["ghost_power_pct"] = 4.0 + 28.0 * s * g
        r["crash_count"] = int(3 * s * g)
        r["isolation_score"] = 1.0 - 0.75 * s * g
        return r, True

    return r, False


# --------------------------------------------------------------------------
# Discovery
# --------------------------------------------------------------------------

def load_agents(specs, verbose=True):
    """Import and construct each agent. Never raises: a failure is a result."""
    loaded, failed = [], []
    for key, module_path, cls_name, kwargs in specs:
        try:
            mod = importlib.import_module(module_path)
        except Exception as e:
            failed.append((key, cls_name, "IMPORT_FAILED", "%s: %s" % (type(e).__name__, e)))
            continue
        cls = getattr(mod, cls_name, None)
        if cls is None:
            failed.append((key, cls_name, "CLASS_NOT_FOUND",
                           "module imported but %s is absent" % cls_name))
            continue
        try:
            inst = cls(**kwargs)
        except Exception as e:
            failed.append((key, cls_name, "CONSTRUCT_FAILED",
                           "%s: %s" % (type(e).__name__, e)))
            continue
        if not hasattr(inst, "update"):
            failed.append((key, cls_name, "NO_UPDATE_METHOD",
                           "public methods: %s" % [m for m in dir(inst) if not m.startswith("_")]))
            continue
        loaded.append((key, cls_name, inst, cls, kwargs))

    if verbose:
        print("=" * 72)
        print("1. DISCOVERY")
        print("=" * 72)
        for key, cls_name, _, _, _ in loaded:
            print("  [OK]   %-8s %s" % (key, cls_name))
        for key, cls_name, code, detail in failed:
            print("  [FAIL] %-8s %-36s %s" % (key, cls_name, code))
            print("         %s" % detail)
        print("  %d/%d agents loaded" % (len(loaded), len(specs)))
        print()
    return loaded, failed


def fresh(cls, kwargs):
    """A new agent instance. Agents carry learned baselines, so every trial
    gets a clean one — otherwise trial N is contaminated by trial N-1."""
    return cls(**kwargs)


# --------------------------------------------------------------------------
# Scoring
# --------------------------------------------------------------------------

def run_trial(agent, rows):
    """Feed a sequence of rows. Return True if the agent fired at least once."""
    fired = False
    for row in rows:
        try:
            out = agent.update(row)
        except Exception:
            # An agent that raises on well-formed telemetry has failed the
            # trial. It does not get to be counted as a non-firing pass.
            return None
        if out:
            fired = True
    return fired


def qualify(loaded, n_clean, n_event, warmup, seed, verbose=True, phantom=True):
    """Per-agent TPR/FPR plus silence detection."""
    results = {}
    if verbose:
        print("=" * 72)
        print("2. PER-AGENT TPR / FPR   (%d clean, %d event trials, warmup %d)"
              % (n_clean, n_event, warmup))
        print("=" * 72)

    for key, cls_name, _inst, cls, kwargs in loaded:
        rng = random.Random(seed + zlib.crc32(key.encode()) % 100000)
        # zlib.crc32, not hash(): Python randomizes string hashing per
        # process unless PYTHONHASHSEED is set, which made identical
        # invocations produce different trial data and different TPRs.
        errors = 0

        # --- clean trials: agent must stay silent -------------------------
        # Split by idle state. An agent that is clean on cold-idle and noisy
        # on context-alive is not 50% accurate, it is misconfigured, and the
        # aggregate FPR hides which.
        fp = 0
        fp_by_state = {"cold": 0, "ctx_alive": 0}
        n_by_state = {"cold": 0, "ctx_alive": 0}
        for i in range(n_clean):
            state = "cold" if i % 2 == 0 else "ctx_alive"
            n_by_state[state] += 1
            agent = fresh(cls, kwargs)
            rows = [clean_row(rng, j, state=state) for j in range(warmup)]
            r = run_trial(agent, rows)
            if r is None:
                errors += 1
            elif r:
                fp += 1
                fp_by_state[state] += 1

        # --- event trials: agent must fire --------------------------------
        tp = 0
        injectable = True
        severities = []
        for _ in range(n_event):
            agent = fresh(cls, kwargs)
            sev = rng.uniform(0.15, 1.0)     # randomized per trial
            severities.append(sev)
            rows = [clean_row(rng, i) for i in range(warmup)]
            ev, ok = inject(clean_row(rng, warmup), key, sev, rng, 0.0, phantom)
            if not ok:
                injectable = False
                break
            # Ramp across the window. RAMP_WINDOW is 10-20 depending on the
            # agent, and each scores the trend across its own window, so the
            # trajectory must be long enough to fill the largest of them.
            rows += [inject(clean_row(rng, warmup + j), key, sev, rng,
                            (j + 1) / float(SUSTAIN), phantom)[0]
                     for j in range(SUSTAIN)]
            r = run_trial(agent, rows)
            if r is None:
                errors += 1
            elif r:
                tp += 1

        if not injectable:
            results[key] = {"class": cls_name, "status": "NO_SYNTHETIC_PATTERN",
                            "tpr": None, "fpr": None, "errors": errors}
            if verbose:
                print("  %-8s %-36s NO SYNTHETIC PATTERN DEFINED" % (key, cls_name))
            continue

        tpr = tp / float(n_event) if n_event else 0.0
        fpr = fp / float(n_clean) if n_clean else 0.0

        if tp == 0 and fp == 0:
            status = "STRUCTURALLY_SILENT"
        elif tpr < 0.30:
            status = "BELOW_BAR"
        elif fpr > 0.05:
            status = "NOISY"
        else:
            status = "QUALIFIED"

        fpr_cold = (fp_by_state["cold"] / float(n_by_state["cold"])) if n_by_state["cold"] else 0.0
        fpr_ctx = (fp_by_state["ctx_alive"] / float(n_by_state["ctx_alive"])) if n_by_state["ctx_alive"] else 0.0
        misconfigured = (fpr_ctx - fpr_cold) > 0.25

        results[key] = {"class": cls_name, "status": status,
                        "tpr": tpr, "fpr": fpr, "errors": errors,
                        "fpr_cold_idle": fpr_cold, "fpr_ctx_alive": fpr_ctx,
                        "floor_misconfigured": misconfigured,
                        "n_clean": n_clean, "n_event": n_event}
        if verbose:
            print("  %-8s %-36s TPR %5.1f%%  FPR %5.2f%%  %s%s"
                  % (key, cls_name, tpr * 100, fpr * 100, status,
                     "  [%d errors]" % errors if errors else ""))
            if misconfigured:
                print("           FPR cold-idle %5.1f%%  vs  ctx-alive %5.1f%%"
                      % (fpr_cold * 100, fpr_ctx * 100))
                print("           FLOOR MISCONFIGURED: clean on a cold GPU, noisy on one")
                print("           holding a context.")
                print("           Use the context-alive floor, not the cold floor.")

    if verbose:
        print()
        print("  STRUCTURALLY_SILENT means the agent never fired on any input,")
        print("  clean or event. That is a telemetry problem, not an accuracy")
        print("  problem, and no amount of retuning will fix it.")
        print()
    return results


# --------------------------------------------------------------------------
# Pairwise agreement
# --------------------------------------------------------------------------

def pairwise(loaded, results, n_trials, warmup, seed, threshold=0.95, verbose=True, phantom=True):
    """Do two agents fire on the same trials? Above threshold they are
    functionally one agent and should not both carry weight in a vote."""
    live = [(k, c, cl, kw) for k, c, _i, cl, kw in loaded
            if results.get(k, {}).get("status") in ("QUALIFIED", "NOISY", "BELOW_BAR")]
    if len(live) < 2:
        if verbose:
            print("=" * 72)
            print("3. PAIRWISE AGREEMENT")
            print("=" * 72)
            print("  Fewer than 2 live agents. Nothing to correlate.")
            print()
        return {}, []

    rng = random.Random(seed + 7)
    # Build one shared corpus: half clean, half event, mixed agent patterns.
    corpus = []
    for i in range(n_trials):
        rows = [clean_row(rng, j) for j in range(warmup)]
        if i % 2 == 1:
            src = live[rng.randrange(len(live))][0]
            sev = rng.uniform(0.2, 1.0)
            rows += [inject(clean_row(rng, warmup + j), src, sev, rng)[0]
                     for j in range(6)]
        corpus.append(rows)

    votes = {}
    for key, cls_name, cls, kwargs in live:
        v = []
        for rows in corpus:
            agent = fresh(cls, kwargs)
            r = run_trial(agent, rows)
            v.append(1 if r else 0)
        votes[key] = v

    matrix, dupes = {}, []
    keys = [k for k, _, _, _ in live]
    for i, a in enumerate(keys):
        for b in keys[i + 1:]:
            agree = sum(1 for x, y in zip(votes[a], votes[b]) if x == y) / float(n_trials)
            matrix["%s|%s" % (a, b)] = agree
            if agree >= threshold:
                dupes.append((a, b, agree))

    if verbose:
        print("=" * 72)
        print("3. PAIRWISE AGREEMENT   (%d trials, duplicate threshold %.0f%%)"
              % (n_trials, threshold * 100))
        print("=" * 72)
        for pair, agree in sorted(matrix.items(), key=lambda kv: -kv[1]):
            flag = "  <-- DUPLICATE" if agree >= threshold else ""
            print("  %-22s %5.1f%%%s" % (pair.replace("|", " vs "), agree * 100, flag))
        if dupes:
            print()
            print("  %d duplicate pair(s). Merge or cut one of each before" % len(dupes))
            print("  either carries weight in a vote they should be sharing.")
        else:
            print()
            print("  No duplicate pairs. Every live agent contributes a distinct signal.")
        print()
    return matrix, dupes


# --------------------------------------------------------------------------
# Ensemble vs best single — THE PASS/FAIL TEST
# --------------------------------------------------------------------------

def ensemble_test(loaded, results, n_clean, n_event, warmup, seed, verbose=True, phantom=True):
    """Weighted consensus vs. the single best agent, same corpus.

    Weights come from measured TPR, never hand-tuned. An agent below the
    bar carries zero weight rather than a small one: a broken agent that
    votes is worse than a broken agent that abstains.
    """
    live = [(k, c, cl, kw) for k, c, _i, cl, kw in loaded
            if results.get(k, {}).get("status") in ("QUALIFIED", "NOISY")]
    if verbose:
        print("=" * 72)
        print("4. ENSEMBLE vs BEST SINGLE AGENT   <-- PASS/FAIL FOR THE SWARM")
        print("=" * 72)
    if len(live) < 2:
        if verbose:
            print("  Fewer than 2 qualified agents. The ensemble test is not")
            print("  meaningful yet. Get more agents qualified first.")
            print()
        return None

    weights = {k: max(0.0, results[k]["tpr"] - results[k]["fpr"]) for k, _, _, _ in live}
    total_w = sum(weights.values()) or 1.0
    best_key = max(live, key=lambda x: results[x[0]]["tpr"] - results[x[0]]["fpr"])[0]

    rng = random.Random(seed + 13)

    def build(is_event):
        rows = [clean_row(rng, j) for j in range(warmup)]
        if is_event:
            src = live[rng.randrange(len(live))][0]
            sev = rng.uniform(0.2, 1.0)
            rows += [inject(clean_row(rng, warmup + j), src, sev, rng,
                            (j + 1) / float(SUSTAIN), phantom)[0]
                     for j in range(SUSTAIN)]
        return rows

    corpus = [(build(False), False) for _ in range(n_clean)] + \
             [(build(True), True) for _ in range(n_event)]
    rng.shuffle(corpus)

    ens_tp = ens_fp = best_tp = best_fp = 0
    for rows, is_event in corpus:
        score = 0.0
        best_fired = False
        for key, cls_name, cls, kwargs in live:
            agent = fresh(cls, kwargs)
            fired = run_trial(agent, rows)
            if fired:
                score += weights[key]
            if key == best_key:
                best_fired = bool(fired)
        ens_fired = (score / total_w) >= 0.25     # consensus threshold
        if is_event:
            ens_tp += 1 if ens_fired else 0
            best_tp += 1 if best_fired else 0
        else:
            ens_fp += 1 if ens_fired else 0
            best_fp += 1 if best_fired else 0

    ens = {"tpr": ens_tp / float(n_event), "fpr": ens_fp / float(n_clean)}
    best = {"tpr": best_tp / float(n_event), "fpr": best_fp / float(n_clean)}
    ens["score"] = ens["tpr"] - ens["fpr"]
    best["score"] = best["tpr"] - best["fpr"]
    verdict = "ENSEMBLE_WINS" if ens["score"] > best["score"] else "ENSEMBLE_ADDS_NOISE"

    if verbose:
        print("  weights (TPR - FPR, from measured results, not hand-tuned):")
        for k in sorted(weights, key=lambda x: -weights[x]):
            print("    %-8s %.3f" % (k, weights[k]))
        print()
        print("  best single agent (%s):  TPR %5.1f%%  FPR %5.2f%%  score %.3f"
              % (best_key, best["tpr"] * 100, best["fpr"] * 100, best["score"]))
        print("  weighted ensemble:            TPR %5.1f%%  FPR %5.2f%%  score %.3f"
              % (ens["tpr"] * 100, ens["fpr"] * 100, ens["score"]))
        print()
        print("  VERDICT: %s" % verdict)
        if verdict == "ENSEMBLE_ADDS_NOISE":
            print("  The coordination layer is not earning its place. Do not add")
            print("  agents: fix correlation, weighting, or the consensus")
            print("  threshold first. More agents will amplify this, not fix it.")
        print()
    return {"ensemble": ens, "best_single": best, "best_key": best_key,
            "weights": weights, "verdict": verdict}


# --------------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser(description="Watchdog swarm agent qualification")
    ap.add_argument("--n-clean", type=int, default=200)
    ap.add_argument("--n-event", type=int, default=200)
    ap.add_argument("--n-pairwise", type=int, default=120)
    ap.add_argument("--warmup", type=int, default=25,
                    help="clean samples before injection, so agents learn a baseline")
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--dup-threshold", type=float, default=0.95)
    ap.add_argument("--discover-only", action="store_true")
    ap.add_argument("--no-phantom", action="store_true",
                help="withhold fields production telemetry does not supply "
                     "(memory_access_timing_ms, cei_flops_per_joule). This is "
                     "the deployment-truthful measurement.")
    ap.add_argument("--json", type=str, default=None)
    a = ap.parse_args()

    print()
    print("WATCHDOG SWARM — AGENT QUALIFICATION")
    print("seed=%d  warmup=%d  %s" % (a.seed, a.warmup,
                                      datetime.now(timezone.utc).isoformat()))
    print()

    loaded, failed = load_agents(AGENT_SPECS)
    if not loaded:
        print("No agents loaded. Run this from the repository root:")
        print("  cd ~/Watchdog && python3 scripts/swarm_qualification.py")
        return 2
    if a.discover_only:
        return 0

    phantom = not a.no_phantom
    if not phantom:
        print("  --no-phantom: withholding memory_access_timing_ms and\n  cei_flops_per_joule. Agents depending on them will read as\n  STRUCTURALLY_SILENT, which is what they are in deployment.\n")
    results = qualify(loaded, a.n_clean, a.n_event, a.warmup, a.seed, phantom=phantom)
    matrix, dupes = pairwise(loaded, results, a.n_pairwise, a.warmup,
                             a.seed, a.dup_threshold, phantom=phantom)
    ens = ensemble_test(loaded, results, a.n_clean, a.n_event, a.warmup, a.seed, phantom=phantom)

    print("=" * 72)
    print("SUMMARY")
    print("=" * 72)
    counts = {}
    for k, v in results.items():
        counts[v["status"]] = counts.get(v["status"], 0) + 1
    for status in sorted(counts):
        print("  %-22s %d" % (status, counts[status]))
    print("  %-22s %d" % ("IMPORT/CONSTRUCT FAIL", len(failed)))
    print("  %-22s %d" % ("duplicate pairs", len(dupes)))
    if ens:
        print("  %-22s %s" % ("ensemble verdict", ens["verdict"]))
    print()
    qualified = [k for k, v in results.items() if v["status"] == "QUALIFIED"]
    print("  Qualified for the voting pool: %s"
          % (", ".join(sorted(qualified)) if qualified else "NONE"))
    print()

    if a.json:
        blob = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "seed": a.seed, "warmup": a.warmup, "phantom_fields": phantom,
            "n_clean": a.n_clean, "n_event": a.n_event,
            "loaded": [k for k, _, _, _, _ in loaded],
            "failed": [{"agent": k, "class": c, "code": code, "detail": d}
                       for k, c, code, d in failed],
            "per_agent": results,
            "pairwise": matrix,
            "duplicates": [{"a": x, "b": y, "agreement": z} for x, y, z in dupes],
            "ensemble": ens,
            "disclaimer": ("Synthetic randomized trials. Proves the scoring "
                           "logic generalizes across randomized severity. Does "
                           "NOT prove any precursor pattern precedes a real "
                           "event on real hardware."),
        }
        with open(a.json, "w") as f:
            json.dump(blob, f, indent=2)
        print("  written: %s" % a.json)
        print()
    return 0


if __name__ == "__main__":
    sys.exit(main())
