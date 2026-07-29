#!/usr/bin/env python3
"""
capture_contention.py -- Watchdog capture-first experiment.

The question this answers, and nothing more: when a GPU contention event
happens (a measured throughput drop), does it leave ANY visible fingerprint
in NVML/nvidia-smi telemetry? If yes, an automatic detector is possible and
you now have the real numbers to tune it. If no, telemetry-only detection of
this phenomenon is impossible, and you learned that in minutes.

It does NOT run any detector. It records raw telemetry with detection OFF,
through three labelled phases, then analyses the recording offline:

  baseline   -- victim workload running alone
  contended  -- competitor process(es) added; the real event
  recovery   -- competitors killed; does telemetry return?

Two ground truths are captured so the analysis can't fool itself:
  - telemetry CSV (power, util, clocks, temp, mem) tagged with phase
  - the victim's own throughput (iters/sec), so you can confirm the event
    actually occurred, independent of telemetry

Modes:
  python3 capture_contention.py                     # capture + analyse
  python3 capture_contention.py --analyze-only F.csv  # re-analyse offline
                                                       # (no GPU needed)

Needs torch + a CUDA GPU + nvidia-smi to CAPTURE. --analyze-only runs anywhere,
so you can pull the CSV to your phone and re-analyse it there.
"""
import argparse, csv, json, os, statistics, subprocess, sys, tempfile, time
from datetime import datetime, timezone

TELEM_FIELDS = ["power.draw", "utilization.gpu", "utilization.memory",
                "memory.used", "clocks.sm", "clocks.mem", "temperature.gpu"]
CSV_COLS = ["epoch", "iso", "phase", "interval_ms"] + TELEM_FIELDS


# ----------------------------------------------------------------------------
# environment
# ----------------------------------------------------------------------------
def _has_nvidia_smi():
    try:
        subprocess.run(["nvidia-smi", "-L"], capture_output=True, timeout=5)
        return True
    except Exception:
        return False


def _has_torch_gpu():
    try:
        import torch
        return bool(torch.cuda.is_available())
    except Exception:
        return False


# ----------------------------------------------------------------------------
# telemetry sampling (nvidia-smi subprocess; records ACTUAL interval)
# ----------------------------------------------------------------------------
def _sample_once(gpu_index):
    q = "nvidia-smi --query-gpu=" + ",".join(TELEM_FIELDS) + \
        " --format=csv,noheader,nounits --id=" + str(gpu_index)
    try:
        out = subprocess.run(q.split(), capture_output=True, text=True,
                             timeout=5).stdout.strip().splitlines()
        if not out:
            return None
        vals = [v.strip() for v in out[0].split(",")]
        row = {}
        for k, v in zip(TELEM_FIELDS, vals):
            try:
                row[k] = float(v)
            except ValueError:
                row[k] = None          # e.g. [N/A]; never fabricate 0.0
        return row
    except Exception:
        return None


# ----------------------------------------------------------------------------
# workloads (victim reports throughput; competitor just loads the GPU)
# ----------------------------------------------------------------------------
_VICTIM_SRC = r"""
import sys, time, torch
size = int(sys.argv[1]); out = sys.argv[2]
a = torch.randn(size, size, device="cuda")
b = torch.randn(size, size, device="cuda")
torch.cuda.synchronize()
n = 0; t0 = time.time()
with open(out, "a", buffering=1) as f:
    while True:
        _ = a @ b; torch.cuda.synchronize(); n += 1
        now = time.time()
        if now - t0 >= 1.0:
            f.write(f"{now:.3f},{n/(now-t0):.2f}\n"); n = 0; t0 = now
"""

_COMPETITOR_SRC = r"""
import torch
a = torch.randn(4096, 4096, device="cuda")
b = torch.randn(4096, 4096, device="cuda")
torch.cuda.synchronize()
while True:
    _ = a @ b; torch.cuda.synchronize()
"""


def _spawn(src, *args):
    fd, path = tempfile.mkstemp(suffix="_wl.py")
    with os.fdopen(fd, "w") as f:
        f.write(src)
    p = subprocess.Popen([sys.executable, path, *map(str, args)],
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return p, path


def _kill(p, path):
    try:
        p.terminate(); p.wait(timeout=5)
    except Exception:
        p.kill()
    try:
        os.remove(path)
    except OSError:
        pass


# ----------------------------------------------------------------------------
# capture
# ----------------------------------------------------------------------------
def _record_phase(writer, phase, seconds, gpu_index, last_t):
    end = time.time() + seconds
    while time.time() < end:
        row = _sample_once(gpu_index)
        now = time.time()
        interval_ms = round((now - last_t[0]) * 1000, 1)
        last_t[0] = now
        if row is None:
            continue
        rec = {"epoch": round(now, 3),
               "iso": datetime.now(timezone.utc).isoformat(),
               "phase": phase, "interval_ms": interval_ms}
        rec.update(row)
        writer.writerow(rec)


def capture(args):
    if not (_has_torch_gpu() and _has_nvidia_smi()):
        reason = []
        if not _has_torch_gpu():
            reason.append("torch+CUDA GPU not available")
        if not _has_nvidia_smi():
            reason.append("nvidia-smi not found")
        print(json.dumps({"status": "NOT_RUN", "reason": "; ".join(reason)}, indent=2))
        print("\nThis experiment must run ON a rented GPU box. Use --analyze-only "
              "to re-analyse a CSV you already captured.")
        return None

    tp_file = args.out.replace(".csv", "") + "_throughput.csv"
    open(tp_file, "w").close()
    victim, vpath = _spawn(_VICTIM_SRC, args.matmul_size, tp_file)
    time.sleep(args.settle)  # let the victim reach steady state

    phase_bounds = {}
    last_t = [time.time()]
    with open(args.out, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=CSV_COLS, extrasaction="ignore")
        w.writeheader()

        t = time.time(); _record_phase(w, "baseline", args.window, args.gpu_index, last_t)
        phase_bounds["baseline"] = (t, time.time())

        comps = [_spawn(_COMPETITOR_SRC) for _ in range(args.competitors)]
        time.sleep(1.0)
        t = time.time(); _record_phase(w, "contended", args.window, args.gpu_index, last_t)
        phase_bounds["contended"] = (t, time.time())

        for p, pth in comps:
            _kill(p, pth)
        time.sleep(1.0)
        t = time.time(); _record_phase(w, "recovery", args.window, args.gpu_index, last_t)
        phase_bounds["recovery"] = (t, time.time())

    _kill(victim, vpath)
    print(f"capture done -> {args.out}  (+ {tp_file})")
    return args.out, tp_file, phase_bounds


# ----------------------------------------------------------------------------
# offline analysis (runs anywhere; no GPU, no numpy)
# ----------------------------------------------------------------------------
def _cohens_d(a, b):
    if len(a) < 2 or len(b) < 2:
        return None
    ma, mb = statistics.mean(a), statistics.mean(b)
    va, vb = statistics.variance(a), statistics.variance(b)
    pooled = (((len(a) - 1) * va + (len(b) - 1) * vb) / (len(a) + len(b) - 2)) ** 0.5
    if pooled == 0:
        return 0.0 if ma == mb else float("inf")
    return abs(ma - mb) / pooled


def _label(d):
    if d is None:
        return "insufficient data"
    if d == float("inf"):
        return "separates perfectly (zero variance)"
    if d >= 0.8:
        return "CLEAR separation"
    if d >= 0.5:
        return "moderate"
    if d >= 0.2:
        return "small"
    return "negligible"


def analyze(csv_path, tp_file=None):
    rows = []
    with open(csv_path) as f:
        for r in csv.DictReader(f):
            rows.append(r)
    if not rows:
        print("empty CSV"); return

    by_phase = {}
    for r in rows:
        by_phase.setdefault(r["phase"], []).append(r)

    def col(phase, field):
        out = []
        for r in by_phase.get(phase, []):
            v = r.get(field)
            if v not in (None, "", "None"):
                try:
                    out.append(float(v))
                except ValueError:
                    pass
        return out

    print("\n" + "=" * 68)
    print("CAPTURE ANALYSIS  --  does the contention event show up in telemetry?")
    print("=" * 68)

    # achieved sample rate (measured, not assumed)
    intervals = [float(r["interval_ms"]) for r in rows
                 if r.get("interval_ms") not in (None, "", "None")]
    if intervals:
        hz = 1000.0 / statistics.mean(intervals)
        print(f"samples: {len(rows)} | achieved rate: {hz:.1f} Hz "
              f"(mean interval {statistics.mean(intervals):.1f} ms)")
    for ph in ("baseline", "contended", "recovery"):
        print(f"  {ph:10s}: {len(by_phase.get(ph, []))} samples")

    # ground-truth throughput drop (the actual event)
    if tp_file and os.path.exists(tp_file):
        tp = []
        with open(tp_file) as f:
            for line in f:
                parts = line.strip().split(",")
                if len(parts) == 2:
                    try:
                        tp.append((float(parts[0]), float(parts[1])))
                    except ValueError:
                        pass
        if tp and "baseline" in by_phase and "contended" in by_phase:
            b0, b1 = float(by_phase["baseline"][0]["epoch"]), float(by_phase["baseline"][-1]["epoch"])
            c0, c1 = float(by_phase["contended"][0]["epoch"]), float(by_phase["contended"][-1]["epoch"])
            base_tp = [v for t, v in tp if b0 <= t <= b1]
            cont_tp = [v for t, v in tp if c0 <= t <= c1]
            if base_tp and cont_tp:
                mb, mc = statistics.mean(base_tp), statistics.mean(cont_tp)
                drop = (mb - mc) / mb * 100 if mb else 0
                print(f"\nground-truth throughput: {mb:.1f} -> {mc:.1f} iters/s "
                      f"({drop:+.1f}%)  <- the real event")

    # per-field separation baseline vs contended
    print("\nper-field separation (baseline vs contended), strongest first:")
    scored = []
    for fld in TELEM_FIELDS:
        d = _cohens_d(col("baseline", fld), col("contended", fld))
        b, c = col("baseline", fld), col("contended", fld)
        mb = statistics.mean(b) if b else None
        mc = statistics.mean(c) if c else None
        scored.append((fld, d, mb, mc))
    scored.sort(key=lambda x: (x[1] if isinstance(x[1], float) else -1), reverse=True)
    best = None
    for fld, d, mb, mc in scored:
        ds = "n/a" if d is None else ("inf" if d == float("inf") else f"{d:.2f}")
        mbs = "n/a" if mb is None else f"{mb:.1f}"
        mcs = "n/a" if mc is None else f"{mc:.1f}"
        print(f"  {fld:20s} d={ds:>5}  {mbs:>8} -> {mcs:<8}  {_label(d)}")
        if best is None and isinstance(d, float):
            best = (fld, d)

    print("\nVERDICT:")
    if best is None:
        print("  inconclusive -- not enough data. Increase --window and re-run.")
    elif best[1] == float("inf") or best[1] >= 0.8:
        print(f"  SIGNAL PRESENT. '{best[0]}' clearly separates the contention")
        print(f"  event from baseline. An automatic detector is viable; tune its")
        print(f"  threshold to this field using these numbers.")
    elif best[1] >= 0.5:
        print(f"  WEAK SIGNAL. '{best[0]}' moves but not cleanly. A detector might")
        print(f"  work with careful tuning and more samples; treat as unproven.")
    else:
        print(f"  NO USABLE SIGNAL. The strongest field ('{best[0]}') barely moves")
        print(f"  when throughput drops. Telemetry-only automatic detection of this")
        print(f"  event looks NOT viable -- exactly what this experiment exists to")
        print(f"  find out before building a detector on top of it.")
    print("=" * 68 + "\n")


# ----------------------------------------------------------------------------
def main():
    ap = argparse.ArgumentParser(description="Watchdog capture-first contention experiment")
    ap.add_argument("--analyze-only", default="", help="re-analyse an existing CSV (no GPU needed)")
    ap.add_argument("--gpu-index", type=int, default=0)
    ap.add_argument("--window", type=int, default=20, help="seconds per phase")
    ap.add_argument("--settle", type=int, default=5, help="seconds for victim to reach steady state")
    ap.add_argument("--competitors", type=int, default=1)
    ap.add_argument("--matmul-size", type=int, default=4096)
    ap.add_argument("--out", default=f"capture_{int(time.time())}.csv")
    args = ap.parse_args()

    if args.analyze_only:
        tp = args.analyze_only.replace(".csv", "") + "_throughput.csv"
        analyze(args.analyze_only, tp if os.path.exists(tp) else None)
        return

    result = capture(args)
    if result:
        csv_path, tp_file, _ = result
        analyze(csv_path, tp_file)


if __name__ == "__main__":
    main()
