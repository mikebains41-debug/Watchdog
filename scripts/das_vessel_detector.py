#!/usr/bin/env python3
"""
Watchdog subsea -- DAS vessel-proximity detector (module U-152, first build).
Author: Manmohan (Mike) Bains / GPU Optimizer Inc.

Detects ships near a submarine cable from distributed-acoustic-sensing (DAS)
energy, using the same discipline as the rest of Watchdog: learn a quiet
baseline, flag departures from it, and measure the detection rate AND the
false-positive rate on data the detector never learned from.

DATA
  Marlinks-NS DAS dataset -- Ramirez-Torres et al., 2026, CC BY 4.0,
  doi:10.5281/zenodo.15611778. Ten days (16-25 June 2023), 2,553 m segment
  of a 28 km cable off Zeebrugge, Belgium; 10 s windows of spectral energy,
  250 channels x 100 bands, labelled with the distance to the closest
  AIS-reported vessel. The dataset is NOT redistributed here.

LICENCE NOTE
  This file is Watchdog's own code. Nothing is copied from the dataset
  authors' repository (github.com/UAH-PSI/das-vessel-detection), which is
  GPL-3.0; copying from it would impose GPL on Watchdog.

METHOD (deliberately simple and explainable)
  1. Reduce each window to log energy per channel (streamed, so a 14 GB
     file never has to fit in memory).
  2. Learn, per channel, the median and spread of energy on QUIET windows
     (closest vessel > QUIET_M) from the training days only.
  3. Score a window by the mean of its TOPK largest robust z-scores -- a
     ship lights up a stretch of the cable, not the whole segment.
  4. Threshold = the (1 - TARGET_FPR) quantile of training quiet scores.
     Chosen on training days only: no test-day leakage.
  5. Evaluate leave-one-day-out, as the dataset authors recommend: windows
     10 s apart are correlated, so random splits inflate results.

LABELS
  threat : closest vessel <= THREAT_M
  quiet  : closest vessel >  QUIET_M
  gray   : in between -- reported separately, excluded from TPR/FPR, because
           "is a ship at 1.4 km a threat?" is a policy choice, not a label.

WHAT IT CANNOT DO
  It detects acoustic energy consistent with a nearby vessel. It cannot tell
  a vessel from other loud sources on its own, cannot see a vessel that is
  quiet, and has not been validated on any cable but this one.

USAGE
  python3 scripts/das_vessel_detector.py check  --h5 SAMPLE.h5
  python3 scripts/das_vessel_detector.py reduce --h5 FULL.h5 --out feats.npz
  python3 scripts/das_vessel_detector.py eval   --feats feats.npz --json out.json
"""

import argparse
import json
import sys
import time

import numpy as np

EPS = 1e-30
THREAT_M = 1000.0
QUIET_M = 2000.0
TOPK = 10
TARGET_FPR = 0.01
MIN_QUIET = 20

CITATION = ("Marlinks-NS DAS dataset, Ramirez-Torres et al., 2026, CC BY 4.0, "
            "doi:10.5281/zenodo.15611778")


# --------------------------------------------------------------------------
# Reduction
# --------------------------------------------------------------------------

def decode_dates(raw):
    out = []
    for d in raw:
        out.append(d.decode() if isinstance(d, (bytes, np.bytes_)) else str(d))
    return np.array(out)


def detect_mode(block):
    """'linear' if energies are non-negative (sum, then log10); 'log' if the
    values are already logarithmic (negative values present -> average)."""
    return "log" if float(np.min(block)) < 0 else "linear"


def reduce_features(X, n=None, block=64, progress=True):
    """Stream X (anything sliceable on axis 0 -> (b, channels, bands)) into
    per-window, per-channel log energy. Never loads X whole."""
    N = X.shape[0] if n is None else min(n, X.shape[0])
    C = X.shape[1]
    first = np.asarray(X[0:min(block, N)], dtype=np.float64)
    mode = detect_mode(first)
    T = np.empty((N, C), dtype=np.float32)
    t0 = time.time()
    for a in range(0, N, block):
        b = min(N, a + block)
        blk = first if a == 0 else np.asarray(X[a:b], dtype=np.float64)
        if mode == "linear":
            T[a:b] = np.log10(np.maximum(blk.sum(axis=2), EPS))
        else:
            T[a:b] = blk.mean(axis=2)
        if progress and (a // block) % 50 == 0:
            done = b / float(N)
            el = time.time() - t0
            eta = el / done - el if done > 0 else 0
            print("  reduce %6d/%d  %5.1f%%  elapsed %4.0fs  eta %5.0fs"
                  % (b, N, 100 * done, el, eta), flush=True)
    return T, mode


def load_h5(path):
    import pyfive
    f = pyfive.File(path)
    return f, f["X"], np.asarray(f["y"][:], dtype=np.float64), decode_dates(f["datetimes"][:])


# --------------------------------------------------------------------------
# Detector
# --------------------------------------------------------------------------

class DASProximityDetector(object):
    def __init__(self, topk=TOPK, target_fpr=TARGET_FPR, quiet_m=QUIET_M,
                 min_quiet=MIN_QUIET):
        self.topk = topk
        self.target_fpr = target_fpr
        self.quiet_m = quiet_m
        self.min_quiet = min_quiet
        self.median = self.scale = self.threshold = None
        self.n_quiet_fit = 0

    def fit(self, T, y):
        quiet = y > self.quiet_m
        n = int(quiet.sum())
        if n < self.min_quiet:
            raise ValueError("only %d quiet windows (closest vessel > %.0f m); "
                             "need %d to learn a baseline" % (n, self.quiet_m, self.min_quiet))
        Q = T[quiet].astype(np.float64)
        self.median = np.median(Q, axis=0)
        mad = np.median(np.abs(Q - self.median), axis=0) * 1.4826
        self.scale = np.maximum(mad, 1e-6)
        self.threshold = float(np.quantile(self.score(Q), 1.0 - self.target_fpr))
        self.n_quiet_fit = n
        return self

    def score(self, T):
        z = (np.asarray(T, dtype=np.float64) - self.median) / self.scale
        k = max(1, min(self.topk, z.shape[1]))
        return np.sort(z, axis=1)[:, -k:].mean(axis=1)

    def predict(self, T):
        return self.score(T) > self.threshold


def classify(y, threat_m=THREAT_M, quiet_m=QUIET_M):
    threat = y <= threat_m
    quiet = y > quiet_m
    gray = ~threat & ~quiet
    return threat, quiet, gray


def _rate(mask_pred, mask):
    n = int(mask.sum())
    return (float(mask_pred[mask].mean()) if n else float("nan")), n


# --------------------------------------------------------------------------
# Evaluation
# --------------------------------------------------------------------------

def evaluate_day_wise(T, y, dates, **kw):
    days = sorted(set(d[:10] for d in dates))
    if len(days) < 2:
        return None
    day_of = np.array([d[:10] for d in dates])
    rows = []
    tot = dict(tp=0, n_threat=0, fp=0, n_quiet=0, gray_alerts=0, n_gray=0)
    for day in days:
        test = day_of == day
        train = ~test
        det = DASProximityDetector(**kw).fit(T[train], y[train])
        pred = det.predict(T[test])
        threat, quiet, gray = classify(y[test])
        tpr, nt = _rate(pred, threat)
        fpr, nq = _rate(pred, quiet)
        gr, ng = _rate(pred, gray)
        rows.append(dict(day=day, n=int(test.sum()), n_threat=nt, n_quiet=nq, n_gray=ng,
                         tpr=tpr, fpr=fpr, gray_alert_rate=gr,
                         threshold=det.threshold, n_quiet_fit=det.n_quiet_fit))
        tot["tp"] += int(pred[threat].sum()); tot["n_threat"] += nt
        tot["fp"] += int(pred[quiet].sum()); tot["n_quiet"] += nq
        tot["gray_alerts"] += int(pred[gray].sum()); tot["n_gray"] += ng
    pooled = dict(
        tpr=tot["tp"] / float(tot["n_threat"]) if tot["n_threat"] else float("nan"),
        fpr=tot["fp"] / float(tot["n_quiet"]) if tot["n_quiet"] else float("nan"),
        gray_alert_rate=tot["gray_alerts"] / float(tot["n_gray"]) if tot["n_gray"] else float("nan"),
        **tot)
    return dict(folds=rows, pooled=pooled, n_days=len(days))


def pipeline_check(T, y, dates):
    """Single-day sanity check. IN-SAMPLE. NOT A RESULT."""
    threat, quiet, gray = classify(y)
    min_q = MIN_QUIET
    if int(quiet.sum()) < min_q:
        # Not enough clearly-quiet windows: fall back to the farthest third,
        # clearly labelled. Only acceptable for checking the plumbing.
        cut = np.quantile(y, 2.0 / 3.0)
        det = DASProximityDetector(quiet_m=cut, min_quiet=3).fit(T, y)
        basis = "farthest third of windows (closest vessel > %.0f m) -- provisional" % cut
    else:
        det = DASProximityDetector().fit(T, y)
        basis = "windows with closest vessel > %.0f m" % QUIET_M
    s = det.score(T)
    near = y <= THREAT_M
    far = y > np.quantile(y, 2.0 / 3.0)
    return dict(basis=basis, threshold=det.threshold, scores=s,
                mean_score_near=float(s[near].mean()) if near.any() else float("nan"),
                mean_score_far=float(s[far].mean()) if far.any() else float("nan"),
                n_near=int(near.sum()), n_far=int(far.sum()),
                corr_score_vs_distance=float(np.corrcoef(s, y)[0, 1]) if len(y) > 2 else float("nan"))


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------

def cmd_check(a):
    f, X, y, dates = load_h5(a.h5)
    T, mode = reduce_features(X, progress=False)
    r = pipeline_check(T, y, dates)
    print("PIPELINE CHECK -- IN-SAMPLE, ONE DAY, NOT A RESULT")
    print("data:", CITATION)
    print("windows: %d   span: %s -> %s   energy mode: %s" % (len(y), dates[0], dates[-1], mode))
    print("baseline learned from:", r["basis"])
    print("\n%-26s %9s %8s  %s" % ("time (UTC)", "dist (m)", "score", "alert"))
    order = np.argsort(dates)
    for i in order:
        print("%-26s %9.0f %8.2f  %s" % (dates[i], y[i], r["scores"][i],
                                          "ALERT" if r["scores"][i] > r["threshold"] else ""))
    print("\nthreshold (in-sample): %.2f" % r["threshold"])
    print("mean score, ship <= %.0f m : %.2f  (n=%d)" % (THREAT_M, r["mean_score_near"], r["n_near"]))
    print("mean score, farthest third : %.2f  (n=%d)" % (r["mean_score_far"], r["n_far"]))
    print("correlation(score, distance): %.2f   (negative = score rises as ships approach)"
          % r["corr_score_vs_distance"])
    ok = r["mean_score_near"] > r["mean_score_far"] and r["corr_score_vs_distance"] < 0
    print("\nPLUMBING:", "OK -- score rises as the ship approaches" if ok else
          "UNEXPECTED -- inspect before running on the full dataset")
    return 0


def cmd_reduce(a):
    f, X, y, dates = load_h5(a.h5)
    print("reducing %d windows from %s" % (X.shape[0], a.h5))
    T, mode = reduce_features(X, n=a.limit)
    n = T.shape[0]
    np.savez_compressed(a.out, T=T, y=y[:n], dates=dates[:n], mode=mode)
    print("written %s  (%d windows, %d channels, mode=%s)" % (a.out, n, T.shape[1], mode))
    return 0


def cmd_eval(a):
    z = np.load(a.feats, allow_pickle=False)
    T, y, dates = z["T"], z["y"], z["dates"].astype(str)
    r = evaluate_day_wise(T, y, dates)
    if r is None:
        print("Only one day present -- leave-one-day-out needs at least two. "
              "Use 'check' for a single-day pipeline check.")
        return 2
    print("LEAVE-ONE-DAY-OUT EVALUATION  (threat <= %.0f m, quiet > %.0f m, target FPR %.0f%%)"
          % (THREAT_M, QUIET_M, 100 * TARGET_FPR))
    print("data:", CITATION)
    print("\n%-11s %7s %7s %7s %7s %7s %9s" % ("test day", "n", "threat", "quiet", "TPR", "FPR", "gray-alert"))
    for r_ in r["folds"]:
        print("%-11s %7d %7d %7d %6.1f%% %6.2f%% %8.1f%%" % (
            r_["day"], r_["n"], r_["n_threat"], r_["n_quiet"],
            100 * r_["tpr"], 100 * r_["fpr"], 100 * r_["gray_alert_rate"]))
    p = r["pooled"]
    print("\nPOOLED over %d held-out days:" % r["n_days"])
    print("  detection rate (TPR)  %.1f%%  (%d of %d threat windows)" % (100 * p["tpr"], p["tp"], p["n_threat"]))
    print("  false-positive rate   %.2f%%  (%d of %d quiet windows)" % (100 * p["fpr"], p["fp"], p["n_quiet"]))
    print("  gray-zone alert rate  %.1f%%  (%d of %d, excluded from TPR/FPR)" % (
        100 * p["gray_alert_rate"], p["gray_alerts"], p["n_gray"]))
    if a.json:
        out = dict(citation=CITATION, threat_m=THREAT_M, quiet_m=QUIET_M, topk=TOPK,
                   target_fpr=TARGET_FPR, **r)
        with open(a.json, "w") as fh:
            json.dump(out, fh, indent=2, default=float)
        print("\nwritten:", a.json)
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(description="Watchdog DAS vessel-proximity detector")
    sub = ap.add_subparsers(dest="cmd")
    c = sub.add_parser("check"); c.add_argument("--h5", required=True)
    r = sub.add_parser("reduce"); r.add_argument("--h5", required=True)
    r.add_argument("--out", required=True); r.add_argument("--limit", type=int, default=None)
    e = sub.add_parser("eval"); e.add_argument("--feats", required=True); e.add_argument("--json")
    a = ap.parse_args(argv)
    if a.cmd == "check":
        return cmd_check(a)
    if a.cmd == "reduce":
        return cmd_reduce(a)
    if a.cmd == "eval":
        return cmd_eval(a)
    ap.print_help()
    return 1


if __name__ == "__main__":
    sys.exit(main())
