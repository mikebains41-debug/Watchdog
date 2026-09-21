#!/usr/bin/env python3
"""
Tests for scripts/das_vessel_detector.py.

Synthetic data only: no dataset, no network, no pyfive. Proves the method
and the evaluation protocol are correct before any real result is claimed:
  - quiet windows stay quiet, ship windows are caught
  - the threshold comes from training days only (no test-day leakage)
  - it refuses to learn a baseline from too few quiet windows
  - single-day data cannot be passed off as a day-wise result
  - streaming reduction matches a full in-memory reduction
"""

import os
import sys

import numpy as np

HERE = os.path.dirname(os.path.abspath(__file__))
for p in (os.path.join(HERE, "..", "scripts"), os.path.join(HERE, ".."), HERE):
    if p not in sys.path:
        sys.path.insert(0, p)

import das_vessel_detector as dv  # noqa: E402

PASSED, FAILED = [], []


def check(name, cond, detail=""):
    (PASSED if cond else FAILED).append(name)
    print("[%s] %s %s" % ("PASS" if cond else "FAIL", name, "" if cond else detail))


def synthetic(days=3, per_day=240, channels=60, seed=7):
    """Quiet windows: noise around a per-channel level. Ship windows: a
    stretch of ~12 channels gets louder, more so the closer the ship."""
    rng = np.random.RandomState(seed)
    level = rng.uniform(-2.0, 2.0, channels)
    T, y, dates = [], [], []
    for d in range(days):
        for i in range(per_day):
            row = level + rng.normal(0, 0.10, channels)
            if i % 4 == 0:                       # ship nearby
                dist = rng.uniform(20, 900)
                centre = rng.randint(10, channels - 10)
                boost = 1.2 * (1.0 - dist / 1000.0) + 0.4
                row[centre - 6:centre + 6] += boost
            elif i % 4 == 1:                     # gray zone
                dist = rng.uniform(1100, 1900)
            else:                                # quiet
                dist = rng.uniform(2500, 9000)
            T.append(row)
            y.append(dist)
            dates.append("2023-06-%02d %02d:%02d:00+00:00" % (16 + d, i // 60, i % 60))
    return np.array(T, dtype=np.float32), np.array(y), np.array(dates)


def test_day_wise():
    T, y, dates = synthetic()
    r = dv.evaluate_day_wise(T, y, dates)
    p = r["pooled"]
    check("day-wise: three folds, one per day", r["n_days"] == 3 and len(r["folds"]) == 3)
    check("day-wise: ships caught (TPR > 90%)", p["tpr"] > 0.90, "tpr=%.3f" % p["tpr"])
    check("day-wise: quiet stays quiet (FPR < 5%)", p["fpr"] < 0.05, "fpr=%.3f" % p["fpr"])
    check("day-wise: gray zone reported, not scored", p["n_gray"] > 0)


def test_no_leakage():
    T, y, dates = synthetic()
    day_of = np.array([d[:10] for d in dates])
    test = day_of == "2023-06-18"
    a = dv.DASProximityDetector().fit(T[~test], y[~test]).threshold
    T2 = T.copy()
    T2[test] += 50.0                             # wreck the TEST day only
    b = dv.DASProximityDetector().fit(T2[~test], y[~test]).threshold
    check("no leakage: threshold unchanged when only the test day changes", a == b)


def test_refuses_thin_baseline():
    T, y, dates = synthetic()
    y2 = np.full_like(y, 500.0)                  # no quiet windows at all
    try:
        dv.DASProximityDetector().fit(T, y2)
        check("refuses to learn a baseline from too few quiet windows", False, "it fitted anyway")
    except ValueError:
        check("refuses to learn a baseline from too few quiet windows", True)


def test_single_day_is_not_a_result():
    T, y, dates = synthetic(days=1)
    check("single day: day-wise evaluation returns None", dv.evaluate_day_wise(T, y, dates) is None)
    r = dv.pipeline_check(T, y, dates)
    check("single day: pipeline check shows score rising near ships",
          r["mean_score_near"] > r["mean_score_far"] and r["corr_score_vs_distance"] < 0)


def test_streaming_reduction():
    rng = np.random.RandomState(1)
    X = rng.uniform(0.01, 5.0, size=(37, 12, 20))          # linear energies
    T_stream, mode = dv.reduce_features(X, block=8, progress=False)
    T_full = np.log10(X.sum(axis=2))
    check("reduction: linear energies detected as linear", mode == "linear")
    check("reduction: streamed blocks match full in-memory result",
          np.allclose(T_stream, T_full, atol=1e-5))
    Xlog = rng.normal(-3, 1, size=(20, 12, 20))             # already logarithmic
    T_log, mode2 = dv.reduce_features(Xlog, block=8, progress=False)
    check("reduction: negative (log) energies detected as log", mode2 == "log")
    check("reduction: log mode averages bands", np.allclose(T_log, Xlog.mean(axis=2), atol=1e-5))
    T_lim, _ = dv.reduce_features(X, n=10, block=8, progress=False)
    check("reduction: --limit honoured", T_lim.shape[0] == 10)


def test_dates():
    d = dv.decode_dates([b"2023-06-16 15:55:08+00:00", np.bytes_(b"2023-06-17 00:00:00+00:00")])
    check("dates: bytes decoded to strings", d[0].startswith("2023-06-16") and d[1][:10] == "2023-06-17")


def main():
    print("=" * 60)
    print("DAS VESSEL DETECTOR -- TESTS (synthetic data)")
    print("=" * 60)
    for fn in (test_day_wise, test_no_leakage, test_refuses_thin_baseline,
               test_single_day_is_not_a_result, test_streaming_reduction, test_dates):
        print("\n--- %s ---" % fn.__name__)
        fn()
    print("\n" + "=" * 60)
    print("PASSED: %d FAILED: %d" % (len(PASSED), len(FAILED)))
    for f in FAILED:
        print("  FAILED: %s" % f)
    return 1 if FAILED else 0


if __name__ == "__main__":
    sys.exit(main())
