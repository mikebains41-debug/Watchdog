import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from telemetry.cei_report import CEIDistribution, precision_ratio

PASSED = []
FAILED = []


def check(name, condition, detail=""):
    if condition:
        PASSED.append(name)
        print(f"[PASS] {name}")
    else:
        FAILED.append(name)
        print(f"[FAIL] {name} {detail}")


def test_single_run_rejected():
    try:
        CEIDistribution([5.68e9])
        check("single run raises ValueError instead of being treated as fact",
              False)
    except ValueError:
        check("single run raises ValueError instead of being treated as fact",
              True)


def test_empty_rejected():
    try:
        CEIDistribution([])
        check("empty list raises ValueError", False)
    except ValueError:
        check("empty list raises ValueError", True)


def test_cv_computed_matches_high_variance_pattern():
    runs = [4.5e9, 5.0e9, 5.68e9, 6.2e9, 6.8e9, 4.2e9, 5.9e9]
    d = CEIDistribution(runs)
    r = d.report()
    check("cv is computed from this distribution's own data",
          r['cv'] is not None, f"got {r}")
    check("reliable() flags this high-variance data as NOT reliable",
          d.reliable(cv_threshold=0.10) is False, f"cv={r['cv']}")


def test_low_variance_marked_reliable():
    runs = [5.0e9, 5.05e9, 4.95e9, 5.02e9, 4.98e9]
    d = CEIDistribution(runs)
    check("low-variance distribution is marked reliable",
          d.reliable(cv_threshold=0.10) is True)


def test_median_resists_single_outlier():
    runs = [5.0e9, 5.1e9, 4.9e9, 5.05e9, 50.0e9]
    d = CEIDistribution(runs)
    check("median resists a single 10x outlier",
          4.5e9 <= d.median <= 5.5e9, f"median={d.median}")


def test_ratio_computed_from_medians():
    fp8 = CEIDistribution([9.5e11, 9.6e11, 9.55e11])
    fp32 = CEIDistribution([3.1e11, 3.2e11, 3.15e11])
    ratio = precision_ratio(fp8, fp32)
    check("precision_ratio computes median(a)/median(b)",
          2.9 <= ratio <= 3.2, f"got {ratio}")


def test_ratio_rejects_zero_median():
    zero_dist = CEIDistribution([0.0, 0.0, 0.0])
    normal_dist = CEIDistribution([1.0, 2.0, 3.0])
    try:
        precision_ratio(zero_dist, normal_dist)
        check("ratio against zero median raises instead of returning inf/nan",
              False)
    except ValueError:
        check("ratio against zero median raises instead of returning inf/nan",
              True)


if __name__ == '__main__':
    tests = [v for k, v in sorted(globals().items()) if k.startswith('test_')]
    for t in tests:
        try:
            t()
        except Exception as e:
            check(t.__name__, False, f"EXCEPTION {e!r}")

    print("\n" + "=" * 60)
    print(f"PASSED: {len(PASSED)}   FAILED: {len(FAILED)}")
    if FAILED:
        print("\nFailures:")
        for f in FAILED:
            print(f"  - {f}")
    print("=" * 60)
    sys.exit(1 if FAILED else 0)
