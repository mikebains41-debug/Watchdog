import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from detection.business_signals import CovertMiningDetector, BillingIntegrityDetector

PASSED = []
FAILED = []


def check(name, condition, detail=""):
    if condition:
        PASSED.append(name)
        print(f"[PASS] {name}")
    else:
        FAILED.append(name)
        print(f"[FAIL] {name} {detail}")


def row(**kw):
    base = {'index': 0, 'iso_timestamp': '2026-07-25T00:00:00'}
    base.update(kw)
    return base


def test_mining_positive_sustained_flat_high_util():
    d = CovertMiningDetector(min_duration_samples=600, require_consecutive=1)
    result = None
    for _ in range(601):
        result = d.update(row(**{'utilization.gpu': 99, 'power.draw': 680, 'power.limit': 700})) or result
    check("MINING POSITIVE: fires on sustained flat near-TDP utilization",
          result is not None and result['type'] == 'COVERT_MINING_PATTERN', f"got {result}")


def test_mining_negative_normal_training_variance():
    d = CovertMiningDetector(min_duration_samples=600, require_consecutive=1)
    results = []
    for i in range(601):
        util = min(85 + (i % 20), 100)
        power = 500 + (i % 50)
        results.append(d.update(row(**{'utilization.gpu': util, 'power.draw': power, 'power.limit': 700})))
    fired = [r for r in results if r]
    check("MINING NEGATIVE: silent on normal high-variance training load",
          len(fired) == 0, f"fired {len(fired)} times -- FALSE POSITIVE")


def test_mining_negative_short_burst():
    d = CovertMiningDetector(min_duration_samples=600, require_consecutive=1)
    results = []
    for _ in range(100):
        results.append(d.update(row(**{'utilization.gpu': 99, 'power.draw': 680, 'power.limit': 700})))
    fired = [r for r in results if r]
    check("MINING NEGATIVE: silent on a short burst below min_duration_samples",
          len(fired) == 0, f"fired {len(fired)} times")


def test_mining_message_states_authorization_unknown():
    d = CovertMiningDetector(min_duration_samples=600, require_consecutive=1)
    result = None
    for _ in range(601):
        result = d.update(row(**{'utilization.gpu': 99, 'power.draw': 680, 'power.limit': 700})) or result
    check("MINING: message explicitly states authorization cannot be determined",
          result is not None and 'NOT confirm' in result['message'], f"got {result['message'] if result else 'none'}")


def test_billing_positive_ghost_power_during_billed_idle():
    d = BillingIntegrityDetector(baseline_min_samples=30, require_consecutive=5)
    for _ in range(30):
        d.update(row(**{'power.draw': 65, 'utilization.gpu': 0}))
    result = None
    for _ in range(6):
        result = d.update(row(**{'power.draw': 140, 'utilization.gpu': 0})) or result
    check("BILLING POSITIVE: fires when idle-billed time shows real power draw",
          result is not None and result['type'] == 'BILLING_INTEGRITY_GAP', f"got {result}")


def test_billing_negative_genuine_idle():
    d = BillingIntegrityDetector(baseline_min_samples=30, require_consecutive=5)
    for _ in range(30):
        d.update(row(**{'power.draw': 65, 'utilization.gpu': 0}))
    results = []
    for _ in range(10):
        results.append(d.update(row(**{'power.draw': 68, 'utilization.gpu': 0})))
    fired = [r for r in results if r]
    check("BILLING NEGATIVE: silent on genuinely idle GPU near baseline",
          len(fired) == 0, f"fired {len(fired)} times -- FALSE POSITIVE")


def test_billing_negative_active_util_not_flagged():
    d = BillingIntegrityDetector(baseline_min_samples=30, require_consecutive=5)
    for _ in range(30):
        d.update(row(**{'power.draw': 65, 'utilization.gpu': 0}))
    results = []
    for _ in range(10):
        results.append(d.update(row(**{'power.draw': 300, 'utilization.gpu': 80})))
    fired = [r for r in results if r]
    check("BILLING NEGATIVE: silent when utilization is genuinely non-zero",
          len(fired) == 0, f"fired {len(fired)} times")


def test_billing_no_cost_estimate_without_rate():
    d = BillingIntegrityDetector(baseline_min_samples=30, require_consecutive=5)
    for _ in range(30):
        d.update(row(**{'power.draw': 65, 'utilization.gpu': 0}))
    result = None
    for _ in range(6):
        result = d.update(row(**{'power.draw': 140, 'utilization.gpu': 0})) or result
    check("BILLING: does not invent a dollar figure when no rate is supplied",
          result is not None and result['estimated_cost_usd'] is None,
          f"got {result['estimated_cost_usd'] if result else 'no alert'}")


def test_billing_cost_estimate_when_rate_supplied():
    d = BillingIntegrityDetector(baseline_min_samples=30, require_consecutive=5, rate_usd_per_kwh=0.12)
    for _ in range(30):
        d.update(row(**{'power.draw': 65, 'utilization.gpu': 0}))
    result = None
    t = 0.0
    for _ in range(6):
        t += 1.0
        result = d.update(row(**{'power.draw': 140, 'utilization.gpu': 0}), now=t) or result
    check("BILLING: produces a numeric cost estimate when a rate is supplied",
          result is not None and isinstance(result['estimated_cost_usd'], float),
          f"got {result['estimated_cost_usd'] if result else 'no alert'}")


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
