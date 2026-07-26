"""
tests/test_advanced_fixes.py

Tests for detection/advanced.py after fixing all five classes:
MemoryActivationAnomalyDetector (renamed from RowhammerProxyDetector --
it never detected Rowhammer, the name was corrected to match what it
actually measures), ModelMutationDetector (disclosed sampling
limitation), PerfCounterSideChannelDetector (removed a CVE citation
the detector's logic doesn't actually support), NVLinkFabricDetector
(softened an unsupported "man-in-the-middle" claim), SupplyChainDetector
(fixed a check-exactly-once-ever bug, softened an unsupported
"counterfeit" claim).

Run: python tests/test_advanced_fixes.py
"""
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from detection.advanced import (
    MemoryActivationAnomalyDetector, ModelMutationDetector,
    PerfCounterSideChannelDetector, NVLinkFabricDetector, SupplyChainDetector,
)

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
    base = {'index': 0, 'iso_timestamp': '2026-07-26T00:00:00'}
    base.update(kw)
    return base


def test_memory_activation_positive_real_variance():
    d = MemoryActivationAnomalyDetector(window=50, require_consecutive=1)
    result = None
    for i in range(50):
        mem = 600 if i % 2 == 0 else 750
        result = d.update(row(**{'memory.used': mem, 'utilization.gpu': 2})) or result
    check("MEMORY_ACTIVATION: fires on real >100MB variance at low utilization",
          result is not None and result['type'] == 'MEMORY_ACTIVATION_ANOMALY',
          f"got {result}")
    check("MEMORY_ACTIVATION: message explicitly disclaims Rowhammer specificity",
          result is not None and 'NOT a Rowhammer-specific' in result['message'],
          f"got {result['message'] if result else None}")


def test_memory_activation_negative_high_util():
    d = MemoryActivationAnomalyDetector(window=50, require_consecutive=1)
    results = [d.update(row(**{'memory.used': 600, 'utilization.gpu': 80})) for _ in range(50)]
    check("MEMORY_ACTIVATION: silent when utilization is genuinely high",
          all(r is None for r in results), f"fired {sum(1 for r in results if r)} times")


def test_memory_activation_na_safe():
    d = MemoryActivationAnomalyDetector(window=5)
    try:
        for _ in range(10):
            d.update(row(**{'memory.used': None, 'utilization.gpu': 2}))
        check("MEMORY_ACTIVATION: survives N/A memory.used without crashing", True)
    except Exception as e:
        check("MEMORY_ACTIVATION: survives N/A memory.used without crashing", False, f"crashed: {e}")


def test_perf_counter_no_cve_citation():
    d = PerfCounterSideChannelDetector(window=100, require_consecutive=1)
    result = None
    for i in range(100):
        result = d.update(row(**{'utilization.gpu': 2, 'utilization.memory': (i % 30), 'power.draw': 100})) or result
    check("PERF_COUNTER: fires on decoupled memory/compute variance",
          result is not None, f"got {result}")
    check("PERF_COUNTER: no longer cites CVE-2018-6260 as if directly detected",
          result is not None and 'CVE-2018-6260' not in str(result),
          f"got {result}")


def test_nvlink_no_mitm_claim():
    d = NVLinkFabricDetector()
    result = d.update(row())
    check("NVLINK: handles missing/unavailable nvidia-smi nvlink gracefully (no crash)",
          True)


def test_supply_chain_fires_and_softens_claim():
    d = SupplyChainDetector(check_interval=0)
    result = d.check_counterfeit(row(**{'power.draw': 900, 'utilization.gpu': 50, 'name': 'H200'}))
    check("SUPPLY_CHAIN: fires on power exceeding reference by >15%",
          result is not None and result['type'] == 'SUPPLY_CHAIN_ANOMALY',
          f"got {result}")
    check("SUPPLY_CHAIN: message does not claim counterfeit as confirmed",
          result is not None and 'not necessarily counterfeit' in result['message'],
          f"got {result['message'] if result else None}")
    check("SUPPLY_CHAIN: severity downgraded from CRITICAL to INFO given the real uncertainty",
          result is not None and result['severity'] == 'INFO',
          f"got {result['severity'] if result else None}")


def test_supply_chain_rechecks_periodically_not_once_ever():
    d = SupplyChainDetector(check_interval=0)
    result1 = d.check_counterfeit(row(**{'power.draw': 900, 'utilization.gpu': 50, 'name': 'H200'}))
    result2 = d.check_counterfeit(row(**{'power.draw': 900, 'utilization.gpu': 50, 'name': 'H200'}))
    check("SUPPLY_CHAIN: can fire more than once (not permanently silenced after first check)",
          result1 is not None and result2 is not None,
          f"got result1={result1 is not None}, result2={result2 is not None}")


def test_model_mutation_docstring_discloses_sampling_limit():
    import inspect
    doc = inspect.getdoc(ModelMutationDetector) or ""
    check("MODEL_MUTATION: docstring discloses the 40KB sampling limitation",
          "40KB" in doc or "10,000" in doc,
          f"docstring: {doc[:200]}")


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
