import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from detection.fleet_aggregation import FleetAggregator
from detection.tamper_detection import PowerLimitTamperDetector
from detection.hashrate_correlation import HashrateCorrelationDetector

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


# --- FleetAggregator ---

def test_fleet_aggregator_counts_affected_nodes():
    f = FleetAggregator(fleet_size=100)
    for node in range(5):
        f.ingest({'type': 'GHOST_POWER', 'severity': 'WARNING'}, node_id=node)
    s = f.summary()
    check("FLEET: counts distinct affected nodes correctly",
          s['affected_node_count'] == 5, f"got {s['affected_node_count']}")
    check("FLEET: computes affected node percentage against fleet_size",
          s['affected_node_pct'] == 5.0, f"got {s['affected_node_pct']}")


def test_fleet_aggregator_groups_by_alert_type():
    f = FleetAggregator(fleet_size=10)
    f.ingest({'type': 'GHOST_POWER', 'severity': 'WARNING'}, node_id=1)
    f.ingest({'type': 'GHOST_POWER', 'severity': 'WARNING'}, node_id=2)
    f.ingest({'type': 'COVERT_MINING_PATTERN', 'severity': 'WARNING'}, node_id=3)
    s = f.summary()
    check("FLEET: groups alerts by type with correct node counts",
          s['by_alert_type']['GHOST_POWER']['node_count'] == 2
          and s['by_alert_type']['COVERT_MINING_PATTERN']['node_count'] == 1,
          f"got {s['by_alert_type']}")


def test_fleet_aggregator_prunes_old_alerts():
    f = FleetAggregator(fleet_size=10, window_seconds=60)
    f.ingest({'type': 'GHOST_POWER', 'severity': 'WARNING'}, node_id=1, now=0.0)
    s = f.summary(now=120.0)
    check("FLEET: prunes alerts outside the rolling window",
          s['total_alerts_in_window'] == 0, f"got {s['total_alerts_in_window']}")


def test_fleet_aggregator_top_affected_nodes():
    f = FleetAggregator(fleet_size=10)
    for _ in range(5):
        f.ingest({'type': 'GHOST_POWER'}, node_id=1)
    f.ingest({'type': 'GHOST_POWER'}, node_id=2)
    top = f.top_affected_nodes(n=1)
    check("FLEET: top_affected_nodes ranks the noisiest node first",
          top[0][0] == 1 and top[0][1] == 5, f"got {top}")


# --- PowerLimitTamperDetector ---

def test_tamper_negative_no_change():
    d = PowerLimitTamperDetector(require_consecutive=3)
    d.update(row(**{'power.limit': 700}))
    results = [d.update(row(**{'power.limit': 700})) for _ in range(5)]
    check("TAMPER NEGATIVE: silent when power.limit never changes",
          all(r is None for r in results), f"got {results}")


def test_tamper_positive_unapproved_change():
    d = PowerLimitTamperDetector(require_consecutive=3)
    d.update(row(**{'power.limit': 700}))
    result = None
    for _ in range(4):
        result = d.update(row(**{'power.limit': 500})) or result
    check("TAMPER POSITIVE: fires on sustained deviation from baseline with no approved list",
          result is not None and result['type'] == 'POWER_LIMIT_TAMPER', f"got {result}")


def test_tamper_negative_approved_change():
    d = PowerLimitTamperDetector(approved_power_limits_w=[700, 500], require_consecutive=3)
    d.update(row(**{'power.limit': 700}))
    results = []
    for _ in range(5):
        results.append(d.update(row(**{'power.limit': 500})))
    fired = [r for r in results if r]
    check("TAMPER NEGATIVE: silent when new limit is in the approved list",
          len(fired) == 0, f"fired {len(fired)} times")


def test_tamper_positive_unapproved_despite_list_supplied():
    d = PowerLimitTamperDetector(approved_power_limits_w=[700], require_consecutive=3)
    d.update(row(**{'power.limit': 700}))
    result = None
    for _ in range(4):
        result = d.update(row(**{'power.limit': 350})) or result
    check("TAMPER POSITIVE: fires when new limit is NOT in the approved list",
          result is not None and result['approved_limits_supplied'] is True, f"got {result}")


# --- HashrateCorrelationDetector ---

def test_hashrate_negative_stable_efficiency():
    d = HashrateCorrelationDetector(min_correlation_samples=10, power_per_hash_tolerance=0.25)
    for _ in range(10):
        d.calibrate(power_w=300, hashrate=100)
    results = []
    for _ in range(5):
        results.append(d.process(power_w=305, hashrate=101, gpu_index=0))
    fired = [r for r in results if r]
    check("HASHRATE NEGATIVE: silent when power-per-hash stays close to baseline",
          len(fired) == 0, f"fired {len(fired)} times")


def test_hashrate_positive_efficiency_deviation():
    d = HashrateCorrelationDetector(min_correlation_samples=10, power_per_hash_tolerance=0.25,
                                     require_consecutive=3)
    for _ in range(10):
        d.calibrate(power_w=300, hashrate=100)
    result = None
    for _ in range(4):
        result = d.process(power_w=300, hashrate=50, gpu_index=0) or result
    check("HASHRATE POSITIVE: fires on sustained large power-per-hash deviation",
          result is not None and result['type'] == 'HASHRATE_POWER_MISMATCH', f"got {result}")


def test_hashrate_silent_before_calibration():
    d = HashrateCorrelationDetector(min_correlation_samples=10)
    result = d.process(power_w=300, hashrate=50, gpu_index=0)
    check("HASHRATE: returns None before calibration baseline is established",
          result is None, f"got {result}")


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
