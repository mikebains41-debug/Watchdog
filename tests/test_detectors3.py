#!/usr/bin/env python3
# Author: Manmohan (Mike) Bains -- Watchdog
"""
tests/test_detectors3.py

Tests for two new detectors from 2025-2026 research:

  BMCExposureDetector                 -- Black Hat USA 2026 BMC exposure
  ShadowInitPackageIntegrityDetector  -- ShadowInit malware supply-chain

Run: python3 tests/test_detectors3.py
"""
import sys
import os
import json
from unittest.mock import patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from detection.hardware_attacks import (
    BMCExposureDetector,
    ShadowInitPackageIntegrityDetector,
)

PASSED, FAILED = [], []

def check(name, cond, detail=""):
    if cond:
        PASSED.append(name); print(f"[PASS] {name}")
    else:
        FAILED.append(name); print(f"[FAIL] {name} {detail}")

CLEAN_PKGS = [
    {'name': 'torch', 'version': '2.1.0'},
    {'name': 'numpy', 'version': '1.26.0'},
    {'name': 'requests', 'version': '2.31.0'},
]
MANY_PKGS = [{'name': f'pkg{i}', 'version': '1.0'} for i in range(30)]
SQUATTED_PKGS = [
    {'name': 'torch', 'version': '2.1.0'},
    {'name': 'torchh', 'version': '2.1.0'},
]

# ---- BMC ----

def test_bmc_no_ports_open():
    d = BMCExposureDetector()
    with patch.object(d, '_probe_udp', return_value=False), \
         patch.object(d, '_probe_tcp', return_value=False):
        check("BMC NEGATIVE: returns None when no BMC ports reachable",
              d.check() is None)

def test_bmc_ipmi_reachable():
    d = BMCExposureDetector()
    def probe_udp(host, port):
        return host == '127.0.0.1' and port == 623
    with patch.object(d, '_probe_udp', side_effect=probe_udp), \
         patch.object(d, '_probe_tcp', return_value=False):
        r = d.check()
        check("BMC POSITIVE: fires when IPMI port 623 reachable",
              r is not None and r['type'] == 'BMC_MANAGEMENT_INTERFACE_EXPOSED'
              and r['severity'] == 'CRITICAL', f"got {r}")
        if r:
            check("BMC: alert mentions IPMI port", '623' in r['message'])
            check("BMC: alert mentions Black Hat 2026", 'Black Hat' in r['message'])
            check("BMC: alert names CVE-2013-4786", 'CVE-2013-4786' in r['message'])

def test_bmc_redfish_reachable():
    d = BMCExposureDetector()
    def probe_tcp(host, port):
        return host == '127.0.0.1' and port == 5000
    with patch.object(d, '_probe_udp', return_value=False), \
         patch.object(d, '_probe_tcp', side_effect=probe_tcp):
        r = d.check()
        check("BMC POSITIVE: fires when Redfish port 5000 reachable",
              r is not None and r['severity'] == 'CRITICAL')
        if r:
            check("BMC: alert mentions MegaRAC CVE for port 5000",
                  'CVE-2024-54085' in r['message'] or
                  '5000' in str(r['exposed_ports']))

def test_bmc_fires_once():
    d = BMCExposureDetector()
    with patch.object(d, '_probe_udp', return_value=True), \
         patch.object(d, '_probe_tcp', return_value=False):
        r1 = d.check()
        r2 = d.update({})
        check("BMC: fires once then stays silent",
              r1 is not None and r2 is None)

def test_bmc_honest_limits_in_message():
    d = BMCExposureDetector()
    with patch.object(d, '_probe_udp', return_value=True), \
         patch.object(d, '_probe_tcp', return_value=False):
        r = d.check()
        check("BMC: message discloses firewall may block at higher layer",
              r is not None and 'firewall' in r['message'])
        check("BMC: message discloses negative does not mean secure",
              r is not None and 'Negative result' in r['message'])

# ---- ShadowInit ----

def test_shadow_small_env_clean():
    d = ShadowInitPackageIntegrityDetector(unpinned_threshold=20)
    with patch.object(d, '_get_packages', return_value=CLEAN_PKGS), \
         patch.object(d, '_get_editable', return_value=[]):
        check("SHADOW NEGATIVE: silent on small clean env",
              d.check() is None)

def test_shadow_many_packages_fires():
    d = ShadowInitPackageIntegrityDetector(unpinned_threshold=20)
    with patch.object(d, '_get_packages', return_value=MANY_PKGS), \
         patch.object(d, '_get_editable', return_value=[]):
        r = d.check()
        check("SHADOW POSITIVE: fires when package count exceeds threshold",
              r is not None and r['type'] == 'SUPPLY_CHAIN_PACKAGE_RISK')
        if r:
            check("SHADOW: severity is INFO for count-only finding",
                  r['severity'] == 'INFO')

def test_shadow_typosquat_critical():
    d = ShadowInitPackageIntegrityDetector()
    with patch.object(d, '_get_packages', return_value=SQUATTED_PKGS), \
         patch.object(d, '_get_editable', return_value=[]):
        r = d.check()
        check("SHADOW POSITIVE: fires CRITICAL on typosquat",
              r is not None and r['severity'] == 'CRITICAL', f"got {r}")
        if r:
            check("SHADOW: identifies the typosquat package",
                  'torchh' in r['message'])

def test_shadow_editable_warning():
    d = ShadowInitPackageIntegrityDetector(unpinned_threshold=100)
    with patch.object(d, '_get_packages', return_value=CLEAN_PKGS), \
         patch.object(d, '_get_editable',
                      return_value=[{'name': 'my-evil-pkg', 'version': '1.0'}]):
        r = d.check()
        check("SHADOW POSITIVE: fires WARNING on editable installs",
              r is not None and r['severity'] == 'WARNING', f"got {r}")

def test_shadow_pip_unavailable():
    d = ShadowInitPackageIntegrityDetector()
    with patch.object(d, '_get_packages', return_value=None):
        check("SHADOW: returns None when pip unavailable",
              d.check() is None)

def test_shadow_fires_once():
    d = ShadowInitPackageIntegrityDetector(unpinned_threshold=20)
    with patch.object(d, '_get_packages', return_value=MANY_PKGS), \
         patch.object(d, '_get_editable', return_value=[]):
        r1 = d.check()
        r2 = d.update({})
        check("SHADOW: fires once then stays silent",
              r1 is not None and r2 is None)

def test_shadow_message_discloses_alternatives():
    d = ShadowInitPackageIntegrityDetector(unpinned_threshold=20)
    with patch.object(d, '_get_packages', return_value=MANY_PKGS), \
         patch.object(d, '_get_editable', return_value=[]):
        r = d.check()
        check("SHADOW: message discloses unpinned pkgs common in ML",
              r is not None and 'common in legitimate' in r['message'])

if __name__ == '__main__':
    for _name, _fn in sorted(globals().items()):
        if _name.startswith('test_'):
            try:
                _fn()
            except Exception as e:
                check(_name, False, f"EXCEPTION {e!r}")
    print("\n" + "=" * 60)
    print(f"PASSED: {len(PASSED)}   FAILED: {len(FAILED)}")
    if FAILED:
        for f in FAILED:
            print(f"  - {f}")
    print("=" * 60)
    sys.exit(1 if FAILED else 0)
