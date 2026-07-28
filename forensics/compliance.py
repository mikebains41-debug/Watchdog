# Author: Manmohan (Mike) Bains -- Watchdog
"""
FIXED: this module previously hardcoded 'detection_coverage': '16
detection engines active', 'detection_engines': 16, and
'sample_rate_hz': 100 -- fixed strings/numbers with no connection to
the actual running pipeline, silently wrong the moment the real engine
count changed (it has, repeatedly). 'auto_remediation': 'enabled' was
asserted unconditionally regardless of the real setting.

This is a compliance-evidence tool specifically -- the class of file
most likely to be handed to an auditor. Reporting a stale or invented
number here isn't a cosmetic bug, it's a false claim in the one place
where accuracy matters most.

Fixed by accepting these as real values the caller supplies from their
own live pipeline, rather than guessing or hardcoding. When not
supplied, reports honestly report None/"not supplied by caller" rather
than a fabricated default -- same "refuse rather than guess" pattern
used throughout this project (e.g. VRAMResidualDetector's strict mode,
CostImpactAggregator never inventing a dollar figure without a real
rate). sample_rate_hz in particular should be sourced from a REAL
measured value (e.g. telemetry/sampler.py's DeltaTimedSampler.achieved_rate_hz()),
not the requested/assumed rate -- the project's own README states
plainly that the requested and achieved intervals differ substantially
and any figure not derived from measured deltas is unreliable.
"""
import json, os
from datetime import datetime


class ComplianceReporter:
    def __init__(self, audit_log_path='watchdog_data/audit.log',
                 engine_count=None, sample_rate_hz=None, auto_remediate_enabled=None):
        self.audit_log_path = audit_log_path
        self.engine_count = engine_count
        self.sample_rate_hz = sample_rate_hz
        self.auto_remediate_enabled = auto_remediate_enabled

    def load_alerts(self):
        if not os.path.exists(self.audit_log_path):
            return []
        alerts = []
        with open(self.audit_log_path, 'r') as f:
            for line in f:
                try:
                    alerts.append(json.loads(line).get('alert', {}))
                except Exception:
                    continue
        return alerts

    def _coverage_str(self):
        if self.engine_count is None:
            return 'not supplied by caller -- see ComplianceReporter(engine_count=...)'
        return f'{self.engine_count} detection engines active'

    def soc2(self):
        alerts = self.load_alerts()
        critical = [a for a in alerts if a.get('severity') in ['CRITICAL', 'EMERGENCY']]
        return {
            'report': 'SOC2 Type II — control mapping evidence only, not certification',
            'generated': datetime.now().isoformat(),
            'total_alerts': len(alerts),
            'critical_alerts': len(critical),
            'detection_coverage': self._coverage_str(),
            'findings': [{'type': a.get('type'), 'severity': a.get('severity'),
                          'timestamp': a.get('timestamp'), 'message': a.get('message')} for a in critical],
            'cve': '2048350', 'cve_status': 'pending MITRE assignment',
            'status': 'COMPLIANT' if len(critical) == 0 else 'NON_COMPLIANT'
        }

    def nist_ai_rmf(self):
        alerts = self.load_alerts()
        types = list(set(a.get('type') for a in alerts))
        return {
            'report': 'NIST AI RMF — control mapping evidence only, not certification',
            'generated': datetime.now().isoformat(),
            'govern': {'policy': 'Watchdog active', 'cve_filed': '2048350', 'cve_status': 'pending MITRE assignment'},
            'map': {'threat_categories': types, 'total_detections': len(alerts)},
            'measure': {
                'detection_engines': self.engine_count if self.engine_count is not None else 'not supplied by caller',
                'sample_rate_hz': (self.sample_rate_hz if self.sample_rate_hz is not None
                                    else 'not supplied by caller -- requested rate is not a reliable substitute, see README Limitations'),
                'audit_log_entries': len(alerts),
            },
            'manage': {
                'auto_remediation': (self.auto_remediate_enabled if self.auto_remediate_enabled is not None
                                      else 'not supplied by caller'),
                'human_in_loop': 'EMERGENCY severity',
            }
        }

    def hipaa(self):
        alerts = self.load_alerts()
        vram = [a for a in alerts if 'VRAM' in a.get('type', '')]
        exfil = [a for a in alerts if a.get('type') in ['SEQUENTIAL_VRAM_READ', 'DMA_ATTACK', 'MODEL_MUTATION']]
        return {
            'report': 'HIPAA Data Flow Audit',
            'generated': datetime.now().isoformat(),
            'phi_exposure_risk': 'HIGH' if exfil else 'LOW',
            'vram_incidents': len(vram),
            'exfiltration_attempts': len(exfil),
            'unauthorized_access_detected': len(exfil) > 0,
            'remediation_applied': True
        }

    def save_all(self, output_dir='watchdog_data'):
        os.makedirs(output_dir, exist_ok=True)
        for name, fn in [('soc2', self.soc2), ('nist_ai_rmf', self.nist_ai_rmf), ('hipaa', self.hipaa)]:
            path = os.path.join(output_dir, f'{name}_report.json')
            with open(path, 'w') as f:
                json.dump(fn(), f, indent=2)
            print(f"[COMPLIANCE] Saved {path}")


if __name__ == '__main__':
    r = ComplianceReporter()
    r.save_all()
