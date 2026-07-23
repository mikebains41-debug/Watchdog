#!/usr/bin/env python3
"""
Watchdog AIDR v2.0 - Attested Report Generator
Produces a structured alert report formatted for Serial Alice attestation.

When submitted to Serial Alice, each Watchdog alert session becomes:
- Ed25519 + ML-DSA-65 signed
- Merkle batched
- Polygon blockchain anchored
- Independently verifiable at api.serialalice.pt

This makes every Watchdog security finding as credible as the
GPU Energy Optimizer measurements in the June 27 2026 validation report.

# Author: Manmohan (Mike) Bains -- Watchdog AIDR
"""
import json, hashlib, time
from datetime import datetime, timezone


class WatchdogAttestedReport:
    """
    Formats a Watchdog alert session for Serial Alice attestation submission.

    Serial Alice attests:
    - The alert types detected
    - The timestamps they occurred
    - The GPU telemetry values that triggered them
    - The CVSS scores assigned
    - That the report is unaltered since generation

    Serial Alice does NOT attest:
    - Whether the detection methodology is correct
    - Regulatory conformance
    - Anything not in the signed payload
    """

    def __init__(self, session_id=None, gpu_arch='H200', operator=''):
        self.session_id = session_id or self._generate_session_id()
        self.gpu_arch = gpu_arch
        self.operator = operator
        self.alerts = []
        self.telemetry_samples = 0
        self.start_time = datetime.now(timezone.utc).isoformat()
        self.end_time = None

    def _generate_session_id(self):
        ts = str(time.time()).encode()
        return 'wdog-' + hashlib.sha256(ts).hexdigest()[:16]

    def add_alert(self, alert):
        self.alerts.append({
            'type': alert.get('type'),
            'severity': alert.get('severity'),
            'cvss_score': alert.get('cvss_score'),
            'cvss_vector': alert.get('cvss_vector'),
            'cvss_severity': alert.get('cvss_severity'),
            'gpu': alert.get('gpu'),
            'timestamp': alert.get('timestamp'),
            'message': alert.get('message'),
        })

    def add_telemetry_count(self, count):
        self.telemetry_samples += count

    def finalize(self):
        self.end_time = datetime.now(timezone.utc).isoformat()

    def build_attestation_payload(self):
        """
        Builds the canonical payload for Serial Alice submission.
        This is what gets signed and anchored.
        """
        if not self.end_time:
            self.finalize()

        critical = [a for a in self.alerts if a.get('cvss_score', 0) >= 9.0]
        high = [a for a in self.alerts if 7.0 <= a.get('cvss_score', 0) < 9.0]
        medium = [a for a in self.alerts if 4.0 <= a.get('cvss_score', 0) < 7.0]

        payload = {
            'schema': 'watchdog-attestation-v1.0',
            'session': {
                'session_id': self.session_id,
                'gpu_arch': self.gpu_arch,
                'operator': self.operator,
                'start_time': self.start_time,
                'end_time': self.end_time,
                'telemetry_samples': self.telemetry_samples,
            },
            'summary': {
                'total_alerts': len(self.alerts),
                'critical_count': len(critical),
                'high_count': len(high),
                'medium_count': len(medium),
                'highest_cvss': max((a.get('cvss_score', 0) for a in self.alerts), default=0),
                'alert_types_detected': sorted(set(a['type'] for a in self.alerts)),
                'gpus_monitored': sorted(set(str(a.get('gpu', 0)) for a in self.alerts)),
            },
            'alerts': self.alerts,
            'cve_reference': 'CVE-2048350 (pending assignment)',
            'watchdog_version': '2.0',
            'author': 'Manmohan Mike Bains',
            'attestation_note': (
                'This payload is formatted for Serial Alice attestation. '
                'Serial Alice will sign and anchor this report making '
                'every finding independently verifiable. '
                'Serial Alice attests measurement integrity only — '
                'not detection methodology or regulatory conformance.'
            ),
        }

        payload['payload_hash'] = hashlib.sha256(
            json.dumps(payload, sort_keys=True).encode()
        ).hexdigest()

        return payload

    def export_json(self, path=None):
        payload = self.build_attestation_payload()
        if path:
            with open(path, 'w') as f:
                json.dump(payload, f, indent=2)
            print(f"[ATTESTED REPORT] Written to {path}")
            print(f"[ATTESTED REPORT] Session: {self.session_id}")
            print(f"[ATTESTED REPORT] Alerts: {payload['summary']['total_alerts']}")
            print(f"[ATTESTED REPORT] Payload hash: {payload['payload_hash'][:32]}...")
            print(f"[ATTESTED REPORT] Submit to Serial Alice for signing and Polygon anchoring")
        return payload

    def print_summary(self, payload=None):
        if not payload:
            payload = self.build_attestation_payload()
        print(f"\n{'='*55}")
        print(f"WATCHDOG ATTESTED REPORT SUMMARY")
        print(f"{'='*55}")
        print(f"Session ID:     {payload['session']['session_id']}")
        print(f"GPU Arch:       {payload['session']['gpu_arch']}")
        print(f"Start:          {payload['session']['start_time']}")
        print(f"End:            {payload['session']['end_time']}")
        print(f"Samples:        {payload['session']['telemetry_samples']}")
        print(f"Total alerts:   {payload['summary']['total_alerts']}")
        print(f"Critical:       {payload['summary']['critical_count']}")
        print(f"High:           {payload['summary']['high_count']}")
        print(f"Medium:         {payload['summary']['medium_count']}")
        print(f"Highest CVSS:   {payload['summary']['highest_cvss']}")
        print(f"Types detected: {payload['summary']['alert_types_detected']}")
        print(f"Payload hash:   {payload['payload_hash'][:32]}...")
        print(f"{'='*55}")
        print(f"Ready for Serial Alice attestation submission.")
        print(f"{'='*55}\n")
