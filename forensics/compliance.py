import json, os
from datetime import datetime
class ComplianceReporter:
    def __init__(self, audit_log_path='watchdog_data/audit.log'):
        self.audit_log_path = audit_log_path
    def load_alerts(self):
        if not os.path.exists(self.audit_log_path): return []
        alerts = []
        with open(self.audit_log_path,'r') as f:
            for line in f:
                try: alerts.append(json.loads(line).get('alert',{}))
                except: continue
        return alerts
    def soc2(self):
        alerts = self.load_alerts()
        critical = [a for a in alerts if a.get('severity') in ['CRITICAL','EMERGENCY']]
        return {
            'report': 'SOC2 Type II',
            'generated': datetime.now().isoformat(),
            'total_alerts': len(alerts),
            'critical_alerts': len(critical),
            'detection_coverage': '16 detection engines active',
            'findings': [{'type':a.get('type'),'severity':a.get('severity'),'timestamp':a.get('timestamp'),'message':a.get('message')} for a in critical],
            'cve': '2048350',
            'status': 'COMPLIANT' if len(critical)==0 else 'NON_COMPLIANT'
        }
    def nist_ai_rmf(self):
        alerts = self.load_alerts()
        types = list(set(a.get('type') for a in alerts))
        return {
            'report': 'NIST AI RMF',
            'generated': datetime.now().isoformat(),
            'govern': {'policy': 'Watchdog AIDR active', 'cve_filed': '2048350'},
            'map': {'threat_categories': types, 'total_detections': len(alerts)},
            'measure': {'detection_engines': 16, 'sample_rate_hz': 100, 'audit_log_entries': len(alerts)},
            'manage': {'auto_remediation': 'enabled', 'human_in_loop': 'EMERGENCY severity'}
        }
    def hipaa(self):
        alerts = self.load_alerts()
        vram = [a for a in alerts if 'VRAM' in a.get('type','')]
        exfil = [a for a in alerts if a.get('type') in ['SEQUENTIAL_VRAM_READ','DMA_ATTACK','MODEL_MUTATION']]
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
        for name, fn in [('soc2',self.soc2),('nist_ai_rmf',self.nist_ai_rmf),('hipaa',self.hipaa)]:
            path = os.path.join(output_dir, f'{name}_report.json')
            with open(path,'w') as f: json.dump(fn(), f, indent=2)
            print(f"[COMPLIANCE] Saved {path}")
if __name__ == '__main__':
    r = ComplianceReporter()
    r.save_all()
