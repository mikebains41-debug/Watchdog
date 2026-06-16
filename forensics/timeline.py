import json, os, collections
from datetime import datetime
class AttackTimeline:
    MITRE_ATLAS = {
        'GHOST_POWER':'AML.T0048 — Energy side-channel reconnaissance',
        'VRAM_RESIDUAL':'AML.T0012 — GPU memory persistence exploitation',
        'POWER_SIDE_CHANNEL':'AML.T0043 — Power-based covert channel',
        'THERMAL_EMANATION':'AML.T0044 — Thermal covert channel',
        'CROSS_TENANT_BLEEDING':'AML.T0049 — Cross-tenant isolation failure',
        'TIMING_COVERT_CHANNEL':'AML.T0045 — Timing-based covert channel',
        'CROSS_WORKLOAD_CLUSTER':'AML.T0050 — Coordinated multi-GPU attack',
        'ROWHAMMER_PROXY':'AML.T0021 — Memory fault injection proxy',
        'MODEL_MUTATION':'AML.T0031 — Model backdoor injection',
        'PERF_COUNTER_SIDE_CHANNEL':'AML.T0046 — CVE-2018-6260 perf counter leak',
        'NVLINK_ANOMALY':'AML.T0055 — Fabric path manipulation',
        'SUPPLY_CHAIN_ANOMALY':'AML.T0008 — Hardware supply chain compromise',
    }
    def __init__(self, audit_log_path='watchdog_data/audit.log'):
        self.audit_log_path = audit_log_path
        self.events = []
    def load(self):
        if not os.path.exists(self.audit_log_path): return []
        self.events = []
        with open(self.audit_log_path,'r') as f:
            for line in f:
                try:
                    entry = json.loads(line)
                    alert = entry.get('alert',{})
                    self.events.append({'timestamp':entry.get('iso_timestamp'),'type':alert.get('type'),'severity':alert.get('severity'),'gpu':alert.get('gpu'),'message':alert.get('message'),'confidence':alert.get('confidence'),'mitre':self.MITRE_ATLAS.get(alert.get('type',''),'Unknown')})
                except: continue
        self.events.sort(key=lambda x: x.get('timestamp',''))
        return self.events
    def reconstruct(self):
        events = self.load()
        if not events: return "No events in audit log."
        lines = []
        lines.append(f"=== ATTACK TIMELINE RECONSTRUCTION ===")
        lines.append(f"Generated: {datetime.now().isoformat()}")
        lines.append(f"Total events: {len(events)}")
        lines.append(f"Time range: {events[0]['timestamp']} → {events[-1]['timestamp']}")
        lines.append("")
        type_counts = collections.Counter(e['type'] for e in events)
        lines.append("=== EVENT SUMMARY ===")
        for etype, count in type_counts.most_common():
            lines.append(f"  {etype}: {count} events")
        lines.append("")
        lines.append("=== MITRE ATLAS MAPPING ===")
        seen = set()
        for e in events:
            if e['type'] not in seen:
                lines.append(f"  {e['type']} → {e['mitre']}")
                seen.add(e['type'])
        lines.append("")
        lines.append("=== CHRONOLOGICAL EVENTS ===")
        for e in events:
            lines.append(f"[{e['timestamp']}] [{e['severity']}] {e['type']} GPU:{e['gpu']} conf:{e['confidence']} — {e['message']}")
        lines.append("")
        sev_counts = collections.Counter(e['severity'] for e in events)
        if sev_counts.get('EMERGENCY',0) > 0 or sev_counts.get('CRITICAL',0) > 0:
            lines.append("=== VERDICT: ACTIVE THREAT DETECTED ===")
        elif sev_counts.get('WARNING',0) > 0:
            lines.append("=== VERDICT: ANOMALIES DETECTED — INVESTIGATE ===")
        else:
            lines.append("=== VERDICT: NO CRITICAL THREATS ===")
        return '\n'.join(lines)
    def save_report(self, output_path=None):
        report = self.reconstruct()
        path = output_path or self.audit_log_path.replace('audit.log','attack_timeline.txt')
        with open(path,'w') as f: f.write(report)
        print(f"Timeline saved: {path}")
        return path
if __name__ == '__main__':
    t = AttackTimeline()
    print(t.reconstruct())
