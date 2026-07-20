#!/usr/bin/env python3
"""
Watchdog AIDR v2.0 - Multi-GPU Attack Timeline & Kill Chain Report
Builds chronological attack timeline across multiple GPUs.
Identifies kill chain stages, first-seen GPU, propagation patterns.
Maps to MITRE ATLAS and MITRE ATT&CK for ICS frameworks.
Author: Manmohan Mike Bains
"""
import json, time
from datetime import datetime, timezone
from collections import defaultdict

KILL_CHAIN_MAP = {
    'SUPPLY_CHAIN_ANOMALY':          {'stage':'Initial Access',      'mitre_atlas':'AML.T0010','mitre_ics':'T0862'},
    'LASER_INJECTION':               {'stage':'Initial Access',      'mitre_atlas':'AML.T0010','mitre_ics':'T0883'},
    'DMA_ATTACK':                    {'stage':'Execution',           'mitre_atlas':'AML.T0011','mitre_ics':'T0807'},
    'CLOCK_GLITCH':                  {'stage':'Execution',           'mitre_atlas':'AML.T0011','mitre_ics':'T0807'},
    'VOLTAGE_GLITCH':                {'stage':'Execution',           'mitre_atlas':'AML.T0011','mitre_ics':'T0807'},
    'PROMPT_INJECTION_SIDEEFFECT':   {'stage':'Execution',           'mitre_atlas':'AML.T0051','mitre_ics':'T0807'},
    'INTER_AGENT_HANDOFF_ANOMALY':   {'stage':'Lateral Movement',    'mitre_atlas':'AML.T0012','mitre_ics':'T0812'},
    'CROSS_TENANT_BLEEDING':         {'stage':'Lateral Movement',    'mitre_atlas':'AML.T0012','mitre_ics':'T0812'},
    'MIG_PARTITION_DESYNC':          {'stage':'Lateral Movement',    'mitre_atlas':'AML.T0012','mitre_ics':'T0812'},
    'NVLINK_ANOMALY':                {'stage':'Lateral Movement',    'mitre_atlas':'AML.T0012','mitre_ics':'T0812'},
    'CACHE_SIDE_CHANNEL':            {'stage':'Collection',          'mitre_atlas':'AML.T0035','mitre_ics':'T0830'},
    'PERF_COUNTER_SIDE_CHANNEL':     {'stage':'Collection',          'mitre_atlas':'AML.T0035','mitre_ics':'T0830'},
    'POWER_SIDE_CHANNEL':            {'stage':'Collection',          'mitre_atlas':'AML.T0035','mitre_ics':'T0830'},
    'THERMAL_EMANATION':             {'stage':'Collection',          'mitre_atlas':'AML.T0035','mitre_ics':'T0830'},
    'TIMING_COVERT_CHANNEL':         {'stage':'Collection',          'mitre_atlas':'AML.T0035','mitre_ics':'T0830'},
    'ROWHAMMER_PROXY':               {'stage':'Collection',          'mitre_atlas':'AML.T0035','mitre_ics':'T0830'},
    'SEQUENTIAL_VRAM_READ':          {'stage':'Exfiltration',        'mitre_atlas':'AML.T0037','mitre_ics':'T0830'},
    'VRAM_RESIDUAL':                 {'stage':'Exfiltration',        'mitre_atlas':'AML.T0037','mitre_ics':'T0830'},
    'AGENT_VRAM_RETENTION':          {'stage':'Exfiltration',        'mitre_atlas':'AML.T0037','mitre_ics':'T0830'},
    'MODEL_MUTATION':                {'stage':'Impact',              'mitre_atlas':'AML.T0031','mitre_ics':'T0831'},
    'INFERENCE_POWER_ANOMALY':       {'stage':'Impact',              'mitre_atlas':'AML.T0031','mitre_ics':'T0831'},
    'AGENT_ORCHESTRATION_ANOMALY':   {'stage':'Impact',              'mitre_atlas':'AML.T0048','mitre_ics':'T0831'},
    'GHOST_POWER':                   {'stage':'Defense Evasion',     'mitre_atlas':'AML.T0015','mitre_ics':'T0872'},
    'CROSS_WORKLOAD_CLUSTER':        {'stage':'Command and Control',  'mitre_atlas':'AML.T0011','mitre_ics':'T0884'},
}

STAGE_ORDER = [
    'Initial Access',
    'Execution',
    'Lateral Movement',
    'Collection',
    'Exfiltration',
    'Impact',
    'Defense Evasion',
    'Command and Control',
]

class AttackTimelineBuilder:
    def __init__(self):
        self.events = []

    def add_alert(self, alert):
        self.events.append({
            'timestamp': alert.get('timestamp', datetime.now(timezone.utc).isoformat()),
            'type': alert.get('type'),
            'severity': alert.get('severity'),
            'cvss_score': alert.get('cvss_score', 0),
            'gpu': alert.get('gpu', 0),
            'message': alert.get('message', ''),
            'kill_chain': KILL_CHAIN_MAP.get(alert.get('type',''), {
                'stage': 'Unknown',
                'mitre_atlas': 'N/A',
                'mitre_ics': 'N/A'
            })
        })

    def build_report(self, output_path=None):
        if not self.events:
            return {'error': 'No events recorded'}
        sorted_events = sorted(self.events, key=lambda x: x['timestamp'])
        gpus_affected = sorted(set(str(e['gpu']) for e in self.events))
        first_event = sorted_events[0]
        last_event = sorted_events[-1]
        stages_seen = []
        for stage in STAGE_ORDER:
            if any(e['kill_chain']['stage'] == stage for e in sorted_events):
                stages_seen.append(stage)
        report = {
            'report_metadata': {
                'title': 'Multi-GPU Attack Timeline & Kill Chain Report',
                'generated_at': datetime.now(timezone.utc).isoformat(),
                'system': 'Watchdog AIDR v2.0',
                'author': 'Manmohan Mike Bains',
                'cve_reference': 'CVE-2048350 (pending assignment)',
                'frameworks': ['MITRE ATLAS', 'MITRE ATT&CK for ICS'],
            },
            'attack_summary': {
                'total_events': len(self.events),
                'gpus_affected': gpus_affected,
                'gpu_count': len(gpus_affected),
                'first_event': first_event['timestamp'],
                'last_event': last_event['timestamp'],
                'first_gpu': str(first_event['gpu']),
                'kill_chain_stages': stages_seen,
                'attack_pattern': self._classify_attack_pattern(stages_seen),
                'highest_cvss': max(e['cvss_score'] for e in self.events),
                'critical_count': sum(1 for e in self.events if e.get('cvss_score',0) >= 9.0),
            },
            'kill_chain_timeline': self._kill_chain_timeline(sorted_events),
            'propagation_analysis': self._build_propagation(sorted_events),
            'chronological_events': sorted_events,
            'mitre_atlas_techniques': sorted(set(
                e['kill_chain']['mitre_atlas'] for e in self.events
                if e['kill_chain']['mitre_atlas'] != 'N/A'
            )),
            'mitre_ics_techniques': sorted(set(
                e['kill_chain']['mitre_ics'] for e in self.events
                if e['kill_chain']['mitre_ics'] != 'N/A'
            )),
        }
        if output_path:
            with open(output_path, 'w') as f:
                json.dump(report, f, indent=2)
            print(f"[TIMELINE] Report written to {output_path}")
        return report

    def _kill_chain_timeline(self, events):
        timeline = {}
        for stage in STAGE_ORDER:
            stage_events = [e for e in events if e['kill_chain']['stage'] == stage]
            if stage_events:
                timeline[stage] = {
                    'event_count': len(stage_events),
                    'first_seen': stage_events[0]['timestamp'],
                    'gpus': sorted(set(str(e['gpu']) for e in stage_events)),
                    'alert_types': sorted(set(e['type'] for e in stage_events)),
                    'max_cvss': max(e['cvss_score'] for e in stage_events),
                    'mitre_atlas': sorted(set(e['kill_chain']['mitre_atlas'] for e in stage_events)),
                }
        return timeline

    def _build_propagation(self, events):
        if len(set(str(e['gpu']) for e in events)) < 2:
            return {'multi_gpu': False, 'note': 'Single GPU — no propagation detected'}
        gpu_first_seen = {}
        for e in events:
            g = str(e['gpu'])
            if g not in gpu_first_seen:
                gpu_first_seen[g] = e['timestamp']
        origin = min(gpu_first_seen, key=gpu_first_seen.get)
        spread = sorted(gpu_first_seen.items(), key=lambda x: x[1])
        return {
            'multi_gpu': True,
            'origin_gpu': origin,
            'spread_sequence': [{'gpu': g, 'first_seen': t} for g, t in spread],
            'propagation_pattern': 'Sequential' if len(spread) > 2 else 'Simultaneous',
        }

    def _classify_attack_pattern(self, stages):
        if 'Exfiltration' in stages and 'Lateral Movement' in stages:
            return 'Advanced Persistent Threat — Multi-stage exfiltration with lateral movement'
        elif 'Exfiltration' in stages:
            return 'Data Exfiltration — Model weights or VRAM contents targeted'
        elif 'Impact' in stages and 'Execution' in stages:
            return 'Sabotage — Model tampering or inference manipulation'
        elif 'Collection' in stages:
            return 'Reconnaissance — Side-channel intelligence gathering'
        elif 'Initial Access' in stages:
            return 'Initial Compromise — Supply chain or physical attack'
        else:
            return 'Unknown Pattern'
