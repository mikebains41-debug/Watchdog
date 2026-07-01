"""
Watchdog AIDR v2.0 - Compliance Evidence Report Generator
Produces structured JSON evidence reports mapping Watchdog alerts to
relevant controls in the following frameworks:
- SOC2 Type II (Security, Availability, Confidentiality)
- EU AI Act (Article 9 Risk Management, Article 13 Transparency)
- NIST AI RMF (GOVERN, MAP, MEASURE, MANAGE)
- NIST CSF 2.0 (IDENTIFY, PROTECT, DETECT, RESPOND, RECOVER)

IMPORTANT: These reports are compliance EVIDENCE, not certifications.
They document which framework controls are relevant to observed alerts
and support an organization's certification journey. Formal SOC2 Type II
or ISO 27001 certification requires an accredited third-party auditor.
Watchdog does not issue certifications and these reports must not be
represented as such.
"""
import json, time, os
from datetime import datetime, timezone

FRAMEWORK_MAP = {
    'GHOST_POWER':               {'soc2': ['CC6.1','CC7.2'],         'eu_ai_act': ['Art.9','Art.17'],  'nist_rmf': ['MEASURE 2.5','MANAGE 1.3'],  'nist_csf': ['DE.AE-2','RS.AN-1']},
    'VRAM_RESIDUAL':             {'soc2': ['CC6.1','CC6.7','CC7.2'], 'eu_ai_act': ['Art.9','Art.10'],  'nist_rmf': ['MEASURE 2.5','MANAGE 2.2'],  'nist_csf': ['PR.DS-1','DE.AE-2']},
    'POWER_SIDE_CHANNEL':        {'soc2': ['CC6.1','CC7.2'],         'eu_ai_act': ['Art.9'],           'nist_rmf': ['MEASURE 2.5'],               'nist_csf': ['DE.AE-2']},
    'THERMAL_EMANATION':         {'soc2': ['CC6.1'],                 'eu_ai_act': ['Art.9'],           'nist_rmf': ['MEASURE 2.5'],               'nist_csf': ['DE.AE-2']},
    'CROSS_TENANT_BLEEDING':     {'soc2': ['CC6.1','CC6.7'],         'eu_ai_act': ['Art.9','Art.10'],  'nist_rmf': ['MEASURE 2.5','MANAGE 2.2'],  'nist_csf': ['PR.DS-1','DE.AE-2']},
    'TIMING_COVERT_CHANNEL':     {'soc2': ['CC6.1','CC7.2'],         'eu_ai_act': ['Art.9'],           'nist_rmf': ['MEASURE 2.5'],               'nist_csf': ['DE.AE-2']},
    'CROSS_WORKLOAD_CLUSTER':    {'soc2': ['CC7.2','CC7.3'],         'eu_ai_act': ['Art.9','Art.17'],  'nist_rmf': ['MANAGE 1.3','MANAGE 2.2'],   'nist_csf': ['RS.AN-1','RS.MI-1']},
    'CLOCK_GLITCH':              {'soc2': ['CC7.2','A1.2'],          'eu_ai_act': ['Art.9'],           'nist_rmf': ['MEASURE 2.5'],               'nist_csf': ['DE.AE-2','RS.AN-1']},
    'VOLTAGE_GLITCH':            {'soc2': ['CC7.2','A1.2'],          'eu_ai_act': ['Art.9'],           'nist_rmf': ['MEASURE 2.5'],               'nist_csf': ['DE.AE-2','RS.AN-1']},
    'DMA_ATTACK':                {'soc2': ['CC6.1','CC7.2','CC7.3'], 'eu_ai_act': ['Art.9'],           'nist_rmf': ['MANAGE 1.3'],                'nist_csf': ['RS.MI-1','RS.AN-1']},
    'LASER_INJECTION':           {'soc2': ['CC6.4','CC7.2'],         'eu_ai_act': ['Art.9'],           'nist_rmf': ['MEASURE 2.5'],               'nist_csf': ['PR.AC-2','DE.AE-2']},
    'CACHE_SIDE_CHANNEL':        {'soc2': ['CC6.1','CC7.2'],         'eu_ai_act': ['Art.9'],           'nist_rmf': ['MEASURE 2.5'],               'nist_csf': ['DE.AE-2']},
    'MIG_PARTITION_DESYNC':      {'soc2': ['CC6.1','CC6.7'],         'eu_ai_act': ['Art.9','Art.10'],  'nist_rmf': ['MEASURE 2.5','MANAGE 2.2'],  'nist_csf': ['PR.DS-1','DE.AE-2']},
    'SEQUENTIAL_VRAM_READ':      {'soc2': ['CC6.1','CC6.7','CC7.3'], 'eu_ai_act': ['Art.9','Art.10'],  'nist_rmf': ['MANAGE 1.3','MANAGE 2.2'],   'nist_csf': ['RS.MI-1','DE.AE-2']},
    'INFERENCE_POWER_ANOMALY':   {'soc2': ['CC7.2','CC9.2'],         'eu_ai_act': ['Art.9','Art.13'],  'nist_rmf': ['MEASURE 2.5','MAP 5.1'],     'nist_csf': ['DE.AE-2','DE.CM-7']},
    'AGENT_ORCHESTRATION_ANOMALY':{'soc2':['CC7.2','CC9.2'],         'eu_ai_act': ['Art.9','Art.13'],  'nist_rmf': ['MEASURE 2.5','MANAGE 1.3'],  'nist_csf': ['DE.AE-2','RS.AN-1']},
    'PROMPT_INJECTION_SIDEEFFECT':{'soc2':['CC6.1','CC7.2'],         'eu_ai_act': ['Art.9','Art.15'],  'nist_rmf': ['MEASURE 2.5'],               'nist_csf': ['DE.AE-2']},
    'AGENT_VRAM_RETENTION':      {'soc2': ['CC6.1','CC6.7'],         'eu_ai_act': ['Art.9','Art.10'],  'nist_rmf': ['MEASURE 2.5','MANAGE 2.2'],  'nist_csf': ['PR.DS-1','DE.AE-2']},
    'INTER_AGENT_HANDOFF_ANOMALY':{'soc2':['CC7.2','CC9.2'],         'eu_ai_act': ['Art.9','Art.13'],  'nist_rmf': ['MEASURE 2.5','MANAGE 1.3'],  'nist_csf': ['DE.AE-2','RS.AN-1']},
    'ROWHAMMER_PROXY':           {'soc2': ['CC7.2'],                 'eu_ai_act': ['Art.9'],           'nist_rmf': ['MEASURE 2.5'],               'nist_csf': ['DE.AE-2']},
    'MODEL_MUTATION':            {'soc2': ['CC6.1','CC7.2','CC7.3'], 'eu_ai_act': ['Art.9','Art.15'],  'nist_rmf': ['MANAGE 1.3','MANAGE 2.2'],   'nist_csf': ['RS.MI-1','DE.AE-2']},
    'PERF_COUNTER_SIDE_CHANNEL': {'soc2': ['CC6.1','CC7.2'],         'eu_ai_act': ['Art.9'],           'nist_rmf': ['MEASURE 2.5'],               'nist_csf': ['DE.AE-2']},
    'NVLINK_ANOMALY':            {'soc2': ['CC7.2','A1.2'],          'eu_ai_act': ['Art.9'],           'nist_rmf': ['MEASURE 2.5'],               'nist_csf': ['DE.AE-2','RS.AN-1']},
    'SUPPLY_CHAIN_ANOMALY':      {'soc2': ['CC9.1','CC9.2'],         'eu_ai_act': ['Art.9','Art.17'],  'nist_rmf': ['MAP 5.1','MANAGE 1.3'],      'nist_csf': ['ID.SC-4','RS.AN-1']},
}

class ComplianceReportGenerator:
    def __init__(self, org_name='', system_name='Watchdog AIDR v2.0', gpu_info=None):
        self.org_name = org_name
        self.system_name = system_name
        self.gpu_info = gpu_info or []

    def generate(self, alerts, state_summary=None, duration_seconds=None, output_path=None):
        now = datetime.now(timezone.utc)
        report = {
            'report_metadata': {
                'title': 'GPU Security Compliance Report',
                'system': self.system_name,
                'organization': self.org_name,
                'generated_at': now.isoformat(),
                'period_seconds': duration_seconds,
                'cve_reference': 'CVE-2048350',
                'frameworks': ['SOC2 Type II (evidence mapping)', 'EU AI Act (evidence mapping)', 'NIST AI RMF 1.0 (evidence mapping)', 'NIST CSF 2.0 (evidence mapping)']
            },
            'executive_summary': self._executive_summary(alerts, state_summary),
            'alert_findings': self._alert_findings(alerts),
            'framework_coverage': self._framework_coverage(alerts),
            'soc2_mapping': self._soc2_section(alerts),
            'eu_ai_act_mapping': self._eu_ai_act_section(alerts),
            'nist_rmf_mapping': self._nist_rmf_section(alerts),
            'nist_csf_mapping': self._nist_csf_section(alerts),
            'remediation_summary': self._remediation_section(alerts),
        }
        if output_path:
            with open(output_path, 'w') as f:
                json.dump(report, f, indent=2)
            print(f"[COMPLIANCE] Report written to {output_path}")
        return report

    def _executive_summary(self, alerts, state_summary):
        critical = [a for a in alerts if a.get('cvss_score',0) >= 9.0]
        high = [a for a in alerts if 7.0 <= a.get('cvss_score',0) < 9.0]
        medium = [a for a in alerts if 4.0 <= a.get('cvss_score',0) < 7.0]
        return {
            'total_alerts': len(alerts),
            'critical_count': len(critical),
            'high_count': len(high),
            'medium_count': len(medium),
            'highest_cvss': max((a.get('cvss_score',0) for a in alerts), default=0),
            'alert_state_summary': state_summary or {},
            'compliance_status': 'REQUIRES_ATTENTION' if critical else 'REVIEW_RECOMMENDED' if high else 'PASS'
        }

    def _alert_findings(self, alerts):
        findings = []
        for a in alerts:
            fw = FRAMEWORK_MAP.get(a.get('type',''), {})
            findings.append({
                'type': a.get('type'),
                'severity': a.get('severity'),
                'cvss_score': a.get('cvss_score'),
                'cvss_vector': a.get('cvss_vector'),
                'gpu': a.get('gpu'),
                'timestamp': a.get('timestamp'),
                'message': a.get('message'),
                'soc2_controls': fw.get('soc2', []),
                'eu_ai_act_articles': fw.get('eu_ai_act', []),
                'nist_rmf_functions': fw.get('nist_rmf', []),
                'nist_csf_subcategories': fw.get('nist_csf', []),
            })
        return sorted(findings, key=lambda x: x.get('cvss_score',0), reverse=True)

    def _framework_coverage(self, alerts):
        types = set(a.get('type') for a in alerts)
        soc2 = set()
        eu = set()
        rmf = set()
        csf = set()
        for t in types:
            fw = FRAMEWORK_MAP.get(t, {})
            soc2.update(fw.get('soc2', []))
            eu.update(fw.get('eu_ai_act', []))
            rmf.update(fw.get('nist_rmf', []))
            csf.update(fw.get('nist_csf', []))
        return {
            'soc2_controls_triggered': sorted(soc2),
            'eu_ai_act_articles_triggered': sorted(eu),
            'nist_rmf_functions_triggered': sorted(rmf),
            'nist_csf_subcategories_triggered': sorted(csf),
        }

    def _soc2_section(self, alerts):
        controls = {}
        for a in alerts:
            for ctrl in FRAMEWORK_MAP.get(a.get('type',''), {}).get('soc2', []):
                if ctrl not in controls:
                    controls[ctrl] = []
                controls[ctrl].append(a.get('type'))
        return controls

    def _eu_ai_act_section(self, alerts):
        articles = {}
        for a in alerts:
            for art in FRAMEWORK_MAP.get(a.get('type',''), {}).get('eu_ai_act', []):
                if art not in articles:
                    articles[art] = []
                articles[art].append(a.get('type'))
        return articles

    def _nist_rmf_section(self, alerts):
        functions = {}
        for a in alerts:
            for fn in FRAMEWORK_MAP.get(a.get('type',''), {}).get('nist_rmf', []):
                if fn not in functions:
                    functions[fn] = []
                functions[fn].append(a.get('type'))
        return functions

    def _nist_csf_section(self, alerts):
        cats = {}
        for a in alerts:
            for cat in FRAMEWORK_MAP.get(a.get('type',''), {}).get('nist_csf', []):
                if cat not in cats:
                    cats[cat] = []
                cats[cat].append(a.get('type'))
        return cats

    def _remediation_section(self, alerts):
        recs = []
        for a in alerts:
            score = a.get('cvss_score', 0)
            if score >= 9.0:
                priority = 'IMMEDIATE'
            elif score >= 7.0:
                priority = 'HIGH'
            else:
                priority = 'MEDIUM'
            recs.append({
                'alert_type': a.get('type'),
                'priority': priority,
                'cvss_score': score,
                'recommended_action': a.get('message', ''),
            })
        return sorted(recs, key=lambda x: x['cvss_score'], reverse=True)
