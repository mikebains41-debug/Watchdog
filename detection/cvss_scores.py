# Author: Manmohan (Mike) Bains -- Watchdog
"""
Watchdog v2.0 - CVSS v3.1 Scoring
Maps each detection engine alert type to a CVSS v3.1 base score and vector.
Scores reflect GPU infrastructure threat model:
- Confidentiality: proprietary model weights, training data, VRAM contents
- Integrity: model tampering, firmware, boot attestation
- Availability: power attacks, hardware damage, service disruption
"""

CVSS_MAP = {
    # Base Engines
    'GHOST_POWER': {
        'score': 6.8,
        'vector': 'CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:L/I:N/A:H',
        'severity': 'MEDIUM',
        'rationale': 'Local attacker, elevated power state post-workload, availability impact via resource exhaustion, scope changed due to hypervisor boundary'
    },
    'VRAM_RESIDUAL': {
        'score': 8.4,
        'vector': 'CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:N/A:N',
        'severity': 'HIGH',
        'rationale': 'CVE-2048350 (pending MITRE assignment) - VRAM contents recoverable after process exit, high confidentiality impact (model weights, training data), scope changed (cross-tenant)'
    },
    'POWER_SIDE_CHANNEL': {
        'score': 5.9,
        'vector': 'CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:C/C:H/I:N/A:N',
        'severity': 'MEDIUM',
        'rationale': 'High attack complexity, local access required, confidentiality impact via workload fingerprinting'
    },
    'THERMAL_EMANATION': {
        'score': 4.7,
        'vector': 'CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:C/C:L/I:N/A:N',
        'severity': 'MEDIUM',
        'rationale': 'Thermal covert channel, high complexity, limited confidentiality impact'
    },
    'CROSS_TENANT_BLEEDING': {
        'score': 7.5,
        'vector': 'CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:C/C:H/I:N/A:N',
        'severity': 'HIGH',
        'rationale': 'Cross-tenant power bleed detects neighbor workload, confidentiality impact, scope changed'
    },
    'TIMING_COVERT_CHANNEL': {
        'score': 5.9,
        'vector': 'CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:C/C:H/I:N/A:N',
        'severity': 'MEDIUM',
        'rationale': 'Regular timing patterns indicate covert channel, high complexity'
    },
    'CROSS_WORKLOAD_CLUSTER': {
        'score': 9.3,
        'vector': 'CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H',
        'severity': 'CRITICAL',
        'rationale': 'Coordinated attack across multiple GPUs, full CIA impact, scope changed'
    },

    # Hardware Attack Engines
    'CLOCK_GLITCH': {
        'score': 7.8,
        'vector': 'CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H',
        'severity': 'HIGH',
        'rationale': 'Clock glitch injection can cause computation errors, full local CIA impact'
    },
    'VOLTAGE_GLITCH': {
        'score': 8.2,
        'vector': 'CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:L',
        'severity': 'HIGH',
        'rationale': 'Voltage glitch bypasses security boundaries, high C/I impact, scope changed'
    },
    'DMA_ATTACK': {
        'score': 9.6,
        'vector': 'CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H',
        'severity': 'CRITICAL',
        'rationale': 'DMA attack bypasses OS, no privileges required, full CIA impact, scope changed'
    },
    'LASER_INJECTION': {
        'score': 7.1,
        'vector': 'CVSS:3.1/AV:P/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
        'severity': 'HIGH',
        'rationale': 'Physical access required (AV:P), but full CIA impact once achieved'
    },

    # Memory Attack Engines
    'CACHE_SIDE_CHANNEL': {
        'score': 5.9,
        'vector': 'CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:C/C:H/I:N/A:N',
        'severity': 'MEDIUM',
        'rationale': 'L2 cache side-channel, high complexity, confidentiality impact via memory access patterns'
    },
    'MIG_PARTITION_DESYNC': {
        'score': 7.5,
        'vector': 'CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:C/C:H/I:N/A:N',
        'severity': 'HIGH',
        'rationale': 'MIG partition boundary violation, cross-partition side channel, scope changed'
    },
    'SEQUENTIAL_VRAM_READ': {
        'score': 9.0,
        'vector': 'CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:N/A:H',
        'severity': 'CRITICAL',
        'rationale': 'Bulk VRAM read = model exfiltration, high C and A impact, scope changed'
    },

    # LLM / Agentic AI Engines
    'INFERENCE_POWER_ANOMALY': {
        'score': 7.7,
        'vector': 'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N',
        'severity': 'HIGH',
        'rationale': 'Network-accessible inference endpoint, model substitution or adversarial input attack'
    },
    'AGENT_ORCHESTRATION_ANOMALY': {
        'score': 8.8,
        'vector': 'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:N',
        'severity': 'HIGH',
        'rationale': 'Agent covert mining or model extraction over network, scope changed via orchestration layer'
    },
    'PROMPT_INJECTION_SIDEEFFECT': {
        'score': 6.5,
        'vector': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N',
        'severity': 'MEDIUM',
        'rationale': 'Network vector, no privileges required, adversarial prompt or jailbreak attempt'
    },
    'AGENT_VRAM_RETENTION': {
        'score': 8.4,
        'vector': 'CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:N/A:N',
        'severity': 'HIGH',
        'rationale': 'CVE-2048350 (pending MITRE assignment) applied to agentic AI - proprietary drug discovery data in VRAM post-session, scope changed'
    },
    'INTER_AGENT_HANDOFF_ANOMALY': {
        'score': 8.1,
        'vector': 'CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:C/C:H/I:H/A:N',
        'severity': 'HIGH',
        'rationale': 'Compromised upstream agent poisoning downstream agent pipeline, network vector, scope changed'
    },

    # Advanced Engines
    'MEMORY_ACTIVATION_ANOMALY': {
        'score': 5.6,
        'vector': 'CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:L/I:H/A:N',
        'severity': 'MEDIUM',
        'rationale': 'Sustained high-variance memory usage at low compute utilization -- NOT Rowhammer-specific; renamed from ROWHAMMER_PROXY after confirming the detector cannot see the actual bit-flip access pattern real Rowhammer-class attacks require'
    },
    'MODEL_MUTATION': {
        'score': 9.1,
        'vector': 'CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:N',
        'severity': 'CRITICAL',
        'rationale': 'Model tampering or backdoor injection, critical C/I impact, scope changed'
    },
    'MEMORY_UTIL_DECOUPLED_FROM_COMPUTE': {
        'score': 5.9,
        'vector': 'CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:C/C:H/I:N/A:N',
        'severity': 'MEDIUM',
        'rationale': 'CVE-2018-6260 performance counter side-channel, high complexity'
    },
    'NVLINK_ANOMALY': {
        'score': 7.3,
        'vector': 'CVSS:3.1/AV:L/AC:H/PR:H/UI:N/S:C/C:H/I:H/A:N',
        'severity': 'HIGH',
        'rationale': 'NVLink man-in-the-middle on GPU interconnect, high C/I impact'
    },
    'SUPPLY_CHAIN_ANOMALY': {
        'score': 7.8,
        'vector': 'CVSS:3.1/AV:P/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N',
        'severity': 'HIGH',
        'rationale': 'Counterfeit or tampered hardware, physical vector, scope changed, high C/I'
    },

    # Infrastructure
    'PCIE_ANOMALY': {
        'score': 6.7,
        'vector': 'CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:C/C:L/I:H/A:L',
        'severity': 'MEDIUM',
        'rationale': 'PCIe health anomaly, potential integrity impact via bus manipulation'
    },
    'FAN_WEAR': {
        'score': 4.0,
        'vector': 'CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H',
        'severity': 'MEDIUM',
        'rationale': 'Predictive failure, availability impact only'
    },
    'CAPACITOR_AGING': {
        'score': 4.0,
        'vector': 'CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H',
        'severity': 'MEDIUM',
        'rationale': 'Predictive failure, availability impact only'
    },
    'PACKAGE_CRACKING': {
        'score': 5.5,
        'vector': 'CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H',
        'severity': 'MEDIUM',
        'rationale': 'Physical degradation, high availability impact'
    },
}

def get_cvss(alert_type):
    """Return CVSS data for a given alert type. Returns None if not mapped."""
    return CVSS_MAP.get(alert_type)

def enrich_alert(alert):
    """Add CVSS score and vector to an alert dict in-place. Returns alert."""
    cvss = get_cvss(alert.get('type',''))
    if cvss:
        alert['cvss_score'] = cvss['score']
        alert['cvss_vector'] = cvss['vector']
        alert['cvss_severity'] = cvss['severity']
        alert['cvss_rationale'] = cvss['rationale']
    return alert
