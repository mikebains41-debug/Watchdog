# Author: Manmohan (Mike) Bains -- Watchdog
"""
detection/migration_recommendation.py

Generates human-readable migration/rebalancing RECOMMENDATIONS when
Agent 3 (ThermalEventPredictor) or Agent 4 (TenantIsolationRiskScorer)
predictions fire. Does NOT execute any migration -- advisory only,
same human-approval-required philosophy already used throughout
remediation/response.py and orchestration/cluster_actions.py.

HONEST LIMITATION, stated rather than hidden: this has no real MIG
topology or fleet awareness. It does not know which other slice or GPU
is actually cooler, less-loaded, or even exists. It names the SOURCE
GPU and the reason clearly, and explicitly leaves identifying an
actual migration target to a human operator or a real orchestration
system that has that awareness -- this tool doesn't, and doesn't
pretend to.
"""


class MigrationRecommendationGenerator:
    def __init__(self):
        self.recommendation_count = 0

    def process(self, prediction_alert):
        alert_type = prediction_alert.get('type')
        if alert_type == 'THERMAL_THROTTLE_PREDICTED':
            return self._thermal_recommendation(prediction_alert)
        elif alert_type == 'TENANT_ISOLATION_RISK':
            return self._isolation_recommendation(prediction_alert)
        return None

    def _thermal_recommendation(self, alert):
        self.recommendation_count += 1
        gpu = alert.get('gpu')
        samples = alert.get('estimated_samples_to_throttle')
        confidence = alert.get('confidence_pct')
        return {
            'type': 'MIGRATION_RECOMMENDED',
            'severity': 'INFO',
            'gpu': gpu,
            'reason': 'thermal',
            'source_prediction': 'THERMAL_THROTTLE_PREDICTED',
            'source_confidence_pct': confidence,
            'estimated_samples_to_event': samples,
            'timestamp': alert.get('timestamp'),
            'message': (f"RECOMMENDATION (not automatic): GPU{gpu} predicted to reach "
                        f"thermal throttle in ~{samples} samples (confidence "
                        f"{confidence}%). Consider migrating non-critical workload to a "
                        f"cooler GPU. This tool does not know which GPU that is -- it has "
                        f"no fleet topology awareness. A human or a real orchestration "
                        f"system with that awareness should choose the actual target."),
            'action_taken': None,
        }

    def _isolation_recommendation(self, alert):
        self.recommendation_count += 1
        gpu = alert.get('gpu')
        risk = alert.get('risk_score_pct')
        return {
            'type': 'MIGRATION_RECOMMENDED',
            'severity': 'INFO',
            'gpu': gpu,
            'reason': 'tenant_isolation_risk',
            'source_prediction': 'TENANT_ISOLATION_RISK',
            'source_risk_pct': risk,
            'timestamp': alert.get('timestamp'),
            'message': (f"RECOMMENDATION (not automatic): GPU{gpu} shows elevated tenant "
                        f"isolation risk ({risk}%, simulation-based -- see "
                        f"TenantIsolationRiskScorer's own disclosed limitations, including "
                        f"its permanently degraded timing signal given current telemetry "
                        f"collection). Consider reviewing workload placement. This is NOT "
                        f"confirmation of an actual breach."),
            'action_taken': None,
        }
