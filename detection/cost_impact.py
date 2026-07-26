# Author: Manmohan (Mike) Bains -- Watchdog AIDR
"""
detection/cost_impact.py

Aggregates BillingIntegrityDetector's real BILLING_INTEGRITY_GAP
alerts (already logged to AuditLedger) into a fleet-wide summary:
total ghost-power time observed, and a dollar estimate ONLY when the
underlying alerts actually carried one.

HONEST DESIGN, matching BillingIntegrityDetector's own discipline:
this never invents a cost figure. If BillingIntegrityDetector was
constructed without a rate_usd_per_kwh, its alerts carry
estimated_cost_usd=None, and this aggregator reports that plainly --
it does not apply its own assumed rate on top to manufacture a number
that looks more complete than the underlying data actually is.
"""


class CostImpactAggregator:
    def __init__(self, ledger):
        self.ledger = ledger

    def summary(self, limit=10000):
        entries = [
            e for e in self.ledger.get_entries(record_type='ALERT', limit=limit)
            if e.get('payload', {}).get('type') == 'BILLING_INTEGRITY_GAP'
        ]

        if not entries:
            return {
                'events_observed': 0,
                'affected_gpus': [],
                'total_ghost_seconds': 0.0,
                'total_estimated_cost_usd': None,
                'note': 'No BILLING_INTEGRITY_GAP alerts in the ledger yet.',
            }

        affected_gpus = sorted(set(e['payload'].get('gpu') for e in entries), key=str)

        max_ghost_seconds_by_gpu = {}
        max_cost_by_gpu = {}
        any_cost_present = False
        for e in entries:
            p = e['payload']
            gpu = p.get('gpu')
            secs = p.get('cumulative_ghost_seconds', 0.0) or 0.0
            if gpu not in max_ghost_seconds_by_gpu or secs > max_ghost_seconds_by_gpu[gpu]:
                max_ghost_seconds_by_gpu[gpu] = secs
            cost = p.get('estimated_cost_usd')
            if cost is not None:
                any_cost_present = True
                if gpu not in max_cost_by_gpu or cost > max_cost_by_gpu[gpu]:
                    max_cost_by_gpu[gpu] = cost

        total_ghost_seconds = sum(max_ghost_seconds_by_gpu.values())
        total_cost = sum(max_cost_by_gpu.values()) if any_cost_present else None

        return {
            'events_observed': len(entries),
            'affected_gpus': affected_gpus,
            'total_ghost_seconds': round(total_ghost_seconds, 1),
            'total_ghost_hours': round(total_ghost_seconds / 3600.0, 3),
            'total_estimated_cost_usd': (round(total_cost, 4) if total_cost is not None else None),
            'note': (None if any_cost_present else
                     'No rate_usd_per_kwh was ever supplied to BillingIntegrityDetector -- '
                     'physical time totals are real, cost is not estimated without a real rate.'),
        }
