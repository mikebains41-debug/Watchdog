"""
detection/fleet_aggregation.py

Rolls up per-GPU alerts (from any detector in this repo) into a
fleet-wide view: "N of M GPUs currently showing anomaly type X" instead
of one alert at a time. This is the layer a 3,000-GPU operator actually
needs -- a single-GPU alert stream does not scale to that audience on
its own.

STILL UNRESOLVED, stated rather than hidden:
  This module only aggregates alerts that are actually produced upstream
  by other detectors -- it invents no new detection logic of its own.
  It has not been run against a real multi-GPU fleet; the data structures
  and rollup logic are unit-tested against synthetic alert streams only.
"""
import time
import collections


class FleetAggregator:
    def __init__(self, fleet_size=None, window_seconds=300):
        self.fleet_size = fleet_size
        self.window_seconds = window_seconds
        self.alert_log = collections.deque()

    def ingest(self, alert, node_id=None, now=None):
        t = now if now is not None else time.time()
        entry = dict(alert)
        entry['_node_id'] = node_id if node_id is not None else alert.get('gpu', 0)
        entry['_ingested_at'] = t
        self.alert_log.append(entry)
        self._prune(t)

    def _prune(self, now):
        while self.alert_log and (now - self.alert_log[0]['_ingested_at']) > self.window_seconds:
            self.alert_log.popleft()

    def summary(self, now=None):
        t = now if now is not None else time.time()
        self._prune(t)

        by_type = collections.defaultdict(set)
        by_node = collections.defaultdict(set)
        severity_counts = collections.Counter()

        for entry in self.alert_log:
            atype = entry.get('type', 'UNKNOWN')
            node = entry['_node_id']
            by_type[atype].add(node)
            by_node[node].add(atype)
            severity_counts[entry.get('severity', 'UNKNOWN')] += 1

        affected_nodes = set(by_node.keys())
        result = {
            'window_seconds': self.window_seconds,
            'total_alerts_in_window': len(self.alert_log),
            'fleet_size': self.fleet_size,
            'affected_node_count': len(affected_nodes),
            'affected_node_pct': (
                round(len(affected_nodes) / self.fleet_size * 100, 2)
                if self.fleet_size else None
            ),
            'by_alert_type': {
                atype: {
                    'node_count': len(nodes),
                    'node_ids': sorted(nodes, key=str),
                }
                for atype, nodes in by_type.items()
            },
            'severity_breakdown': dict(severity_counts),
            'timestamp': t,
        }
        return result

    def top_affected_nodes(self, n=10):
        by_node = collections.defaultdict(int)
        for entry in self.alert_log:
            by_node[entry['_node_id']] += 1
        return sorted(by_node.items(), key=lambda kv: kv[1], reverse=True)[:n]
