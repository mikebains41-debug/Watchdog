"""
Watchdog AIDR v2.0 - Alert State Management
Tracks alert lifecycle: OPEN -> ACKNOWLEDGED -> RESOLVED
Prevents duplicate alerts, enables SOC workflow integration.
"""
import time, json, os
from datetime import datetime

class AlertState:
    OPEN = 'OPEN'
    ACKNOWLEDGED = 'ACKNOWLEDGED'
    RESOLVED = 'RESOLVED'

class AlertStateManager:
    def __init__(self, resolve_after_seconds=300, state_file=None):
        self.resolve_after = resolve_after_seconds
        self.state_file = state_file
        self.alerts = {}
        if state_file and os.path.exists(state_file):
            self._load()

    def _key(self, alert):
        return f"{alert.get('type','UNKNOWN')}:gpu{alert.get('gpu','0')}"

    def process(self, alert):
        key = self._key(alert)
        now = time.time()
        if key in self.alerts:
            existing = self.alerts[key]
            if existing['state'] == AlertState.OPEN:
                existing['last_seen'] = now
                existing['count'] += 1
                return 'DUPLICATE'
            elif existing['state'] == AlertState.ACKNOWLEDGED:
                existing['last_seen'] = now
                existing['count'] += 1
                return 'SUPPRESSED'
            elif existing['state'] == AlertState.RESOLVED:
                self.alerts[key] = self._new_entry(alert, now)
                return 'REOPENED'
        self.alerts[key] = self._new_entry(alert, now)
        if self.state_file:
            self._save()
        return 'NEW'

    def _new_entry(self, alert, now):
        return {
            'state': AlertState.OPEN,
            'alert': alert,
            'opened_at': now,
            'last_seen': now,
            'acknowledged_at': None,
            'resolved_at': None,
            'count': 1,
            'notes': []
        }

    def acknowledge(self, alert_type, gpu=0, note=''):
        key = f"{alert_type}:gpu{gpu}"
        if key in self.alerts:
            self.alerts[key]['state'] = AlertState.ACKNOWLEDGED
            self.alerts[key]['acknowledged_at'] = time.time()
            if note:
                self.alerts[key]['notes'].append({
                    'ts': datetime.now().isoformat(),
                    'note': note
                })
            if self.state_file:
                self._save()
            return True
        return False

    def resolve(self, alert_type, gpu=0, note=''):
        key = f"{alert_type}:gpu{gpu}"
        if key in self.alerts:
            self.alerts[key]['state'] = AlertState.RESOLVED
            self.alerts[key]['resolved_at'] = time.time()
            if note:
                self.alerts[key]['notes'].append({
                    'ts': datetime.now().isoformat(),
                    'note': note
                })
            if self.state_file:
                self._save()
            return True
        return False

    def auto_resolve_stale(self):
        now = time.time()
        resolved = []
        for key, entry in self.alerts.items():
            if entry['state'] == AlertState.OPEN:
                if now - entry['last_seen'] > self.resolve_after:
                    entry['state'] = AlertState.RESOLVED
                    entry['resolved_at'] = now
                    entry['notes'].append({
                        'ts': datetime.now().isoformat(),
                        'note': f"Auto-resolved after {self.resolve_after}s without recurrence"
                    })
                    resolved.append(key)
        if resolved and self.state_file:
            self._save()
        return resolved

    def get_open(self):
        return {k: v for k, v in self.alerts.items() if v['state'] == AlertState.OPEN}

    def get_all(self):
        return self.alerts

    def summary(self):
        states = [v['state'] for v in self.alerts.values()]
        return {
            'total': len(states),
            'open': states.count(AlertState.OPEN),
            'acknowledged': states.count(AlertState.ACKNOWLEDGED),
            'resolved': states.count(AlertState.RESOLVED)
        }

    def _save(self):
        try:
            serializable = {}
            for k, v in self.alerts.items():
                entry = dict(v)
                entry['alert'] = dict(v['alert'])
                serializable[k] = entry
            with open(self.state_file, 'w') as f:
                json.dump(serializable, f, indent=2)
        except Exception as e:
            print(f"[STATE] Save error: {e}")

    def _load(self):
        try:
            with open(self.state_file) as f:
                self.alerts = json.load(f)
        except Exception as e:
            print(f"[STATE] Load error: {e}")
