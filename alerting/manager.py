import json, os, time, hashlib, urllib.request
from datetime import datetime
SEVERITY_LEVELS = {'INFO':0,'WARNING':1,'CRITICAL':2,'EMERGENCY':3}
SEVERITY_COLORS = {'INFO':'#36a64f','WARNING':'#ffcc00','CRITICAL':'#ff4444','EMERGENCY':'#7b0000'}
class AuditLog:
    def __init__(self, path='watchdog_data/audit.log'):
        os.makedirs(os.path.dirname(path), exist_ok=True)
        self.path = path
        self.last_hash = '0'*64
        self._load_last_hash()
    def _load_last_hash(self):
        if os.path.exists(self.path):
            with open(self.path,'r') as f: lines = f.readlines()
            if lines:
                try: self.last_hash = json.loads(lines[-1]).get('hash','0'*64)
                except: pass
    def append(self, alert):
        entry = {'iso_timestamp':datetime.now().isoformat(),'alert':alert,'prev_hash':self.last_hash}
        entry_str = json.dumps(entry, sort_keys=True)
        entry['hash'] = hashlib.sha256(entry_str.encode()).hexdigest()
        self.last_hash = entry['hash']
        with open(self.path,'a') as f: f.write(json.dumps(entry)+'\n')
        return entry['hash']
    def verify(self):
        if not os.path.exists(self.path): return True, 0
        with open(self.path,'r') as f: lines = f.readlines()
        prev = '0'*64
        for i, line in enumerate(lines):
            try:
                entry = json.loads(line)
                stored = entry.pop('hash')
                if entry.get('prev_hash') != prev: return False, i
                computed = hashlib.sha256(json.dumps(entry,sort_keys=True).encode()).hexdigest()
                if computed != stored: return False, i
                prev = stored
                entry['hash'] = stored
            except: return False, i
        return True, len(lines)
class ConfidenceScorer:
    CONFIDENCE_MAP = {'GHOST_POWER':0.95,'VRAM_RESIDUAL':0.98,'POWER_SIDE_CHANNEL':0.75,'THERMAL_EMANATION':0.65,'CROSS_TENANT_BLEEDING':0.85,'TIMING_COVERT_CHANNEL':0.70,'CROSS_WORKLOAD_CLUSTER':0.90}
    def score(self, alert):
        base = self.CONFIDENCE_MAP.get(alert.get('type'),0.5)
        if alert.get('severity')=='EMERGENCY': base = min(1.0, base+0.05)
        alert['confidence'] = round(base, 2)
        return alert
class SlackAlerter:
    def __init__(self, webhook_url=None):
        self.webhook_url = webhook_url or os.environ.get('WATCHDOG_SLACK_WEBHOOK')
    def send(self, alert):
        if not self.webhook_url: return False
        payload = {'attachments':[{'color':SEVERITY_COLORS.get(alert.get('severity'),'#ccc'),'title':f"[{alert.get('severity')}] {alert.get('type')}","text":alert.get('message',''),'footer':'Watchdog AIDR — CVE-2048350 (pending assignment)'}]}
        try:
            data = json.dumps(payload).encode()
            req = urllib.request.Request(self.webhook_url, data=data, headers={'Content-Type':'application/json'})
            urllib.request.urlopen(req, timeout=5)
            return True
        except Exception as e:
            print(f"[SLACK ERROR] {e}")
            return False
class AlertManager:
    def __init__(self, min_severity='WARNING', slack_webhook=None, audit_log_path='watchdog_data/audit.log'):
        self.min_severity = SEVERITY_LEVELS.get(min_severity,1)
        self.audit = AuditLog(audit_log_path)
        self.scorer = ConfidenceScorer()
        self.slack = SlackAlerter(slack_webhook)
        self.recent = {}
        self.alert_count = 0
    def handle(self, alert):
        sev = SEVERITY_LEVELS.get(alert.get('severity','INFO'),0)
        if sev < self.min_severity: return
        key = f"{alert.get('type')}_{alert.get('gpu')}"
        now = time.time()
        if key in self.recent and now-self.recent[key] < 60: return
        self.recent[key] = now
        alert = self.scorer.score(alert)
        alert['alert_id'] = self.alert_count
        self.alert_count += 1
        self.audit.append(alert)
        print(f"\n{'='*60}")
        print(f"[WATCHDOG ALERT #{alert['alert_id']}]")
        print(f"Severity  : {alert.get('severity')}")
        print(f"Type      : {alert.get('type')}")
        print(f"GPU       : {alert.get('gpu')}")
        print(f"Confidence: {alert.get('confidence')}")
        print(f"Message   : {alert.get('message')}")
        print(f"{'='*60}\n")
        self.slack.send(alert)
        return alert
