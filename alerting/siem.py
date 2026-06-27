"""
Watchdog AIDR v2.0 - SIEM Integration
Supports: PagerDuty Events API v2, Splunk HEC, Microsoft Sentinel,
          Datadog Events API
Each integration is optional — only fires if credentials are set.
"""
import json, time, os
from datetime import datetime

try:
    import urllib.request as urlreq
    import urllib.error as urlerr
except ImportError:
    urlreq = None

def _post(url, payload, headers):
    try:
        data = json.dumps(payload).encode('utf-8')
        req = urlreq.Request(url, data=data, headers=headers, method='POST')
        with urlreq.urlopen(req, timeout=10) as resp:
            return resp.status, resp.read().decode()
    except Exception as e:
        return None, str(e)

class PagerDutyIntegration:
    """PagerDuty Events API v2"""
    URL = 'https://events.pagerduty.com/v2/enqueue'

    def __init__(self, routing_key=None):
        self.routing_key = routing_key or os.environ.get('PD_ROUTING_KEY')

    def send(self, alert):
        if not self.routing_key:
            return False, 'No PD_ROUTING_KEY set'
        severity_map = {'EMERGENCY': 'critical', 'CRITICAL': 'critical',
                        'WARNING': 'warning', 'INFO': 'info'}
        payload = {
            'routing_key': self.routing_key,
            'event_action': 'trigger',
            'dedup_key': f"watchdog:{alert.get('type')}:gpu{alert.get('gpu',0)}",
            'payload': {
                'summary': alert.get('message', alert.get('type')),
                'severity': severity_map.get(alert.get('severity','WARNING'), 'warning'),
                'source': f"Watchdog AIDR v2.0 - GPU {alert.get('gpu',0)}",
                'timestamp': alert.get('timestamp', datetime.utcnow().isoformat()),
                'custom_details': {
                    'alert_type': alert.get('type'),
                    'cvss_score': alert.get('cvss_score'),
                    'cvss_vector': alert.get('cvss_vector'),
                    'gpu': alert.get('gpu'),
                    'cve': 'CVE-2048350' if 'VRAM' in alert.get('type','') else None,
                }
            }
        }
        status, body = _post(self.URL, payload,
                             {'Content-Type': 'application/json',
                              'X-Routing-Key': self.routing_key})
        return status == 202, body


class SplunkHECIntegration:
    """Splunk HTTP Event Collector"""

    def __init__(self, hec_url=None, token=None, index='watchdog'):
        self.url = (hec_url or os.environ.get('SPLUNK_HEC_URL','')) + '/services/collector/event'
        self.token = token or os.environ.get('SPLUNK_HEC_TOKEN')
        self.index = index

    def send(self, alert):
        if not self.token:
            return False, 'No SPLUNK_HEC_TOKEN set'
        payload = {
            'time': time.time(),
            'host': 'watchdog-aidr',
            'source': 'watchdog',
            'sourcetype': 'gpu_security',
            'index': self.index,
            'event': {
                'alert_type': alert.get('type'),
                'severity': alert.get('severity'),
                'cvss_score': alert.get('cvss_score'),
                'cvss_vector': alert.get('cvss_vector'),
                'gpu': alert.get('gpu'),
                'message': alert.get('message'),
                'timestamp': alert.get('timestamp'),
            }
        }
        status, body = _post(self.url, payload,
                             {'Content-Type': 'application/json',
                              'Authorization': f'Splunk {self.token}'})
        return status == 200, body


class SentinelIntegration:
    """Microsoft Sentinel Custom Log via Data Collector API"""

    def __init__(self, workspace_id=None, shared_key=None, log_type='WatchdogAIDR'):
        self.workspace_id = workspace_id or os.environ.get('SENTINEL_WORKSPACE_ID')
        self.shared_key = shared_key or os.environ.get('SENTINEL_SHARED_KEY')
        self.log_type = log_type

    def _build_signature(self, date, content_length):
        import hmac, hashlib, base64
        string_to_hash = f"POST\n{content_length}\napplication/json\nx-ms-date:{date}\n/api/logs"
        key = base64.b64decode(self.shared_key)
        sig = base64.b64encode(hmac.new(key, string_to_hash.encode('utf-8'), hashlib.sha256).digest()).decode()
        return f"SharedKey {self.workspace_id}:{sig}"

    def send(self, alert):
        if not self.workspace_id or not self.shared_key:
            return False, 'No SENTINEL_WORKSPACE_ID or SENTINEL_SHARED_KEY set'
        url = f"https://{self.workspace_id}.ods.opinsights.azure.com/api/logs?api-version=2016-04-01"
        body = json.dumps([{
            'AlertType': alert.get('type'),
            'Severity': alert.get('severity'),
            'CVSSScore': alert.get('cvss_score'),
            'CVSSVector': alert.get('cvss_vector'),
            'GPU': alert.get('gpu'),
            'Message': alert.get('message'),
            'Timestamp': alert.get('timestamp'),
        }])
        date = datetime.utcnow().strftime('%a, %d %b %Y %H:%M:%S GMT')
        sig = self._build_signature(date, len(body))
        status, resp = _post(url, json.loads(body),
                             {'Content-Type': 'application/json',
                              'Authorization': sig,
                              'Log-Type': self.log_type,
                              'x-ms-date': date})
        return status == 200, resp


class DatadogIntegration:
    """Datadog Events API"""
    URL = 'https://api.datadoghq.com/api/v1/events'

    def __init__(self, api_key=None):
        self.api_key = api_key or os.environ.get('DD_API_KEY')

    def send(self, alert):
        if not self.api_key:
            return False, 'No DD_API_KEY set'
        priority_map = {'EMERGENCY': 'normal', 'CRITICAL': 'normal',
                        'WARNING': 'low', 'INFO': 'low'}
        alert_type_map = {'EMERGENCY': 'error', 'CRITICAL': 'error',
                          'WARNING': 'warning', 'INFO': 'info'}
        payload = {
            'title': f"[Watchdog] {alert.get('type')} on GPU {alert.get('gpu',0)}",
            'text': alert.get('message',''),
            'priority': priority_map.get(alert.get('severity','WARNING'), 'low'),
            'alert_type': alert_type_map.get(alert.get('severity','WARNING'), 'warning'),
            'tags': [
                f"watchdog:aidr",
                f"gpu:{alert.get('gpu',0)}",
                f"alert_type:{alert.get('type','').lower()}",
                f"cvss:{alert.get('cvss_score',0)}",
                f"severity:{alert.get('severity','').lower()}",
            ],
            'source_type_name': 'watchdog_aidr',
        }
        status, body = _post(self.URL, payload,
                             {'Content-Type': 'application/json',
                              'DD-API-KEY': self.api_key})
        return status == 202, body


class SIEMRouter:
    """
    Routes alerts to all configured SIEM integrations.
    Only sends to integrations with credentials set.
    """
    def __init__(self):
        self.integrations = {
            'pagerduty': PagerDutyIntegration(),
            'splunk': SplunkHECIntegration(),
            'sentinel': SentinelIntegration(),
            'datadog': DatadogIntegration(),
        }

    def route(self, alert):
        results = {}
        for name, integration in self.integrations.items():
            try:
                ok, msg = integration.send(alert)
                results[name] = {'sent': ok, 'response': msg[:100] if msg else ''}
            except Exception as e:
                results[name] = {'sent': False, 'response': str(e)[:100]}
        return results

    def status(self):
        configured = []
        unconfigured = []
        checks = {
            'pagerduty': os.environ.get('PD_ROUTING_KEY'),
            'splunk': os.environ.get('SPLUNK_HEC_TOKEN'),
            'sentinel': os.environ.get('SENTINEL_WORKSPACE_ID'),
            'datadog': os.environ.get('DD_API_KEY'),
        }
        for name, val in checks.items():
            if val:
                configured.append(name)
            else:
                unconfigured.append(name)
        return {'configured': configured, 'unconfigured': unconfigured}
