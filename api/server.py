import json, os, time
from datetime import datetime
class PrometheusExporter:
    def __init__(self): self.metrics = {}
    def set(self, name, value, labels=None, help_text='', metric_type='gauge'):
        self.metrics[name] = {'value':value,'labels':labels or {},'help':help_text,'type':metric_type}
    def render(self):
        lines = []
        for name, m in self.metrics.items():
            lines.append(f"# HELP {name} {m['help']}")
            lines.append(f"# TYPE {name} {m['type']}")
            lp = ','.join(f'{k}="{v}"' for k,v in m['labels'].items())
            label_str = f'{{{lp}}}' if lp else ''
            lines.append(f"{name}{label_str} {m['value']}")
        return '\n'.join(lines)+'\n'
exporter = PrometheusExporter()
_state = {'alerts':[],'telemetry':[],'start_time':datetime.now().isoformat(),'gpu_count':0,'alert_count':0}
def update_state(alerts=None, telemetry_row=None, gpu_count=None):
    if alerts:
        _state['alerts'].extend(alerts)
        _state['alert_count'] += len(alerts)
        if len(_state['alerts']) > 1000: _state['alerts'] = _state['alerts'][-1000:]
    if telemetry_row:
        _state['telemetry'].append(telemetry_row)
        if len(_state['telemetry']) > 10000: _state['telemetry'] = _state['telemetry'][-10000:]
    if gpu_count is not None: _state['gpu_count'] = gpu_count
try:
    from fastapi import FastAPI
    from fastapi.responses import PlainTextResponse
    import uvicorn
    app = FastAPI(title="Watchdog AIDR", version="1.0.0")
    @app.get("/")
    def root(): return {"platform":"Watchdog AIDR","version":"1.0.0","author":"Mike Bains CVE 2048350","status":"running","uptime_since":_state['start_time']}
    @app.get("/status")
    def status(): return {"status":"running","gpu_count":_state['gpu_count'],"alert_count":_state['alert_count'],"last_alert":_state['alerts'][-1] if _state['alerts'] else None,"timestamp":datetime.now().isoformat()}
    @app.get("/alerts")
    def get_alerts(severity:str=None, limit:int=100):
        alerts = _state['alerts']
        if severity: alerts = [a for a in alerts if a.get('severity')==severity.upper()]
        return {"count":len(alerts),"alerts":alerts[-limit:]}
    @app.get("/metrics", response_class=PlainTextResponse)
    def metrics():
        exporter.set('watchdog_alerts_total',_state['alert_count'],help_text='Total alerts',metric_type='counter')
        exporter.set('watchdog_gpu_count',_state['gpu_count'],help_text='GPUs monitored')
        type_counts = {}
        for a in _state['alerts']:
            t = a.get('type','UNKNOWN')
            type_counts[t] = type_counts.get(t,0)+1
        for atype, count in type_counts.items():
            exporter.set('watchdog_alert_type_total',count,labels={'type':atype},help_text='Alerts by type',metric_type='counter')
        if _state['telemetry']:
            latest = _state['telemetry'][-1]
            gpu = str(latest.get('index',0))
            exporter.set('watchdog_gpu_power_watts',latest.get('power.draw',0),labels={'gpu':gpu},help_text='GPU power watts')
            exporter.set('watchdog_gpu_memory_used_mb',latest.get('memory.used',0),labels={'gpu':gpu},help_text='VRAM used MB')
            exporter.set('watchdog_gpu_temp_celsius',latest.get('temperature.gpu',0),labels={'gpu':gpu},help_text='GPU temp C')
            exporter.set('watchdog_gpu_util_pct',latest.get('utilization.gpu',0),labels={'gpu':gpu},help_text='GPU util pct')
        return exporter.render()
    @app.get("/attest")
    def attest(): return {"cve":"2048350","filed":"2026-05-31","ghost_power":"CONFIRMED","vram_residual":"CONFIRMED","nvml_blind":"CONFIRMED","cross_tenant":"PENDING T-32","timestamp":datetime.now().isoformat()}
    @app.get("/health")
    def health(): return {"status":"ok","timestamp":datetime.now().isoformat()}
    def run_api(host="0.0.0.0", port=8080): uvicorn.run(app, host=host, port=port, log_level="warning")
except ImportError:
    print("[API] pip3 install fastapi uvicorn --break-system-packages")
    def run_api(host="0.0.0.0", port=8080): print("FastAPI not installed")
