# Author: Manmohan (Mike) Bains -- Watchdog AIDR
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


# FIXED: this API had no reference to the running DetectionPipeline at
# all -- every route only ever touched _state and exporter, both purely
# local to this file. Nothing in watchdog.py's main() ever called
# update_state() either, so /status, /alerts, and /metrics always showed
# empty data in a real run regardless of what the detectors were doing.
# That larger disconnect is NOT fully fixed here (update_state() still
# needs to be wired into watchdog.py's on_alert/on_sample callbacks,
# separately) -- this specific fix only gives the API a way to reach the
# pipeline for the ONE thing that needed it: throughput ingestion,
# since ThroughputContentionDetector requires a workload-reported
# iterations/sec value that nvidia-smi cannot supply and process(row)
# never reaches (see DetectionPipeline.calibrate_throughput/
# process_throughput docstrings in detection/engines.py).
_pipeline = None


def set_pipeline(pipeline):
    """Called by watchdog.py before starting the API thread, with the
    DetectionPipeline instance (not FullDetectionPipeline -- the
    throughput methods live on the base DetectionPipeline, accessible
    as FullDetectionPipeline.base)."""
    global _pipeline
    _pipeline = pipeline


def handle_throughput_request(pipeline, body):
    """
    Pure logic for the /throughput endpoint, deliberately factored out
    from FastAPI routing so it can be tested without fastapi installed
    -- neither this environment nor, as of tonight, the target Termux
    environment has fastapi available to test the real HTTP layer
    against. Takes a plain dict (the parsed JSON body) and the pipeline
    object, returns a plain dict (the JSON response). The FastAPI route
    itself is a two-line wrapper around this function.

    Body: {"throughput": <float, required>,
           "gpu_index": <int, optional, default 0>,
           "mode": "calibrate" | "process" (optional, default "process"),
           "timestamp": <str, optional>}

    "calibrate" mode: feed a sample YOU have verified is uncontended.
    Call repeatedly until the detector's own baseline is established
    (see ThroughputContentionDetector's calibrated property) before
    switching to "process" mode -- matches the same explicit,
    never-auto-learn-from-live-data discipline used throughout this
    codebase's other detectors.

    "process" mode: evaluate a live sample against the calibrated
    baseline. Any real alert is fed into update_state() so it shows up
    in /alerts and /metrics like any other alert.
    """
    if pipeline is None:
        return {"error": "No pipeline attached to this API instance -- "
                          "run_api() was called without a pipeline "
                          "reference. Throughput ingestion is not "
                          "available."}

    # set_pipeline() now receives the FULL pipeline (see watchdog.py),
    # since /hashrate needs a detector that lives there. The throughput
    # methods live on the base DetectionPipeline, so reach through when
    # a .base exists -- and still work if a bare base is passed directly.
    pipeline = getattr(pipeline, 'base', pipeline)

    throughput = body.get("throughput")
    if throughput is None:
        return {"error": "Missing required field 'throughput'"}
    try:
        throughput = float(throughput)
    except (TypeError, ValueError):
        return {"error": f"'throughput' must be a number, got {body.get('throughput')!r}"}

    gpu_index = body.get("gpu_index", 0)
    mode = body.get("mode", "process")
    timestamp = body.get("timestamp") or datetime.now().isoformat()

    if mode == "calibrate":
        pipeline.calibrate_throughput(throughput)
        calibrated = getattr(getattr(pipeline, 'throughput_contention', None), 'calibrated', None)
        return {"mode": "calibrate", "throughput": throughput,
                "calibrated": calibrated, "timestamp": timestamp}

    if mode == "process":
        alert = pipeline.process_throughput(throughput, gpu_index=gpu_index, timestamp=timestamp)
        if alert:
            update_state(alerts=[alert])
        return {"mode": "process", "throughput": throughput,
                "alert": alert, "timestamp": timestamp}

    return {"error": f"Unknown mode '{mode}', expected 'calibrate' or 'process'"}


def handle_hashrate_request(pipeline, body):
    """
    Pure logic for the /hashrate endpoint, factored out from FastAPI
    routing so it can be tested without fastapi installed -- same
    structure and reasoning as handle_throughput_request() above, which
    this deliberately mirrors rather than inventing a different shape
    for the same problem.

    HashrateCorrelationDetector needs TWO externally-supplied values,
    not one: the pool-reported hashrate AND the power draw it should be
    correlated against. Watchdog can read power itself, but only the
    caller knows which power reading corresponds to the hashrate sample
    they are reporting -- pairing a pool figure against whatever power
    happened to be sampled at an unrelated moment would silently
    produce a meaningless ratio. Both are required here for that reason.

    Body: {"hashrate": <float, required>,
           "power_w": <float, required>,
           "gpu_index": <int, optional, default 0>,
           "mode": "calibrate" | "process" (optional, default "process"),
           "timestamp": <str, optional>}

    "calibrate" mode: feed samples YOU have verified represent normal,
    authorized mining on this device. Same explicit,
    never-auto-learn-from-live-data discipline as /throughput.

    "process" mode: evaluate a live sample against that baseline. Any
    real alert is fed into update_state() so it appears in /alerts and
    /metrics like any other alert.
    """
    if pipeline is None:
        return {"error": "No pipeline attached to this API instance -- "
                          "run_api() was called without a pipeline "
                          "reference. Hashrate ingestion is not "
                          "available."}

    detector = getattr(pipeline, 'hashrate_correlation', None)
    if detector is None:
        return {"error": "This pipeline has no hashrate_correlation detector attached."}

    hashrate = body.get("hashrate")
    if hashrate is None:
        return {"error": "Missing required field 'hashrate'"}
    try:
        hashrate = float(hashrate)
    except (TypeError, ValueError):
        return {"error": f"'hashrate' must be a number, got {body.get('hashrate')!r}"}

    power_w = body.get("power_w")
    if power_w is None:
        return {"error": "Missing required field 'power_w' -- the power "
                          "reading this hashrate sample should be correlated "
                          "against. Not read from telemetry automatically, "
                          "since only the caller knows which power reading "
                          "corresponds to their hashrate sample."}
    try:
        power_w = float(power_w)
    except (TypeError, ValueError):
        return {"error": f"'power_w' must be a number, got {body.get('power_w')!r}"}

    gpu_index = body.get("gpu_index", 0)
    mode = body.get("mode", "process")
    timestamp = body.get("timestamp") or datetime.now().isoformat()

    if mode == "calibrate":
        detector.calibrate(power_w, hashrate)
        return {"mode": "calibrate", "hashrate": hashrate, "power_w": power_w,
                "baseline_established": detector.baseline_ratio is not None,
                "calibration_samples": len(detector.samples),
                "samples_needed": detector.min_correlation_samples,
                "timestamp": timestamp}

    if mode == "process":
        alert = detector.process(power_w, hashrate, gpu_index=gpu_index, timestamp=timestamp)
        if alert:
            update_state(alerts=[alert])
        return {"mode": "process", "hashrate": hashrate, "power_w": power_w,
                "alert": alert, "timestamp": timestamp}

    return {"error": f"Unknown mode '{mode}', expected 'calibrate' or 'process'"}


try:
    from fastapi import FastAPI, Request
    from fastapi.responses import PlainTextResponse
    import uvicorn
    app = FastAPI(title="Watchdog AIDR", version="1.0.0")
    @app.get("/")
    def root(): return {"service": "Watchdog AIDR", "version": "1.0.0", "endpoints": ["/status", "/alerts", "/metrics", "/attest", "/health", "/throughput", "/hashrate"]}
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
    def attest(): return {"cve":"2048350","cve_status":"pending MITRE assignment","filed":"2026-05-31","ghost_power":"CONFIRMED","vram_residual":"CONFIRMED","nvml_blind":"CONFIRMED","cross_tenant":"PENDING T-32","timestamp":datetime.now().isoformat()}
    @app.get("/health")
    def health(): return {"status":"ok","timestamp":datetime.now().isoformat()}
    @app.post("/throughput")
    async def ingest_throughput(request: Request):
        body = await request.json()
        return handle_throughput_request(_pipeline, body)
    @app.post("/hashrate")
    async def ingest_hashrate(request: Request):
        body = await request.json()
        return handle_hashrate_request(_pipeline, body)
    # Attach the webhook bridge -- alerting/prometheus_webhook_bridge.py
    # already implements POST /v2/alerts/webhook correctly (confirmed by
    # reading its source), it was just never registered on a live app.
    # Wrapped in its own try/except so a failure here reports clearly
    # rather than falling through to the misleading "FastAPI not
    # installed" message below when fastapi actually IS installed.
    try:
        from alerting.prometheus_webhook_bridge import register_webhook
        register_webhook(app)
    except Exception as e:
        print(f"[API] Webhook bridge not registered: {e}")

    def run_api(host="0.0.0.0", port=8080): uvicorn.run(app, host=host, port=port, log_level="warning")
except ImportError:
    print("[API] pip3 install fastapi uvicorn --break-system-packages")
    def run_api(host="0.0.0.0", port=8080): print("FastAPI not installed")
