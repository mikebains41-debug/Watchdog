# Author: Manmohan (Mike) Bains -- Watchdog AIDR
"""
Watchdog AIDR v2.0 - Prometheus Alertmanager Webhook Bridge
Receives Alertmanager payloads and routes through SIEMRouter.

Wire into Alertmanager config:
  receivers:
    - name: watchdog-bridge
      webhook_configs:
        - url: http://watchdog-api:8080/v2/alerts/webhook
"""
import os, sys, json
from datetime import datetime, timezone

SEVERITY_CVSS = {
    "CRITICAL": (9.6, "CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"),
    "WARNING":  (7.5, "CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"),
    "INFO":     (4.0, "CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:L/I:N/A:N"),
}

def enrich_prometheus_alert(labels, annotations):
    severity = labels.get("severity", "warning").upper()
    cvss_score, cvss_vector = SEVERITY_CVSS.get(severity, (5.0, ""))
    return {
        "type": labels.get("alertname", "PROMETHEUS_ALERT"),
        "severity": severity,
        "gpu": labels.get("gpu", 0),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "message": annotations.get("summary", "Prometheus alert"),
        "cvss_score": cvss_score,
        "cvss_vector": cvss_vector,
        "cve": labels.get("cve", ""),
        "source": "prometheus_alertmanager",
    }

def process_webhook_payload(payload_dict):
    try:
        from alerting.siem import SIEMRouter
        router = SIEMRouter()
    except ImportError:
        router = None
    results = []
    for alert in payload_dict.get("alerts", []):
        enriched = enrich_prometheus_alert(
            alert.get("labels", {}),
            alert.get("annotations", {})
        )
        print(f"[WEBHOOK] {enriched['type']} cvss={enriched['cvss_score']}")
        if router:
            results.append({"alert": enriched["type"], "routed": router.route(enriched)})
        else:
            results.append({"alert": enriched["type"], "routed": "SIEM_NOT_CONFIGURED"})
    return {"status": "PROCESSED", "count": len(results), "results": results}

try:
    from fastapi import FastAPI
    from pydantic import BaseModel
    from typing import List, Dict

    class PrometheusAlertModel(BaseModel):
        status: str = ""
        labels: Dict[str, str] = {}
        annotations: Dict[str, str] = {}
        startsAt: str = ""
        endsAt: str = ""

    class AlertmanagerPayload(BaseModel):
        receiver: str = ""
        status: str = ""
        alerts: List[PrometheusAlertModel] = []
        externalURL: str = ""

    def register_webhook(app):
        @app.post("/v2/alerts/webhook", tags=["Alerting"])
        async def receive_alert(payload: AlertmanagerPayload):
            return process_webhook_payload({
                "alerts": [{"labels": a.labels, "annotations": a.annotations}
                           for a in payload.alerts]
            })
except ImportError:
    pass

if __name__ == "__main__":
    test = {"alerts": [{"labels": {"alertname": "WatchdogGhostPowerDetected",
        "severity": "warning", "gpu": "0", "cve": "CVE-2048350 (pending assignment)"},
        "annotations": {"summary": "Ghost power 147.96W at 0% util"}}]}
    print(process_webhook_payload(test))
