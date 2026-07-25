# Author: Manmohan (Mike) Bains -- Watchdog AIDR
"""
Watchdog AIDR v2.0 - Threat Intelligence Engine
IOC matching against known GPU attack signatures.
Correlates live alerts against known threat actor TTPs.
Cross-references MITRE ATLAS and CVE database.
"""
import json, time, hashlib
from datetime import datetime, timezone

KNOWN_IOCS = {
    # FIXED: this dictionary previously contained 8 fabricated "known
    # campaigns" -- invented names, attribution, first-seen dates, and
    # CVSS scores presented as if they were real, sourced threat
    # intelligence. They were not. Several also referenced detector
    # alert types that do not exist anywhere in this codebase (e.g.
    # BOOT_ATTESTATION_FAIL, when the real type is ATTESTATION_FAILURE),
    # meaning those entries could never have fired correctly even if the
    # underlying data had been real.
    #
    # Rather than guess at "corrected" replacements, the fabricated
    # entries have been removed entirely. The correlation logic below
    # (ingest_alert / correlate) is legitimate, reusable code and is
    # left intact -- it will honestly report zero IOC matches until
    # real entries are added here.
    #
    # An entry belongs in this dictionary only when it is backed by an
    # actual, citable source: a real CVE, a real vendor security
    # advisory, or a real incident report -- not an invented scenario,
    # however plausible-sounding. Every "indicators" value must be
    # verified against the actual \'type\' string a real detector in this
    # codebase emits, not assumed from a class name.
}

class ThreatIntelEngine:
    def __init__(self):
        self.alert_window = []
        self.window_seconds = 300
        self.matches = []

    def ingest_alert(self, alert):
        now = time.time()
        self.alert_window.append({
            "type": alert.get("type"),
            "gpu": alert.get("gpu", 0),
            "timestamp": now,
            "cvss": alert.get("cvss_score", 0)
        })
        self.alert_window = [
            a for a in self.alert_window
            if now - a["timestamp"] < self.window_seconds
        ]
        return self.correlate()

    def correlate(self):
        active_types = set(a["type"] for a in self.alert_window)
        hits = []
        for ioc_name, ioc in KNOWN_IOCS.items():
            matched = [i for i in ioc["indicators"] if i in active_types]
            if len(matched) >= ioc["min_match"]:
                hit = {
                    "ioc_name": ioc_name,
                    "description": ioc["description"],
                    "matched_indicators": matched,
                    "required_indicators": ioc["indicators"],
                    "match_count": len(matched),
                    "severity": ioc["severity"],
                    "cvss": ioc["cvss"],
                    "mitre_atlas": ioc["mitre_atlas"],
                    "cve": ioc["cve"],
                    "threat_actor": ioc["threat_actor"],
                    "detected_at": datetime.now(timezone.utc).isoformat(),
                    "confidence": round(len(matched) / len(ioc["indicators"]) * 100, 1)
                }
                hits.append(hit)
                print(f"[THREAT INTEL] IOC MATCH: {ioc_name}")
                print(f"  Description: {ioc['description']}")
                print(f"  Matched: {matched}")
                print(f"  Severity: {ioc['severity']} | CVSS: {ioc['cvss']}")
                print(f"  Confidence: {hit['confidence']}%")
                if ioc.get("cve"):
                    print(f"  CVE: {ioc['cve']}")
        if hits:
            self.matches.extend(hits)
        return hits

    def get_threat_summary(self):
        if not self.matches:
            return {"status": "CLEAN", "ioc_matches": 0, "matches": []}
        critical = [m for m in self.matches if m["severity"] == "CRITICAL"]
        return {
            "status": "THREAT_DETECTED" if critical else "SUSPICIOUS",
            "ioc_matches": len(self.matches),
            "critical_matches": len(critical),
            "highest_cvss": max(m["cvss"] for m in self.matches),
            "threat_actors": list(set(m["threat_actor"] for m in self.matches)),
            "matches": self.matches
        }

    def generate_ioc_report(self, output_path=None):
        report = {
            "report_metadata": {
                "title": "Threat Intelligence IOC Match Report",
                "generated_at": datetime.now(timezone.utc).isoformat(),
                "system": "Watchdog AIDR v2.0",
                "ioc_database_version": "2026.06",
                "total_iocs_checked": len(KNOWN_IOCS),
            },
            "threat_summary": self.get_threat_summary(),
            "active_window_alerts": len(self.alert_window),
            "window_seconds": self.window_seconds,
        }
        if output_path:
            import json
            with open(output_path, "w") as f:
                json.dump(report, f, indent=2)
            print(f"[THREAT INTEL] Report written to {output_path}")
        return report
