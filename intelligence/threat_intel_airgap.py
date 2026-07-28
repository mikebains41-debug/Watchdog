# Author: Manmohan (Mike) Bains -- Watchdog
"""
Watchdog v2.0 - Air-Gapped Threat Intel Engine
Extends ThreatIntelEngine with offline signed IOC bundle support.
Falls back to built-in IOCs if no bundles are present.
"""
from intelligence.threat_intel import ThreatIntelEngine, KNOWN_IOCS
from forensics.ioc_bundle import load_all_bundles

class AirGappedThreatIntel(ThreatIntelEngine):
    def __init__(self, bundle_dir=None):
        super().__init__()
        self.ioc_db = dict(KNOWN_IOCS)
        self._load_bundles(bundle_dir)

    def _load_bundles(self, bundle_dir=None):
        try:
            bundle_iocs = load_all_bundles(bundle_dir)
            if bundle_iocs:
                self.ioc_db.update(bundle_iocs)
                print(f"[AIRGAP] Loaded {len(bundle_iocs)} IOCs from bundles. Total: {len(self.ioc_db)}")
            else:
                print(f"[AIRGAP] No bundles found. Using {len(self.ioc_db)} built-in IOCs.")
        except Exception as e:
            print(f"[AIRGAP] Bundle load error: {e}. Using built-in IOCs.")

    def correlate(self):
        active_types = set(a["type"] for a in self.alert_window)
        hits = []
        for ioc_name, ioc in self.ioc_db.items():
            matched = [i for i in ioc.get("indicators", []) if i in active_types]
            if len(matched) >= ioc.get("min_match", 2):
                hit = {
                    "ioc_name": ioc_name,
                    "description": ioc.get("description", ""),
                    "matched_indicators": matched,
                    "severity": ioc.get("severity", "HIGH"),
                    "cvss": ioc.get("cvss", 7.0),
                    "mitre_atlas": ioc.get("mitre_atlas", []),
                    "cve": ioc.get("cve"),
                    "confidence": round(len(matched) / len(ioc.get("indicators", [matched])) * 100, 1),
                    "source": "bundle" if ioc_name not in KNOWN_IOCS else "builtin",
                }
                hits.append(hit)
                print(f"[AIRGAP THREAT] {ioc_name} — {hit['confidence']}% confidence")
        if hits:
            self.matches.extend(hits)
        return hits
