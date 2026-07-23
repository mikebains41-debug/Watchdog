#!/usr/bin/env python3
# Watchdog AIDR
# Author: Manmohan (Mike) Bains -- Watchdog AIDR
# Project: GPU Optimizer / Watchdog
#
# ConfidentialComputingIntegrityDetector
# ========================================
# WHY THIS EXISTS
#   Independent security research from IBM and Ohio State University
#   (July 2025, reported by SDxCentral) reverse-engineered NVIDIA's
#   GPU Confidential Computing (GPU-CC) and found:
#     1. GPU-CC does NOT encrypt GPU memory at runtime -- it relies on
#        access-control mechanisms (firewalls), not encryption, unlike
#        CPU-based confidential computing.
#     2. Attackers with physical or remote access can manipulate GPU-CC
#        security configuration using tools like nvTrust or
#        out-of-band interfaces such as BMC.
#   Given GPU-CC's security model depends on its access-control
#   configuration staying intact, monitoring for unexpected CHANGES to
#   that configuration is a legitimate, real defensive measure.
#
# WHAT THIS DETECTS
#   Polls the real, standard `nvidia-smi conf-compute -q` command (the
#   same command already used in this repo's host_isolation_audit
#   findings) and alerts if reported Confidential Computing status
#   changes from its baseline -- most critically, an unexpected
#   ON-to-OFF transition.
#
# WHAT THIS DOES NOT DO
#   Does not attempt to manipulate GPU-CC settings, use nvTrust, or
#   access any BMC/out-of-band interface. Only reads standard,
#   documented nvidia-smi status output -- pure monitoring.
#
# HONEST STATUS
#   Detection logic tested with mocked subprocess output (4/4 tests
#   passing), confirming parsing and state-change logic work
#   correctly. NOT yet run against a real GPU with Confidential
#   Computing hardware -- same honest limitation as NVLinkFabricDetector.

import re
import time
import subprocess
from datetime import datetime


class ConfidentialComputingIntegrityDetector:
    def __init__(self, check_interval=60):
        self.check_interval = check_interval
        self.last_check = None
        self.baseline_cc_state = None
        self.last_alert = None

    def query_cc_state(self):
        try:
            r = subprocess.run(
                ["nvidia-smi", "conf-compute", "-q"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            return r.stdout.strip()
        except Exception:
            return None

    def _parse_state(self, raw):
        if not raw:
            return None
        m = re.search(r"status\s*:?\s*(ON|OFF)", raw, re.IGNORECASE)
        if m:
            return m.group(1).upper()
        return None

    def check(self, gpu_index=0):
        now = time.time()
        if self.last_check and now - self.last_check < self.check_interval:
            return None
        self.last_check = now

        raw = self.query_cc_state()
        state = self._parse_state(raw)
        if state is None:
            return None

        if self.baseline_cc_state is None:
            self.baseline_cc_state = state
            return None

        if state != self.baseline_cc_state:
            now2 = time.time()
            if self.last_alert and now2 - self.last_alert < 60:
                return None
            self.last_alert = now2
            previous = self.baseline_cc_state
            self.baseline_cc_state = state
            severity = "CRITICAL" if previous == "ON" and state == "OFF" else "WARNING"
            return {
                "type": "CC_STATE_CHANGE",
                "severity": severity,
                "gpu": gpu_index,
                "previous_state": previous,
                "current_state": state,
                "timestamp": datetime.now().isoformat(),
                "message": (
                    f"Confidential Computing state changed from {previous} to {state} -- "
                    f"possible unauthorized security downgrade or configuration tampering "
                    f"(per IBM/Ohio State GPU-CC research: access-control relied upon, not encryption)"
                ),
            }
        return None
