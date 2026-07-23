#!/usr/bin/env python3
# Watchdog AIDR
# Author: Manmohan (Mike) Bains -- Watchdog AIDR
# Project: GPU Optimizer / Watchdog
#
# ECCErrorTrendDetector
# =======================
# WHAT THIS DETECTS
#   NVIDIA GPUs with ECC-protected memory (A100, H100, H200, B200,
#   B300) expose real, standard NVML/nvidia-smi counters for
#   correctable and uncorrectable memory errors:
#     ecc.errors.corrected.volatile.total
#     ecc.errors.uncorrected.volatile.total
#   These are legitimate, documented nvidia-smi query fields. This
#   detector watches them for two signals:
#     1. ANY increase in uncorrectable errors -- rare and serious.
#     2. A rising RATE of correctable errors over a rolling window --
#        an early-warning signal for memory degradation.
#
# WHY THIS MATTERS
#   Per academic Rowhammer research (GPUHammer, USENIX Security 2025),
#   HBM-based data center GPUs rely on on-die ECC to mask single
#   bit-flips. ECC error COUNTS are the direct, legitimate observable
#   signal for memory-disturbance events on this hardware class --
#   watching this counter is the correct, non-exploit way to gain
#   visibility into the phenomenon that research describes.
#
# HONEST STATUS
#   Detection logic only -- does not include or require any attack
#   code. Tested with synthetic data matching real nvidia-smi field
#   names (4/4 tests passing). Not yet run against real ECC error
#   events on live hardware.

import time
import collections
from datetime import datetime


class ECCErrorTrendDetector:
    def __init__(self, correctable_rate_threshold=5, window=50):
        self.correctable_rate_threshold = correctable_rate_threshold
        self.window = window
        self.history = collections.deque(maxlen=window)
        self.last_uncorrected = None
        self.last_alert = None

    def update(self, row):
        corrected = float(row.get('ecc.errors.corrected.volatile.total', 0))
        uncorrected = float(row.get('ecc.errors.uncorrected.volatile.total', 0))

        if self.last_uncorrected is not None and uncorrected > self.last_uncorrected:
            delta = uncorrected - self.last_uncorrected
            self.last_uncorrected = uncorrected
            return {
                'type': 'ECC_UNCORRECTABLE_ERROR',
                'severity': 'EMERGENCY',
                'gpu': row.get('index'),
                'uncorrected_total': uncorrected,
                'delta': delta,
                'timestamp': row.get('iso_timestamp'),
                'message': f"Uncorrectable ECC error detected (+{delta:.0f}) -- possible hardware fault or memory-disturbance event exceeding on-die ECC correction capacity",
            }
        self.last_uncorrected = uncorrected

        self.history.append(corrected)
        if len(self.history) < self.window:
            return None
        vals = list(self.history)
        rate = vals[-1] - vals[0]
        if rate > self.correctable_rate_threshold:
            now = time.time()
            if self.last_alert and now - self.last_alert < 60:
                return None
            self.last_alert = now
            return {
                'type': 'ECC_CORRECTABLE_TREND',
                'severity': 'WARNING',
                'gpu': row.get('index'),
                'corrected_total': corrected,
                'rate_over_window': rate,
                'window_size': self.window,
                'timestamp': row.get('iso_timestamp'),
                'message': f"Correctable ECC error rate rising ({rate:.0f} over {self.window} samples) -- possible early-stage memory degradation",
            }
        return None
