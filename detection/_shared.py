# Author: Manmohan (Mike) Bains -- Watchdog
"""
detection/_shared.py

_EventState and _f were originally defined inside engines.py.
throughput_contention_detector.py needs _EventState too, and engines.py
now needs to import ThroughputContentionDetector (to wire it into
DetectionPipeline) -- if _EventState stayed in engines.py, that would
create a circular import: engines -> throughput_contention_detector ->
engines. Extracting the shared pieces here breaks the cycle at its root
instead of working around it with a deferred/local import.
"""

import time


class _EventState:
    """Turns a per-sample boolean into start/stop events."""

    def __init__(self, require_consecutive=3, refire_after_s=300):
        self.require_consecutive = require_consecutive
        self.refire_after_s = refire_after_s
        self._streak = 0
        self._active = False
        self._last_emit = None

    def should_emit(self, condition_met, now=None):
        now = time.time() if now is None else now
        if not condition_met:
            self._streak = 0
            self._active = False
            return False
        self._streak += 1
        if self._streak < self.require_consecutive:
            return False
        if not self._active:
            self._active = True
            self._last_emit = now
            return True
        if self.refire_after_s and (now - self._last_emit) >= self.refire_after_s:
            self._last_emit = now
            return True
        return False

    @property
    def active(self):
        return self._active


def _f(row, key, default=0.0):
    """nvidia-smi emits '[N/A]' and '' for unsupported fields. Treat as absent."""
    v = row.get(key, default)
    if v is None:
        return None
    s = str(v).strip()
    if s == '' or s.startswith('[') or s.lower() in ('n/a', 'na', 'unknown'):
        return None
    try:
        return float(s)
    except (TypeError, ValueError):
        return None
