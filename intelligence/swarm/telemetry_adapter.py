# Author: Manmohan (Mike) Bains -- Watchdog AIDR
"""
intelligence/swarm/telemetry_adapter.py

Translates a real Watchdog telemetry row (nvidia-smi field names) into
the format the 5 prediction agents expect.

WHAT'S REAL, mapped directly from confirmed collected fields
(agent/telemetry.py's QUERY_FIELDS): power_watts, gpu_util,
mem_clock_mhz, sm_clock_mhz, temp_c, vram_used_mb.

WHAT'S NOT AVAILABLE, left as honest safe defaults rather than
fabricated -- stated per field, not glossed over:

  cei_flops_per_joule: nvidia-smi cannot report FLOPs delivered under
    any field name -- the same reason ThroughputContentionDetector
    needs a separate calibrate/process entry point rather than
    process(row). Left at 0. Both CEIDegradationForecaster (agent2)
    and EUAIActComplianceForecaster (agent5) already gate on
    `cei <= 0` in their own code -- with this adapter, both will
    correctly, permanently stay silent rather than crash or fire on a
    fabricated number, until something real feeds them an actual CEI
    value through a separate path not built here.

  ghost_power_pct, idle_power_w, crash_count, isolation_score: all
    derived/aggregate metrics agent5 needs, none of which exist as raw
    nvidia-smi fields or are computed anywhere else in this pipeline
    yet. Left at safe defaults (0, 0, 0, 1.0 respectively) -- moot in
    practice, since agent5 is already blocked by the cei gate above
    and never reaches the code that would use these.

  memory_access_timing_ms: needs active latency probing (write a
    pattern, measure access time), not passive telemetry -- the same
    technique security/active_vram_residency already uses elsewhere in
    this project, not wired to this adapter. Left at 0.
    TenantIsolationRiskScorer (agent4) will NOT crash on this -- it
    defaults timing_ms to 0 internally -- but its timing-based signal
    (20% of its weighted confidence score) will always compute to 0,
    meaning agent4 runs in a documented degraded state, not at its
    already-modest validated 24.5% detection rate.
"""


def adapt_row_to_swarm_telemetry(row):
    return {
        'power_watts': row.get('power.draw', 0) or 0,
        'gpu_util': row.get('utilization.gpu', 0) or 0,
        'mem_clock_mhz': row.get('clocks.mem', 0) or 0,
        'sm_clock_mhz': row.get('clocks.sm', 0) or 0,
        'temp_c': row.get('temperature.gpu', 0) or 0,
        'vram_used_mb': row.get('memory.used', 0) or 0,
        'timestamp': row.get('iso_timestamp'),
        'cei_flops_per_joule': 0,
        'ghost_power_pct': 0,
        'idle_power_w': 0,
        'crash_count': 0,
        'isolation_score': 1.0,
        'memory_access_timing_ms': 0,
    }
