# Author: Manmohan (Mike) Bains -- Watchdog AIDR
"""
intelligence/compliance_metrics.py

Supplies the three fields EUAIActComplianceForecaster (agent5) needs
beyond cei_flops_per_joule, which intelligence/cei_benchmark.py already
closed. Before this, run_cei_benchmark() passed safe hardcoded defaults
(ghost_power_pct=0, crash_count=0, isolation_score=1.0) -- values that
look like real measurements in agent5's output but were never measured
at all.

Each field below is derived from REAL observed pipeline state. What
each one actually measures is stated precisely, because two of the
three do NOT mean what their names might suggest to someone comparing
them against Serial Alice's certificate figures:

  ghost_power_pct -- HONEST AND DIRECT. The percentage of observed
    samples where GhostPowerDetector's own learned idle baseline was
    exceeded while NVML reported 0% utilization. This is a real ratio
    over real samples, computed from the same baseline the live
    detector uses. It measures how OFTEN ghost power was observed, not
    what fraction of wattage was ghost power -- a different quantity
    that would need a separate definition.

  crash_count -- HONEST BUT NARROWER THAN IT SOUNDS. Counts exceptions
    raised by detectors inside Watchdog's own processing loop. It does
    NOT count GPU workload crashes, CUDA faults, or Xid errors, which
    is what "crash_count: 0 across 11,052 samples" means in Serial
    Alice's certificates. Watchdog has no visibility into a tenant
    workload crashing. Reporting Watchdog's own detector-exception
    count under a field named crash_count risks exactly that
    conflation, so the field name is kept (agent5 requires it) and the
    meaning is stated here and in the returned metadata rather than
    left ambiguous.

  isolation_score -- WEAKEST OF THE THREE, DISCLOSED. Derived from
    TenantIsolationRiskScorer's most recent real risk score, inverted
    (1.0 - risk). Two problems stated rather than hidden: (1) that
    agent is itself permanently degraded, since one of its four
    weighted signals depends on a telemetry field nothing collects, so
    this value inherits that degradation silently; (2) when the agent
    has never fired, this returns 1.0, which means "no isolation risk
    has been observed" -- NOT "isolation has been verified sound."
    Absence of evidence, not evidence of absence.
"""


class ComplianceMetricsTracker:
    def __init__(self):
        self.total_samples = 0
        self.ghost_power_samples = 0
        self.detector_exception_count = 0
        self.last_isolation_risk = None

    def record_sample(self, row, ghost_baseline_w, ghost_threshold_w=15.0):
        """
        Called once per telemetry sample. Counts a ghost-power sample
        using the SAME baseline and threshold logic GhostPowerDetector
        itself uses, rather than a second, independently-drifting
        definition. Does nothing until that baseline exists -- a
        percentage computed before the detector has learned its own
        floor would be meaningless.
        """
        if ghost_baseline_w is None:
            return
        power = row.get('power.draw')
        util = row.get('utilization.gpu')
        if power is None or util is None:
            return
        try:
            power = float(power)
            util = float(util)
        except (TypeError, ValueError):
            return
        self.total_samples += 1
        if util == 0 and (power - ghost_baseline_w) > ghost_threshold_w:
            self.ghost_power_samples += 1

    def record_detector_exception(self):
        """Called when a detector raises inside the processing loop."""
        self.detector_exception_count += 1

    def record_isolation_risk(self, risk_score):
        """
        Called with TenantIsolationRiskScorer's real risk score when
        that agent fires. risk_score expected in 0.0-1.0.
        """
        if risk_score is None:
            return
        try:
            self.last_isolation_risk = float(risk_score)
        except (TypeError, ValueError):
            pass

    def ghost_power_pct(self):
        """
        Percentage of observed samples showing ghost power. Returns
        None -- not 0 -- when no samples have been counted yet, so a
        caller cannot mistake "not measured" for "measured zero".
        """
        if self.total_samples == 0:
            return None
        return (self.ghost_power_samples / self.total_samples) * 100.0

    def isolation_score(self):
        """
        1.0 - most recent real risk score. Returns None when the
        isolation agent has never fired, so the caller decides how to
        treat absence rather than receiving a fabricated 1.0.
        """
        if self.last_isolation_risk is None:
            return None
        return max(0.0, min(1.0, 1.0 - self.last_isolation_risk))

    def as_telemetry_fields(self):
        """
        Returns the three fields in the shape agent5 expects, plus a
        _provenance block describing exactly what each value is and
        whether it was really measured. agent5 itself reads only the
        three named fields; the provenance block exists so the values
        are never silently mistaken for something stronger by a human
        or a downstream report.

        Where a real value does not exist yet, the previous hardcoded
        default is still supplied (agent5's arithmetic requires a
        number) but provenance marks it NOT_MEASURED, so the
        difference is visible rather than hidden.
        """
        gp = self.ghost_power_pct()
        iso = self.isolation_score()
        return {
            'ghost_power_pct': gp if gp is not None else 0,
            'crash_count': self.detector_exception_count,
            'isolation_score': iso if iso is not None else 1.0,
            '_provenance': {
                'ghost_power_pct': (
                    f'MEASURED: {self.ghost_power_samples}/{self.total_samples} '
                    f'samples exceeded the learned idle baseline at 0% '
                    f'utilization'
                ) if gp is not None else
                    'NOT_MEASURED: no samples counted yet (ghost-power baseline '
                    'not established); 0 supplied so agent5 can compute, but '
                    'this is not a measurement',
                'crash_count': (
                    'MEASURED, NARROW: counts exceptions raised by Watchdog\'s '
                    'own detectors during processing. Does NOT count GPU '
                    'workload crashes, CUDA faults, or Xid errors -- Watchdog '
                    'has no visibility into a tenant workload crashing. Not '
                    'comparable to the crash_count figure in Serial Alice\'s '
                    'certificates, which measures a different thing.'
                ),
                'isolation_score': (
                    f'DERIVED, DEGRADED: 1.0 - TenantIsolationRiskScorer\'s last '
                    f'real risk score. That agent is itself permanently degraded '
                    f'(one of four weighted signals needs a telemetry field '
                    f'nothing collects), so this value inherits that.'
                ) if iso is not None else
                    'NOT_MEASURED: isolation agent has never fired; 1.0 supplied '
                    'so agent5 can compute, but this means "no isolation risk '
                    'observed", NOT "isolation verified sound"',
            },
        }
