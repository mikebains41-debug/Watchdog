# Watchdog Daemon Run -- 2026-09-20 00:31:31Z

Live-telemetry run of the Watchdog runtime daemon.

## Summary
- Duration: 300.9s @ 1.0s interval
- Telemetry samples: 1120
- Alerts fired: 0
- Correlated incidents: 0
- Correlator: unified

## Detectors loaded
- rowhammer_precursor
- cryptojacking_onset
- ghost_power

## Detectors skipped (not importable / not applicable)
- (none)

## Files in this run
- `telemetry.csv` -- raw per-GPU telemetry samples
- `alerts.jsonl` -- every detector alert fired
- `incidents.jsonl` -- correlated cross-suite incidents
- `metrics.json` -- run metrics summary

## Honest status
Detector logic was simulation-tested (see main test suite). This is a LIVE-telemetry run on real hardware -- the output is evidence of what the detectors saw, not a validation pass of the detectors themselves. Remediation is gated (plan-only); no destructive actions were auto-executed. Credentials were kept off this box; commit/push these artifacts manually.
