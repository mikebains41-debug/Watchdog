# B200 Metrics — Every Number, One Place

All figures sourced from files in b200_watchdog/. Commit hashes in EVIDENCE.md.

## Contention (4 independent measurements)
| # | Method | Result | Detail |
|---|---|---|---|
| 1 | gpu_audit.py | -53.35% | +/- 1.2%, 3 runs, pod 1 |
| 2 | capture_contention.py | -54.7% | 434.7 -> 196.9 iters/s, pod 1 |
| 3 | gpu_audit.py rerun | -53.38% | +/- 1.05%, pod 1 |
| 4 | gpu_audit.py, new pod | -43.23% | +/- 0.57%, pod 2, kernel 6.8.0-90 |

## VRAM residual
| Exit path | Bytes recovered | Accounting residual |
|---|---|---|
| Graceful | 0 (sustained, 240s) | ~1520MB |
| SIGKILL | 0 (sustained, 240s) | ~1520MB (identical) |

## Cross-GPU isolation
GPU1 memory delta while GPU0 held 976MB: 4MB (noise-level). Isolation held.

## Idle negative control
Contaminated run (GPU0, invalidated): 5 alerts in ~unknown duration.
Clean run (GPU1, valid): 13,710 samples, 1 alert, 51.9W, ~0.007% alert rate.
Achieved sample rate: 3.756Hz (run 2) / 7.105-7.128Hz (run 1), requested 100Hz both times.

## CEI benchmark
7.03e10 FLOPs/joule (70,255,063,866.65 exact). 3,610 matmul iterations, 10.0s,
mean power 706.12W across 50 real power samples, matrix size 4096.

## Residency probe
23.4ms on first call (CUDA warm-up artifact, confirmed by two
independent 5-run reproducibility tests), ~0.3ms steady-state real read
latency on a 512MB VRAM buffer thereafter. See reproducibility_*.json.

## Throttle fields
All 6 flags confirmed present in real telemetry (sw_power_cap, hw_slowdown,
hw_thermal_slowdown, hw_power_brake_slowdown, sw_thermal_slowdown, sync_boost).
All read "Not Active" on idle GPU (correct negative control).

## PCIe telemetry
Static link info: gen/width 5,5,16,16 both GPUs.
Real-time dmon: GPU0 rx=6 tx=5 MB/s, GPU1 rx=4 tx=3 MB/s (real non-zero values).

## NVLink
First raw capture (pre-fix): 18 links/GPU, all reading 0 KiB (idle, correct).
Real cross-GPU transfer delta: Link0 Tx +14,061 KiB during a deliberate .to('cuda:1') transfer.
Post-fix live pipeline: nvlink_tx_kbs 1,280,151,640,314 / nvlink_rx_kbs 1,253,326,746,798 (18 links each, all real).
NVLINK_CONTENTION alert fired: 61,542,977,904 KB/s above learned baseline.

## Detector fire/no-fire results, this session
| Detector | Result | Key number |
|---|---|---|
| AGENT_ORCHESTRATION_ANOMALY | Fired (2x) | 50.9W / 51.9W above idle floor |
| NVLINK_CONTENTION | Fired | 61,542,977,904 KB/s above baseline |
| PROMPT_INJECTION_SIDEEFFECT | Fired | 127.5W above calibrated baseline |
| AgentSessionVRAMRetentionDetector | Correctly silent | subprocess SIGTERM, clean release |
| CovertMiningDetector | Did not fire | ~897W = 89.7% of 1000W limit, just under 90% threshold |
| SequentialVRAMReadDetector | Did not fire (wrong test op both times) | util 90-96%, needed <=5% |
| InterAgentHandoffAnomalyDetector | Inconclusive | util=0.0 in 433/440 samples, sampling-rate limited |

## Bugs found and fixed, this campaign
1. watchdog.py stale import crash (run_residency_challenge)
2. run_tests() self-test structurally broken (needed 3 consecutive samples, sent 1)
3. NVLink parser regex bug (double-escaped backslashes, wrong check order)
4. nvlink_enabled never passed from watchdog.py to TelemetryCollector
5. CSV fieldnames silently dropping nvlink columns (extrasaction=ignore)
6. sample_nvlink() used deprecated -g flag instead of -i

## Tenant files (leftover data on disk, not VRAM)
B200 / RunPod: 2 scans, 2 clean. H200 / Vast.ai: 5 scans, 5 dirty (16 days old).
Sample sizes not comparable yet -- RunPod result should not be treated as settled.
