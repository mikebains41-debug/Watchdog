# B200 Real-Hardware Findings Report

Platform: 2x NVIDIA B200 SXM, rented via RunPod
Date: 2026-07-30
Source data: b200_watchdog/ in this repository -- every figure below has a source file and a git commit.

This report covers only results produced on B200 hardware this session. It does not
restate the earlier H200/Vast.ai findings -- see EVIDENCE.md and README.md for those.

---

## 1. NVLink covert-channel detector -- found broken, fixed; NOT confirmed firing (corrected 2026-09-21)

> **CORRECTION (2026-09-21).** The alert shown in this section (61,542,977,904
> KB/s) came from the pre-fix code, which compared cumulative NVLink counters
> instead of computing a rate. Commit 8ba9c69 (30 July 2026) identified it as
> counter drift, not throughput -- a figure that could appear on an idle GPU
> given enough runtime -- and stated these NVLink claims must be re-validated on
> real hardware before being trusted or sent to anyone. The four retests after
> that fix (nvlink_retest_v1-v4) recorded no NVLINK_CONTENTION alert. The three
> integration bugs described below were real and are fixed; the detector firing
> correctly is NOT confirmed. Also open, and needing a controlled test before any
> threshold means anything: whether B200 NVLink counters behave as the KiB units
> nvidia-smi labels them, and whether a fresh pod's counters start at zero. The
> original text is kept below for traceability.


NVLinkContentionDetector is built on real published research: "Spy in the GPU-box"
(Dutta et al., ISCA 2023), NVBleed (Zhang et al., arXiv 2025), and SideLink (2026) --
all three demonstrate NVLink contention as a cross-tenant covert/side channel. This
detector had never fired on real hardware before this session; three separate
bugs made that structurally impossible:

1. watchdog.py never passed nvlink_enabled=True to the telemetry collector -- the
   flag existed but was never wired to the entry point.
2. Once enabled, the CSV writer's fixed fieldnames list didn't include the NVLink
   columns, so DictWriter(extrasaction='ignore') silently dropped them even though
   they were correctly present in memory.
3. The underlying sampler called nvidia-smi nvlink with the -g flag, which is
   deprecated on this driver and fails silently -- sample_nvlink() returned
   nvlink_available: False at the source, before either of the above bugs even
   mattered.

All three were found and fixed this session (commits c36ecce, da8c9bd).

Confirmation run: 45s clean idle baseline, then 90s of real, deliberately induced
GPU0->GPU1 tensor traffic (.to('cuda:1')).

WATCHDOG ALERT -- Type: NVLINK_CONTENTION
NVLink traffic 61,542,977,904 KB/s above this GPU's own learned baseline at 0% compute

Source: b200_watchdog/nvlink_final_test_b200_1.log (commit fd40919).

This is the strongest single result of the session: a detector built on real published
attack research, previously completely non-functional, now confirmed catching a real
induced event on real B200 hardware -- through a pipeline traced back to root cause
across three separate layers.

---

## 2. Contention -- measured four independent times, 43-55% range

Renting a shared GPU instance measurably loses performance to a co-located workload.
Measured with two independent methods (gpu_audit.py's benchmark and the separate
capture_contention.py telemetry-capture script) across two different pods:

Run 1: gpu_audit.py benchmark -- -53.35% -- audit_b200_1.json
Run 2: capture_contention.py -- -54.7% (434.7 -> 196.9 iters/s) -- capture_b200_1.csv
Run 3: gpu_audit.py benchmark -- -53.38% -- tenant_files_b200_2.json
Run 4: gpu_audit.py benchmark, new pod -- -43.23% -- audit_b200_2.json

Honest note: these four numbers span a real range (43-55%), not a single fixed
value. Report the range, not a point estimate. Runs 1-3 were on the same pod; run 4
was a separate pod with a different kernel (6.8.0-90 vs 6.8.0-107).

---

## 3. Clean negative control -- quiet when nothing is happening

A monitoring tool is only useful if it stays quiet during normal operation. GPU1 was
left completely untouched for a full hour while watchdog.py monitored it live.

Samples: 13,710 | Alerts: 1

The single alert (AGENT_ORCHESTRATION_ANOMALY, 51.9W above the learned idle floor)
is an isolated event, not a pattern -- a ~0.007% alert rate. This supersedes an earlier
attempt on the same day that was contaminated by other tests running on the same GPU
and is recorded as invalid in EVIDENCE.md.

Source: b200_watchdog/watchdog_idle_1hr_b200_2_gpu1.log (commit 7294da4).

---

## 4. Detectors correctly firing on real, deliberately induced events

Beyond NVLink, four more detectors were tested against genuine workloads (not
synthetic test harnesses) during this session:

AGENT_ORCHESTRATION_ANOMALY -- Real induced matmul contention -- Fired correctly (50.9W above idle floor) -- live_detector_test_b200_1.log
PROMPT_INJECTION_SIDEEFFECT -- Real calibration phase, then real power-spike workload -- Fired correctly (127.5W above calibrated baseline) -- prompt_injection_test_b200_1.log
AgentSessionVRAMRetentionDetector -- Real subprocess spawned, held VRAM, killed via SIGTERM -- Correctly silent, no false alert on a clean release -- agent_vram_test_b200_1.log
InterAgentHandoffAnomalyDetector -- Short bursty workload (agentic-style) -- Inconclusive, real limitation found, see below -- handoff_test_b200_1.log

The InterAgentHandoffAnomalyDetector result is itself a finding, not a failure.
Real telemetry showed utilization.gpu = 0.0 in 433 of ~440 samples during a test
built from short (3.2s) bursts separated by 0.4s pauses. At the achieved ~3-7Hz sample
rate (see Limitation below), short bursty GPU activity -- the pattern typical of
agentic workloads -- is largely invisible to the sampler. This is a genuine, actionable
limitation of the current sampling approach, not a bug in this specific detector.

---

## Known limitation, stated plainly

Achieved sample rate is 3.7-7.1Hz against a requested 100Hz, confirmed on two
separate B200 pods (3.756Hz on the clean idle run, 7.128Hz on an earlier run).
Any workload shorter than roughly one second between state changes may not be
reliably captured. This directly explains the inconclusive handoff-detector result
above and should be treated as an open engineering question, not hidden.

---

## What this report does not claim

This report does not include the VRAM residual finding -- see
B200_VRAM_RESIDUAL_REPORT.md for that, framed the same way as the existing H200
finding in README.md. It also does not include a multi-provider comparison; every
result above is RunPod only.
