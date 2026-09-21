#!/usr/bin/env python3
# Author: Manmohan (Mike) Bains -- Watchdog
"""
scripts/run_negative_control.py

Runs the real DetectionPipeline against LIVE nvidia-smi output for a set
duration and reports the negative-control result: alerts on (presumably)
idle hardware. Expected result: alerts == 0.

STATUS: this script has NOT been executed against real GPU hardware by
anyone. There is no GPU in the environment that wrote it. It has only been
checked for import errors and argument parsing. Do not report its output
as a validated negative control until it has actually been run on a real
idle GPU and the output reviewed.

Usage:
  python3 scripts/run_negative_control.py --seconds 3600 --interval 1.0

Requires:
  - nvidia-smi on PATH
  - a GPU that is genuinely idle for the whole run. This is a NEGATIVE
    control -- any workload on the target GPU during the run invalidates
    the result. Run it alone, on a pod with nothing else scheduled.

Known gap: compute_apps (needed by VRAMResidualDetector) is not queried by
this harness. It runs with vram_strict=False, so VRAMResidualDetector is
constructed but will not evaluate. Wiring in
`nvidia-smi --query-compute-apps=pid,used_memory` is separate follow-up
work, not done here.
"""

import argparse
import subprocess
import sys
import time
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from detection.engines import DetectionPipeline
from telemetry.sampler import DeltaTimedSampler


NVIDIA_SMI_FIELDS = (
    "index,power.draw,utilization.gpu,utilization.memory,"
    "memory.used,temperature.gpu"
)


def sample_nvidia_smi(gpu_index=0):
    out = subprocess.check_output(
        ["nvidia-smi", f"--query-gpu={NVIDIA_SMI_FIELDS}",
         "--format=csv,noheader,nounits", "-i", str(gpu_index)],
        text=True, timeout=5,
    )
    parts = [p.strip() for p in out.strip().split(",")]
    idx, power, util, mem_util, mem_used, temp = parts
    return {
        'index': int(idx),
        'power.draw': float(power),
        'utilization.gpu': float(util),
        'utilization.memory': float(mem_util),
        'memory.used': float(mem_used),
        'temperature.gpu': float(temp),
        'iso_timestamp': None,
        'compute_apps': None,
    }


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--seconds', type=int, default=3600,
                    help="Duration to run (default: 3600 = 1 hour)")
    p.add_argument('--interval', type=float, default=1.0,
                    help="Requested seconds between samples")
    p.add_argument('--gpu', type=int, default=0)
    args = p.parse_args()

    pipeline = DetectionPipeline(vram_strict=False)
    sampler = DeltaTimedSampler(lambda: sample_nvidia_smi(args.gpu))
    fired = []          # (alert, the exact row that produced it)

    print(f"Negative control: {args.seconds}s on GPU {args.gpu}.")
    print("GPU must be genuinely idle for the entire run -- any workload "
          "invalidates this result.\n")

    start = time.time()
    n = 0
    try:
        while time.time() - start < args.seconds:
            row = sampler.sample()
            row['iso_timestamp'] = time.strftime('%Y-%m-%dT%H:%M:%S')
            alerts = pipeline.process(row) or []
            for a in alerts:
                fired.append({'alert': a, 'triggering_row': dict(row)})
            n += 1
            time.sleep(max(0, args.interval - 0.01))
    except KeyboardInterrupt:
        print("\nInterrupted by user -- reporting partial results below.")

    print("\n" + "=" * 60)
    print("RESULT -- expect alerts == 0 for a valid negative control")
    print(pipeline.stats())
    print("Sampling (actual measured rate, not requested):")
    print(sampler.stats())
    print("=" * 60)
    if fired:
        import json
        out = 'negative_control_alerts.jsonl'
        with open(out, 'w') as f:
            for e in fired:
                f.write(json.dumps(e, default=str) + "\n")
        print(f"\n{len(fired)} alert(s) fired. Each is saved in {out} WITH the exact")
        print("telemetry row that produced it -- power, util, memory, compute_apps --")
        print("so it can be checked against its own sample, not a reading taken later.")
        for e in fired[:3]:
            a, r = e['alert'], e['triggering_row']
            print("  %s on gpu %s: power=%s util=%s mem=%s" % (
                a.get('type'), a.get('gpu'),
                r.get('power.draw'), r.get('utilization.gpu'), r.get('memory.used')))
    else:
        print("\n0 alerts -- clean negative control.")


if __name__ == '__main__':
    main()
