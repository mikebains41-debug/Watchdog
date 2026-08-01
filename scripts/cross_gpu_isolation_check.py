#!/usr/bin/env python3
"""
scripts/cross_gpu_isolation_check.py

Live cross-GPU isolation check. Runs compute ONLY on GPU0 and checks
whether GPU1 -- which never receives any tensor operations -- shows
any change in memory or utilization. This reproduces the cross-GPU
residual finding from the original research: compute activity on one
GPU leaving residual data/state on a second, completely idle GPU in
the same pod.

Usage: python3 scripts/cross_gpu_isolation_check.py
Requires: 2+ CUDA GPUs, torch.

Interpretation:
  - GPU1 memory delta == 0  -> isolation held on this hardware/session.
  - GPU1 memory delta != 0  -> live reproduction of cross-GPU bleed;
    matches the finding documented for H200 in the original research
    (528MB residual on an untouched GPU after compute on a sibling GPU).
"""
import torch
import subprocess


def mem(gpu):
    out = subprocess.run(
        ['nvidia-smi', f'--id={gpu}',
         '--query-gpu=memory.used,utilization.gpu',
         '--format=csv,noheader,nounits'],
        capture_output=True, text=True)
    m, u = out.stdout.strip().split(',')
    return float(m), float(u)


def main():
    m1_before, u1_before = mem(1)
    print(f'GPU1 (idle, untouched) BEFORE: mem={m1_before}MB util={u1_before}%')

    # Run compute ONLY on GPU0
    x = torch.rand(8192, 8192, device='cuda:0', dtype=torch.float16)
    for _ in range(30):
        y = x @ x
    torch.cuda.synchronize(0)
    del x, y
    torch.cuda.empty_cache()

    m1_after, u1_after = mem(1)
    print(f'GPU1 (still untouched by any code) AFTER GPU0 workload: '
          f'mem={m1_after}MB util={u1_after}%')
    delta = m1_after - m1_before
    print(f'GPU1 memory delta: {delta}MB (GPU1 never received any tensor operations)')

    if delta != 0:
        print('RESULT: Cross-GPU memory delta detected -- possible isolation bleed. '
              'Investigate further, matches documented H200 finding pattern.')
    else:
        print('RESULT: No cross-GPU memory delta -- isolation held on this run.')


if __name__ == '__main__':
    main()
