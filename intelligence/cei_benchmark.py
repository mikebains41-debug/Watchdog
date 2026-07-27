# Author: Manmohan (Mike) Bains -- Watchdog AIDR
"""
intelligence/cei_benchmark.py

Real CEI (Compute Energy Intensity, FLOPs delivered per joule)
measurement. Unlike passive telemetry, CEI cannot be read from
nvidia-smi under any field name -- it requires knowing how many
floating-point operations a workload actually performed, which only
the workload itself (or a benchmark standing in for it) knows. This is
the same reason ThroughputContentionDetector needs a separate
calibrate/process entry point rather than passive process(row); CEI
needs the same treatment, one level further, since it also needs a
workload with a KNOWN FLOP count, not just a measured rate.

METHODOLOGY, matching the same well-understood benchmark shape behind
Serial Alice's own published CEI figures elsewhere in this project:
matrix multiplication has an exactly countable FLOP cost -- an
(m,k) x (k,n) matmul performs m*k*n multiply-accumulate operations,
counted as 2 FLOPs each (one multiply, one add).

  1. Run a real, timed matmul workload of known dimensions on the GPU.
  2. Sample power draw via nvidia-smi throughout the run.
  3. CEI = total FLOPs delivered / (mean power watts * elapsed seconds).

HONEST STATUS: this module's arithmetic -- FLOP counting, the CEI
formula itself -- is tested against synthetic, mocked values in this
session, confirming the MATH is correct. It has NOT been run against
real GPU hardware, and cannot produce a real CEI number until it is --
that requires actual rented GPU access. Nothing about mocking torch or
nvidia-smi can substitute for a real workload actually computing and a
real power rail actually being read.
"""
import time
import subprocess


def compute_matmul_flops(m, k, n, iterations=1):
    """FLOPs for `iterations` repetitions of an (m,k) x (k,n) matmul.
    2 FLOPs (one multiply, one add) per multiply-accumulate term."""
    return 2 * m * k * n * iterations


def sample_power_w(gpu_index=0):
    """
    One real nvidia-smi power.draw sample. Returns None if
    unavailable (no GPU, no nvidia-smi, malformed output) rather than
    a fabricated 0 -- a caller must handle None explicitly, matching
    the same discipline used throughout this project's other
    nvidia-smi-based detectors.
    """
    try:
        r = subprocess.run(
            ['nvidia-smi', f'--id={gpu_index}',
             '--query-gpu=power.draw', '--format=csv,noheader,nounits'],
            capture_output=True, text=True, timeout=5
        )
        if r.returncode != 0:
            return None
        val = r.stdout.strip()
        if val in ('', '[N/A]'):
            return None
        return float(val)
    except Exception:
        return None


class CEIBenchmarkRunner:
    """
    Runs a real matmul workload on real CUDA hardware, sampling power
    throughout, and computes a real CEI value. Requires PyTorch with
    CUDA -- an explicit, stated requirement, not a silent fallback,
    since CEI cannot be measured without actually computing something.
    """
    def __init__(self, gpu_index=0, matrix_size=4096, power_sample_interval_s=0.2):
        self.gpu_index = gpu_index
        self.matrix_size = matrix_size
        self.power_sample_interval_s = power_sample_interval_s

    def run(self, duration_s=10):
        """
        Runs matmul iterations for duration_s seconds, sampling power
        throughout. Returns a result dict, or None if torch/CUDA is
        unavailable or no power samples could be collected -- never a
        fabricated CEI value standing in for a real measurement.
        """
        try:
            import torch
            if not torch.cuda.is_available():
                return None
        except ImportError:
            return None

        device = torch.device(f'cuda:{self.gpu_index}')
        m = k = n = self.matrix_size
        a = torch.randn(m, k, device=device)
        b = torch.randn(k, n, device=device)

        power_samples = []
        iterations = 0
        start = time.time()
        last_sample_ts = 0
        while time.time() - start < duration_s:
            c = a @ b
            torch.cuda.synchronize()
            iterations += 1
            now = time.time()
            if now - last_sample_ts >= self.power_sample_interval_s:
                p = sample_power_w(self.gpu_index)
                if p is not None:
                    power_samples.append(p)
                last_sample_ts = now
        elapsed = time.time() - start

        del a, b, c
        torch.cuda.empty_cache()

        if not power_samples:
            return None

        total_flops = compute_matmul_flops(m, k, n, iterations=iterations)
        mean_power_w = sum(power_samples) / len(power_samples)
        total_joules = mean_power_w * elapsed
        cei = (total_flops / total_joules) if total_joules > 0 else None

        return {
            'cei_flops_per_joule': cei,
            'total_flops': total_flops,
            'iterations': iterations,
            'elapsed_s': elapsed,
            'mean_power_w': mean_power_w,
            'power_sample_count': len(power_samples),
            'matrix_size': self.matrix_size,
        }
