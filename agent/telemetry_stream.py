# Author: Manmohan (Mike) Bains -- Watchdog
"""agent/telemetry_stream.py -- P0 fix for the 4-6 Hz vs 100 Hz gap.
Replaces per-sample nvidia-smi spawns with ONE persistent -lms stream.
Same row schema as sample_gpu(); reuses telemetry.py parsing.
HARDWARE-UNVERIFIED off-GPU: run --selftest first."""
import subprocess, time, csv, os
from datetime import datetime
from agent.telemetry import (QUERY_FIELDS, CORE_FIELDS, parse_numeric_fields,
    sample_compute_apps, sample_nvlink, detect_gpus, _safe_fmt)
from telemetry.sampler import DeltaTimedSampler


class StreamingTelemetryCollector:
    def __init__(self, sample_hz=100, output_dir='watchdog_data', gpu_index=None,
                 on_sample=None, nvlink_enabled=False, nvlink_interval_s=5.0,
                 compute_apps_interval_s=1.0):
        self.sample_hz = sample_hz
        self.output_dir = output_dir
        self.gpu_index = gpu_index
        self.on_sample = on_sample
        self.running = False
        self.sample_count = 0
        self.timer = DeltaTimedSampler(sample_fn=lambda: {})
        self.compute_apps_interval_s = compute_apps_interval_s
        self._last_compute_apps_ts = 0.0
        self._compute_apps_cache = {}
        self.nvlink_enabled = nvlink_enabled
        self.nvlink_interval_s = nvlink_interval_s
        self._last_nvlink_ts = 0.0
        self._nvlink_cache = {}
        self._extended = True
        self._proc = None
        os.makedirs(output_dir, exist_ok=True)

    def _build_cmd(self, fields):
        loop_ms = max(1, int(round(1000.0 / self.sample_hz)))
        cmd = ['nvidia-smi', '--query-gpu=' + ','.join(fields),
               '--format=csv,noheader,nounits', '-lms', str(loop_ms)]
        if self.gpu_index is not None:
            cmd += [f'--id={self.gpu_index}']
        return cmd

    def _expected_gpu_count(self):
        if self.gpu_index is not None:
            return 1
        n = len(detect_gpus())
        return n if n > 0 else 1

    def _refresh_caches(self, rows, now):
        if now - self._last_compute_apps_ts >= self.compute_apps_interval_s:
            self._last_compute_apps_ts = now
            try:
                self._compute_apps_cache = sample_compute_apps()
            except Exception:
                pass
        if self.nvlink_enabled and (now - self._last_nvlink_ts >= self.nvlink_interval_s):
            self._last_nvlink_ts = now
            for row in rows:
                idx = row.get('index', 0)
                try:
                    self._nvlink_cache[idx] = sample_nvlink(idx)
                except Exception:
                    pass

    def _line_to_row(self, line, fields, interval_ms):
        line = line.strip()
        if not line:
            return None
        vals = [v.strip() for v in line.split(',')]
        if len(vals) < len(fields):
            return None
        row = dict(zip(fields, vals))
        row['iso_timestamp'] = datetime.now().isoformat()
        row = parse_numeric_fields(row)
        row['compute_apps'] = self._compute_apps_cache.get(row.get('uuid'), [])
        cached = self._nvlink_cache.get(row.get('index', 0))
        if cached:
            row.update(cached)
        row['actual_interval_ms'] = interval_ms
        return row

    def start(self, duration_seconds=None):
        self.running = True
        ts = datetime.now().strftime('%Y%m%d_%H%M%S')
        csv_path = os.path.join(self.output_dir, f'telemetry_{ts}.csv')
        fields = QUERY_FIELDS if self._extended else CORE_FIELDS
        n_gpus = self._expected_gpu_count()
        print(f"[WATCHDOG] Streaming backend -- requested {self.sample_hz}Hz "
              f"(loop {max(1, int(round(1000.0/self.sample_hz)))}ms) -> {csv_path}")
        print("[WATCHDOG] Actual achieved rate will be measured and reported below, not assumed.")
        print(f"[WATCHDOG] GPUs: {detect_gpus()}")
        fieldnames = ['iso_timestamp'] + QUERY_FIELDS + [
            'actual_interval_ms', 'nvlink_available', 'nvlink_tx_kbs', 'nvlink_rx_kbs']
        self._proc = subprocess.Popen(self._build_cmd(fields),
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, bufsize=1)
        time.sleep(0.15)
        if self._proc.poll() is not None and self._extended:
            self._extended = False
            fields = CORE_FIELDS
            print("[WATCHDOG] Extended telemetry fields not supported -- falling back to core fields.")
            self._proc = subprocess.Popen(self._build_cmd(fields),
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, bufsize=1)
        start = time.time()
        group = []
        with open(csv_path, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction='ignore')
            writer.writeheader()
            for line in self._proc.stdout:
                if not self.running:
                    break
                if not line.strip():
                    continue
                group.append(line)
                if len(group) < n_gpus:
                    continue
                timing = self.timer.sample()
                interval_ms = timing['actual_interval_ms']
                now = time.time()
                pre_rows = [self._line_to_row(l, fields, interval_ms) for l in group]
                rows = [r for r in pre_rows if r is not None]
                group = []
                self._refresh_caches(rows, now)
                for row in rows:
                    writer.writerow(row)
                    self.sample_count += 1
                    if self.on_sample:
                        self.on_sample(row)
                elapsed = now - start
                if int(elapsed) % 60 == 0 and elapsed > 1 and rows:
                    stats = self.timer.stats()
                    for row in rows:
                        print(f"[t+{int(elapsed)}s] GPU{row.get('index','?')}: "
                              f"{_safe_fmt(row.get('power.draw'))}W "
                              f"mem={_safe_fmt(row.get('memory.used'),'.0f')}MB "
                              f"temp={_safe_fmt(row.get('temperature.gpu'),'.0f')}C "
                              f"util={_safe_fmt(row.get('utilization.gpu'),'.0f')}%")
                    print(f"[WATCHDOG] Actual achieved rate: {stats['achieved_hz']}Hz "
                          f"(requested {self.sample_hz}Hz) -- min/mean/max interval: "
                          f"{stats['min_ms']}/{stats['mean_ms']}/{stats['max_ms']}ms")
                if duration_seconds and elapsed >= duration_seconds:
                    break
        self.stop()
        final = self.timer.stats()
        print(f"[WATCHDOG] Done. {self.sample_count} samples -> {csv_path}")
        print(f"[WATCHDOG] Final actual achieved rate: {final['achieved_hz']}Hz "
              f"(requested {self.sample_hz}Hz)")
        return csv_path

    def stop(self):
        self.running = False
        if self._proc and self._proc.poll() is None:
            try:
                self._proc.terminate()
                self._proc.wait(timeout=3)
            except Exception:
                try:
                    self._proc.kill()
                except Exception:
                    pass


def _selftest():
    print("[selftest] simulating nvidia-smi --query-gpu stream, no GPU needed")
    c = StreamingTelemetryCollector(sample_hz=100, gpu_index=0)
    c._extended = False
    _vals = {'timestamp': '2026/07/30 17:58:26.376', 'index': '1',
        'uuid': 'GPU-8411eb10-e97e-f7aa-98e7-606b298432f3', 'name': 'NVIDIA B200',
        'power.draw': '184.19', 'power.limit': '1000.0', 'utilization.gpu': '0.0',
        'utilization.memory': '0.0', 'memory.used': '182632.0', 'memory.free': '727.0',
        'memory.total': '183359.0', 'clocks.sm': '120.0', 'clocks.mem': '3996.0',
        'clocks.gr': '120.0', 'temperature.gpu': '28.0', 'pstate': 'P0',
        'ecc.errors.corrected.volatile.total': '0',
        'ecc.errors.uncorrected.volatile.total': '0'}
    sample_line = ",".join(_vals[f] for f in CORE_FIELDS)
    assert len(sample_line.split(',')) == len(CORE_FIELDS)
    row = c._line_to_row(sample_line, CORE_FIELDS, interval_ms=10.0)
    assert row is not None
    assert row['name'] == 'NVIDIA B200', row.get('name')
    assert row['power.draw'] == 184.19, row.get('power.draw')
    assert row['memory.used'] == 182632.0, row.get('memory.used')
    assert row['pstate'] == 'P0', row.get('pstate')
    assert row['compute_apps'] == []
    assert row['actual_interval_ms'] == 10.0
    assert 'iso_timestamp' in row
    na_line = sample_line.replace("184.19", "[N/A]")
    row2 = c._line_to_row(na_line, CORE_FIELDS, interval_ms=10.0)
    assert row2['power.draw'] is None, "N/A must become None, never 0.0"
    assert c._line_to_row("", CORE_FIELDS, 10.0) is None
    assert c._line_to_row("1,2,3", CORE_FIELDS, 10.0) is None
    print("[selftest] PASS -- row schema matches sample_gpu(); N/A->None preserved")


if __name__ == '__main__':
    import sys
    if '--selftest' in sys.argv:
        _selftest()
    else:
        print("Usage: python3 -m agent.telemetry_stream --selftest")
