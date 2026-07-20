import subprocess, time, csv, os
from datetime import datetime

from telemetry.sampler import DeltaTimedSampler

SAMPLE_HZ = 100
QUERY_FIELDS = ['timestamp','index','uuid','name','power.draw','power.limit','utilization.gpu','utilization.memory','memory.used','memory.free','memory.total','clocks.sm','clocks.mem','clocks.gr','temperature.gpu','pstate','ecc.errors.corrected.volatile.total','ecc.errors.uncorrected.volatile.total']

COMPUTE_APPS_FIELDS = ['gpu_uuid', 'pid', 'used_memory']


def sample_compute_apps():
    cmd = ['nvidia-smi', f'--query-compute-apps={",".join(COMPUTE_APPS_FIELDS)}',
           '--format=csv,noheader,nounits']
    result = {}
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
        for line in r.stdout.strip().split('\n'):
            if not line.strip():
                continue
            parts = [p.strip() for p in line.split(',')]
            if len(parts) < 3:
                continue
            uuid, pid, used_memory = parts[0], parts[1], parts[2]
            try:
                entry = {'pid': int(pid), 'used_memory': float(used_memory)}
            except ValueError:
                continue
            result.setdefault(uuid, []).append(entry)
    except Exception:
        pass
    return result


def sample_gpu(gpu_index=None):
    cmd = ['nvidia-smi','--query-gpu='+','.join(QUERY_FIELDS),'--format=csv,noheader,nounits']
    if gpu_index is not None: cmd += [f'--id={gpu_index}']
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
        compute_apps_by_gpu = sample_compute_apps()
        rows = []
        for line in r.stdout.strip().split('\n'):
            if not line.strip(): continue
            vals = [v.strip() for v in line.split(',')]
            if len(vals) < len(QUERY_FIELDS): continue
            row = dict(zip(QUERY_FIELDS, vals))
            row['iso_timestamp'] = datetime.now().isoformat()
            for f in ['power.draw','power.limit','utilization.gpu','utilization.memory','memory.used','memory.free','memory.total','clocks.sm','clocks.mem','clocks.gr','temperature.gpu']:
                try: row[f] = float(row[f])
                except: row[f] = 0.0
            row['compute_apps'] = compute_apps_by_gpu.get(row.get('uuid'), [])
            rows.append(row)
        return rows
    except: return []


def detect_gpus():
    try:
        r = subprocess.run(['nvidia-smi','--query-gpu=index,name','--format=csv,noheader'],capture_output=True,text=True,timeout=5)
        return [l.strip() for l in r.stdout.strip().split('\n') if l.strip()]
    except: return []


class TelemetryCollector:
    """
    FIXED vs. original: SAMPLE_HZ=100 was requested but never verified as
    achieved -- the collector silently assumed it was hitting 100Hz with
    no measurement to back that up. telemetry/sampler.py's
    DeltaTimedSampler was built earlier specifically to fix this, but was
    never actually wired in here until now.

    self.timer measures the ACTUAL wall-clock gap between loop
    iterations using a monotonic clock. It wraps a no-op probe (not
    sample_gpu() directly, since sample_gpu() returns a LIST of rows --
    one per GPU on a multi-GPU node -- while DeltaTimedSampler's API is
    built around a single-value probe). The measured interval from one
    call to timer.sample() is then attached to every row produced by
    that same loop iteration, since all of a multi-GPU sample_gpu() call
    happens within the same wall-clock instant for practical purposes.

    'actual_interval_ms' is now written to the CSV, per the collector's
    own README/Limitations promise: "the collector must log measured
    inter-sample deltas, not the requested rate."
    """
    def __init__(self, sample_hz=SAMPLE_HZ, output_dir='watchdog_data', gpu_index=None, on_sample=None):
        self.sample_hz = sample_hz
        self.output_dir = output_dir
        self.gpu_index = gpu_index
        self.on_sample = on_sample
        self.running = False
        self.sample_count = 0
        self.timer = DeltaTimedSampler(sample_fn=lambda: {})
        os.makedirs(output_dir, exist_ok=True)

    def start(self, duration_seconds=None):
        self.running = True
        ts = datetime.now().strftime('%Y%m%d_%H%M%S')
        csv_path = os.path.join(self.output_dir, f'telemetry_{ts}.csv')
        print(f"[WATCHDOG] Starting -- requested {self.sample_hz}Hz → {csv_path}")
        print(f"[WATCHDOG] Actual achieved rate will be measured and "
              f"reported below, not assumed.")
        print(f"[WATCHDOG] GPUs: {detect_gpus()}")
        fieldnames = ['iso_timestamp'] + QUERY_FIELDS + ['actual_interval_ms']
        with open(csv_path,'w',newline='') as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction='ignore')
            writer.writeheader()
            start = time.time()
            while self.running:
                loop_start = time.time()
                timing_row = self.timer.sample()
                actual_interval_ms = timing_row['actual_interval_ms']
                rows = sample_gpu(self.gpu_index)
                for row in rows:
                    row['actual_interval_ms'] = actual_interval_ms
                    writer.writerow(row)
                    self.sample_count += 1
                    if self.on_sample: self.on_sample(row)
                elapsed = time.time() - start
                if int(elapsed) % 60 == 0 and elapsed > 1:
                    stats = self.timer.stats()
                    for row in rows:
                        print(f"[t+{int(elapsed)}s] GPU{row.get('index','?')}: {row.get('power.draw',0):.1f}W mem={row.get('memory.used',0):.0f}MB temp={row.get('temperature.gpu',0):.0f}C util={row.get('utilization.gpu',0):.0f}%")
                    print(f"[WATCHDOG] Actual achieved rate: "
                          f"{stats['achieved_hz']}Hz (requested "
                          f"{self.sample_hz}Hz) -- min/mean/max interval: "
                          f"{stats['min_ms']}/{stats['mean_ms']}/{stats['max_ms']}ms")
                if duration_seconds and elapsed >= duration_seconds: break
                time.sleep(max(0,(1/self.sample_hz)-(time.time()-loop_start)))
        final_stats = self.timer.stats()
        print(f"[WATCHDOG] Done. {self.sample_count} samples → {csv_path}")
        print(f"[WATCHDOG] Final actual achieved rate: "
              f"{final_stats['achieved_hz']}Hz (requested {self.sample_hz}Hz)")
        return csv_path

    def stop(self): self.running = False
