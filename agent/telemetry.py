import subprocess, time, csv, os
from datetime import datetime
SAMPLE_HZ = 100
QUERY_FIELDS = ['timestamp','index','name','power.draw','power.limit','utilization.gpu','utilization.memory','memory.used','memory.free','memory.total','clocks.sm','clocks.mem','clocks.gr','temperature.gpu','pstate','ecc.errors.corrected.volatile.total','ecc.errors.uncorrected.volatile.total']
def sample_gpu(gpu_index=None):
    cmd = ['nvidia-smi','--query-gpu='+','.join(QUERY_FIELDS),'--format=csv,noheader,nounits']
    if gpu_index is not None: cmd += [f'--id={gpu_index}']
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
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
            rows.append(row)
        return rows
    except: return []
def detect_gpus():
    try:
        r = subprocess.run(['nvidia-smi','--query-gpu=index,name','--format=csv,noheader'],capture_output=True,text=True,timeout=5)
        return [l.strip() for l in r.stdout.strip().split('\n') if l.strip()]
    except: return []
class TelemetryCollector:
    def __init__(self, sample_hz=SAMPLE_HZ, output_dir='watchdog_data', gpu_index=None, on_sample=None):
        self.sample_hz = sample_hz
        self.output_dir = output_dir
        self.gpu_index = gpu_index
        self.on_sample = on_sample
        self.running = False
        self.sample_count = 0
        os.makedirs(output_dir, exist_ok=True)
    def start(self, duration_seconds=None):
        self.running = True
        ts = datetime.now().strftime('%Y%m%d_%H%M%S')
        csv_path = os.path.join(self.output_dir, f'telemetry_{ts}.csv')
        print(f"[WATCHDOG] Starting at {self.sample_hz}Hz → {csv_path}")
        print(f"[WATCHDOG] GPUs: {detect_gpus()}")
        with open(csv_path,'w',newline='') as f:
            writer = csv.DictWriter(f, fieldnames=['iso_timestamp']+QUERY_FIELDS, extrasaction='ignore')
            writer.writeheader()
            start = time.time()
            while self.running:
                loop_start = time.time()
                rows = sample_gpu(self.gpu_index)
                for row in rows:
                    writer.writerow(row)
                    self.sample_count += 1
                    if self.on_sample: self.on_sample(row)
                elapsed = time.time() - start
                if int(elapsed) % 60 == 0 and elapsed > 1:
                    for row in rows:
                        print(f"[t+{int(elapsed)}s] GPU{row.get('index','?')}: {row.get('power.draw',0):.1f}W mem={row.get('memory.used',0):.0f}MB temp={row.get('temperature.gpu',0):.0f}C util={row.get('utilization.gpu',0):.0f}%")
                if duration_seconds and elapsed >= duration_seconds: break
                time.sleep(max(0,(1/self.sample_hz)-(time.time()-loop_start)))
        print(f"[WATCHDOG] Done. {self.sample_count} samples → {csv_path}")
        return csv_path
    def stop(self): self.running = False
