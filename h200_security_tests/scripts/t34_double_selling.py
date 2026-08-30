import torch, time, csv, os, statistics, sys
from datetime import datetime

#pynvml removed
#handle removed
gpu_id = 0 if torch.cuda.device_count() > 0 else None
device = f'cuda:{gpu_id}'
session = sys.argv[1] if len(sys.argv) > 1 else "morning"
os.makedirs("./results/t34", exist_ok=True)
csv_path = f"./results/t34/t34_{session}_100hz.csv"

with open(csv_path, "w") as f:
    csv.writer(f).writerow(["timestamp","run","phase","elapsed_s","power_w","gpu_util_pct","mem_util_pct","vram_mb","mem_clock_mhz","sm_clock_mhz","pstate"])

def sample(duration, phase, run=0, elapsed=0):
    start = time.time()
    with open(csv_path, "a") as f:
        w = csv.writer(f)
        while time.time() - start < duration:
            p = pynvml.nvmlDeviceGetPowerUsage(h)/1000.0
            u = pynvml.nvmlDeviceGetUtilizationRates(h)
            m = pynvml.nvmlDeviceGetMemoryInfo(h).used//1024//1024
            mc = pynvml.nvmlDeviceGetClockInfo(h.NVML_CLOCK_MEM)
            sc = pynvml.nvmlDeviceGetClockInfo(h.NVML_CLOCK_SM)
            ps = pynvml.nvmlDeviceGetPerformanceState(h)
            w.writerow([time.time(),run,phase,elapsed,p,u.gpu,u.memory,m,mc,sc,ps])
            f.flush()
            time.sleep(0.01)

print(f"=== T-34 DOUBLE-SELLING DETECTION H200 100Hz - {session.upper()} ===")
print("Author: Manmohan Mike Bains CVE 2048350")
print("Start:", datetime.now().isoformat())

results = []

for run in range(10):
    print(f"\nRun {run+1}/10")
    a = torch.randn(8192,8192,device=device,dtype=torch.float16)
    b = torch.randn(8192,8192,device=device,dtype=torch.float16)
    torch.cuda.synchronize()
    run_start = time.perf_counter()
    for _ in range(20):
        c = torch.mm(a,b)
    torch.cuda.synchronize()
    elapsed = time.perf_counter() - run_start
    sample(10,"benchmark",run,elapsed)
    results.append(elapsed)
    print(f"  Elapsed: {elapsed:.4f}s")
    del a,b,c
    torch.cuda.empty_cache()
    sample(2,"idle_between_runs",run,0)

mean = statistics.mean(results)
stdev = statistics.stdev(results)
jitter = (stdev/mean)*100
print(f"\n=== T-34 {session.upper()} RESULTS ===")
print(f"Mean: {mean:.4f}s  StdDev: {stdev:.4f}s  Jitter: {jitter:.2f}%")
print(f"DOUBLE SELLING LIKELY: {jitter > 5.0}")
print("End:", datetime.now().isoformat())
