import torch, time, csv, os
from datetime import datetime

#pynvml removed
#handle removed
gpu_id = 0 if torch.cuda.device_count() > 0 else None
device = f'cuda:{gpu_id}'
os.makedirs("./results/t30", exist_ok=True)
csv_path = "./results/t30/t30_raw_100hz.csv"
idle_power = 0

with open(csv_path, "w") as f:
    csv.writer(f).writerow(["timestamp","phase","workload_num","power_w","gpu_util_pct","mem_util_pct","vram_mb","mem_clock_mhz","sm_clock_mhz","pstate","ghost_detected"])

def sample(duration, phase, workload_num=0):
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
            ghost = 1 if p > idle_power + 20 else 0
            w.writerow([time.time(),phase,workload_num,p,u.gpu,u.memory,m,mc,sc,ps,ghost])
            f.flush()
            time.sleep(0.01)

print("=== T-30 SCHEDULER ORACLE H200 100Hz ===")
print("Author: Manmohan Mike Bains CVE 2048350")
print("Start:", datetime.now().isoformat())

baseline_readings = []
for _ in range(100):
    baseline_readings.append(pynvml.nvmlDeviceGetPowerUsage(h)/1000.0)
    time.sleep(0.01)
idle_power = sum(baseline_readings)/len(baseline_readings)
print(f"Idle baseline: {idle_power:.2f}W")

for run in range(5):
    print(f"\nWorkload {run+1}/5")
    sample(10,"baseline",run)
    t = torch.randn(8192,8192,device=device,dtype=torch.float16)
    for _ in range(50):
        c = torch.mm(t,t)
    torch.cuda.synchronize()
    sample(10,"compute",run)
    del t, c
    torch.cuda.empty_cache()
    sample(60,"ghost_window",run)
    p_now = pynvml.nvmlDeviceGetPowerUsage(h)/1000.0
    print(f"  Ghost detected: {p_now > idle_power + 20} ({p_now:.2f}W vs {idle_power:.2f}W)")
    time.sleep(2)
    sample(30,"attacker_window",run)

print("=== T-30 COMPLETE ===")
print("End:", datetime.now().isoformat())
