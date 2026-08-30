import torch, time, csv, os, struct, math
from datetime import datetime

#pynvml removed
#handle removed
gpu_id = 0 if torch.cuda.device_count() > 0 else None
device = f'cuda:{gpu_id}'
os.makedirs("./results/t31", exist_ok=True)
csv_path = "./results/t31/t31_power_100hz.csv"

with open(csv_path, "w") as f:
    csv.writer(f).writerow(["timestamp","phase","power_w","gpu_util_pct","mem_util_pct","vram_mb","mem_clock_mhz","sm_clock_mhz","pstate"])

def sample(duration, phase):
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
            w.writerow([time.time(),phase,p,u.gpu,u.memory,m,mc,sc,ps])
            f.flush()
            time.sleep(0.01)

def entropy(data):
    if len(data)==0: return 0
    counts={}
    for b in data: counts[b]=counts.get(b,0)+1
    e=0
    for c in counts.values():
        p=c/len(data)
        if p>0: e-=p*math.log2(p)
    return e

def read_residual(label):
    probe = torch.empty(8192,8192,device=device,dtype=torch.float32)
    raw = probe.cpu().numpy().tobytes()
    ent = entropy(raw[:100000])
    float_vals = struct.unpack('f'*1000, raw[:4000])
    nonzero = sum(1 for v in float_vals if abs(v) > 0.0001)
    marker_hits = sum(1 for v in float_vals if abs(v-1.23456789) < 0.001)
    print(f"  [{label}] Entropy:{ent:.4f} NonZero:{nonzero} MarkerHits:{marker_hits} Size:{len(raw)//1024//1024}MB")
    del probe
    return ent, nonzero

print("=== T-31 VRAM CONTENT CLASSIFICATION H200 100Hz ===")
print("Author: Manmohan Mike Bains CVE 2048350")
print("Start:", datetime.now().isoformat())

print("\nPHASE 1 - FP32 WORKLOAD")
t = torch.ones(8192,8192,device=device,dtype=torch.float32)*1.23456789
torch.cuda.synchronize()
sample(10,"fp32_compute")
del t
torch.cuda.empty_cache()
sample(5,"fp32_settle")
read_residual("FP32 after graceful exit")

print("\nPHASE 2 - FP16 WORKLOAD")
t2 = torch.ones(8192,8192,device=device,dtype=torch.float16)*2.5
torch.cuda.synchronize()
sample(10,"fp16_compute")
del t2
torch.cuda.empty_cache()
sample(5,"fp16_settle")
read_residual("FP16 after graceful exit")

print("\nPHASE 3 - PERSISTENCE CHECK")
torch.cuda.empty_cache()
time.sleep(5)
read_residual("After second empty_cache persistence check")

print("\n=== T-31 COMPLETE ===")
print("End:", datetime.now().isoformat())
