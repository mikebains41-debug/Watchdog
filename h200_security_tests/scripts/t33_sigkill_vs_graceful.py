import torch, time, csv, os, struct, multiprocessing, signal
from datetime import datetime

#pynvml removed
#handle removed
gpu_id = 0 if torch.cuda.device_count() > 0 else None
device = f'cuda:{gpu_id}'
os.makedirs("./results/t33", exist_ok=True)
csv_path = "./results/t33/t33_raw_100hz.csv"
MARKER = 9.87654321

with open(csv_path, "w") as f:
    csv.writer(f).writerow(["timestamp","phase","exit_type","power_w","gpu_util_pct","mem_util_pct","vram_mb","mem_clock_mhz","sm_clock_mhz","pstate","residual_mb","nonzero_count"])

def sample(duration, phase, exit_type, residual_mb=0, nonzero=0):
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
            w.writerow([time.time(),phase,exit_type,p,u.gpu,u.memory,m,mc,sc,ps,residual_mb,nonzero])
            f.flush()
            time.sleep(0.01)

def read_residual():
    probe = torch.empty(8192,8192,device=device,dtype=torch.float32)
    raw = probe.cpu().numpy().tobytes()
    float_vals = struct.unpack('f'*(len(raw)//4), raw)
    nonzero = sum(1 for v in float_vals if abs(v) > 0.0001)
    residual_mb = pynvml.nvmlDeviceGetMemoryInfo(h).used//1024//1024
    del probe
    torch.cuda.empty_cache()
    return residual_mb, nonzero

def child_worker():
    import torch, time
    t = torch.full((8192,8192), 9.87654321, device='cuda:0', dtype=torch.float32)
    torch.cuda.synchronize()
    time.sleep(10)

print("=== T-33 SIGKILL VS GRACEFUL EXIT H200 100Hz ===")
print("Author: Manmohan Mike Bains CVE 2048350")
print("Start:", datetime.now().isoformat())

print("\nTEST 1 - GRACEFUL EXIT")
t = torch.full((8192,8192), MARKER, device=device, dtype=torch.float32)
torch.cuda.synchronize()
sample(10,"compute","graceful")
del t
torch.cuda.empty_cache()
sample(5,"settle","graceful")
res_mb, nonzero = read_residual()
print(f"  Graceful residual: {res_mb}MB  Non-zero: {nonzero}")
sample(10,"post_exit","graceful", res_mb, nonzero)

print("\nTEST 2 - REAL SIGKILL")
p = multiprocessing.Process(target=child_worker)
p.start()
time.sleep(5)
os.kill(p.pid, signal.SIGKILL)
p.join()
print("  Child killed with SIGKILL")
sample(5,"settle","sigkill")
res_mb2, nonzero2 = read_residual()
print(f"  SIGKILL residual: {res_mb2}MB  Non-zero: {nonzero2}")
sample(10,"post_exit","sigkill", res_mb2, nonzero2)

print(f"\n=== T-33 RESULTS ===")
print(f"Graceful: {res_mb}MB  Non-zero: {nonzero}")
print(f"SIGKILL:  {res_mb2}MB  Non-zero: {nonzero2}")
print(f"SIGKILL SAFER: {nonzero2 < nonzero}")
print("=== T-33 COMPLETE ===")
print("End:", datetime.now().isoformat())
