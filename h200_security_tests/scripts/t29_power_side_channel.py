import torch, time, csv, os
from datetime import datetime

#pynvml removed
#handle removed
gpu_id = 0 if torch.cuda.device_count() > 0 else None
device = f'cuda:{gpu_id}'
os.makedirs("./results/t29", exist_ok=True)
csv_path = "./results/t29/t29_raw_100hz.csv"

with open(csv_path, "w") as f:
    csv.writer(f).writerow(["timestamp","phase","matrix_size","precision","batch_size","power_w","gpu_util_pct","mem_util_pct","vram_mb","mem_clock_mhz","sm_clock_mhz","pstate"])

def sample(duration, phase, matrix_size=0, precision="", batch_size=0):
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
            w.writerow([time.time(),phase,matrix_size,precision,batch_size,p,u.gpu,u.memory,m,mc,sc,ps])
            f.flush()
            time.sleep(0.01)

print("=== T-29 POWER SIDE CHANNEL H200 100Hz ===")
print("Author: Manmohan Mike Bains CVE 2048350")
print("Start:", datetime.now().isoformat())

sample(10,"idle_baseline")

for sz in [2048,4096,8192,16384,32768]:
    for bs in [1,8,32,128]:
        for pname,ptype in [("fp32",torch.float32),("fp16",torch.float16)]:
            print(f"Matrix:{sz} Batch:{bs} Precision:{pname}")
            try:
                sample(3,"pre_compute_idle",sz,pname,bs)
                t = torch.randn(bs,sz,sz,device=device,dtype=ptype)
                torch.cuda.synchronize()
                sample(10,"compute",sz,pname,bs)
                del t
                torch.cuda.empty_cache()
                sample(5,"settle",sz,pname,bs)
            except RuntimeError:
                print("  OOM skipped")
                torch.cuda.empty_cache()

print("=== T-29 COMPLETE ===")
print("End:", datetime.now().isoformat())
