import torch, time, csv, os
from datetime import datetime

if not torch.cuda.is_available():
    print("ERROR: CUDA not available")
    exit(1)

#pynvml removed
#handle removed
os.makedirs("/root/results", exist_ok=True)
csv_path = "/root/results/t28_100hz.csv"
with open(csv_path, "w") as f:
    csv.writer(f).writerow(["timestamp", "power_w"])

print("=== T-28 TIMING ATTACK – 20 min, 100Hz sampling, status every 10s ===")
print("Start:", datetime.now().isoformat())
start_total = time.time()

sizes = [4096,8192,16384]
names = ["SMALL","MEDIUM","LARGE"]
decay_sec = 120
idle_sec = 13.33

def log_duration(duration, phase_name):
    start_phase = time.time()
    last_print = start_phase
    with open(csv_path, "a") as f:
        w = csv.writer(f)
        while time.time() - start_phase < duration:
            p = pynvml.nvmlDeviceGetPowerUsage(h)/1000.0
            w.writerow([time.time(), p])
            f.flush()
            time.sleep(0.01)
            now = time.time()
            if now - last_print >= 10:
                print(f"  {phase_name}: {now-start_phase:.0f}s elapsed, current power {p:.1f}W")
                last_print = now

for sz, nm in zip(sizes, names):
    for rep in range(3):
        print(f"\n{nm} rep{rep+1} | tensor {sz}x{sz}")
        t = torch.randn(sz, sz, device="cuda:0", dtype=torch.float16)
        for _ in range(50): z = torch.mm(t, t)
        torch.cuda.synchronize()
        print("  Compute done. Logging decay...")
        log_duration(decay_sec, "Decay")
        del t, z
        torch.cuda.empty_cache()
        print("  Cleaned. Logging idle...")
        log_duration(idle_sec, "Idle")
        elapsed_total = time.time() - start_total
        print(f"  Total progress: {elapsed_total/60:.1f} min / 20 min")

print(f"\n=== DONE in {(time.time()-start_total)/60:.1f} minutes ===")
print("End:", datetime.now().isoformat())
