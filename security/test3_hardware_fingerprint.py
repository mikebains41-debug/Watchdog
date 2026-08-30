import subprocess,time,torch,gc

def s(idx=0):
    r=subprocess.run(["nvidia-smi",f"--id={idx}","--query-gpu=power.draw,utilization.gpu","--format=csv,noheader,nounits"],capture_output=True,text=True)
    return r.stdout.strip()

def pw(row): return float(row.split(",")[0].strip())

print("=== TEST 3: Hardware Fingerprint ===",flush=True)
print("Recording cold boot fingerprint ...",flush=True)
cold=pw(s(0))
print(f"Cold boot power: {cold}W",flush=True)
print("Triggering shift ...",flush=True)
t=torch.randn(8000,8000,dtype=torch.float32,device="cuda:0")
torch.cuda.synchronize()
time.sleep(600)
del t;gc.collect();torch.cuda.empty_cache()
time.sleep(30)
shifted=pw(s(0))
print(f"Shifted power: {shifted}W",flush=True)
print(f"Fingerprint delta: {shifted-cold:.4f}W",flush=True)
print("NOTE: Run on multiple GPUs to compare fingerprint deltas",flush=True)
