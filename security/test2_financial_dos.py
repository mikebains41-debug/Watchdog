import subprocess,time,torch,gc

def s(idx=0):
    r=subprocess.run(["nvidia-smi",f"--id={idx}","--query-gpu=power.draw,utilization.gpu","--format=csv,noheader,nounits"],capture_output=True,text=True)
    return r.stdout.strip()

def pw(row): return float(row.split(",")[0].strip())

print("=== TEST 2: Financial DoS ===",flush=True)
print("COLD baseline GPU0:",s(0),flush=True)
print("Triggering permanent shift ...",flush=True)
t=torch.randn(8000,8000,dtype=torch.float32,device="cuda:0")
torch.cuda.synchronize()
time.sleep(600)
del t;gc.collect();torch.cuda.empty_cache()
time.sleep(30)
print("POST-SHIFT baseline GPU0:",s(0),flush=True)
print("Running benign inference workload ...",flush=True)
import time as t2
start=t2.time()
t3=torch.randn(1000,1000,dtype=torch.float32,device="cuda:0")
torch.matmul(t3,t3)
torch.cuda.synchronize()
duration=t2.time()-start
shifted_power=pw(s(0))
print(f"Benign workload power on shifted GPU: {shifted_power}W duration:{duration:.2f}s",flush=True)
