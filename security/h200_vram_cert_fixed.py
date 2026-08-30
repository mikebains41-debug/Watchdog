import torch,gc,subprocess,time
from datetime import datetime

def s():
    r=subprocess.run(["nvidia-smi","--query-gpu=memory.used,power.draw,utilization.gpu","--format=csv,noheader,nounits"],capture_output=True,text=True)
    return r.stdout.strip()

print("H200 TEST-06 FULL PROFILE (faithful reproduction)")
print("Manmohan Mike Bains")
print("Start:",datetime.now().isoformat())

log=[]
def sample(phase):
    ts=datetime.now().isoformat()
    raw=s()
    print(phase,ts,raw,flush=True)
    log.append((phase,ts,raw))

t1=torch.randn(8000,8000,dtype=torch.float32,device="cuda:0")
torch.cuda.synchronize()
start=time.time()
while time.time()-start<240:
    sample("FP32");time.sleep(0.1)

t2=torch.randn(8000,8000,dtype=torch.float16,device="cuda:0")
torch.cuda.synchronize()
start=time.time()
while time.time()-start<240:
    sample("FP16");time.sleep(0.1)

del t1,t2;gc.collect();torch.cuda.empty_cache()
start=time.time()
while time.time()-start<240:
    sample("EXIT");time.sleep(0.1)

start=time.time()
while time.time()-start<240:
    sample("SETTLE");time.sleep(0.1)

print("\n=== DONE ===")
