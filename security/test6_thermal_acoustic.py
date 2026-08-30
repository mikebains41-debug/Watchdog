import subprocess,time,torch,gc

def s(idx=0):
    r=subprocess.run(["nvidia-smi",f"--id={idx}","--query-gpu=power.draw,utilization.gpu,temperature.gpu","--format=csv,noheader,nounits"],capture_output=True,text=True)
    return r.stdout.strip()

def temp(row): return float(row.split(",")[2].strip())
def pw(row): return float(row.split(",")[0].strip())

print("=== TEST 6: Thermal and Acoustic Side Effects ===",flush=True)
print("PRE-SHIFT temp and power:",s(0),flush=True)
t=torch.randn(8000,8000,dtype=torch.float32,device="cuda:0")
torch.cuda.synchronize()
time.sleep(600)
del t;gc.collect();torch.cuda.empty_cache()
time.sleep(30)
print("POST-SHIFT temp and power:",s(0),flush=True)
print("Monitoring temperature and fan for 5 minutes ...",flush=True)
for i in range(10):
    time.sleep(30)
    r=subprocess.run(["nvidia-smi","--query-gpu=power.draw,temperature.gpu,fan.speed","--format=csv,noheader,nounits"],capture_output=True,text=True)
    print(f"T+{(i+1)*30}s: {r.stdout.strip()}",flush=True)
