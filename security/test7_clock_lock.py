import subprocess,time,torch,gc

def s():
    r=subprocess.run(["nvidia-smi","--query-gpu=power.draw,utilization.gpu,clocks.current.sm,clocks.current.memory","--format=csv,noheader,nounits"],capture_output=True,text=True)
    return r.stdout.strip()

print("=== TEST 7: Memory Clock Lock After Shift ===",flush=True)
print("PRE-SHIFT:",s(),flush=True)
t=torch.randn(8000,8000,dtype=torch.float32,device="cuda:0")
torch.cuda.synchronize()
time.sleep(600)
del t;gc.collect();torch.cuda.empty_cache()
time.sleep(30)
print("POST-SHIFT:",s(),flush=True)
print("Monitoring for 5 minutes ...",flush=True)
for i in range(10):
    time.sleep(30)
    print(f"T+{(i+1)*30}s:",s(),flush=True)
