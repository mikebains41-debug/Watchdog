import subprocess,time,torch,gc,multiprocessing,os,signal

def s(idx=0):
    r=subprocess.run(["nvidia-smi",f"--id={idx}","--query-gpu=power.draw,utilization.gpu","--format=csv,noheader,nounits"],capture_output=True,text=True)
    return r.stdout.strip()

def pw(row): return float(row.split(",")[0].strip())

# TENANT A: trigger shift
def tenant_a():
    import torch,time,gc
    t=torch.randn(8000,8000,dtype=torch.float32,device="cuda:0")
    torch.cuda.synchronize()
    time.sleep(600)
    del t;gc.collect();torch.cuda.empty_cache()
    print("TENANT A: exited",flush=True)

# TENANT B: monitor power and detect signal
def tenant_b():
    import subprocess,time
    def s():
        r=subprocess.run(["nvidia-smi","--query-gpu=power.draw","--format=csv,noheader,nounits"],capture_output=True,text=True)
        return float(r.stdout.strip())
    baseline=s()
    print(f"TENANT B: baseline {baseline}W",flush=True)
    time.sleep(650)
    post=s()
    print(f"TENANT B: post {post}W",flush=True)
    delta=post-baseline
    bit="1" if delta>20 else "0"
    print(f"TENANT B: delta {delta:.2f}W signal bit={bit}",flush=True)

print("=== TEST 1: Covert Channel ===",flush=True)
p1=multiprocessing.Process(target=tenant_a)
p2=multiprocessing.Process(target=tenant_b)
p1.start();p2.start()
p1.join();p2.join()
