import subprocess,time,torch,gc

# NOTE: Test 4 requires MIG enabled on bare metal with 2 partitions
# CUDA_VISIBLE_DEVICES must be set to specific MIG UUIDs
# Run partition A first, then partition B separately

def s():
    r=subprocess.run(["nvidia-smi","--query-gpu=power.draw,utilization.gpu","--format=csv,noheader,nounits"],capture_output=True,text=True)
    return r.stdout.strip()

def pw(row): return float(row.split(",")[0].strip())

import sys
phase=sys.argv[1] if len(sys.argv)>1 else "a"

if phase=="a":
    print("=== TEST 4: MIG Partition A - Triggering shift ===",flush=True)
    print("Baseline:",s(),flush=True)
    t=torch.randn(8000,8000,dtype=torch.float32,device="cuda:0")
    torch.cuda.synchronize()
    time.sleep(600)
    del t;gc.collect();torch.cuda.empty_cache()
    print("Shift triggered. Partition A exiting.",flush=True)
    print("POST-SHIFT:",s(),flush=True)
elif phase=="b":
    print("=== TEST 4: MIG Partition B - Checking leakage ===",flush=True)
    for i in range(10):
        time.sleep(30)
        print(f"T+{(i+1)*30}s partition B power:",s(),flush=True)
