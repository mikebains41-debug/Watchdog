import subprocess,time
from datetime import datetime

def s():
    r=subprocess.run(["nvidia-smi","--query-gpu=power.draw,utilization.gpu,clocks.current.sm,clocks.current.memory","--format=csv,noheader,nounits"],capture_output=True,text=True)
    return r.stdout.strip()

def pw(row): return float(row.split(",")[0].strip())
def sm(row): return float(row.split(",")[2].strip())
def mem(row): return float(row.split(",")[3].strip())

print("=== TEST 5: Recovery Attempts ===",flush=True)
print("Baseline:",s(),flush=True)
print("Attempting nvidia-smi -r ...",flush=True)
subprocess.run(["nvidia-smi","-r"])
time.sleep(5)
print("After reset:",s(),flush=True)
print("Attempting driver reload ...",flush=True)
subprocess.run(["rmmod","nvidia_uvm"],capture_output=True)
subprocess.run(["modprobe","nvidia_uvm"],capture_output=True)
time.sleep(5)
print("After driver reload:",s(),flush=True)
