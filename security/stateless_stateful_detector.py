import subprocess

def get_workload_type(gpu_id=0):
    r=subprocess.run(["nvidia-smi",f"--id={gpu_id}","--query-compute-apps=pid,used_memory","--format=csv,noheader,nounits"],capture_output=True,text=True)
    lines=[l for l in r.stdout.strip().split("\n") if l]
    if not lines:
        return "idle"
    total_mem=sum(float(l.split(",")[1].strip()) for l in lines if len(l.split(","))>1)
    return "stateful" if total_mem>10000 else "stateless"

def get_threshold(workload_type):
    return {"idle":20,"stateless":30,"stateful":50}.get(workload_type,20)

if __name__=="__main__":
    wtype=get_workload_type()
    thresh=get_threshold(wtype)
    print(f"Workload type: {wtype} | Ghost power threshold: {thresh}W")
