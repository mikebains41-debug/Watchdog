import subprocess,time

def get_energy_efficiency(gpu_id=0,duration=10):
    samples=[]
    start=time.time()
    while time.time()-start<duration:
        r=subprocess.run(["nvidia-smi",f"--id={gpu_id}","--query-gpu=power.draw,utilization.gpu","--format=csv,noheader,nounits"],capture_output=True,text=True)
        row=r.stdout.strip()
        power=float(row.split(",")[0].strip())
        util=float(row.split(",")[1].strip())
        samples.append((power,util))
        time.sleep(0.1)
    avg_power=sum(s[0] for s in samples)/len(samples)
    avg_util=sum(s[1] for s in samples)/len(samples)
    efficiency=avg_util/avg_power if avg_power>0 else 0
    print(f"# HELP gpu_energy_efficiency Compute utilization per watt")
    print(f"# TYPE gpu_energy_efficiency gauge")
    print(f"gpu_energy_efficiency{{gpu=\"{gpu_id}\"}} {efficiency:.6f}")
    print(f"gpu_power_draw_watts{{gpu=\"{gpu_id}\"}} {avg_power:.2f}")
    print(f"gpu_utilization_percent{{gpu=\"{gpu_id}\"}} {avg_util:.2f}")

if __name__=="__main__":
    get_energy_efficiency(0)
