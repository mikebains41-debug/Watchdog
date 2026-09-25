import subprocess, time, sys, os
sys.path.insert(0, os.path.abspath('.'))
from detection.engines import ResidentGhostPowerDetector

DEV = 0
def smi():
    out = subprocess.check_output(["nvidia-smi","--query-gpu=index,power.draw,utilization.gpu,memory.used","--format=csv,noheader,nounits"], text=True)
    rows=[]
    for ln in out.strip().splitlines():
        i,p,u,m = [x.strip() for x in ln.split(",")]
        rows.append({"index":i,"power.draw":float(p),"utilization.gpu":float(u),"memory.used":float(m)})
    return rows

def sh(cmd):
    try: subprocess.run(cmd, check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except Exception: pass

try:
    import torch
    hold = torch.zeros(int(4e9//4), device=f"cuda:{DEV}")
    a = torch.randn(4096,4096,device=f"cuda:{DEV}")
    for _ in range(5): a = a @ a
    torch.cuda.synchronize()
    det = {r["index"]: ResidentGhostPowerDetector(min_samples=15, require_consecutive=5) for r in smi()}

    print("PHASE 1 loaded-idle, learn floor ~25s (must stay silent)")
    for _ in range(25):
        row = next(r for r in smi() if r["index"]==str(DEV))
        det[str(DEV)].update(row)
        time.sleep(1)
    print("  floor learned for GPU%d: %s W" % (DEV, det[str(DEV)].floor_w))

    print("PHASE 2 pin clocks high, no compute -> high power at 0%% util ~45s (must FIRE)")
    sh(["nvidia-smi","-i",str(DEV),"-lgc","1980,1980"])
    fired=[]
    for k in range(45):
        row = next(r for r in smi() if r["index"]==str(DEV))
        a = det[str(DEV)].update(row)
        tag = ""
        if a:
            fired.append(a); tag = " <== %s d=%.1f" % (a["type"], a.get("delta_w",0))
        if k % 5 == 0 or a:
            print("  P%2d: %.1fW util=%d%% mem=%.0f%s" % (k, row["power.draw"], row["utilization.gpu"], row["memory.used"], tag))
        time.sleep(1)
    sh(["nvidia-smi","-i",str(DEV),"-rgc"])

    hit = [a for a in fired if a["type"]=="GHOST_POWER_RESIDENT"]
    print("VERDICT:", "PASS -- GHOST_POWER_RESIDENT fired on live GPU%d"%DEV if hit
          else "MISSED -- see rows above: if util never hit 0 or power stayed near floor, induction failed, not the detector")
except Exception:
    import traceback; traceback.print_exc()
    subprocess.run(["nvidia-smi","-i",str(DEV),"-rgc"], check=False)
