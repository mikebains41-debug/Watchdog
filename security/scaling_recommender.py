import subprocess,json
from datetime import datetime

def recommend_scaling(architecture,ghost_power_w,baseline_w):
    delta=ghost_power_w-baseline_w
    rec={"architecture":architecture,"ghost_power_w":ghost_power_w,"baseline_w":baseline_w,"delta_w":delta,"timestamp":datetime.utcnow().isoformat()}
    if delta>50:
        rec["recommendation"]="horizontal"
        rec["reason"]=f"Permanent power shift of {delta:.1f}W detected. Use multiple smaller GPUs instead of vertical scaling."
    else:
        rec["recommendation"]="vertical"
        rec["reason"]="Power state within acceptable range."
    return rec

if __name__=="__main__":
    result=recommend_scaling("B300-SXM6-288GB",235.27,163.17)
    print(json.dumps(result,indent=2))
