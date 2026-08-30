"""
GPU Parallel Validator v1.0 - Private
Author: Manmohan (Mike) Bains
Contact: mikebains41@gmail.com
AgentShield parallel validation — ghost power, VRAM residual,
NVML blindness run simultaneously and cross-validate.
PRIVATE - DO NOT DISTRIBUTE
"""

import subprocess
import concurrent.futures
import datetime
import json

GHOST_DETECTION_WINDOW_SECONDS = 30
GHOST_ALERT_THRESHOLD_W = 20.0

ARCHITECTURE_BASELINES = {
    "A100": 67.0,
    "H100": 69.5,
    "H200": 79.0,
    "B200": 143.0,
    "B300": 179.0,
}

def detect_architecture():
    try:
        r = subprocess.run(["nvidia-smi","--query-gpu=name","--format=csv,noheader"],
                           capture_output=True,text=True,timeout=10)
        name = r.stdout.strip().upper()
        for arch in ARCHITECTURE_BASELINES:
            if arch in name:
                return arch, ARCHITECTURE_BASELINES[arch]
        return "UNKNOWN", 67.0
    except:
        return "UNKNOWN", 67.0

def read_gpu(gpu_index=0):
    try:
        cmd = ["nvidia-smi",f"--id={gpu_index}",
               "--query-gpu=power.draw,utilization.gpu,utilization.memory,"
               "memory.used,memory.total,clocks.current.memory",
               "--format=csv,noheader,nounits"]
        r = subprocess.run(cmd,capture_output=True,text=True,timeout=10)
        p = [x.strip() for x in r.stdout.strip().split(",")]
        return {
            "power_watts":float(p[0]),"util_gpu_pct":float(p[1]),
            "util_mem_pct":float(p[2]),"vram_used_mb":float(p[3]),
            "vram_total_mb":float(p[4]),"mem_clock_mhz":float(p[5]),
            "timestamp":datetime.datetime.utcnow().isoformat(),
            "gpu_index":gpu_index
        }
    except Exception as e:
        return {"error":str(e)}

def check_ghost_power(gpu_index,baseline_w):
    data = read_gpu(gpu_index)
    if "error" in data:
        return {"check":"ghost_power","result":"ERROR","detail":data["error"]}
    ghost = data["power_watts"] - baseline_w
    detected = ghost > GHOST_ALERT_THRESHOLD_W and data["util_gpu_pct"] == 0
    return {"check":"ghost_power","result":"DETECTED" if detected else "CLEAN",
            "power_w":data["power_watts"],"baseline_w":baseline_w,
            "ghost_overhead_w":round(ghost,2),"util_pct":data["util_gpu_pct"],
            "timestamp":data["timestamp"]}

def check_vram_residual(gpu_index):
    data = read_gpu(gpu_index)
    if "error" in data:
        return {"check":"vram_residual","result":"ERROR","detail":data["error"]}
    residual = data["util_mem_pct"] == 0 and data["vram_used_mb"] > 100
    return {"check":"vram_residual","result":"DETECTED" if residual else "CLEAN",
            "vram_used_mb":data["vram_used_mb"],"util_mem_pct":data["util_mem_pct"],
            "timestamp":data["timestamp"]}

def check_nvml_blindness(gpu_index):
    data = read_gpu(gpu_index)
    if "error" in data:
        return {"check":"nvml_blindness","result":"ERROR","detail":data["error"]}
    blind = data["power_watts"] > 100 and data["util_gpu_pct"] == 0
    return {"check":"nvml_blindness","result":"DETECTED" if blind else "CLEAN",
            "power_w":data["power_watts"],"util_pct":data["util_gpu_pct"],
            "mem_clock_mhz":data["mem_clock_mhz"],"timestamp":data["timestamp"]}

def run_parallel_validation(gpu_index=0):
    arch, baseline_w = detect_architecture()
    print(f"[PARALLEL VALIDATOR] GPU {gpu_index} — Architecture: {arch} — Baseline: {baseline_w}W")
    print(f"[PARALLEL VALIDATOR] Running 3 checks simultaneously...")
    with concurrent.futures.ThreadPoolExecutor(max_workers=3) as ex:
        f1 = ex.submit(check_ghost_power,gpu_index,baseline_w)
        f2 = ex.submit(check_vram_residual,gpu_index)
        f3 = ex.submit(check_nvml_blindness,gpu_index)
        results = [f1.result(),f2.result(),f3.result()]
    detections = [r for r in results if r["result"]=="DETECTED"]
    report = {
        "validator":"GPU Parallel Validator v1.0",
        "author":"Manmohan (Mike) Bains",
        "architecture":arch,"baseline_w":baseline_w,
        "gpu_index":gpu_index,
        "timestamp":datetime.datetime.utcnow().isoformat(),
        "checks_run":3,"detections":len(detections),
        "cross_validated":len(detections)>=2,
        "results":results
    }
    for r in results:
        print(f"  [{r['check'].upper()}] {r['result']}")
    if report["cross_validated"]:
        print(f"  CROSS-VALIDATED: {len(detections)}/3 checks confirmed anomaly")
    filename = f"parallel_validation_{datetime.datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.json"
    with open(filename,"w") as f:
        json.dump(report,f,indent=2)
    print(f"  Architecture: {arch} | Baseline: {baseline_w}W | Report: {filename}")
    return report

if __name__ == "__main__":
    run_parallel_validation(gpu_index=0)
