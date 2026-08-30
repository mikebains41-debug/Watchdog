import json,os,subprocess,datetime

LEARNING_FILE = os.path.expanduser("~/gpu-core-private/security/gpu_baselines.json")

def load_baselines():
    try:
        with open(LEARNING_FILE,"r") as f:
            return json.load(f)
    except:
        return {}

def save_baseline(gpu_uuid, power_w):
    baselines = load_baselines()
    if gpu_uuid not in baselines:
        baselines[gpu_uuid] = {"readings":[],"learned_baseline":None}
    baselines[gpu_uuid]["readings"].append({"power_w":power_w,"timestamp":datetime.datetime.utcnow().isoformat()})
    readings = [r["power_w"] for r in baselines[gpu_uuid]["readings"][-30:]]
    baselines[gpu_uuid]["learned_baseline"] = round(min(readings),2)
    baselines[gpu_uuid]["sample_count"] = len(readings)
    with open(LEARNING_FILE,"w") as f:
        json.dump(baselines,f,indent=2)
    return baselines[gpu_uuid]["learned_baseline"]

def get_learned_baseline(gpu_uuid, fallback_w=67.0):
    baselines = load_baselines()
    if gpu_uuid in baselines and baselines[gpu_uuid]["learned_baseline"]:
        return baselines[gpu_uuid]["learned_baseline"]
    return fallback_w
