import json,datetime,subprocess

def log_anomaly(anomaly_type,gpu_id,power_w,vram_mb=None,cert_id=None):
    entry={"timestamp":datetime.datetime.utcnow().isoformat(),"anomaly_type":anomaly_type,"gpu_id":gpu_id,"power_w":power_w,"vram_residual_mb":vram_mb,"certificate_id":cert_id,"nvml_utilization":0}
    with open("/tmp/gpu_optimizer_anomalies.jsonl","a") as f:
        f.write(json.dumps(entry)+"\n")
    print(f"LOGGED: {anomaly_type} GPU{gpu_id} {power_w}W cert={cert_id}")

if __name__=="__main__":
    log_anomaly("GHOST_POWER",0,163.17,628,"sa-522b61bd2d854e3796e9d47613065814")
    log_anomaly("PERMANENT_POWER_STATE_SHIFT",0,235.27,628,"sa-4227a1de5cf04b15ba814c8a78ca1f61")
