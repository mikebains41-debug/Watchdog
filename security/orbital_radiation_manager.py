#!/usr/bin/env python3
# Orbital Radiation Management Module
# Tracks radiation-induced GPU degradation over mission lifetime
# Differentiates radiation events from ghost power
# Phase 3 — Orbital GPU Optimizer
#
# Key radiation facts for LEO B300 deployments:
# - Single Event Upsets caused by cosmic rays
# - ECC corrected errors normal — uncorrected = critical
# - 95% radiation availability baseline
# - GPU degradation accumulates over mission lifetime
# - Cannot mechanically repair in orbit

import subprocess,json,time
from datetime import datetime

ECC_CORRECTED_WARNING=10
ECC_CORRECTED_CRITICAL=50
ECC_UNCORRECTED_CRITICAL=1
GHOST_POWER_THRESHOLD_W=90.0
RADIATION_GHOST_ECC_THRESHOLD=5
MISSION_START=datetime.utcnow().isoformat()

degradation_log=[]
total_ecc_corrected={}
total_ecc_uncorrected={}

def get_radiation_metrics():
    r=subprocess.run(["nvidia-smi","--query-gpu=index,power.draw,utilization.gpu,ecc.errors.corrected.volatile.total,ecc.errors.uncorrected.volatile.total,ecc.errors.corrected.aggregate.total,temperature.gpu","--format=csv,noheader,nounits"],capture_output=True,text=True)
    metrics=[]
    for line in r.stdout.strip().split("\n"):
        if not line: continue
        p=[x.strip() for x in line.split(",")]
        gpu_id=int(p[0])
        ecc_corr_vol=int(p[3]) if p[3].isdigit() else 0
        ecc_uncorr_vol=int(p[4]) if p[4].isdigit() else 0
        ecc_corr_agg=int(p[5]) if p[5].isdigit() else 0
        if gpu_id not in total_ecc_corrected:
            total_ecc_corrected[gpu_id]=0
            total_ecc_uncorrected[gpu_id]=0
        total_ecc_corrected[gpu_id]+=ecc_corr_vol
        total_ecc_uncorrected[gpu_id]+=ecc_uncorr_vol
        metrics.append({
            "gpu_id":gpu_id,
            "power_watts":float(p[1]),
            "utilization":float(p[2]),
            "ecc_corrected_volatile":ecc_corr_vol,
            "ecc_uncorrected_volatile":ecc_uncorr_vol,
            "ecc_corrected_aggregate":ecc_corr_agg,
            "ecc_corrected_mission_total":total_ecc_corrected[gpu_id],
            "ecc_uncorrected_mission_total":total_ecc_uncorrected[gpu_id],
            "temperature_c":float(p[6]) if len(p)>6 else 0
        })
    return metrics

def classify_anomaly(g):
    power=g["power_watts"]
    util=g["utilization"]
    ecc_corr=g["ecc_corrected_volatile"]
    ecc_uncorr=g["ecc_uncorrected_volatile"]
    anomalies=[]
    if ecc_uncorr>ECC_UNCORRECTED_CRITICAL:
        anomalies.append({"type":"RADIATION_DAMAGE_CRITICAL","severity":"CRITICAL","detail":f"{ecc_uncorr} uncorrectable ECC errors — potential permanent damage","action":"ISOLATE_GPU"})
        print(f"[CRITICAL] GPU{g["gpu_id"]} RADIATION DAMAGE — {ecc_uncorr} uncorrectable errors",flush=True)
    if util==0 and power>GHOST_POWER_THRESHOLD_W:
        if ecc_corr>RADIATION_GHOST_ECC_THRESHOLD:
            anomalies.append({"type":"RADIATION_INDUCED_POWER_ANOMALY","severity":"MEDIUM","detail":f"Power anomaly with {ecc_corr} ECC errors — radiation event not ghost power","action":"MONITOR"})
            print(f"[RADIATION EVENT] GPU{g["gpu_id"]} {power}W — radiation induced not ghost power",flush=True)
        else:
            anomalies.append({"type":"ORBITAL_GHOST_POWER","severity":"HIGH","detail":f"Ghost power {power}W at 0% util — confirmed PERMANENT_POWER_STATE_SHIFT","action":"LOG_AND_REPORT"})
            print(f"[ORBITAL GHOST] GPU{g["gpu_id"]} {power}W @ 0% util — PERMANENT_POWER_STATE_SHIFT confirmed",flush=True)
    if ecc_corr>ECC_CORRECTED_CRITICAL:
        anomalies.append({"type":"HIGH_RADIATION_ZONE","severity":"HIGH","detail":f"{ecc_corr} corrected ECC errors — high radiation environment","action":"INCREASE_REDUNDANCY"})
    elif ecc_corr>ECC_CORRECTED_WARNING:
        anomalies.append({"type":"ELEVATED_RADIATION","severity":"MEDIUM","detail":f"{ecc_corr} corrected ECC errors — elevated radiation","action":"MONITOR_CLOSELY"})
    return anomalies

def calculate_radiation_availability(gpu_id):
    total=total_ecc_corrected.get(gpu_id,0)+total_ecc_uncorrected.get(gpu_id,0)
    if total==0:
        return 1.0
    availability=max(0.0,1.0-(total_ecc_uncorrected.get(gpu_id,0)/max(total,1))*0.05)
    return round(availability,4)

def run_radiation_monitor(output_file="radiation_log.jsonl"):
    print("=== GPU Optimizer Radiation Management Module ===",flush=True)
    print(f"Mission start: {MISSION_START}",flush=True)
    while True:
        metrics=get_radiation_metrics()
        for g in metrics:
            anomalies=classify_anomaly(g)
            availability=calculate_radiation_availability(g["gpu_id"])
            entry={
                "timestamp":datetime.utcnow().isoformat(),
                "gpu_id":g["gpu_id"],
                "radiation_availability":availability,
                "ecc_corrected_volatile":g["ecc_corrected_volatile"],
                "ecc_uncorrected_volatile":g["ecc_uncorrected_volatile"],
                "ecc_mission_total_corrected":g["ecc_corrected_mission_total"],
                "ecc_mission_total_uncorrected":g["ecc_uncorrected_mission_total"],
                "temperature_c":g["temperature_c"],
                "anomalies":anomalies
            }
            if anomalies:
                with open(output_file,"a") as f:
                    f.write(json.dumps(entry)+"\n")
        time.sleep(0.01)

if __name__=="__main__":
    run_radiation_monitor()
