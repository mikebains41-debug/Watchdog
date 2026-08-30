#!/usr/bin/env python3
"""
Phase 4 Hardware Fingerprint + Full Metrics Check
Run once before any test to capture complete hardware identity and health snapshot.
Author: Manmohan Mike Bains CVE 2048350
"""
import json, os, time
from datetime import datetime

#pynvml removed
#handle removed
os.makedirs("./results/metadata", exist_ok=True)

print("=== PHASE 4 HARDWARE FINGERPRINT ===")
print("Author: Manmohan Mike Bains CVE 2048350")
print("Start:", datetime.now().isoformat())

def safe(fn, *args, default="unavailable"):
    try:
        return fn(*args)
    except Exception:
        return default

# Hardware Identity
name = safe(pynvml.nvmlDeviceGetName, h)
serial = safe(pynvml.nvmlDeviceGetSerial, h)
part = safe(pynvml.nvmlDeviceGetBoardPartNumber, h)
uuid = safe(pynvml.nvmlDeviceGetUUID, h)
driver = safe(pynvml.nvmlSystemGetDriverVersion)
cuda = safe(pynvml.nvmlSystemGetCudaDriverVersion)
compute_mode = safe(pynvml.nvmlDeviceGetComputeMode, h)
virt_mode = safe(pynvml.nvmlDeviceGetVirtualizationMode, h)
driver_model = safe(pynvml.nvmlDeviceGetDriverModel, h)

# Power & Limits
power_w = safe(lambda: pynvml.nvmlDeviceGetPowerUsage(h)/1000.0)
power_limit = safe(lambda: pynvml.nvmlDeviceGetEnforcedPowerLimit(h)/1000.0)
power_default = safe(lambda: pynvml.nvmlDeviceGetPowerManagementDefaultLimit(h)/1000.0)
power_mgmt_mode = safe(pynvml.nvmlDeviceGetPowerManagementMode, h)
total_energy_mj = safe(pynvml.nvmlDeviceGetTotalEnergyConsumption, h)

# Thermal
temp_gpu = safe(pynvml.nvmlDeviceGetTemperature, h.NVML_TEMPERATURE_GPU)
fan_speed = safe(pynvml.nvmlDeviceGetFanSpeed, h)

# Clocks
mem_clock = safe(pynvml.nvmlDeviceGetClockInfo, h.NVML_CLOCK_MEM)
sm_clock = safe(pynvml.nvmlDeviceGetClockInfo, h.NVML_CLOCK_SM)
max_mem_clock = safe(pynvml.nvmlDeviceGetMaxClockInfo, h.NVML_CLOCK_MEM)
max_sm_clock = safe(pynvml.nvmlDeviceGetMaxClockInfo, h.NVML_CLOCK_SM)
pstate = safe(pynvml.nvmlDeviceGetPerformanceState, h)

# Memory
mem = safe(pynvml.nvmlDeviceGetMemoryInfo, h)
vram_total = safe(lambda: mem.total//1024//1024) if mem != "unavailable" else "unavailable"
vram_used = safe(lambda: mem.used//1024//1024) if mem != "unavailable" else "unavailable"
vram_free = safe(lambda: mem.free//1024//1024) if mem != "unavailable" else "unavailable"
bar1 = safe(pynvml.nvmlDeviceGetBAR1MemoryInfo, h)
bar1_used = safe(lambda: bar1.bar1Used//1024//1024) if bar1 != "unavailable" else "unavailable"
bar1_total = safe(lambda: bar1.bar1Total//1024//1024) if bar1 != "unavailable" else "unavailable"

# Utilization
util = safe(pynvml.nvmlDeviceGetUtilizationRates, h)
gpu_util = safe(lambda: util.gpu) if util != "unavailable" else "unavailable"
mem_util = safe(lambda: util.memory) if util != "unavailable" else "unavailable"

# ECC Errors
ecc_sbe = safe(pynvml.nvmlDeviceGetMemoryErrorCounter, h,
    pynvml.NVML_MEMORY_ERROR_TYPE_CORRECTED,
    pynvml.NVML_AGGREGATE_ECC)
ecc_dbe = safe(pynvml.nvmlDeviceGetMemoryErrorCounter, h,
    pynvml.NVML_MEMORY_ERROR_TYPE_UNCORRECTED,
    pynvml.NVML_AGGREGATE_ECC)

# PCIe
pcie_gen = safe(pynvml.nvmlDeviceGetCurrPcieLinkGeneration, h)
pcie_width = safe(pynvml.nvmlDeviceGetCurrPcieLinkWidth, h)
pcie_replay = safe(pynvml.nvmlDeviceGetPcieReplayCounter, h)

# Encoder / Decoder
enc_util = safe(lambda: pynvml.nvmlDeviceGetEncoderUtilization(h)[0])
dec_util = safe(lambda: pynvml.nvmlDeviceGetDecoderUtilization(h)[0])

# Running Processes
try:
    procs = pynvml.nvmlDeviceGetComputeRunningProcesses(h)
    process_list = [{"pid": p.pid, "vram_mb": p.usedGpuMemory//1024//1024 if p.usedGpuMemory else 0} for p in procs]
except Exception:
    process_list = []

# Throttling
throttle_reasons = safe(pynvml.nvmlDeviceGetCurrentClocksThrottleReasons, h)

# Build fingerprint
fingerprint = {
    "timestamp": datetime.now().isoformat(),
    "cve": "2048350",
    "hardware_identity": {
        "name": name,
        "serial": serial,
        "board_part_number": part,
        "uuid": uuid,
        "driver_version": driver,
        "cuda_driver_version": cuda,
        "compute_mode": str(compute_mode),
        "virtualization_mode": str(virt_mode),
        "driver_model": str(driver_model)
    },
    "power": {
        "current_w": power_w,
        "limit_enforced_w": power_limit,
        "limit_default_w": power_default,
        "management_mode": str(power_mgmt_mode),
        "total_energy_mj": total_energy_mj
    },
    "thermal": {
        "gpu_temp_c": temp_gpu,
        "fan_speed_pct": fan_speed
    },
    "clocks": {
        "mem_clock_mhz": mem_clock,
        "sm_clock_mhz": sm_clock,
        "max_mem_clock_mhz": max_mem_clock,
        "max_sm_clock_mhz": max_sm_clock,
        "pstate": str(pstate)
    },
    "memory": {
        "vram_total_mb": vram_total,
        "vram_used_mb": vram_used,
        "vram_free_mb": vram_free,
        "bar1_used_mb": bar1_used,
        "bar1_total_mb": bar1_total
    },
    "utilization": {
        "gpu_util_pct": gpu_util,
        "mem_util_pct": mem_util,
        "encoder_util_pct": enc_util,
        "decoder_util_pct": dec_util
    },
    "ecc": {
        "correctable_sbe": ecc_sbe,
        "uncorrectable_dbe": ecc_dbe
    },
    "pcie": {
        "link_gen": pcie_gen,
        "link_width": pcie_width,
        "replay_counter": pcie_replay
    },
    "processes": process_list,
    "throttle_reasons": str(throttle_reasons)
}

# Save
out_path = "./results/metadata/hardware_fingerprint.json"
with open(out_path, "w") as f:
    json.dump(fingerprint, f, indent=2)

print(json.dumps(fingerprint, indent=2))
print(f"\nSaved to {out_path}")
print("=== FINGERPRINT COMPLETE ===")
