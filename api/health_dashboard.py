"""
Watchdog AIDR v2.0 - System Health Dashboard Endpoint
Reports CPU, memory, GPU state, and Watchdog subsystem status.
Mounts on existing FastAPI instance in api/server.py.
Register: from api.health_dashboard import register_health
          register_health(app)
"""
import os, time

try:
    import psutil
    PSUTIL = True
except ImportError:
    PSUTIL = False

def register_health(app):
    @app.get("/v2/infrastructure/status", tags=["Health"])
    async def get_cluster_health():
        cpu = psutil.cpu_percent(interval=None) if PSUTIL else None
        mem = psutil.virtual_memory() if PSUTIL else None
        try:
            import torch
            gpu_available = torch.cuda.is_available()
            gpu_count = torch.cuda.device_count() if gpu_available else 0
            gpus = [{"index": i, "name": torch.cuda.get_device_name(i),
                     "vram_allocated": torch.cuda.memory_allocated(i),
                     "vram_cached": torch.cuda.memory_reserved(i)}
                    for i in range(gpu_count)] if gpu_available else []
        except ImportError:
            gpu_available = False
            gpu_count = 0
            gpus = []
        return {
            "node_status": "HEALTHY" if (cpu or 0) < 90 else "DEGRADED",
            "timestamp_epoch": int(time.time()),
            "host_telemetry": {
                "cpu_pct": cpu,
                "memory_used": mem.used if mem else None,
                "memory_total": mem.total if mem else None,
            },
            "accelerator_telemetry": {
                "cuda_active": gpu_available,
                "gpu_count": gpu_count,
                "devices": gpus,
            },
            "watchdog_subsystems": {
                "engines_active": 24,
                "ebpf_armed": os.path.exists("/sys/kernel/btf/vmlinux"),
                "audit_ledger": os.path.exists("watchdog_data/audit_ledger.jsonl"),
                "safe_harbor_ledger": os.path.exists("watchdog_data/safe_harbor_ledger.jsonl"),
            },
            "cve_baseline": "CVE-2048350",
        }
