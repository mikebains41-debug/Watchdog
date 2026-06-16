import subprocess, os
from datetime import datetime
class ClusterOrchestration:
    def kubernetes_taint(self, node_name, key='watchdog.quarantine', value='true'):
        try:
            r = subprocess.run(['kubectl','taint','nodes',node_name,f'{key}={value}:NoSchedule'],capture_output=True,text=True,timeout=10)
            if r.returncode == 0: return 'TAINT_APPLIED'
            return f'TAINT_FAILED: {r.stderr[:100]}'
        except Exception as e:
            return f'KUBECTL_NOT_AVAILABLE: {e}'
    def slurm_evict_job(self, job_id):
        try:
            r = subprocess.run(['scancel', str(job_id)], capture_output=True, text=True, timeout=10)
            if r.returncode == 0: return 'JOB_EVICTED'
            return f'EVICT_FAILED: {r.stderr[:100]}'
        except Exception as e:
            return f'SLURM_NOT_AVAILABLE: {e}'
    def nvlink_disable(self, gpu_index, link_index):
        try:
            r = subprocess.run(['nvidia-smi','nvlink','-d',str(link_index),'-i',str(gpu_index)],capture_output=True,text=True,timeout=10)
            if r.returncode == 0: return 'NVLINK_DISABLED'
            return f'NVLINK_DISABLE_FAILED: {r.stderr[:100]}'
        except Exception as e:
            return f'NVLINK_ERROR: {e}'
