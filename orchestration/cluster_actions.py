# Author: Manmohan (Mike) Bains -- Watchdog
import subprocess, os, re
from datetime import datetime


def _valid_target(value, kind):
    """Return (ok, cleaned_or_reason).

    Found 2026-09-21: every action below shelled out with no validation, so
    slurm_evict_job(None) built `scancel None` and ran it -- on a real SLURM
    controller that reaches the cluster. These actions are destructive and
    human-gated; a null or malformed target must be refused BEFORE any
    subprocess call, not left for the external tool to interpret.

    kind 'node'   : non-empty token, no shell metacharacters
    kind 'jobid'  : digits only
    kind 'index'  : digits only (GPU index / NVLink link index)
    """
    if value is None:
        return False, "target is None"
    t = str(value).strip()
    if t == "" or t.lower() == "none":
        return False, "target is empty"
    if kind in ("jobid", "index"):
        if not t.isdigit():
            return False, "%s must be a non-negative integer, got %r" % (kind, value)
        return True, t
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*", t):
        return False, "node name has invalid characters: %r" % value
    return True, t


class ClusterOrchestration:
    def kubernetes_taint(self, node_name, key='watchdog.quarantine', value='true'):
        ok, node = _valid_target(node_name, 'node')
        if not ok:
            return 'REFUSED_NO_TARGET: kubernetes_taint needs a node name -- ' + node
        try:
            r = subprocess.run(['kubectl','taint','nodes',node,f'{key}={value}:NoSchedule'],capture_output=True,text=True,timeout=10)
            if r.returncode == 0: return 'TAINT_APPLIED'
            return f'TAINT_FAILED: {r.stderr[:100]}'
        except FileNotFoundError:
            return 'KUBECTL_NOT_AVAILABLE: kubectl not found'
        except Exception as e:
            return f'KUBECTL_ERROR: {e}'
    def slurm_evict_job(self, job_id):
        ok, jid = _valid_target(job_id, 'jobid')
        if not ok:
            return 'REFUSED_NO_TARGET: slurm_evict_job needs a job id -- ' + jid
        try:
            r = subprocess.run(['scancel', jid], capture_output=True, text=True, timeout=10)
            if r.returncode == 0: return 'JOB_EVICTED'
            return f'EVICT_FAILED: {r.stderr[:100]}'
        except FileNotFoundError:
            return 'SLURM_NOT_AVAILABLE: scancel not found'
        except Exception as e:
            return f'SLURM_ERROR: {e}'
    def nvlink_disable(self, gpu_index, link_index):
        okg, gi = _valid_target(gpu_index, 'index')
        okl, li = _valid_target(link_index, 'index')
        if not okg:
            return 'REFUSED_NO_TARGET: nvlink_disable needs a gpu index -- ' + gi
        if not okl:
            return 'REFUSED_NO_TARGET: nvlink_disable needs a link index -- ' + li
        try:
            r = subprocess.run(['nvidia-smi','nvlink','-d',li,'-i',gi],capture_output=True,text=True,timeout=10)
            if r.returncode == 0: return 'NVLINK_DISABLED'
            return f'NVLINK_DISABLE_FAILED: {r.stderr[:100]}'
        except FileNotFoundError:
            return 'NVLINK_NOT_AVAILABLE: nvidia-smi not found'
        except Exception as e:
            return f'NVLINK_ERROR: {e}'
