# Author: Manmohan (Mike) Bains -- Watchdog
import subprocess, os, re
from datetime import datetime, timezone

# Adversarial review 2026-09-25 (Watchdog two-engine, Engine 2). Three findings,
# all PROPOSED -- verified by tests/test_cluster_actions_hardening.py:
#   F1 MEDIUM  kubernetes_taint key/value reached the kubectl arg unvalidated
#              (safe defaults, but any caller passing telemetry-derived values
#              had no guard). Now validated with the same token rule as node.
#   F2 LOW     _valid_target had no length bound. Capped at 253 (K8s node limit).
#   F3 LOW     destructive human-gated actions left no audit record. Each attempt
#              and result now appended to an audit log.
# Injection surface was already closed (arg lists, no shell=True, isdigit for
# ids); these are hardening, not a fix for a live exploit.

_AUDIT_PATH = os.environ.get("WATCHDOG_CLUSTER_AUDIT", "watchdog_data/cluster_actions.log")
_MAX_TOKEN = 253  # Kubernetes node-name / label limit; also bounds every token


def _audit(action, target, result):
    """Append-only record of every destructive action attempt and its result.
    Best-effort: never let a logging failure block or crash the action path."""
    try:
        os.makedirs(os.path.dirname(_AUDIT_PATH), exist_ok=True)
        line = "%s\t%s\t%s\t%s\n" % (datetime.now(timezone.utc).isoformat(), action,
                                     target, str(result)[:200].replace("\n", " "))
        with open(_AUDIT_PATH, "a") as fh:
            fh.write(line)
    except OSError:
        pass
    return result


def _valid_target(value, kind):
    """Return (ok, cleaned_or_reason).

    Found 2026-09-21: every action below shelled out with no validation, so
    slurm_evict_job(None) built `scancel None` and ran it -- on a real SLURM
    controller that reaches the cluster. These actions are destructive and
    human-gated; a null or malformed target must be refused BEFORE any
    subprocess call, not left for the external tool to interpret.

    kind 'node'   : non-empty token, no shell metacharacters, length-bounded
    kind 'jobid'  : digits only
    kind 'index'  : digits only (GPU index / NVLink link index)
    kind 'label'  : k8s taint key or value token (F1) -- letters/digits/._-/ and
                    empty allowed (an empty taint value is legal)
    """
    if value is None:
        return False, "target is None"
    t = str(value).strip()
    if kind == "label":
        # taint key/value: bounded, safe token set; empty value is valid k8s
        if len(t) > _MAX_TOKEN:
            return False, "label too long (%d > %d)" % (len(t), _MAX_TOKEN)
        if t != "" and not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._/-]*", t):
            return False, "label has invalid characters: %r" % value
        return True, t
    if t == "" or t.lower() == "none":
        return False, "target is empty"
    if len(t) > _MAX_TOKEN:
        return False, "%s too long (%d > %d)" % (kind, len(t), _MAX_TOKEN)
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
            return _audit('kubernetes_taint', node_name, 'REFUSED_NO_TARGET: needs a node name -- ' + node)
        # F1: validate key and value before they reach the kubectl argument
        okk, k = _valid_target(key, 'label')
        if not okk:
            return _audit('kubernetes_taint', node_name, 'REFUSED_BAD_LABEL: key -- ' + k)
        okv, v = _valid_target(value, 'label')
        if not okv:
            return _audit('kubernetes_taint', node_name, 'REFUSED_BAD_LABEL: value -- ' + v)
        try:
            r = subprocess.run(['kubectl','taint','nodes',node,f'{k}={v}:NoSchedule'],capture_output=True,text=True,timeout=10)
            res = 'TAINT_APPLIED' if r.returncode == 0 else f'TAINT_FAILED: {r.stderr[:100]}'
            return _audit('kubernetes_taint', node, res)
        except FileNotFoundError:
            return _audit('kubernetes_taint', node, 'KUBECTL_NOT_AVAILABLE: kubectl not found')
        except Exception as e:
            return _audit('kubernetes_taint', node, f'KUBECTL_ERROR: {e}')

    def slurm_evict_job(self, job_id):
        ok, jid = _valid_target(job_id, 'jobid')
        if not ok:
            return _audit('slurm_evict_job', job_id, 'REFUSED_NO_TARGET: needs a job id -- ' + jid)
        try:
            r = subprocess.run(['scancel', jid], capture_output=True, text=True, timeout=10)
            res = 'JOB_EVICTED' if r.returncode == 0 else f'EVICT_FAILED: {r.stderr[:100]}'
            return _audit('slurm_evict_job', jid, res)
        except FileNotFoundError:
            return _audit('slurm_evict_job', jid, 'SLURM_NOT_AVAILABLE: scancel not found')
        except Exception as e:
            return _audit('slurm_evict_job', jid, f'SLURM_ERROR: {e}')

    def nvlink_disable(self, gpu_index, link_index):
        okg, gi = _valid_target(gpu_index, 'index')
        okl, li = _valid_target(link_index, 'index')
        if not okg:
            return _audit('nvlink_disable', gpu_index, 'REFUSED_NO_TARGET: needs a gpu index -- ' + gi)
        if not okl:
            return _audit('nvlink_disable', link_index, 'REFUSED_NO_TARGET: needs a link index -- ' + li)
        try:
            r = subprocess.run(['nvidia-smi','nvlink','-d',li,'-i',gi],capture_output=True,text=True,timeout=10)
            res = 'NVLINK_DISABLED' if r.returncode == 0 else f'NVLINK_DISABLE_FAILED: {r.stderr[:100]}'
            return _audit('nvlink_disable', '%s/%s' % (gi, li), res)
        except FileNotFoundError:
            return _audit('nvlink_disable', gi, 'NVLINK_NOT_AVAILABLE: nvidia-smi not found')
        except Exception as e:
            return _audit('nvlink_disable', gi, f'NVLINK_ERROR: {e}')
