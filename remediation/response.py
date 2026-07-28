# Author: Manmohan (Mike) Bains -- Watchdog
import os, subprocess, time, json
from datetime import datetime
from orchestration.cluster_actions import ClusterOrchestration
REMEDIATION_LOG = 'watchdog_data/remediation.log'
def log_action(action, result, alert):
    os.makedirs('watchdog_data', exist_ok=True)
    entry = {'timestamp':datetime.now().isoformat(),'action':action,'result':result,'alert_type':alert.get('type'),'gpu':alert.get('gpu')}
    with open(REMEDIATION_LOG,'a') as f: f.write(json.dumps(entry)+'\n')
    print(f"[REMEDIATION] {action} → {result}")


class RemediationEngine:
    """
    FIXED vs. original (see git history):
      - VRAM_RESIDUAL's action was 'clear_vram', calling
        torch.cuda.empty_cache() in WATCHDOG'S OWN process. This could
        never have worked: VRAMResidualDetector fires on memory left by a
        PID that has ALREADY EXITED. There is no live process left to
        release anything from, and Watchdog itself doesn't hold that
        memory -- empty_cache() only releases the CALLING process's own
        allocator cache. It returned 'VRAM_CLEARED' as if it succeeded
        regardless of whether anything actually happened.

        Replaced with 'gpu_memory_reset', gated into HUMAN_REQUIRED since
        the only real way to reclaim orphaned VRAM is a GPU-level reset,
        which is disruptive to every other tenant sharing that GPU and
        needs elevated privileges -- not something to auto-fire.

      - _kill_gpu_processes killed EVERY compute process on the GPU, with
        no way to distinguish the actual offender from an innocent job
        sharing it, because none of the alert-producing detectors mapped
        to kill_process (DMAAttackDetector, SequentialVRAMReadDetector,
        AgentOrchestrationAnomalyDetector) identify a specific PID -- they
        detect a GPU-level pattern, not a process.

        Rather than guess and kill everyone, this now REFUSES to act when
        no specific PID is available in the alert, and only targets a
        named process when one actually is provided (alert['pid'] or
        alert['exited_pid']).

    ADDED (prediction-to-remediation bridge): explicit entries for the
    5-agent prediction layer's alert types, plus MigrationRecommended.
    None of these are new behavior -- every prediction alert type was
    ALREADY reaching this class's handle() method via on_alert in
    main(), and ALREADY fell through to the default ['log_only'] since
    it wasn't in this dict. This makes that safe default explicit and
    auditable instead of accidental. No new action type was invented --
    even the REAL, confirmed GHOST_POWER detection (not the prediction)
    only ever maps to log_only; predictions get the same treatment as
    their corresponding detections, not a more aggressive one.
    """
    TYPE_ACTIONS = {'GHOST_POWER':['log_only'],'VRAM_RESIDUAL':['log_only','gpu_memory_reset'],'DMA_ATTACK':['kill_process'],'SEQUENTIAL_VRAM_READ':['kill_process'],'MODEL_MUTATION':['kill_process','quarantine_partition'],'AGENT_ORCHESTRATION_ANOMALY':['kill_process'],'CLOCK_GLITCH':['log_only'],'LASER_INJECTION':['log_only'],'MIG_PARTITION_DESYNC':['quarantine_partition'],
                     'GHOST_POWER_PREDICTED':['log_only'],'THERMAL_THROTTLE_PREDICTED':['log_only'],'TENANT_ISOLATION_RISK':['log_only'],'CEI_DEGRADATION_PREDICTED':['log_only'],'EU_AI_ACT_COMPLIANCE_RISK':['log_only'],'MIGRATION_RECOMMENDED':['log_only']}
    HUMAN_REQUIRED = ['pcie_bus_reset','power_cycle','firmware_rollback','gpu_memory_reset','kubernetes_taint','slurm_evict_job','nvlink_disable']

    def __init__(self, auto_remediate=False, require_human=True):
        self.auto_remediate = auto_remediate
        self.require_human = require_human
        self.action_count = 0
        self.cluster = ClusterOrchestration()

    def handle(self, alert):
        alert_type = alert.get('type','UNKNOWN')
        actions = self.TYPE_ACTIONS.get(alert_type,['log_only'])
        for action in actions:
            if action in self.HUMAN_REQUIRED and self.require_human:
                log_action(action,'SKIPPED_HUMAN_REQUIRED',alert); continue
            if not self.auto_remediate and action != 'log_only':
                log_action(action,'SKIPPED_AUTO_DISABLED',alert); continue
            result = self._execute(action, alert.get('gpu',0), alert)
            log_action(action, result, alert)
            self.action_count += 1

    def _execute(self, action, gpu, alert):
        try:
            if action == 'log_only': return 'LOGGED'
            elif action == 'kill_process': return self._kill_gpu_processes(gpu, alert)
            elif action == 'gpu_memory_reset': return self._gpu_memory_reset(gpu)
            elif action == 'quarantine_partition': return self._quarantine_mig(gpu)
            elif action == 'kubernetes_taint': return self._kubernetes_taint(alert)
            elif action == 'slurm_evict_job': return self._slurm_evict_job(alert)
            elif action == 'nvlink_disable': return self._nvlink_disable(gpu, alert)
            else: return f'UNKNOWN_{action}'
        except Exception as e: return f'ERROR:{e}'

    def _kill_gpu_processes(self, gpu, alert):
        """
        FIXED: only kills a SPECIFIC targeted PID if the alert names one.
        None of the current kill_process-mapped alert types provide one
        yet -- so as of this fix, this always refuses, which is correct:
        a safe refusal is better than a blind kill of everyone on the GPU.
        If a future detector adds pid/exited_pid to its alert dict, this
        path activates automatically and targets only that process.
        """
        target_pid = alert.get('pid') or alert.get('exited_pid')
        try:
            r = subprocess.run(['nvidia-smi','--query-compute-apps=pid','--format=csv,noheader',f'--id={gpu}'],capture_output=True,text=True,timeout=5)
            pids = [p.strip() for p in r.stdout.strip().split('\n') if p.strip()]
            if not pids: return 'NO_PROCESSES'
            if target_pid is None:
                return (f'REFUSED_NO_TARGET_PID_IN_ALERT -- {len(pids)} '
                        f'process(es) present, would have been killed '
                        f'blindly under the old behavior')
            target_pid = str(target_pid)
            if target_pid not in pids:
                return f'TARGET_PID_{target_pid}_NOT_FOUND_ON_GPU_{gpu}'
            try: subprocess.run(['kill','-9',target_pid],timeout=3)
            except: pass
            return f'KILLED_TARGETED_PID_{target_pid}'
        except Exception as e: return f'KILL_FAILED:{e}'

    def _gpu_memory_reset(self, gpu):
        """
        Gated into HUMAN_REQUIRED (see class docstring) -- this only runs
        at all if require_human=False was explicitly chosen. Deliberately
        does not attempt an actual nvidia-smi --gpu-reset call: that is a
        genuinely disruptive, privileged action never verified against
        real hardware in this codebase, matching the same honest
        placeholder pattern _quarantine_mig() already uses below for a
        similarly dangerous action.
        """
        return ('GPU_MEMORY_RESET_REQUIRES_HUMAN_APPROVAL -- orphaned VRAM '
                'from an already-exited process cannot be reclaimed from a '
                'third-party process; only a privileged GPU reset can, and '
                'that disrupts every other tenant on the GPU')

    def _quarantine_mig(self, gpu):
        return 'MIG_QUARANTINE_REQUIRES_HUMAN_APPROVAL'

    def _kubernetes_taint(self, alert):
        """
        Requires alert['node_name']. No current detector provides this
        field, so this always refuses today -- same honest-refusal
        pattern as _kill_gpu_processes above, not a bug.
        """
        node_name = alert.get('node_name')
        if not node_name:
            return 'REFUSED_NO_TARGET_NODE_IN_ALERT'
        return self.cluster.kubernetes_taint(node_name)

    def _slurm_evict_job(self, alert):
        """
        Requires alert['job_id']. No current detector provides this
        field, so this always refuses today.
        """
        job_id = alert.get('job_id')
        if not job_id:
            return 'REFUSED_NO_TARGET_JOB_ID_IN_ALERT'
        return self.cluster.slurm_evict_job(job_id)

    def _nvlink_disable(self, gpu, alert):
        """
        Requires alert['link_index']. NVLinkContentionDetector reports
        aggregate tx/rx across all links on a GPU, not which specific
        link -- so it cannot supply this field as currently built. This
        always refuses today.
        """
        link_index = alert.get('link_index')
        if link_index is None:
            return 'REFUSED_NO_TARGET_LINK_INDEX_IN_ALERT'
        return self.cluster.nvlink_disable(gpu, link_index)
