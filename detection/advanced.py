# Author: Manmohan (Mike) Bains -- Watchdog AIDR
import time, collections, hashlib, subprocess
from datetime import datetime
from detection._shared import _EventState, _f


class MemoryActivationAnomalyDetector:
    """
    FIXED vs. original (was RowhammerProxyDetector, alert type
    ROWHAMMER_PROXY):

    The original name and alert type claimed to detect Rowhammer-class
    attacks. It did not, and could not -- the actual logic below is
    "memory usage stays high and variable while compute utilization
    stays near zero," which is structurally identical to
    DMAAttackDetector's signal. Real Rowhammer/GPUBreach-class attacks
    work by repeatedly activating a narrow set of specific DRAM rows at
    high frequency to induce physical bit flips in adjacent memory --
    a precise access-pattern and timing signature that standard
    nvidia-smi telemetry (memory.used, utilization.gpu) cannot see at
    all. A real Rowhammer attack could run with a tiny, fixed memory
    footprint at high compute utilization, which this detector would
    never flag; conversely, ordinary bulk data loading at low
    utilization would trigger it despite having nothing to do with
    Rowhammer. The name has been corrected to describe what this
    detector actually measures, not what it doesn't.

    A materially better proxy for Rowhammer-class activity likely
    exists in this GPU's own ECC error counters
    (ecc.errors.corrected.volatile.total /
    ecc.errors.uncorrected.volatile.total, both already collected by
    agent/telemetry.py) -- induced bit flips in ECC-protected memory
    should show up there directly, which is a much closer match to the
    actual attack mechanism than memory-usage variance. Not built here
    to avoid duplicating detection/ecc_error_trend_detector.py, whose
    contents were not reviewed as part of this fix -- check that file
    before building a second, competing ECC-based detector.

    STILL UNRESOLVED, stated rather than hidden: this cannot
    distinguish the pattern below from legitimate bulk data loading at
    low utilization, same discrimination gap as DMAAttackDetector.
    """
    def __init__(self, activation_threshold=1000000, window=50,
                 require_consecutive=1, refire_after_s=60):
        self.threshold = activation_threshold
        self.window = window
        self.history = collections.deque(maxlen=window)
        self.state = _EventState(require_consecutive=require_consecutive,
                                  refire_after_s=refire_after_s)

    def update(self, row):
        mem_used = _f(row, 'memory.used')
        util = _f(row, 'utilization.gpu')
        if mem_used is None or util is None:
            return None
        self.history.append({'mem': mem_used, 'util': util, 'ts': row.get('iso_timestamp')})
        if len(self.history) < self.window:
            return None
        mem_vals = [r['mem'] for r in self.history]
        mem_variance = max(mem_vals) - min(mem_vals)
        low_util_high_mem = [r for r in self.history if r['util'] < 5 and r['mem'] > 500]
        condition = len(low_util_high_mem) > self.window * 0.6 and mem_variance > 100
        if not self.state.should_emit(condition):
            return None
        return {
            'type': 'MEMORY_ACTIVATION_ANOMALY',
            'severity': 'INFO',
            'gpu': row.get('index'),
            'mem_variance_mb': round(mem_variance, 2),
            'low_util_high_mem_samples': len(low_util_high_mem),
            'timestamp': row.get('iso_timestamp'),
            'message': (f"Sustained high, variable memory usage "
                        f"(variance={mem_variance:.0f}MB) at low compute "
                        f"utilization -- consistent with bulk data "
                        f"loading, checkpoint I/O, or unusual memory "
                        f"access patterns. NOT a Rowhammer-specific "
                        f"signal; standard telemetry cannot detect the "
                        f"actual bit-flip access pattern real "
                        f"Rowhammer-class attacks use."),
        }


class ModelMutationDetector:
    """
    Periodically hashes a small sample of VRAM to detect unexpected
    content changes between checks -- a real, reasonable technique for
    catching unauthorized model tampering.

    STILL UNRESOLVED, stated rather than hidden: only samples the
    first 10,000 float32 values (40KB) of a 1024x1024-float probe
    allocation, not the workload's actual model weights, and not most
    of the GPU's VRAM. A change outside this specific sampled region
    would not be detected. This is a spot-check, not comprehensive
    VRAM integrity verification.
    """
    def __init__(self, check_interval=300):
        self.check_interval = check_interval
        self.checksums = {}
        self.last_check = {}

    def compute_vram_checksum(self, gpu_index=0):
        try:
            import torch
            if not torch.cuda.is_available(): return None
            probe = torch.empty(1024*1024, dtype=torch.float32, device=f'cuda:{gpu_index}')
            sample = probe[:10000].cpu().numpy().tobytes()
            del probe
            return hashlib.sha256(sample).hexdigest()
        except: return None

    def check(self, gpu_index=0):
        now = time.time()
        last = self.last_check.get(gpu_index, 0)
        if now - last < self.check_interval: return None
        self.last_check[gpu_index] = now
        checksum = self.compute_vram_checksum(gpu_index)
        if checksum is None: return None
        if gpu_index in self.checksums and self.checksums[gpu_index] != checksum:
            alert = {'type':'MODEL_MUTATION','severity':'WARNING','gpu':gpu_index,'prev_checksum':self.checksums[gpu_index][:16]+'...','curr_checksum':checksum[:16]+'...','timestamp':datetime.now().isoformat(),'message':f"VRAM content changed in the sampled 40KB probe region between checks -- possible model tampering, or simply new data occupying this specific memory region. Only a small sample is checked, not the full allocation; absence of a signal here does not confirm the rest of VRAM is unchanged."}
            self.checksums[gpu_index] = checksum
            return alert
        self.checksums[gpu_index] = checksum
        return None


class PerfCounterSideChannelDetector:
    """
    FIXED vs. original: previously cited CVE-2018-6260 (a real NVIDIA
    driver GPU performance-counter side-channel vulnerability,
    confirmed via independent verification) as if this detector reads
    performance counters. It does not -- it uses the same
    utilization.gpu / utilization.memory / power.draw fields every
    other detector in this codebase uses. The CVE citation has been
    removed from the alert to avoid implying a direct connection this
    detector doesn't have; the underlying heuristic (memory-utilization
    variance decoupled from compute-utilization variance) is kept as a
    generic anomaly signal, honestly labeled as such.
    """
    def __init__(self, window=100, require_consecutive=1, refire_after_s=60):
        self.window = window
        self.history = collections.deque(maxlen=window)
        self.state = _EventState(require_consecutive=require_consecutive,
                                  refire_after_s=refire_after_s)

    def update(self, row):
        util_gpu = _f(row, 'utilization.gpu')
        util_mem = _f(row, 'utilization.memory')
        power = _f(row, 'power.draw')
        if util_gpu is None or util_mem is None or power is None:
            return None
        self.history.append({'util_gpu': util_gpu, 'util_mem': util_mem, 'power': power})
        if len(self.history) < self.window:
            return None
        vals = list(self.history)
        gpu_utils = [r['util_gpu'] for r in vals]
        mem_utils = [r['util_mem'] for r in vals]
        gpu_variance = max(gpu_utils) - min(gpu_utils)
        mem_variance = max(mem_utils) - min(mem_utils)
        condition = util_gpu < 5 and mem_variance > 20 and gpu_variance < 5
        if not self.state.should_emit(condition):
            return None
        return {
            'type': 'MEMORY_UTIL_DECOUPLED_FROM_COMPUTE',
            'severity': 'INFO',
            'gpu': row.get('index'),
            'util_gpu': util_gpu,
            'mem_util_variance': round(mem_variance, 2),
            'timestamp': row.get('iso_timestamp'),
            'message': (f"Memory utilization variance {mem_variance:.1f}% "
                        f"while compute utilization stays flat at "
                        f"{util_gpu:.0f}% -- an unusual decoupling worth "
                        f"noting, not a confirmed detection of any "
                        f"specific named vulnerability. Standard "
                        f"telemetry does not expose actual performance "
                        f"counter access, so this cannot confirm or rule "
                        f"out a performance-counter side channel "
                        f"specifically."),
        }


class NVLinkFabricDetector:
    """
    FIXED vs. original: "possible link disable or man-in-the-middle on
    interconnect" claimed a specific attack type from a simple status
    string check. An inactive or errored NVLink status has many benign
    causes -- hardware not present, driver state, thermal throttling,
    a cable/connector issue -- none of which are man-in-the-middle
    attacks. Message reworded to report the observation without
    naming an unconfirmed cause.
    """
    def __init__(self, window=50):
        self.window = window
        self.history = collections.deque(maxlen=window)

    def sample(self):
        try:
            r = subprocess.run(['nvidia-smi','nvlink','--status'],capture_output=True,text=True,timeout=5)
            return r.stdout.strip()
        except: return None

    def update(self, row):
        status = self.sample()
        if not status: return None
        if 'inactive' in status.lower() or 'error' in status.lower():
            return {'type':'NVLINK_ANOMALY','severity':'INFO','gpu':row.get('index'),'timestamp':row.get('iso_timestamp'),'message':f"NVLink fabric reports inactive or error status -- cause unconfirmed. Consistent with expected hardware absence, a driver/link state change, thermal throttling, or a physical connection issue. Not confirmed to indicate tampering or an attack."}
        return None


class SupplyChainDetector:
    """
    FIXED vs. original: two issues.
      - Checked exactly once per process lifetime (self.checked = True
        permanently after the first qualifying sample), then went
        silent forever regardless of what happened afterward. Now
        re-checks periodically instead.
      - "possible counterfeit or tampered device" from a power draw
        exceeding an expected reference value by 15% overclaims: a
        legitimate factory-overclocked SKU, a different card variant,
        or simple measurement timing would trigger this identically to
        actual counterfeit hardware. Message reworded to report the
        deviation without naming an unconfirmed cause.

    STILL UNRESOLVED, stated rather than hidden: the expected-power
    reference table below is a rough, unvalidated placeholder, not
    measured against real hardware in this project.
    """
    def __init__(self, expected_efficiency_flops_per_watt=None, check_interval=3600):
        self.check_interval = check_interval
        self.last_check = 0

    def check_counterfeit(self, row):
        now = time.time()
        if now - self.last_check < self.check_interval:
            return None
        power = _f(row, 'power.draw')
        util = _f(row, 'utilization.gpu')
        name = row.get('name', '')
        if power is None or util is None or util < 1 or power < 10:
            return None
        self.last_check = now
        expected = {'H200':700,'B200':1000,'H100':700,'A100':400}
        expected_power = None
        for gpu, ep in expected.items():
            if gpu in name: expected_power = ep; break
        if expected_power and power > expected_power * 1.15:
            return {'type':'SUPPLY_CHAIN_ANOMALY','severity':'INFO','gpu':row.get('index'),'name':name,'power_w':power,'expected_max_w':expected_power,'timestamp':row.get('iso_timestamp'),'message':f"Power draw {power:.0f}W exceeds this unvalidated reference table's expected {expected_power}W for {name} by more than 15% -- cause unconfirmed. Consistent with a different card variant, factory overclock, or measurement timing, not necessarily counterfeit or tampered hardware."}
        return None
