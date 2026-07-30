# Author: Manmohan (Mike) Bains -- Watchdog
import subprocess, time, csv, os
from datetime import datetime

from telemetry.sampler import DeltaTimedSampler

SAMPLE_HZ = 100
CORE_FIELDS = ['timestamp','index','uuid','name','power.draw','power.limit','utilization.gpu','utilization.memory','memory.used','memory.free','memory.total','clocks.sm','clocks.mem','clocks.gr','temperature.gpu','pstate','ecc.errors.corrected.volatile.total','ecc.errors.uncorrected.volatile.total']

# Throttle reasons report "Active" or "Not Active" -- flags, not values.
# Added deliberately BECAUSE they need no threshold: every existing
# detector infers constraint from a numeric threshold somebody had to
# choose, and the one real-hardware session showed those thresholds
# firing on nothing. These are the hardware reporting its own state
# directly. Not yet consumed by any detector; collected first so a real
# hardware session produces the data needed to decide whether they are
# worth acting on, rather than guessing at that in advance.
THROTTLE_FIELDS = ['clocks_throttle_reasons.sw_power_cap',
                   'clocks_throttle_reasons.hw_slowdown',
                   'clocks_throttle_reasons.hw_thermal_slowdown',
                   'clocks_throttle_reasons.hw_power_brake_slowdown',
                   'clocks_throttle_reasons.sw_thermal_slowdown',
                   'clocks_throttle_reasons.sync_boost']

QUERY_FIELDS = CORE_FIELDS + THROTTLE_FIELDS

# Some driver and GPU combinations reject an entire --query-gpu call if
# any single requested field is unsupported, which would take all
# telemetry down rather than just the new fields. sample_gpu() therefore
# tries the extended set once, and on failure falls back permanently to
# CORE_FIELDS for the life of the process rather than retrying every
# sample. Whether the fallback ever triggers is unknown until this runs
# on real hardware -- no GPU was available to verify it here.
_extended_fields_supported = True

COMPUTE_APPS_FIELDS = ['gpu_uuid', 'pid', 'used_memory']

NUMERIC_FIELDS = ['power.draw','power.limit','utilization.gpu','utilization.memory','memory.used','memory.free','memory.total','clocks.sm','clocks.mem','clocks.gr','temperature.gpu']


def parse_numeric_fields(row, fields=NUMERIC_FIELDS):
    """
    Converts the given fields in `row` from strings to floats in place,
    and returns the modified row. Fields that fail to parse -- most
    commonly nvidia-smi's literal '[N/A]' string, which some drivers
    report for a metric a given GPU doesn't support -- are set to None,
    NOT a fabricated 0.0.

    FIXED: this previously wrote 0.0 on any parse failure, silently
    conflating "genuinely reads zero" with "this GPU can't report this
    metric at all" -- two very different facts a detector might act on
    very differently (e.g. 0% utilization is meaningful; "unknown
    utilization" reported as 0% could look like a real idle reading).
    All 16 pipeline detectors + 4 base engines were checked and
    confirmed to handle a real None safely (via detection._shared._f(),
    or by not parsing these fields as floats at all) before this change
    was made -- see the git history for that verification work, spread
    across several commits fixing each detector that wasn't already
    safe.
    """
    for f in fields:
        try:
            row[f] = float(row[f])
        except (ValueError, TypeError, KeyError):
            row[f] = None
    return row


def _safe_fmt(val, fmt='.1f'):
    """
    Formats a value for the periodic console status print, showing
    'N/A' instead of crashing when the value is None. Needed as of the
    parse_numeric_fields() fix above: row.get(key, 0) only supplies its
    default when the KEY is absent, not when the value is explicitly
    None -- so a naive f-string like f"{row.get('power.draw',0):.1f}"
    would raise TypeError the instant a real N/A field came through,
    which is now a genuinely reachable case rather than a theoretical
    one.
    """
    if val is None:
        return 'N/A'
    return format(val, fmt)


def parse_nvlink_output(stdout_text):
    """
    Parses `nvidia-smi nvlink -g <index> -gt d` output. Factored out from
    the subprocess call so this parsing logic can be tested against
    real-shaped sample text without needing NVLink hardware -- no GPU
    with NVLink exists in the environment that wrote this, so this is
    UNVERIFIED against real nvidia-smi output. The expected format is
    documented by NVIDIA as:

        GPU 0: NVLink Data Tx:
           Link 0: 1234 KiB
           Link 1: 5678 KiB
        GPU 0: NVLink Data Rx:
           Link 0: 2345 KiB
           Link 1: 6789 KiB

    If real output differs, this needs adjusting -- exactly the kind of
    thing scripts/hardware_preflight_check.py exists to catch before a
    paid session; NVLink support should be added there before relying
    on this in production.

    Returns {'nvlink_available': bool, 'nvlink_tx_kbs': float or None,
    'nvlink_rx_kbs': float or None}. Most GPUs without NVLink hardware
    (L40S, RTX-series, T4, most single-GPU rentals) will report
    nvlink_available=False rather than a fabricated zero -- zero traffic
    on present hardware and "no NVLink hardware at all" are different
    facts and must not be conflated.

    EXTENDED: previously parsed each "Link N: <value>" line, added its
    value into a combined tx_total/rx_total, and discarded the
    per-link value and the link number itself -- meaning link_index was
    never available anywhere downstream, even though NVIDIA's own
    documented output format already breaks the data down per link.
    Now also returns nvlink_tx_kbs_by_link and nvlink_rx_kbs_by_link,
    dicts mapping int link index -> float KiB. The existing aggregate
    fields are computed identically to before (same sum, same
    behavior) so nothing that already depends on them changes. Same
    UNVERIFIED-against-real-hardware caveat applies to the per-link
    extraction as to the aggregate parsing above it.
    """
    tx_total = 0.0
    rx_total = 0.0
    tx_by_link = {}
    rx_by_link = {}
    mode = None
    found_any = False
    import re
    inline_re = re.compile(r'^Link\s+(\d+):\s+Data\s+(Tx|Rx):\s+([\d.]+)\s*KiB', re.IGNORECASE)
    for line in stdout_text.splitlines():
        line = line.strip()
        if not line:
            continue
        m = inline_re.match(line)
        if m:
            # Real B200 format: "Link N: Data Tx: X KiB" -- Tx/Rx interleaved
            # per link on one line, confirmed against actual nvlink -gt d
            # output. Checked BEFORE the header-style branches below, since
            # this line also contains the substring "data tx"/"data rx" and
            # would otherwise be misidentified as a header line and its
            # value silently discarded via continue -- this was the exact
            # bug that made nvlink_available=False on real hardware.
            link_num = int(m.group(1))
            kind = m.group(2).lower()
            val = float(m.group(3))
            found_any = True
            if kind == 'tx':
                tx_total += val
                tx_by_link[link_num] = val
            else:
                rx_total += val
                rx_by_link[link_num] = val
            continue
        if 'data tx' in line.lower():
            mode = 'tx'
            continue
        if 'data rx' in line.lower():
            mode = 'rx'
            continue
        if line.lower().startswith('link') and ':' in line:
            try:
                label, rest = line.split(':', 1)
                link_num = int(label.strip().split()[1])
                val_str = rest.strip().split()[0]
                val = float(val_str)
                found_any = True
                if mode == 'tx':
                    tx_total += val
                    tx_by_link[link_num] = val
                elif mode == 'rx':
                    rx_total += val
                    rx_by_link[link_num] = val
            except (ValueError, IndexError):
                continue
    if not found_any:
        return {'nvlink_available': False, 'nvlink_tx_kbs': None, 'nvlink_rx_kbs': None,
                'nvlink_tx_kbs_by_link': {}, 'nvlink_rx_kbs_by_link': {}}
    return {'nvlink_available': True, 'nvlink_tx_kbs': tx_total, 'nvlink_rx_kbs': rx_total,
            'nvlink_tx_kbs_by_link': tx_by_link, 'nvlink_rx_kbs_by_link': rx_by_link}


def sample_nvlink(gpu_index=0):
    """
    NVLink throughput sampling via `nvidia-smi nvlink -g <index> -gt d`,
    a documented NVIDIA subcommand -- deliberately NOT attempted via the
    --query-gpu CSV interface QUERY_FIELDS uses for everything else,
    since NVLink field support there varies by driver version in ways
    this environment (no GPU present) cannot verify. This subcommand is
    per-GPU-index, unlike the combined QUERY_FIELDS query -- calling it
    for every GPU on every sample at high sample_hz adds a real
    subprocess-spawn cost per GPU. Callers running at high Hz on
    multi-GPU nodes should rate-limit calls to this separately from the
    main telemetry loop rather than call it every sample -- an open
    design point best settled by measuring the real cost on target
    hardware, not assumed here. NOT auto-wired into sample_gpu()'s
    per-sample hot path for exactly this reason -- see
    NVLinkContentionDetector's docstring in detection/hardware_attacks.py
    for the full integration status.
    """
    try:
        r = subprocess.run(['nvidia-smi', 'nvlink', '-g', str(gpu_index), '-gt', 'd'],
                            capture_output=True, text=True, timeout=5)
        if r.returncode != 0 or not r.stdout.strip():
            return {'nvlink_available': False, 'nvlink_tx_kbs': None, 'nvlink_rx_kbs': None,
                    'nvlink_tx_kbs_by_link': {}, 'nvlink_rx_kbs_by_link': {}}
        return parse_nvlink_output(r.stdout)
    except Exception:
        return {'nvlink_available': False, 'nvlink_tx_kbs': None, 'nvlink_rx_kbs': None,
                'nvlink_tx_kbs_by_link': {}, 'nvlink_rx_kbs_by_link': {}}


def sample_compute_apps():
    cmd = ['nvidia-smi', f'--query-compute-apps={",".join(COMPUTE_APPS_FIELDS)}',
           '--format=csv,noheader,nounits']
    result = {}
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
        for line in r.stdout.strip().split('\n'):
            if not line.strip():
                continue
            parts = [p.strip() for p in line.split(',')]
            if len(parts) < 3:
                continue
            uuid, pid, used_memory = parts[0], parts[1], parts[2]
            try:
                entry = {'pid': int(pid), 'used_memory': float(used_memory)}
            except ValueError:
                continue
            result.setdefault(uuid, []).append(entry)
    except Exception:
        pass
    return result


def sample_gpu(gpu_index=None):
    global _extended_fields_supported
    fields = QUERY_FIELDS if _extended_fields_supported else CORE_FIELDS
    cmd = ['nvidia-smi','--query-gpu='+','.join(fields),'--format=csv,noheader,nounits']
    if gpu_index is not None: cmd += [f'--id={gpu_index}']
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
        if r.returncode != 0 and _extended_fields_supported:
            # This driver or GPU rejects one of the throttle fields.
            # Drop to the core set permanently rather than losing all
            # telemetry, and say so once rather than silently degrading.
            _extended_fields_supported = False
            print("[WATCHDOG] Extended telemetry fields (throttle reasons) "
                  "not supported by this driver/GPU -- falling back to core "
                  "fields for the remainder of this process.")
            fields = CORE_FIELDS
            cmd = ['nvidia-smi','--query-gpu='+','.join(fields),'--format=csv,noheader,nounits']
            if gpu_index is not None: cmd += [f'--id={gpu_index}']
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
        compute_apps_by_gpu = sample_compute_apps()
        rows = []
        for line in r.stdout.strip().split('\n'):
            if not line.strip(): continue
            vals = [v.strip() for v in line.split(',')]
            if len(vals) < len(fields): continue
            row = dict(zip(fields, vals))
            row['iso_timestamp'] = datetime.now().isoformat()
            row = parse_numeric_fields(row)
            row['compute_apps'] = compute_apps_by_gpu.get(row.get('uuid'), [])
            rows.append(row)
        return rows
    except: return []


def detect_gpus():
    try:
        r = subprocess.run(['nvidia-smi','--query-gpu=index,name','--format=csv,noheader'],capture_output=True,text=True,timeout=5)
        return [l.strip() for l in r.stdout.strip().split('\n') if l.strip()]
    except: return []


class TelemetryCollector:
    """
    FIXED vs. original: SAMPLE_HZ=100 was requested but never verified as
    achieved -- the collector silently assumed it was hitting 100Hz with
    no measurement to back that up. telemetry/sampler.py's
    DeltaTimedSampler was built earlier specifically to fix this, but was
    never actually wired in here until now.

    self.timer measures the ACTUAL wall-clock gap between loop
    iterations using a monotonic clock. It wraps a no-op probe (not
    sample_gpu() directly, since sample_gpu() returns a LIST of rows --
    one per GPU on a multi-GPU node -- while DeltaTimedSampler's API is
    built around a single-value probe). The measured interval from one
    call to timer.sample() is then attached to every row produced by
    that same loop iteration, since all of a multi-GPU sample_gpu() call
    happens within the same wall-clock instant for practical purposes.

    'actual_interval_ms' is now written to the CSV, per the collector's
    own README/Limitations promise: "the collector must log measured
    inter-sample deltas, not the requested rate."
    """
    def __init__(self, sample_hz=SAMPLE_HZ, output_dir='watchdog_data', gpu_index=None,
                 on_sample=None, nvlink_enabled=False, nvlink_interval_s=5.0):
        self.sample_hz = sample_hz
        self.output_dir = output_dir
        self.gpu_index = gpu_index
        self.on_sample = on_sample
        self.running = False
        self.sample_count = 0
        self.timer = DeltaTimedSampler(sample_fn=lambda: {})
        # NVLink sampling, OFF by default. sample_nvlink() spawns a
        # subprocess PER GPU, so calling it every sample at high
        # sample_hz would add exactly the cost both its own docstring
        # and NVLinkContentionDetector's warn about -- and would
        # silently degrade the achieved rate DeltaTimedSampler exists
        # to honestly measure. Instead it refreshes at most once per
        # nvlink_interval_s and the cached values are merged into every
        # row in between. Default OFF rather than ON so no existing
        # deployment silently changes behavior; a caller enabling it is
        # making a deliberate choice about that subprocess cost.
        self.nvlink_enabled = nvlink_enabled
        self.nvlink_interval_s = nvlink_interval_s
        self._last_nvlink_ts = 0.0
        self._nvlink_cache = {}
        os.makedirs(output_dir, exist_ok=True)

    def _maybe_refresh_nvlink(self, rows, now):
        """
        Refreshes the per-GPU NVLink cache at most once per
        nvlink_interval_s, then merges the cached values into every row
        of the current sample. Rows between refreshes carry the last
        known values -- real, just not resampled that instant. Rows get
        no nvlink keys at all when disabled, so nvlink_available stays
        absent rather than a fabricated False.
        """
        if not self.nvlink_enabled:
            return
        if now - self._last_nvlink_ts >= self.nvlink_interval_s:
            self._last_nvlink_ts = now
            for row in rows:
                idx = row.get('index', 0)
                try:
                    self._nvlink_cache[idx] = sample_nvlink(idx)
                except Exception:
                    pass
        for row in rows:
            cached = self._nvlink_cache.get(row.get('index', 0))
            if cached:
                row.update(cached)

    def start(self, duration_seconds=None):
        self.running = True
        ts = datetime.now().strftime('%Y%m%d_%H%M%S')
        csv_path = os.path.join(self.output_dir, f'telemetry_{ts}.csv')
        print(f"[WATCHDOG] Starting -- requested {self.sample_hz}Hz → {csv_path}")
        print(f"[WATCHDOG] Actual achieved rate will be measured and "
              f"reported below, not assumed.")
        print(f"[WATCHDOG] GPUs: {detect_gpus()}")
        fieldnames = ['iso_timestamp'] + QUERY_FIELDS + ['actual_interval_ms']
        with open(csv_path,'w',newline='') as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction='ignore')
            writer.writeheader()
            start = time.time()
            while self.running:
                loop_start = time.time()
                timing_row = self.timer.sample()
                actual_interval_ms = timing_row['actual_interval_ms']
                rows = sample_gpu(self.gpu_index)
                self._maybe_refresh_nvlink(rows, time.time())
                for row in rows:
                    row['actual_interval_ms'] = actual_interval_ms
                    writer.writerow(row)
                    self.sample_count += 1
                    if self.on_sample: self.on_sample(row)
                elapsed = time.time() - start
                if int(elapsed) % 60 == 0 and elapsed > 1:
                    stats = self.timer.stats()
                    for row in rows:
                        print(f"[t+{int(elapsed)}s] GPU{row.get('index','?')}: "
                              f"{_safe_fmt(row.get('power.draw'))}W "
                              f"mem={_safe_fmt(row.get('memory.used'),'.0f')}MB "
                              f"temp={_safe_fmt(row.get('temperature.gpu'),'.0f')}C "
                              f"util={_safe_fmt(row.get('utilization.gpu'),'.0f')}%")
                    print(f"[WATCHDOG] Actual achieved rate: "
                          f"{stats['achieved_hz']}Hz (requested "
                          f"{self.sample_hz}Hz) -- min/mean/max interval: "
                          f"{stats['min_ms']}/{stats['mean_ms']}/{stats['max_ms']}ms")
                if duration_seconds and elapsed >= duration_seconds: break
                time.sleep(max(0,(1/self.sample_hz)-(time.time()-loop_start)))
        final_stats = self.timer.stats()
        print(f"[WATCHDOG] Done. {self.sample_count} samples → {csv_path}")
        print(f"[WATCHDOG] Final actual achieved rate: "
              f"{final_stats['achieved_hz']}Hz (requested {self.sample_hz}Hz)")
        return csv_path

    def stop(self): self.running = False
