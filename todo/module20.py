#!/usr/bin/env python3
import sys
sys.exit("UNGATED: this module performs privileged destructive actions with no safety gate. See SECURITY_REVIEW_2026-09-04.md H1. Port module21 gating before running.")

"""
Watchdog — Host Security (B200)
Combines: LLC flood (was 20) + container isolation (was 22)
        + CPU side-channel (was 25) + pre-exec guard (was 30)

B200 host may be x86 Xeon or NVIDIA Grace (ARM Neoverse V2).
Module detects CPU arch and acts accordingly for SMT operations.
Pre-exec guard runs as background thread (/proc poll; eBPF if bcc available).
"""
import subprocess, time, datetime, json, os, signal
import platform, hashlib, threading

try:
    from bcc import BPF
    BCC_AVAILABLE = True
except ImportError:
    BCC_AVAILABLE = False

# ── Constants ───────────────────────────────────────────────────────
LLC_SPIKE           = 5       # 5x baseline = flood
LLC_LOCK_HZ         = 800000  # Hz — cpupower -f value (not "800MHz" string)
SPECTRE_COOLDOWN    = 1800    # 30 min — dmesg lines are static post-boot
SMT_RESTORE_S       = 10      # seconds before re-onlining offlined CPUs
EXEC_POLL_S         = 0.5     # /proc poll interval for pre-exec guard

MINER_KEYWORDS = [
    "xmrig", "cgminer", "bfgminer", "ethminer", "nbminer",
    "t-rex", "lolminer", "teamredminer", "nanominer", "phoenixminer"
]

ALLOWED_PATH_PREFIXES = [
    "/usr/bin/", "/usr/sbin/", "/usr/lib/", "/bin/", "/sbin/",
    "/opt/conda/", "/usr/local/bin/", "/usr/local/lib/",
]

BPF_PROGRAM = r"""
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
struct exec_event_t {
    u32  pid;
    u32  ppid;
    char comm[TASK_COMM_LEN];
    char filename[256];
};
BPF_PERF_OUTPUT(exec_events);
TRACEPOINT_PROBE(syscalls, sys_enter_execve) {
    struct exec_event_t evt = {};
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    evt.pid  = bpf_get_current_pid_tgid() >> 32;
    evt.ppid = task->real_parent->tgid;
    bpf_get_current_comm(&evt.comm, sizeof(evt.comm));
    bpf_probe_read_user_str(&evt.filename, sizeof(evt.filename), args->filename);
    exec_events.perf_submit(args, &evt, sizeof(evt));
    return 0;
}
"""

def now_iso():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()

def stamp():
    return datetime.datetime.now().strftime("%Y%m%d_%H%M%S")

def is_arm():
    m = platform.machine()
    return m.startswith("aarch") or m == "arm64"

# ── Lock (shared with bus_interconnect for IOMMU) ──
def acquire_lock(name):
    try:
        fd = os.open(f"/tmp/watchdog_{name}.lock",
                     os.O_CREAT | os.O_EXCL | os.O_WRONLY)
        os.close(fd)
        return True
    except FileExistsError:
        return False

def release_lock(name):
    try:
        os.unlink(f"/tmp/watchdog_{name}.lock")
    except:
        pass

# ── LLC helpers ─────────────────────────────────────────────────────
def get_llc_misses() -> float:
    try:
        out = subprocess.check_output(
            ["perf", "stat", "-e", "LLC-load-misses", "-x", ",", "sleep", "1"],
            text=True, timeout=4, stderr=subprocess.STDOUT)
        for line in out.strip().splitlines():
            parts = line.split(",")
            try:
                return float(parts[0].replace(",", "").strip())
            except:
                continue
        return 0.0
    except:
        return 0.0

def lock_cpu_low():
    try:
        subprocess.check_output(
            ["cpupower", "frequency-set", "-f", str(LLC_LOCK_HZ)],
            text=True, timeout=3, stderr=subprocess.DEVNULL)
        return True
    except:
        return False

def unlock_cpu():
    try:
        subprocess.check_output(
            ["cpupower", "frequency-set", "-g", "performance"],
            text=True, timeout=3, stderr=subprocess.DEVNULL)
        return True
    except:
        return False

# ── Container / DMA helpers ─────────────────────────────────────────
def check_dmesg_breakout():
    try:
        out = subprocess.check_output(
            ["dmesg"], text=True, timeout=3, stderr=subprocess.DEVNULL)
        for line in out.splitlines():
            if "runc" in line.lower() and \
               ("escape" in line.lower() or "break" in line.lower()):
                return line.strip()
        return None
    except:
        return None

def kill_container():
    try:
        with open("/proc/self/cgroup") as f:
            for line in f:
                if "docker" in line:
                    cid = line.strip().split("/")[-1][:12]
                    subprocess.check_output(
                        ["docker", "kill", cid],
                        timeout=5, stderr=subprocess.DEVNULL)
                    return True
        return False
    except:
        return False

def scan_spoofed_pids():
    try:
        for p in os.listdir("/proc"):
            if not p.isdigit():
                continue
            pid = int(p)
            try:
                with open(f"/proc/{p}/status") as f:
                    for line in f:
                        if line.startswith("PPid:"):
                            ppid = int(line.split()[1])
                            if pid in (0, 1) and ppid != 0:
                                return pid
                            break
            except:
                pass
        return None
    except:
        return None

def check_dmesg_dma():
    try:
        out = subprocess.check_output(
            ["dmesg"], text=True, timeout=3, stderr=subprocess.DEVNULL)
        for line in out.splitlines():
            if ("DMAR" in line or "IOMMU" in line) and \
               ("fault" in line.lower() or "error" in line.lower()):
                return line.strip()
        return None
    except:
        return None

def unbind_pcie():
    try:
        with open("/sys/bus/pci/devices/0000:00:00.0/remove", "w") as f:
            f.write("1")
        return True
    except:
        return False

# ── CPU side-channel helpers ────────────────────────────────────────
def check_spectre_dmesg():
    try:
        out = subprocess.check_output(
            ["dmesg"], text=True, timeout=3, stderr=subprocess.DEVNULL)
        for line in out.splitlines():
            if ("spectre" in line.lower() or "meltdown" in line.lower()) \
               and "vulnerable" in line.lower():
                return line.strip()
        return None
    except:
        return None

def flush_cache():
    try:
        with open("/proc/sys/vm/drop_caches", "w") as f:
            f.write("3")
        return True
    except:
        return False

def get_hot_cores(baseline: float, threshold=5.0):
    hot = []
    try:
        for cpu_id in range(os.cpu_count() or 1):
            out = subprocess.check_output(
                ["perf", "stat", "-C", str(cpu_id),
                 "-e", "LLC-load-misses", "-x", ",", "sleep", "0.2"],
                text=True, timeout=3, stderr=subprocess.STDOUT)
            for line in out.strip().splitlines():
                try:
                    misses = float(line.split(",")[0].replace(",", "").strip())
                    if baseline > 0 and misses > baseline * threshold:
                        hot.append(cpu_id)
                except:
                    pass
    except:
        pass
    return hot

def get_sibling(cpu_id):
    try:
        path = f"/sys/devices/system/cpu/cpu{cpu_id}/topology/thread_siblings_list"
        with open(path) as f:
            return [int(s) for s in f.read().strip().split(",")
                    if int(s) != cpu_id]
    except:
        return []

def offline_cpu(cpu_id):
    try:
        with open(f"/sys/devices/system/cpu/cpu{cpu_id}/online", "w") as f:
            f.write("0")
        return True
    except:
        return False

def online_cpu(cpu_id):
    try:
        with open(f"/sys/devices/system/cpu/cpu{cpu_id}/online", "w") as f:
            f.write("1")
        return True
    except:
        return False

# ── Pre-exec guard ──────────────────────────────────────────────────
def sha256(path: str):
    try:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()
    except:
        return None

def is_suspicious(path: str, fhash):
    base = os.path.basename(path).lower()
    for kw in MINER_KEYWORDS:
        if kw in base:
            return True, f"keyword:{kw}"
    for prefix in ALLOWED_PATH_PREFIXES:
        if path.startswith(prefix):
            return False, ""
    if fhash is None:
        return False, ""   # Script (no ELF hash) — allow
    return True, "unknown_binary"

def run_proc_poll(emit_fn):
    known = set(int(p) for p in os.listdir("/proc") if p.isdigit())
    while True:
        try:
            current = set(int(p) for p in os.listdir("/proc") if p.isdigit())
        except:
            time.sleep(EXEC_POLL_S)
            continue
        for pid in current - known:
            try:
                exe   = os.readlink(f"/proc/{pid}/exe")
                fhash = sha256(exe)
                susp, reason = is_suspicious(exe, fhash)
                if susp:
                    os.kill(pid, signal.SIGKILL)
                    emit_fn({"event": "EXEC_BLOCKED_POLL",
                             "pid": pid, "exe": exe,
                             "sha256": fhash, "reason": reason})
            except:
                pass
        known = current
        time.sleep(EXEC_POLL_S)

def run_ebpf(emit_fn):
    b = BPF(text=BPF_PROGRAM)

    def handle(cpu, data, size):
        evt      = b["exec_events"].event(data)
        filename = evt.filename.decode("utf-8", errors="replace")
        pid      = evt.pid
        fhash    = sha256(filename)
        susp, reason = is_suspicious(filename, fhash)
        if susp:
            try:
                os.kill(pid, signal.SIGKILL)
                emit_fn({"event": "EXEC_BLOCKED_EBPF",
                         "pid": pid,
                         "comm": evt.comm.decode("utf-8", errors="replace"),
                         "exe": filename, "sha256": fhash, "reason": reason})
            except:
                pass

    b["exec_events"].open_perf_buffer(handle)
    while True:
        b.perf_buffer_poll()

# ── main ────────────────────────────────────────────────────────────
def main():
    log = open(f"watchdog_host_security_{stamp()}.jsonl", "a")
    arm = is_arm()

    def emit(event: dict):
        event.setdefault("ts", now_iso())
        log.write(json.dumps(event) + "\n")
        log.flush()

    emit({"event": "RUN_START", "module": "host_security", "gpu": "B200",
          "cpu_arch": "arm" if arm else "x86",
          "exec_guard": "ebpf" if BCC_AVAILABLE else "proc_poll"})

    # Start pre-exec guard in background thread
    guard_fn = run_ebpf if BCC_AVAILABLE else run_proc_poll
    t = threading.Thread(target=guard_fn, args=(emit,), daemon=True)
    t.start()

    llc_baseline       = get_llc_misses()
    last_spectre       = 0.0
    offlined_cpus      = []
    t_llc              = time.time() + 3   # LLC check takes 1s, stagger start
    t_container        = time.time()
    t_sidechannel      = time.time()

    while True:
        now = time.time()

        # ── Container / DMA (every 2s) ──
        if now >= t_container:
            t_container = now + 2

            bl = check_dmesg_breakout()
            if bl:
                if kill_container():
                    emit({"event": "CONTAINER_BREAKOUT_BLOCKED",
                          "log": bl, "action": "container_killed"})

            spoofed = scan_spoofed_pids()
            if spoofed:
                try:
                    os.kill(spoofed, signal.SIGKILL)
                    emit({"event": "SPOOFED_PID_KILLED",
                          "pid": spoofed, "action": "SIGKILL"})
                except:
                    pass

            dma = check_dmesg_dma()
            if dma and acquire_lock("iommu"):
                if unbind_pcie():
                    emit({"event": "DMA_ATTACK_BLOCKED",
                          "log": dma, "action": "pcie_unbind_30s"})
                    time.sleep(30)
                    emit({"event": "PCI_REBOUND"})
                release_lock("iommu")

        # ── CPU side-channel (every 4s) ──
        if now >= t_sidechannel:
            t_sidechannel = now + 4

            # Spectre — 30 min cooldown (dmesg lines are static post-boot)
            if now - last_spectre > SPECTRE_COOLDOWN:
                line = check_spectre_dmesg()
                if line:
                    if flush_cache():
                        emit({"event": "SPECTRE_CACHE_FLUSH",
                              "log": line, "action": "drop_caches"})
                        last_spectre = now

            misses = get_llc_misses()
            if llc_baseline > 0 and misses > llc_baseline * LLC_SPIKE:
                if arm:
                    # Grace CPU has no hyperthreading — log only
                    emit({"event": "LLC_SPIKE_ARM",
                          "baseline": llc_baseline, "current": misses,
                          "note": "no_smt_on_grace_cpu"})
                else:
                    # x86: offline siblings of hot cores specifically
                    hot = get_hot_cores(llc_baseline)
                    for cpu_id in hot:
                        for sib in get_sibling(cpu_id):
                            if offline_cpu(sib):
                                offlined_cpus.append(sib)
                                emit({"event": "SMT_SIBLING_OFFLINED",
                                      "hot_cpu": cpu_id, "offlined": sib})
                    if offlined_cpus:
                        time.sleep(SMT_RESTORE_S)
                        for sib in offlined_cpus:
                            online_cpu(sib)
                        emit({"event": "SMT_RESTORED", "cpus": offlined_cpus})
                        offlined_cpus = []

        # ── LLC flood (every 3s, staggered from side-channel) ──
        if now >= t_llc:
            t_llc = now + 3
            misses = get_llc_misses()
            if llc_baseline > 0 and misses > llc_baseline * LLC_SPIKE:
                if lock_cpu_low():
                    emit({"event": "LLC_FLOOD_LOCK",
                          "baseline": llc_baseline, "current": misses,
                          "action": f"{LLC_LOCK_HZ}Hz"})
                    time.sleep(5)
                    if unlock_cpu():
                        emit({"event": "LLC_UNLOCK"})

        time.sleep(2)

if __name__ == "__main__":
    main()
