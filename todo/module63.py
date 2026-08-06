#!/usr/bin/env python3
"""
Watchdog — Module 63: Kernel Module & Unsigned Driver Auditor
Status: FUNCTIONAL — no special hardware required

Attack vector: an attacker with root on the control host loads a kernel
module. From that point the host OS cannot be trusted to report on itself.
A loaded module can hide processes, hide files, hide network connections,
hook syscalls, and intercept everything module58 and module60 rely on.

On a quantum control host this is the highest-privilege persistence
available short of firmware. A malicious module can:
  - Hook the FPGA driver and alter pulse-generation commands in transit
  - Intercept instrument bus traffic before it reaches the serial driver
  - Hide its own presence from /proc/modules while remaining loaded
  - Sniff API tokens out of process memory
  - Survive as an autoloaded module across reboots

WHAT THIS CHECKS (all functional now):
  - Full /proc/modules inventory with baseline drift detection
  - Module signature verification via /sys/module/<name>/taint and the
    kernel taint flags in /proc/sys/kernel/tainted — this is the
    authoritative unsigned-module indicator
  - Kernel lockdown state — with lockdown enabled, unsigned modules cannot
    load at all
  - Module signature enforcement config (CONFIG_MODULE_SIG_FORCE)
  - Out-of-tree module detection (taint flag 'O')
  - Modules with no backing file on disk — a strong rootkit indicator
  - Suspicious module name patterns
  - /proc/modules vs /sys/module cross-check: a module hiding from one
    but present in the other is a definitive rootkit signal
  - modprobe configuration drift — an attacker adding an autoload entry
  - Recently-loaded module detection via dmesg

No fabricated module data.
"""
import os, json, time, datetime, hashlib, subprocess, glob, re

POLL_INTERVAL   = 300
BASELINE_FILE   = "/tmp/watchdog_kernel_module_baseline.json"

# Kernel taint flag bit positions — /proc/sys/kernel/tainted
TAINT_FLAGS = {
    0:  ("P", "Proprietary module loaded"),
    1:  ("F", "Module force-loaded"),
    2:  ("S", "SMP with CPU not designed for SMP"),
    3:  ("R", "Module force-unloaded"),
    4:  ("M", "Machine check exception"),
    5:  ("B", "Bad page referenced"),
    6:  ("U", "Taint requested by userspace"),
    7:  ("D", "Kernel died recently (OOPS/BUG)"),
    8:  ("A", "ACPI table overridden"),
    9:  ("W", "Warning issued"),
    10: ("C", "Staging driver loaded"),
    11: ("I", "Workaround for platform firmware bug"),
    12: ("O", "Out-of-tree module loaded"),
    13: ("E", "Unsigned module loaded"),
    14: ("L", "Soft lockup occurred"),
    15: ("K", "Kernel live-patched"),
    16: ("X", "Auxiliary taint"),
    17: ("T", "Kernel built with struct randomisation plugin"),
}

# Name patterns associated with rootkits and unauthorized hooks.
# Matching on these alone is weak — used as a supporting signal only.
SUSPICIOUS_PATTERNS = [
    "rootkit", "backdoor", "hideproc", "hidefile", "keylog",
    "kbeast", "diamorphine", "reptile", "suterusu", "adore",
    "modhide", "hidedriver", "sniffer", "netspy", "hidport",
]

# Modules that legitimately hook syscalls or touch DMA — worth naming
# when they appear, not automatically bad.
HIGH_PRIVILEGE_MODULES = [
    "vfio", "vfio_pci", "vfio_iommu_type1",
    "kprobe", "kprobes", "systemtap", "stap",
    "nf_hook", "xt_", "ebtable",
    "uio", "uio_pci_generic",
]

def now_iso():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()

def stamp():
    return datetime.datetime.now().strftime("%Y%m%d_%H%M%S")

def load_baseline() -> dict:
    try:
        with open(BASELINE_FILE) as f:
            return json.load(f)
    except:
        return {"modules": {}, "modprobe_conf": {}, "established": now_iso()}

def save_baseline(b: dict):
    try:
        with open(BASELINE_FILE, "w") as f:
            json.dump(b, f, indent=2)
    except:
        pass

def read_file(path: str) -> str | None:
    try:
        with open(path) as f:
            return f.read().strip()
    except (OSError, PermissionError):
        return None

def parse_proc_modules() -> dict:
    """
    /proc/modules — name, size, refcount, dependencies, state, address.
    This is the primary loaded-module inventory.
    """
    modules = {}
    content = read_file("/proc/modules")
    if not content:
        return modules
    for line in content.splitlines():
        parts = line.split()
        if len(parts) < 4:
            continue
        name = parts[0]
        modules[name] = {
            "size":     parts[1],
            "refcount": parts[2],
            "used_by":  parts[3] if parts[3] != "-" else "",
            "state":    parts[4] if len(parts) > 4 else "",
            "address":  parts[5] if len(parts) > 5 else "",
        }
    return modules

def list_sys_modules() -> set:
    """
    /sys/module — the kernel's other view of loaded modules. A module
    present here but absent from /proc/modules (or vice versa) is hiding.
    """
    try:
        return set(os.listdir("/sys/module"))
    except (OSError, PermissionError):
        return set()

def get_module_taint(name: str) -> dict:
    """
    Per-module taint from /sys/module/<name>/taint.
    'O' = out of tree, 'E' = unsigned, 'P' = proprietary, 'F' = force-loaded.
    This is the authoritative signature status per module.
    """
    taint = read_file(f"/sys/module/{name}/taint") or ""
    return {
        "taint":        taint,
        "unsigned":     "E" in taint,
        "out_of_tree":  "O" in taint,
        "proprietary":  "P" in taint,
        "force_loaded": "F" in taint,
    }

def get_module_srcversion(name: str) -> str | None:
    return read_file(f"/sys/module/{name}/srcversion")

def get_module_initstate(name: str) -> str | None:
    return read_file(f"/sys/module/{name}/initstate")

def find_module_file(name: str) -> str | None:
    """
    Locate the .ko file backing a loaded module. A loaded module with no
    file on disk is a strong rootkit indicator — it was injected directly.
    """
    kver = os.uname().release
    candidates = [
        f"/lib/modules/{kver}/kernel/**/{name}.ko*",
        f"/lib/modules/{kver}/extra/**/{name}.ko*",
        f"/lib/modules/{kver}/updates/**/{name}.ko*",
        f"/lib/modules/{kver}/**/{name.replace('_', '-')}.ko*",
    ]
    for pattern in candidates:
        matches = glob.glob(pattern, recursive=True)
        if matches:
            return matches[0]
    return None

def get_kernel_taint() -> dict:
    """Global kernel taint state — decodes the bitmask."""
    raw = read_file("/proc/sys/kernel/tainted")
    if raw is None:
        return {}
    try:
        value = int(raw)
    except ValueError:
        return {}
    flags = []
    for bit, (letter, desc) in TAINT_FLAGS.items():
        if value & (1 << bit):
            flags.append({"bit": bit, "flag": letter, "description": desc})
    return {"value": value, "flags": flags,
             "unsigned_module_loaded": bool(value & (1 << 13)),
             "out_of_tree_loaded":     bool(value & (1 << 12)),
             "force_loaded":           bool(value & (1 << 1))}

def get_lockdown_state() -> str | None:
    """
    Kernel lockdown. With lockdown in integrity or confidentiality mode,
    unsigned module loading is blocked outright.
    """
    raw = read_file("/sys/kernel/security/lockdown")
    if not raw:
        return None
    # Format: "none [integrity] confidentiality" — bracketed is active
    m = re.search(r'\[(\w+)\]', raw)
    return m.group(1) if m else raw

def check_sig_enforce() -> str | None:
    """CONFIG_MODULE_SIG_FORCE state via the module signature parameter."""
    return read_file("/sys/module/module/parameters/sig_enforce")

def scan_modprobe_config() -> dict:
    """
    modprobe.d entries. An attacker adding an autoload or install line
    achieves persistence across reboots.
    """
    configs = {}
    for pattern in ("/etc/modprobe.d/*.conf", "/etc/modules-load.d/*.conf",
                    "/lib/modprobe.d/*.conf", "/etc/modules"):
        for path in glob.glob(pattern):
            try:
                with open(path, errors="replace") as f:
                    content = f.read()
                configs[path] = {
                    "sha256": hashlib.sha256(content.encode()).hexdigest(),
                    "lines":  [l.strip() for l in content.splitlines()
                               if l.strip() and not l.strip().startswith("#")][:30],
                }
            except (OSError, PermissionError):
                continue
    return configs

def check_dmesg_module_loads() -> list:
    """Recent module load events from dmesg."""
    hits = []
    try:
        out = subprocess.check_output(["dmesg"], text=True, timeout=3,
                                       stderr=subprocess.DEVNULL)
        for line in out.splitlines():
            low = line.lower()
            if any(k in low for k in ("loading out-of-tree module",
                                       "module verification failed",
                                       "tainting kernel",
                                       "loading module",
                                       "unknown symbol",
                                       "module license")):
                hits.append(line.strip())
    except Exception:
        pass
    return hits[-20:]

def analyse(proc_mods: dict, sys_mods: set, taint: dict,
            lockdown: str | None, sig_enforce: str | None,
            modprobe: dict, dmesg_hits: list,
            baseline: dict) -> tuple:
    alerts = []
    known         = baseline.get("modules", {})
    known_conf    = baseline.get("modprobe_conf", {})
    proc_names    = set(proc_mods.keys())

    # ── 1. Kernel-level unsigned module taint ──
    if taint.get("unsigned_module_loaded"):
        alerts.append({
            "event":    "UNSIGNED_MODULE_TAINT",
            "severity": "CRITICAL",
            "taint_value": taint.get("value"),
            "flags":    taint.get("flags"),
            "confidence": 0.90,
            "note": ("The kernel is tainted with flag 'E' — an unsigned module "
                     "has been loaded. On a control host with signature "
                     "enforcement this should be impossible. Every observation "
                     "the OS makes about itself is now suspect"),
        })

    if taint.get("force_loaded"):
        alerts.append({
            "event":    "MODULE_FORCE_LOADED",
            "severity": "CRITICAL",
            "confidence": 0.85,
            "note": ("A module was force-loaded, bypassing version and "
                     "signature checks (insmod -f / modprobe --force)"),
        })

    # ── 2. Signature enforcement disabled ──
    if sig_enforce is not None and sig_enforce.upper() in ("N", "0", "OFF"):
        alerts.append({
            "event":    "MODULE_SIG_ENFORCE_DISABLED",
            "severity": "CRITICAL",
            "sig_enforce": sig_enforce,
            "confidence": 0.85,
            "note": ("Kernel module signature enforcement is disabled. Any "
                     "unsigned module can be loaded by root. Enable "
                     "CONFIG_MODULE_SIG_FORCE or kernel lockdown"),
        })

    if lockdown in ("none", None) and sig_enforce is None:
        alerts.append({
            "event":    "KERNEL_LOCKDOWN_NONE",
            "severity": "WARN",
            "lockdown": lockdown,
            "confidence": 0.65,
            "note": ("Kernel lockdown is not active. With lockdown in "
                     "integrity mode, unsigned module loading and direct "
                     "kernel memory access are blocked"),
        })

    # ── 3. /proc/modules vs /sys/module mismatch — rootkit signal ──
    hidden_from_proc = sys_mods - proc_names
    hidden_from_sys  = proc_names - sys_mods
    # Some builtins appear in /sys/module but not /proc/modules legitimately.
    # A module in /proc but NOT /sys is the anomalous direction.
    if hidden_from_sys:
        alerts.append({
            "event":    "MODULE_VIEW_MISMATCH",
            "severity": "CRITICAL",
            "in_proc_not_sys": sorted(hidden_from_sys),
            "confidence": 0.80,
            "note": ("Modules appear in /proc/modules but not /sys/module. "
                     "A module manipulating one view and not the other is "
                     "actively hiding from inspection"),
        })

    # ── 4. Per-module checks ──
    for name, info in proc_mods.items():
        mod_taint = get_module_taint(name)
        srcver    = get_module_srcversion(name)
        initstate = get_module_initstate(name)
        ko_file   = find_module_file(name)

        record = {
            "size":       info.get("size"),
            "taint":      mod_taint.get("taint"),
            "srcversion": srcver,
            "ko_file":    ko_file,
        }

        # New module since baseline
        if name not in known:
            sev = "INFO"
            reasons = []
            if mod_taint.get("unsigned"):
                sev = "CRITICAL"; reasons.append("unsigned")
            if mod_taint.get("out_of_tree"):
                sev = "CRITICAL" if sev == "CRITICAL" else "WARN"
                reasons.append("out-of-tree")
            if ko_file is None:
                sev = "CRITICAL"; reasons.append("no backing .ko file")
            if any(p in name.lower() for p in SUSPICIOUS_PATTERNS):
                sev = "CRITICAL"; reasons.append("suspicious name")

            alerts.append({
                "event":    ("UNAUTHORIZED_KERNEL_MODULE" if sev == "CRITICAL"
                             else "NEW_KERNEL_MODULE"),
                "severity": sev,
                "module":   name,
                "taint":    mod_taint.get("taint"),
                "unsigned": mod_taint.get("unsigned"),
                "out_of_tree": mod_taint.get("out_of_tree"),
                "ko_file":  ko_file,
                "initstate": initstate,
                "reasons":  reasons,
                "confidence": 0.85 if sev == "CRITICAL" else 0.40,
                "note": (("Kernel module loaded since baseline: "
                          + ", ".join(reasons)) if reasons
                         else "New kernel module since baseline"),
            })

        # Module with no file on disk — injected directly
        elif ko_file is None and known[name].get("ko_file") is not None:
            alerts.append({
                "event":    "MODULE_FILE_VANISHED",
                "severity": "CRITICAL",
                "module":   name,
                "was_file": known[name].get("ko_file"),
                "confidence": 0.85,
                "note": ("The .ko file backing this loaded module has been "
                         "deleted from disk while the module stays loaded. "
                         "This is a standard anti-forensics technique"),
            })

        # srcversion changed — different build of the same module name
        elif (known[name].get("srcversion") and srcver
              and known[name]["srcversion"] != srcver):
            alerts.append({
                "event":    "MODULE_SRCVERSION_CHANGED",
                "severity": "CRITICAL",
                "module":   name,
                "was":      known[name]["srcversion"],
                "now":      srcver,
                "confidence": 0.90,
                "note": ("A module with the same name is now a different "
                         "build. The module was replaced — same name, "
                         "different code"),
            })

        # Suspicious name at any time, not just on first appearance
        if any(p in name.lower() for p in SUSPICIOUS_PATTERNS):
            alerts.append({
                "event":    "SUSPICIOUS_DRIVER_LOADED",
                "severity": "CRITICAL",
                "module":   name,
                "matched_pattern": next(p for p in SUSPICIOUS_PATTERNS
                                         if p in name.lower()),
                "confidence": 0.75,
                "note": ("Loaded module name matches a known rootkit or "
                         "hooking pattern"),
            })

        # High-privilege module present
        if any(name.startswith(h) or h in name for h in HIGH_PRIVILEGE_MODULES):
            if name not in known:
                alerts.append({
                    "event":    "HIGH_PRIVILEGE_MODULE",
                    "severity": "WARN",
                    "module":   name,
                    "confidence": 0.55,
                    "note": ("Module with syscall-hooking or direct-DMA "
                             "capability loaded. Legitimate for deliberate "
                             "passthrough or tracing — verify it is expected"),
                })

        known[name] = record

    # ── 5. Module unloaded ──
    for name in list(known.keys()):
        if name not in proc_names:
            alerts.append({
                "event":    "KERNEL_MODULE_UNLOADED",
                "severity": "WARN",
                "module":   name,
                "confidence": 0.50,
                "note": ("Module present at baseline is no longer loaded. If "
                         "this was a security or driver module, verify why"),
            })
            del known[name]

    # ── 6. modprobe config drift ──
    for path, conf in modprobe.items():
        if path in known_conf:
            if known_conf[path].get("sha256") != conf.get("sha256"):
                alerts.append({
                    "event":    "MODPROBE_CONFIG_CHANGED",
                    "severity": "CRITICAL",
                    "path":     path,
                    "lines":    conf.get("lines", [])[:10],
                    "confidence": 0.80,
                    "note": ("modprobe configuration changed. An added install "
                             "or autoload line loads an attacker's module on "
                             "every boot"),
                })
        else:
            alerts.append({
                "event":    "MODPROBE_CONFIG_NEW",
                "severity": "WARN",
                "path":     path,
                "lines":    conf.get("lines", [])[:10],
                "confidence": 0.60,
            })

    # ── 7. dmesg verification failures ──
    for line in dmesg_hits:
        low = line.lower()
        if "verification failed" in low or "tainting kernel" in low:
            alerts.append({
                "event":    "DMESG_MODULE_VERIFICATION_FAILURE",
                "severity": "CRITICAL",
                "log":      line,
                "confidence": 0.85,
                "note": "Kernel logged a module signature verification failure",
            })

    baseline["modules"]       = known
    baseline["modprobe_conf"] = modprobe
    return alerts, baseline

def main():
    log = open(f"module63_{stamp()}.jsonl", "a")

    def emit(event):
        event.setdefault("ts", now_iso())
        log.write(json.dumps(event) + "\n")
        log.flush()

    taint       = get_kernel_taint()
    lockdown    = get_lockdown_state()
    sig_enforce = check_sig_enforce()

    emit({
        "event":  "RUN_START",
        "module": "63_kernel_module_auditor",
        "status": "FUNCTIONAL — no special hardware required",
        "kernel":       os.uname().release,
        "taint_state":  taint,
        "lockdown":     lockdown,
        "sig_enforce":  sig_enforce,
        "checks": [
            "/proc/modules full inventory with drift detection",
            "Per-module taint flags (unsigned / out-of-tree / force-loaded)",
            "Kernel global taint bitmask decode",
            "Kernel lockdown and signature enforcement state",
            "/proc/modules vs /sys/module cross-check (hiding detection)",
            "Loaded modules with no backing .ko file",
            "srcversion drift (same name, different build)",
            "Suspicious module name patterns",
            "modprobe.d / modules-load.d configuration drift",
            "dmesg signature verification failures",
        ],
    })

    baseline = load_baseline()
    first    = not baseline.get("modules")

    while True:
        proc_mods   = parse_proc_modules()
        sys_mods    = list_sys_modules()
        taint       = get_kernel_taint()
        lockdown    = get_lockdown_state()
        sig_enforce = check_sig_enforce()
        modprobe    = scan_modprobe_config()
        dmesg_hits  = check_dmesg_module_loads()

        unsigned = [n for n in proc_mods
                    if get_module_taint(n).get("unsigned")]
        oot      = [n for n in proc_mods
                    if get_module_taint(n).get("out_of_tree")]

        emit({"event": "KERNEL_MODULE_SCAN",
              "modules_loaded":   len(proc_mods),
              "sys_module_count": len(sys_mods),
              "unsigned_modules": unsigned,
              "out_of_tree_modules": oot[:20],
              "taint_flags":      [f["flag"] for f in taint.get("flags", [])],
              "lockdown":         lockdown,
              "modprobe_configs": len(modprobe)})

        if not proc_mods:
            emit({"event": "NO_MODULES_READABLE",
                  "note": ("/proc/modules not readable. Container without "
                           "host kernel visibility, or a hardened environment.")})
            time.sleep(POLL_INTERVAL)
            continue

        if first:
            emit({"event": "KERNEL_MODULE_BASELINE_ESTABLISHED",
                  "modules": len(proc_mods),
                  "unsigned": len(unsigned)})
            baseline["modules"] = {
                n: {"size": i.get("size"),
                    "taint": get_module_taint(n).get("taint"),
                    "srcversion": get_module_srcversion(n),
                    "ko_file": find_module_file(n)}
                for n, i in proc_mods.items()
            }
            baseline["modprobe_conf"] = modprobe
            save_baseline(baseline)
            first = False
            # Static-risk checks still fire on the first pass
            static_alerts, _ = analyse({}, set(), taint, lockdown,
                                        sig_enforce, {}, dmesg_hits,
                                        {"modules": {}, "modprobe_conf": {}})
            for a in static_alerts:
                emit(a)
            time.sleep(POLL_INTERVAL)
            continue

        alerts, baseline = analyse(proc_mods, sys_mods, taint, lockdown,
                                    sig_enforce, modprobe, dmesg_hits,
                                    baseline)
        for a in alerts:
            emit(a)

        if not alerts:
            emit({"event": "KERNEL_MODULE_CLEAN",
                  "modules_checked": len(proc_mods)})

        save_baseline(baseline)
        time.sleep(POLL_INTERVAL)

if __name__ == "__main__":
    main()
