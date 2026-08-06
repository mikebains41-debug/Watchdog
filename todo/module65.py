#!/usr/bin/env python3
"""
Watchdog — Module 65: Process Memory & Ptrace Sentinel
Status: FUNCTIONAL — no special hardware required

Attack vector: every quantum credential on this host lives in the memory of
a running process. IBM_QUANTUM_TOKEN sits in an environment block. Session
tokens sit in SDK objects. Circuit definitions sit in heap allocations
between submission and transmission.

An attacker with the same UID as a QaaS daemon — no root required — can
attach with ptrace and read all of it. PTRACE_ATTACH, PTRACE_PEEKDATA,
done. Or write: PTRACE_POKEDATA injects shellcode into a running daemon
without touching a single file on disk.

Yama's ptrace_scope is the control that stops this, and its default on many
distributions is 0, which means any process may trace any other process
owned by the same user.

Related attacks this covers:
  - Live shellcode injection into a running daemon (writable+executable
    memory regions, or an RWX mapping appearing at runtime)
  - Memory scraping of API bearer tokens
  - process_vm_readv, which reads another process's memory with no ptrace
    attach at all
  - /proc/<pid>/mem opened by a foreign process
  - Core dumps of credential-holding daemons written to disk
  - LD_PRELOAD injection into a daemon's environment

WHAT THIS CHECKS (all functional now):
  - /proc/sys/kernel/yama/ptrace_scope — must be >= 1
  - TracerPid on every process — nonzero means something is attached
  - Sensitive daemons identified by cmdline (python running a quantum SDK,
    scheduler, instrument daemon) and their tracer state specifically
  - RWX memory regions in sensitive processes — writable and executable at
    the same time is the signature of injected code
  - Anonymous executable mappings with no backing file
  - Processes holding /proc/<other-pid>/mem open
  - Core dump configuration: core_pattern piping to a program, and
    whether suid_dumpable allows dumping privileged processes
  - LD_PRELOAD / LD_AUDIT set in a daemon's environment
  - Debugger tooling running (gdb, lldb, strace, ltrace, frida)

Memory contents are never read or logged. Only region flags and metadata.
"""
import os, json, time, datetime, re, glob, stat

POLL_INTERVAL   = 120
BASELINE_FILE   = "/tmp/watchdog_ptrace_baseline.json"

YAMA_PATH       = "/proc/sys/kernel/yama/ptrace_scope"
MIN_PTRACE_SCOPE = 1

# Process cmdline markers that identify a credential-holding daemon
SENSITIVE_MARKERS = [
    "qiskit", "ibm_quantum", "ibm-quantum", "braket", "dwave", "ocean",
    "cirq", "pennylane", "quantum", "qpu", "scheduler", "slurm",
    "watchdog", "module3", "module4", "module5", "module6",
    "instrument", "labone", "zhinst", "pyvisa",
]

# Debuggers and injection frameworks
DEBUGGER_TOOLS = [
    "gdb", "gdbserver", "lldb", "lldb-server",
    "strace", "ltrace", "ptrace", "frida", "frida-server",
    "radare2", "r2", "rr", "drrun", "pin", "valgrind",
    "scanmem", "gameconqueror", "cheat-engine",
]

# Environment variables that hijack a process at load time
INJECTION_ENV_VARS = ["LD_PRELOAD", "LD_AUDIT", "LD_LIBRARY_PATH"]

def now_iso():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()

def stamp():
    return datetime.datetime.now().strftime("%Y%m%d_%H%M%S")

def load_baseline() -> dict:
    try:
        with open(BASELINE_FILE) as f:
            return json.load(f)
    except:
        return {"rwx_counts": {}, "established": now_iso()}

def save_baseline(b: dict):
    try:
        with open(BASELINE_FILE, "w") as f:
            json.dump(b, f, indent=2)
    except:
        pass

def read_file(path: str) -> str | None:
    try:
        with open(path, errors="replace") as f:
            return f.read()
    except (OSError, PermissionError):
        return None

def get_ptrace_scope() -> int | None:
    raw = read_file(YAMA_PATH)
    if raw is None:
        return None
    try:
        return int(raw.strip())
    except ValueError:
        return None

def get_proc_cmdline(pid: str) -> str:
    try:
        with open(f"/proc/{pid}/cmdline", "rb") as f:
            return (f.read().replace(b"\x00", b" ")
                      .decode("utf-8", errors="replace").strip())
    except (OSError, PermissionError):
        return ""

def get_proc_status(pid: str) -> dict:
    """Parse /proc/<pid>/status into a dict."""
    result = {}
    content = read_file(f"/proc/{pid}/status")
    if not content:
        return result
    for line in content.splitlines():
        if ":" not in line:
            continue
        key, _, val = line.partition(":")
        result[key.strip()] = val.strip()
    return result

def is_sensitive_process(cmdline: str) -> bool:
    low = cmdline.lower()
    return any(m in low for m in SENSITIVE_MARKERS)

def scan_tracers() -> list:
    """
    Every process with a nonzero TracerPid. This is the direct evidence
    that something is attached with ptrace right now.
    """
    traced = []
    try:
        for pid in os.listdir("/proc"):
            if not pid.isdigit():
                continue
            status = get_proc_status(pid)
            tracer = status.get("TracerPid", "0")
            try:
                tracer_pid = int(tracer)
            except ValueError:
                continue
            if tracer_pid == 0:
                continue
            cmdline = get_proc_cmdline(pid)
            tracer_cmd = get_proc_cmdline(str(tracer_pid))
            traced.append({
                "pid":         int(pid),
                "name":        status.get("Name", ""),
                "cmdline":     cmdline[:160],
                "tracer_pid":  tracer_pid,
                "tracer_cmd":  tracer_cmd[:160],
                "sensitive":   is_sensitive_process(cmdline),
                "uid":         status.get("Uid", "").split()[0]
                               if status.get("Uid") else None,
            })
    except Exception:
        pass
    return traced

def scan_rwx_regions(pid: str) -> dict:
    """
    Count writable+executable memory regions. A W+X mapping is the
    signature of injected code — normal code is R+X, normal data is R+W.
    """
    result = {"rwx": 0, "anon_exec": 0, "regions": []}
    content = read_file(f"/proc/{pid}/maps")
    if not content:
        return result
    for line in content.splitlines():
        parts = line.split()
        if len(parts) < 2:
            continue
        perms = parts[1]
        path  = parts[5] if len(parts) > 5 else ""
        if "w" in perms and "x" in perms:
            result["rwx"] += 1
            result["regions"].append({"perms": perms,
                                       "path": path or "[anonymous]",
                                       "addr": parts[0]})
        elif "x" in perms and not path:
            result["anon_exec"] += 1
            result["regions"].append({"perms": perms,
                                       "path": "[anonymous-exec]",
                                       "addr": parts[0]})
    return result

def scan_mem_file_holders() -> list:
    """
    Processes holding another process's /proc/<pid>/mem open. Reading that
    file is a direct memory dump with no ptrace attach visible in TracerPid.
    """
    holders = []
    mem_pattern = re.compile(r'^/proc/(\d+)/(mem|pagemap)$')
    try:
        for pid in os.listdir("/proc"):
            if not pid.isdigit():
                continue
            fd_dir = f"/proc/{pid}/fd"
            try:
                for fd in os.listdir(fd_dir):
                    try:
                        target = os.readlink(os.path.join(fd_dir, fd))
                    except (OSError, PermissionError):
                        continue
                    m = mem_pattern.match(target)
                    if m and m.group(1) != pid:
                        target_cmd = get_proc_cmdline(m.group(1))
                        holders.append({
                            "reader_pid":  int(pid),
                            "reader_cmd":  get_proc_cmdline(pid)[:160],
                            "target_pid":  int(m.group(1)),
                            "target_cmd":  target_cmd[:160],
                            "file":        target,
                            "target_sensitive": is_sensitive_process(target_cmd),
                        })
            except (OSError, PermissionError):
                continue
    except Exception:
        pass
    return holders

def scan_debugger_tools() -> list:
    """Debugger or injection framework processes running."""
    found = []
    try:
        for pid in os.listdir("/proc"):
            if not pid.isdigit():
                continue
            cmdline = get_proc_cmdline(pid)
            if not cmdline:
                continue
            base = os.path.basename(cmdline.split()[0]).lower()
            for tool in DEBUGGER_TOOLS:
                if base == tool or base.startswith(tool):
                    found.append({"pid": int(pid), "tool": tool,
                                   "cmd": cmdline[:200]})
                    break
    except Exception:
        pass
    return found

def scan_injection_env() -> list:
    """
    LD_PRELOAD / LD_AUDIT set in any process environment. On a sensitive
    daemon this is code injection at load time.
    """
    found = []
    try:
        for pid in os.listdir("/proc"):
            if not pid.isdigit():
                continue
            environ_path = f"/proc/{pid}/environ"
            try:
                with open(environ_path, "rb") as f:
                    data = f.read(32768)
            except (OSError, PermissionError):
                continue
            text = data.decode("utf-8", errors="replace")
            for var in INJECTION_ENV_VARS:
                marker = f"{var}="
                if marker in text:
                    # Extract just this variable's value
                    for entry in text.split("\x00"):
                        if entry.startswith(marker):
                            value = entry[len(marker):]
                            if not value:
                                continue
                            cmdline = get_proc_cmdline(pid)
                            # LD_LIBRARY_PATH is common and usually benign;
                            # only report it on sensitive processes.
                            if var == "LD_LIBRARY_PATH" and \
                                    not is_sensitive_process(cmdline):
                                continue
                            found.append({
                                "pid":       int(pid),
                                "variable":  var,
                                "value":     value[:200],
                                "cmd":       cmdline[:160],
                                "sensitive": is_sensitive_process(cmdline),
                            })
                            break
    except Exception:
        pass
    return found

def check_core_dump_config() -> dict:
    """
    Core dumps of a credential-holding daemon write its memory — including
    tokens — to disk.
    """
    return {
        "core_pattern":   (read_file("/proc/sys/kernel/core_pattern") or "").strip(),
        "suid_dumpable":  (read_file("/proc/sys/fs/suid_dumpable") or "").strip(),
        "core_uses_pid":  (read_file("/proc/sys/kernel/core_uses_pid") or "").strip(),
    }

def find_sensitive_processes() -> list:
    """Every running process that looks like it holds quantum credentials."""
    found = []
    try:
        for pid in os.listdir("/proc"):
            if not pid.isdigit():
                continue
            cmdline = get_proc_cmdline(pid)
            if cmdline and is_sensitive_process(cmdline):
                status = get_proc_status(pid)
                found.append({
                    "pid":     int(pid),
                    "name":    status.get("Name", ""),
                    "cmdline": cmdline[:200],
                    "uid":     status.get("Uid", "").split()[0]
                               if status.get("Uid") else None,
                    "tracer":  status.get("TracerPid", "0"),
                })
    except Exception:
        pass
    return found

def analyse(scope: int | None, traced: list, mem_holders: list,
            debuggers: list, injections: list, core_cfg: dict,
            sensitive: list, baseline: dict) -> tuple:
    alerts = []
    known_rwx = baseline.get("rwx_counts", {})

    # ── 1. Yama ptrace_scope ──
    if scope is None:
        alerts.append({
            "event":    "YAMA_UNAVAILABLE",
            "severity": "WARN",
            "confidence": 0.60,
            "note": ("Yama LSM is not available on this kernel. There is no "
                     "ptrace restriction — any process can attach to any "
                     "other process owned by the same user and read its "
                     "memory, including API tokens"),
        })
    elif scope < MIN_PTRACE_SCOPE:
        alerts.append({
            "event":    "INSECURE_YAMA_SCOPE",
            "severity": "CRITICAL",
            "ptrace_scope": scope,
            "minimum":  MIN_PTRACE_SCOPE,
            "confidence": 0.90,
            "remediation": "sysctl -w kernel.yama.ptrace_scope=1",
            "note": ("ptrace_scope is 0 — unrestricted. Any process running "
                     "as the same user as a QaaS daemon can attach with "
                     "PTRACE_ATTACH and read every credential and circuit out "
                     "of its memory. No root required"),
        })

    # ── 2. Active tracers ──
    for t in traced:
        sev = "CRITICAL" if t["sensitive"] else "WARN"
        alerts.append({
            "event":    "PTRACE_ATTACH_DETECTED",
            "severity": sev,
            "traced_pid":  t["pid"],
            "traced_cmd":  t["cmdline"],
            "tracer_pid":  t["tracer_pid"],
            "tracer_cmd":  t["tracer_cmd"],
            "sensitive_target": t["sensitive"],
            "confidence": 0.90 if t["sensitive"] else 0.65,
            "note": (("A debugger is attached to a process holding quantum "
                      "credentials. It can read every token and circuit in "
                      "that process's memory, and write to it")
                     if t["sensitive"]
                     else "A process is being traced by another process"),
        })

    # ── 3. /proc/<pid>/mem readers ──
    for h in mem_holders:
        sev = "CRITICAL" if h["target_sensitive"] else "WARN"
        alerts.append({
            "event":    "PROC_MEM_ACCESS",
            "severity": sev,
            "reader_pid":  h["reader_pid"],
            "reader_cmd":  h["reader_cmd"],
            "target_pid":  h["target_pid"],
            "target_cmd":  h["target_cmd"],
            "file":        h["file"],
            "confidence": 0.90 if h["target_sensitive"] else 0.70,
            "note": ("A process holds another process's memory file open. "
                     "This reads memory directly without a ptrace attach "
                     "appearing in TracerPid"),
        })

    # ── 4. Debugger tooling ──
    for d in debuggers:
        alerts.append({
            "event":    "DEBUGGER_TOOL_RUNNING",
            "severity": "WARN",
            "pid":      d["pid"],
            "tool":     d["tool"],
            "cmd":      d["cmd"],
            "confidence": 0.65,
            "note": (f"{d['tool']} is running. On a production control host "
                     "a debugger or memory-inspection tool has no routine "
                     "purpose"),
        })

    # ── 5. LD_PRELOAD / LD_AUDIT injection ──
    for inj in injections:
        sev = "CRITICAL" if inj["sensitive"] else "WARN"
        alerts.append({
            "event":    "LIBRARY_INJECTION_ENV",
            "severity": sev,
            "pid":      inj["pid"],
            "variable": inj["variable"],
            "value":    inj["value"],
            "cmd":      inj["cmd"],
            "confidence": 0.85 if inj["sensitive"] else 0.60,
            "note": ((f"{inj['variable']} is set on a process holding quantum "
                      "credentials. An attacker-supplied library is loaded "
                      "into that process and intercepts every function it calls")
                     if inj["sensitive"]
                     else f"{inj['variable']} set on a running process"),
        })

    # ── 6. RWX memory in sensitive processes ──
    for proc in sensitive:
        pid = str(proc["pid"])
        regions = scan_rwx_regions(pid)
        key = proc["cmdline"][:60]

        if regions["rwx"] > 0:
            prev = known_rwx.get(key, {}).get("rwx", 0)
            if regions["rwx"] > prev:
                alerts.append({
                    "event":    "RWX_MEMORY_REGION",
                    "severity": "CRITICAL",
                    "pid":      proc["pid"],
                    "cmd":      proc["cmdline"][:160],
                    "rwx_count": regions["rwx"],
                    "previous":  prev,
                    "regions":   regions["regions"][:5],
                    "confidence": 0.80,
                    "note": ("A writable AND executable memory region appeared "
                             "in a credential-holding process. Normal code is "
                             "read+execute; normal data is read+write. W+X "
                             "together is the signature of injected code"),
                })

        if regions["anon_exec"] > 0:
            prev_anon = known_rwx.get(key, {}).get("anon_exec", 0)
            if regions["anon_exec"] > prev_anon:
                alerts.append({
                    "event":    "ANONYMOUS_EXEC_MAPPING",
                    "severity": "WARN",
                    "pid":      proc["pid"],
                    "cmd":      proc["cmdline"][:160],
                    "anon_exec_count": regions["anon_exec"],
                    "confidence": 0.60,
                    "note": ("Executable memory with no backing file. Common "
                             "in JIT runtimes, but also how shellcode lands"),
                })

        known_rwx[key] = {"rwx": regions["rwx"],
                           "anon_exec": regions["anon_exec"]}

    # ── 7. Core dump configuration ──
    pattern = core_cfg.get("core_pattern", "")
    if pattern.startswith("|"):
        alerts.append({
            "event":    "CORE_PATTERN_PIPES_TO_PROGRAM",
            "severity": "WARN",
            "core_pattern": pattern,
            "confidence": 0.60,
            "note": ("Core dumps pipe to a program. If a credential-holding "
                     "daemon crashes, its full memory — tokens included — is "
                     "handed to that program"),
        })
    elif pattern and pattern != "core":
        alerts.append({
            "event":    "CORE_PATTERN_CUSTOM",
            "severity": "INFO",
            "core_pattern": pattern,
            "confidence": 0.35,
        })

    if core_cfg.get("suid_dumpable") in ("1", "2"):
        alerts.append({
            "event":    "SUID_DUMPABLE_ENABLED",
            "severity": "WARN",
            "suid_dumpable": core_cfg.get("suid_dumpable"),
            "confidence": 0.65,
            "remediation": "sysctl -w fs.suid_dumpable=0",
            "note": ("Privileged processes can be core-dumped, writing their "
                     "memory to disk"),
        })

    baseline["rwx_counts"] = known_rwx
    return alerts, baseline

def main():
    log = open(f"module65_{stamp()}.jsonl", "a")

    def emit(event):
        event.setdefault("ts", now_iso())
        log.write(json.dumps(event) + "\n")
        log.flush()

    scope = get_ptrace_scope()

    emit({
        "event":  "RUN_START",
        "module": "65_ptrace_memory_sentinel",
        "status": "FUNCTIONAL — no special hardware required",
        "ptrace_scope": scope,
        "min_required": MIN_PTRACE_SCOPE,
        "checks": [
            "Yama ptrace_scope enforcement level",
            "TracerPid on every process (active ptrace attach)",
            "Sensitive daemon identification by cmdline",
            "RWX memory regions in credential-holding processes",
            "Anonymous executable mappings",
            "/proc/<pid>/mem held open by a foreign process",
            "Debugger and injection framework processes",
            "LD_PRELOAD / LD_AUDIT injection into daemons",
            "Core dump configuration (core_pattern, suid_dumpable)",
        ],
        "privacy": "Memory contents are never read or logged — flags and metadata only",
    })

    baseline = load_baseline()

    while True:
        scope       = get_ptrace_scope()
        traced      = scan_tracers()
        mem_holders = scan_mem_file_holders()
        debuggers   = scan_debugger_tools()
        injections  = scan_injection_env()
        core_cfg    = check_core_dump_config()
        sensitive   = find_sensitive_processes()

        emit({"event": "MEMORY_SCAN",
              "ptrace_scope":       scope,
              "traced_processes":   len(traced),
              "mem_file_holders":   len(mem_holders),
              "debugger_tools":     len(debuggers),
              "injection_env_vars": len(injections),
              "sensitive_processes": len(sensitive),
              "core_pattern":       core_cfg.get("core_pattern", "")[:80]})

        alerts, baseline = analyse(scope, traced, mem_holders, debuggers,
                                    injections, core_cfg, sensitive, baseline)
        for a in alerts:
            emit(a)

        if not alerts:
            emit({"event": "MEMORY_INTEGRITY_OK",
                  "ptrace_scope":        scope,
                  "sensitive_processes": len(sensitive),
                  "traced":              0})

        save_baseline(baseline)
        time.sleep(POLL_INTERVAL)

if __name__ == "__main__":
    main()
