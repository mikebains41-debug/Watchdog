#!/usr/bin/env python3
"""
Watchdog — Module 82: Container Runtime Isolation Verifier
Status: FUNCTIONAL — no special hardware required

THE PROBLEM: a RuntimeClass that does not apply is worse than none.

Standard containers share the host kernel through runc. A single kernel
escape breaks the whole machine. Hardened runtimes exist for exactly this:

  gVisor (runsc) — Google's user-space kernel, Sentry. The container
  believes it is making Linux syscalls; gVisor intercepts them and drops
  dangerous ones before they reach the real kernel.

  Kata Containers — drops the workload into a hardware-isolated microVM
  under KVM, with zero shared kernel between workloads.

Both are configured in Kubernetes via RuntimeClass. The failure mode that
matters: the RuntimeClass is declared, the manifest looks right, the pod
schedules — and the handler silently falls back to runc because the
runtime binary is missing on that node, or the handler name does not match
what containerd has configured. The workload runs unisolated while the
operator believes it is sandboxed.

That is the exact category of failure behind the July 2026 evaluation
escape: the containment was believed to be in place and was not.

WHAT THIS MODULE VERIFIES — all functional now:
  1. Which runtime a container is ACTUALLY running under, read from the
     process tree and cgroup, not from the manifest.
  2. gVisor presence: the runsc binary, its version, and whether any
     process is actually running under Sentry.
  3. Kata presence: kata-runtime, the shim, and active microVMs.
  4. containerd and CRI-O runtime handler configuration — whether the
     handler a RuntimeClass names actually exists.
  5. Declared RuntimeClass in pod specs versus the runtime observed.
  6. Seccomp profile applied per process, from /proc/<pid>/status.
  7. AppArmor and SELinux confinement state per process.
  8. Capability sets — a container holding CAP_SYS_ADMIN is not isolated
     regardless of runtime.
  9. Namespace sharing: host PID, network, IPC, and user namespace.
 10. Writable /proc and /sys mounts inside containers.

Detection only. Runtime configuration is an operator action.
"""
import json, os, time, datetime, glob, re, subprocess, hashlib

POLL_INTERVAL   = 300
STATE_FILE      = "/tmp/watchdog_runtime_isolation.json"

HARDENED_RUNTIMES = {
    "runsc":        "gVisor — user-space kernel (Sentry)",
    "kata":         "Kata Containers — hardware-isolated microVM",
    "kata-runtime": "Kata Containers",
    "kata-qemu":    "Kata Containers (QEMU)",
    "kata-fc":      "Kata Containers (Firecracker)",
    "crun-kvm":     "crun with KVM isolation",
    "gvisor":       "gVisor",
    "firecracker":  "Firecracker microVM",
}

WEAK_RUNTIMES = {
    "runc":  "runc — shares the host kernel, no additional isolation",
    "crun":  "crun — shares the host kernel, no additional isolation",
    "docker-runc": "runc via Docker",
}

CONTAINERD_CONFIGS = [
    "/etc/containerd/config.toml",
    "/etc/containerd/config.v2.toml",
    "/var/lib/rancher/k3s/agent/etc/containerd/config.toml",
]
CRIO_CONFIGS = [
    "/etc/crio/crio.conf",
    "/etc/crio/crio.conf.d/*.conf",
]
DOCKER_CONFIG = "/etc/docker/daemon.json"

# Capabilities that defeat container isolation
DANGEROUS_CAPS = {
    "cap_sys_admin":    "mount, namespace manipulation — effectively root on host",
    "cap_sys_ptrace":   "attach to and read any process",
    "cap_sys_module":   "load kernel modules",
    "cap_sys_rawio":    "raw device and port I/O",
    "cap_dac_read_search": "bypass file read permission checks",
    "cap_sys_boot":     "reboot the host",
    "cap_net_admin":    "network stack configuration",
    "cap_setuid":       "arbitrary uid change",
    "cap_bpf":          "load eBPF programs",
    "cap_perfmon":      "performance monitoring across the host",
}

# Capability bitmask positions
CAP_NAMES = {
    0: "cap_chown", 1: "cap_dac_override", 2: "cap_dac_read_search",
    3: "cap_fowner", 4: "cap_fsetid", 5: "cap_kill", 6: "cap_setgid",
    7: "cap_setuid", 8: "cap_setpcap", 9: "cap_linux_immutable",
    10: "cap_net_bind_service", 11: "cap_net_broadcast", 12: "cap_net_admin",
    13: "cap_net_raw", 14: "cap_ipc_lock", 15: "cap_ipc_owner",
    16: "cap_sys_module", 17: "cap_sys_rawio", 18: "cap_sys_chroot",
    19: "cap_sys_ptrace", 20: "cap_sys_pacct", 21: "cap_sys_admin",
    22: "cap_sys_boot", 23: "cap_sys_nice", 24: "cap_sys_resource",
    25: "cap_sys_time", 26: "cap_sys_tty_config", 27: "cap_mknod",
    28: "cap_lease", 29: "cap_audit_write", 30: "cap_audit_control",
    31: "cap_setfcap", 32: "cap_mac_override", 33: "cap_mac_admin",
    34: "cap_syslog", 35: "cap_wake_alarm", 36: "cap_block_suspend",
    37: "cap_audit_read", 38: "cap_perfmon", 39: "cap_bpf",
    40: "cap_checkpoint_restore",
}

SECCOMP_MODES = {
    "0": ("disabled", "NO seccomp filter — full syscall surface exposed"),
    "1": ("strict",   "strict mode"),
    "2": ("filtered", "seccomp-bpf filter active"),
}

AGENT_MARKERS = ["agent", "langchain", "openai", "anthropic", "claude",
                 "gpt", "llm", "inference", "eval", "sandbox", "exploitgym"]

def now_iso():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()

def stamp():
    return datetime.datetime.now().strftime("%Y%m%d_%H%M%S")

def load_state():
    try:
        with open(STATE_FILE) as f:
            return json.load(f)
    except:
        return {"runtime_config_hash": {}, "established": now_iso()}

def save_state(s):
    try:
        with open(STATE_FILE, "w") as f:
            json.dump(s, f)
    except:
        pass

def which(binary):
    for d in os.environ.get("PATH", "/usr/bin:/bin:/usr/sbin:/sbin").split(":"):
        p = os.path.join(d, binary)
        if os.path.isfile(p) and os.access(p, os.X_OK):
            return p
    for d in ("/usr/local/bin", "/opt/kata/bin", "/usr/bin", "/usr/sbin"):
        p = os.path.join(d, binary)
        if os.path.isfile(p):
            return p
    return None

def detect_installed_runtimes():
    """Which hardened runtimes are actually installed on this node."""
    found = {}
    for binary in ("runsc", "kata-runtime", "containerd-shim-kata-v2",
                   "containerd-shim-runsc-v1", "crun", "runc",
                   "firecracker", "cloud-hypervisor"):
        path = which(binary)
        if path:
            entry = {"path": path}
            try:
                out = subprocess.check_output([path, "--version"], text=True,
                                               timeout=5,
                                               stderr=subprocess.STDOUT)
                entry["version"] = out.strip().splitlines()[0][:120]
            except Exception:
                pass
            found[binary] = entry
    return found

def detect_process_runtime(pid):
    """
    What runtime is this process ACTUALLY under? Determined from the
    process tree and kernel-visible markers, not from any manifest.
    """
    markers = {}

    # gVisor sets a distinctive comm and Sentry appears in the tree
    try:
        with open(f"/proc/{pid}/status") as f:
            status = f.read()
        # gVisor's Sentry presents a synthetic /proc; kernel version differs
        markers["status_readable"] = True
    except Exception:
        markers["status_readable"] = False

    # Walk up the parent chain looking for a runtime shim
    chain = []
    cur = pid
    for _ in range(12):
        try:
            with open(f"/proc/{cur}/stat") as f:
                fields = f.read().split()
            ppid = int(fields[3])
            with open(f"/proc/{cur}/cmdline", "rb") as f:
                cmd = (f.read().replace(b"\x00", b" ")
                         .decode("utf-8", errors="replace").strip())
            if cmd:
                chain.append(cmd[:120])
            if ppid <= 1:
                break
            cur = ppid
        except Exception:
            break
    markers["process_chain"] = chain

    chain_text = " ".join(chain).lower()
    runtime = None
    for name in HARDENED_RUNTIMES:
        if name in chain_text:
            runtime = name
            break
    if not runtime:
        for name in WEAK_RUNTIMES:
            if name in chain_text:
                runtime = name
                break
    markers["detected_runtime"] = runtime

    # gVisor exposes a distinctive kernel version string inside the sandbox
    try:
        with open("/proc/version") as f:
            ver = f.read().strip()
        markers["kernel_version"] = ver[:120]
        if "gvisor" in ver.lower() or "gVisor" in ver:
            markers["detected_runtime"] = "runsc"
    except Exception:
        pass

    return markers

def read_process_isolation(pid):
    """Seccomp, capabilities, and confinement for one process."""
    result = {"pid": pid}

    try:
        with open(f"/proc/{pid}/status") as f:
            for line in f:
                k, _, v = line.partition(":")
                k = k.strip()
                v = v.strip()
                if k == "Seccomp":
                    result["seccomp"] = v
                elif k == "Seccomp_filters":
                    result["seccomp_filters"] = v
                elif k == "CapEff":
                    result["cap_eff"] = v
                elif k == "CapBnd":
                    result["cap_bnd"] = v
                elif k == "NoNewPrivs":
                    result["no_new_privs"] = v
                elif k == "Name":
                    result["name"] = v
    except Exception:
        pass

    # AppArmor
    try:
        with open(f"/proc/{pid}/attr/current") as f:
            result["apparmor"] = f.read().strip().replace("\x00", "")
    except Exception:
        pass

    # Namespaces — compare against PID 1 to detect host namespace sharing
    ns = {}
    for name in ("pid", "net", "ipc", "uts", "mnt", "user", "cgroup"):
        try:
            ns[name] = os.readlink(f"/proc/{pid}/ns/{name}")
        except Exception:
            pass
    result["namespaces"] = ns

    try:
        with open(f"/proc/{pid}/cmdline", "rb") as f:
            result["cmd"] = (f.read().replace(b"\x00", b" ")
                               .decode("utf-8", errors="replace").strip()[:200])
    except Exception:
        result["cmd"] = ""

    return result

def decode_capabilities(hex_str):
    """Decode a capability bitmask into names."""
    try:
        value = int(hex_str, 16)
    except (TypeError, ValueError):
        return []
    caps = []
    for bit, name in CAP_NAMES.items():
        if value & (1 << bit):
            caps.append(name)
    return caps

def get_host_namespaces():
    ns = {}
    for name in ("pid", "net", "ipc", "uts", "mnt", "user", "cgroup"):
        try:
            ns[name] = os.readlink(f"/proc/1/ns/{name}")
        except Exception:
            pass
    return ns

def find_containerized_processes():
    """Processes running inside a container, found via cgroup membership."""
    found = []
    try:
        for pid in os.listdir("/proc"):
            if not pid.isdigit():
                continue
            try:
                with open(f"/proc/{pid}/cgroup") as f:
                    cg = f.read()
            except Exception:
                continue
            if not any(m in cg for m in ("docker", "kubepods", "containerd",
                                          "crio", "libpod", "machine.slice")):
                continue
            try:
                with open(f"/proc/{pid}/cmdline", "rb") as f:
                    cmd = (f.read().replace(b"\x00", b" ")
                             .decode("utf-8", errors="replace").strip())
            except Exception:
                cmd = ""
            if not cmd:
                continue
            container_id = None
            m = re.search(r'([0-9a-f]{64})', cg)
            if m:
                container_id = m.group(1)[:12]
            found.append({"pid": int(pid), "cmd": cmd[:200],
                          "container_id": container_id,
                          "cgroup": cg.strip().splitlines()[-1][:160]
                                     if cg.strip() else ""})
    except Exception:
        pass
    return found

def parse_containerd_runtimes():
    """Which runtime handlers containerd actually has configured."""
    handlers = {}
    for path in CONTAINERD_CONFIGS:
        if not os.path.isfile(path):
            continue
        try:
            with open(path, errors="replace") as f:
                content = f.read(512 * 1024)
        except Exception:
            continue
        # containerd runtime handler blocks
        for m in re.finditer(
                r'\[plugins\.[^\]]*containerd\.runtimes\.([A-Za-z0-9_\-]+)\]',
                content):
            name = m.group(1)
            block = content[m.end():m.end() + 600]
            rt = re.search(r'runtime_type\s*=\s*"([^"]+)"', block)
            binpath = re.search(r'BinaryName\s*=\s*"([^"]+)"', block)
            handlers[name] = {
                "config": path,
                "runtime_type": rt.group(1) if rt else None,
                "binary": binpath.group(1) if binpath else None,
            }
    return handlers

def parse_crio_runtimes():
    handlers = {}
    paths = []
    for pattern in CRIO_CONFIGS:
        paths.extend(glob.glob(pattern))
    for path in paths:
        if not os.path.isfile(path):
            continue
        try:
            with open(path, errors="replace") as f:
                content = f.read(512 * 1024)
        except Exception:
            continue
        for m in re.finditer(r'\[crio\.runtime\.runtimes\.([A-Za-z0-9_\-]+)\]',
                             content):
            name = m.group(1)
            block = content[m.end():m.end() + 400]
            rpath = re.search(r'runtime_path\s*=\s*"([^"]+)"', block)
            handlers[name] = {"config": path,
                              "binary": rpath.group(1) if rpath else None}
    return handlers

def find_runtimeclass_declarations():
    """RuntimeClass names declared in pod specs on this node."""
    declared = {}
    for spec in glob.glob("/var/lib/kubelet/pods/*/**/*.json", recursive=True)[:400]:
        try:
            if os.path.getsize(spec) > 512 * 1024:
                continue
            with open(spec, errors="replace") as f:
                content = f.read()
        except Exception:
            continue
        m = re.search(r'"runtimeClassName"\s*:\s*"([^"]+)"', content)
        if m:
            declared[spec] = m.group(1)
    return declared

def check_writable_proc_sys(pid):
    """Writable /proc or /sys inside a container defeats isolation."""
    findings = []
    try:
        with open(f"/proc/{pid}/mountinfo") as f:
            for line in f:
                parts = line.split()
                if len(parts) < 6:
                    continue
                mount_point = parts[4]
                opts = parts[5]
                if mount_point in ("/proc", "/sys") or \
                        mount_point.startswith("/proc/") or \
                        mount_point.startswith("/sys/"):
                    if "ro" not in opts.split(","):
                        findings.append({"mount": mount_point,
                                          "options": opts[:60]})
    except Exception:
        pass
    return findings

def is_agent(cmd):
    low = cmd.lower()
    return any(m in low for m in AGENT_MARKERS)

def analyse(installed, containers, handlers, declared, host_ns, state):
    alerts = []

    hardened_installed = {k: v for k, v in installed.items()
                          if k in ("runsc", "kata-runtime",
                                   "containerd-shim-kata-v2",
                                   "containerd-shim-runsc-v1")}

    # ── 1. RuntimeClass declared but handler missing ──
    for spec, rc_name in declared.items():
        handler = handlers.get(rc_name)
        if not handler:
            alerts.append({
                "event":    "RUNTIMECLASS_HANDLER_MISSING",
                "severity": "CRITICAL",
                "spec":     spec,
                "runtimeclass": rc_name,
                "configured_handlers": sorted(handlers.keys()),
                "confidence": 0.90,
                "note": (f"A pod declares runtimeClassName '{rc_name}' but no "
                         "matching runtime handler is configured on this node. "
                         "The workload does not get the isolation the manifest "
                         "claims. A RuntimeClass that does not apply is worse "
                         "than none — the operator believes the workload is "
                         "sandboxed and it is not"),
                "action": f"Configure the '{rc_name}' handler in containerd, or correct the manifest",
            })
            continue

        binary = handler.get("binary")
        if binary and not os.path.isfile(binary):
            alerts.append({
                "event":    "RUNTIME_BINARY_MISSING",
                "severity": "CRITICAL",
                "runtimeclass": rc_name,
                "expected_binary": binary,
                "config":   handler.get("config"),
                "confidence": 0.90,
                "note": ("The runtime handler is configured but its binary "
                         "does not exist on this node. Container creation will "
                         "fail or silently fall back"),
            })

    # ── 2. Hardened runtime configured but not installed ──
    for name, h in handlers.items():
        rt_type = (h.get("runtime_type") or "").lower()
        binary  = (h.get("binary") or "").lower()
        wants_hardened = any(k in rt_type or k in binary
                             for k in ("runsc", "kata", "gvisor"))
        if wants_hardened and not hardened_installed:
            alerts.append({
                "event":    "HARDENED_RUNTIME_NOT_INSTALLED",
                "severity": "CRITICAL",
                "handler":  name,
                "runtime_type": h.get("runtime_type"),
                "config":   h.get("config"),
                "installed_runtimes": sorted(installed.keys()),
                "confidence": 0.85,
                "note": ("containerd is configured for a hardened runtime but "
                         "no gVisor or Kata binary is present on this node"),
            })

    # ── 3. Per-container isolation state ──
    for c in containers:
        pid = c["pid"]
        iso = read_process_isolation(pid)
        rt  = detect_process_runtime(pid)
        agent = is_agent(c["cmd"])

        detected = rt.get("detected_runtime")
        c["runtime"] = detected

        # Running under a weak runtime while a hardened one is available
        if detected in WEAK_RUNTIMES and hardened_installed:
            alerts.append({
                "event":    "CONTAINER_UNHARDENED_RUNTIME",
                "severity": "CRITICAL" if agent else "WARN",
                "pid":      pid,
                "container_id": c.get("container_id"),
                "cmd":      c["cmd"][:160],
                "actual_runtime": detected,
                "runtime_note":   WEAK_RUNTIMES[detected],
                "available_hardened": sorted(hardened_installed.keys()),
                "is_agent_workload": agent,
                "confidence": 0.80 if agent else 0.60,
                "note": ("This container is running under a runtime that "
                         "shares the host kernel, while a hardened runtime is "
                         "installed and available on this node"
                         + (". This is an AI agent workload — the exact class "
                            "that needs kernel isolation" if agent else "")),
            })

        # Seccomp disabled
        seccomp = iso.get("seccomp")
        if seccomp == "0":
            alerts.append({
                "event":    "CONTAINER_NO_SECCOMP",
                "severity": "CRITICAL" if agent else "WARN",
                "pid":      pid,
                "container_id": c.get("container_id"),
                "cmd":      c["cmd"][:160],
                "is_agent_workload": agent,
                "confidence": 0.80 if agent else 0.60,
                "note": ("No seccomp filter is applied to this container "
                         "process. The full host syscall surface is reachable, "
                         "including the calls used in kernel escape chains"),
                "action": "Apply a seccomp profile — RuntimeDefault at minimum",
            })

        # Dangerous capabilities
        caps = decode_capabilities(iso.get("cap_eff"))
        dangerous = [c_ for c_ in caps if c_ in DANGEROUS_CAPS]
        if dangerous:
            sev = "CRITICAL" if ("cap_sys_admin" in dangerous or agent) else "WARN"
            alerts.append({
                "event":    "CONTAINER_DANGEROUS_CAPABILITIES",
                "severity": sev,
                "pid":      pid,
                "container_id": c.get("container_id"),
                "cmd":      c["cmd"][:160],
                "capabilities": dangerous,
                "descriptions": {d: DANGEROUS_CAPS[d] for d in dangerous},
                "is_agent_workload": agent,
                "confidence": 0.85 if sev == "CRITICAL" else 0.60,
                "note": ("Container holds capabilities that defeat isolation "
                         "regardless of runtime. CAP_SYS_ADMIN in particular is "
                         "effectively root on the host"),
            })

        # No AppArmor / SELinux confinement
        aa = iso.get("apparmor", "")
        if aa in ("unconfined", "") and agent:
            alerts.append({
                "event":    "CONTAINER_UNCONFINED_MAC",
                "severity": "WARN",
                "pid":      pid,
                "cmd":      c["cmd"][:160],
                "apparmor": aa or "none",
                "confidence": 0.60,
                "note": ("Agent workload container has no AppArmor or SELinux "
                         "confinement applied"),
            })

        # NoNewPrivs off
        if iso.get("no_new_privs") == "0" and agent:
            alerts.append({
                "event":    "CONTAINER_NO_NEW_PRIVS_OFF",
                "severity": "WARN",
                "pid":      pid,
                "cmd":      c["cmd"][:160],
                "confidence": 0.65,
                "note": ("NoNewPrivs is not set. A process inside this "
                         "container can gain privileges through setuid "
                         "binaries"),
            })

        # Host namespace sharing
        shared = []
        for name, host_val in host_ns.items():
            if iso.get("namespaces", {}).get(name) == host_val:
                shared.append(name)
        # mnt and cgroup often match legitimately for some setups; flag the
        # ones that unambiguously break isolation.
        critical_shared = [s for s in shared if s in ("pid", "net", "ipc", "user")]
        if critical_shared:
            alerts.append({
                "event":    "CONTAINER_HOST_NAMESPACE_SHARED",
                "severity": "CRITICAL",
                "pid":      pid,
                "container_id": c.get("container_id"),
                "cmd":      c["cmd"][:160],
                "shared_namespaces": critical_shared,
                "is_agent_workload": agent,
                "confidence": 0.85,
                "note": ("This container shares host namespaces. Sharing the "
                         "PID namespace exposes every host process; sharing "
                         "the network namespace exposes every host socket; "
                         "sharing the user namespace removes uid isolation"),
            })

        # Writable /proc or /sys
        writable = check_writable_proc_sys(pid)
        if writable and agent:
            alerts.append({
                "event":    "CONTAINER_WRITABLE_PROC_SYS",
                "severity": "CRITICAL",
                "pid":      pid,
                "cmd":      c["cmd"][:160],
                "mounts":   writable[:6],
                "confidence": 0.80,
                "note": ("An agent container has writable /proc or /sys. "
                         "Writing to /proc/sys or /sys/kernel reconfigures the "
                         "host kernel from inside the container"),
            })

    # ── 4. No hardened runtime at all, with agent workloads present ──
    agent_containers = [c for c in containers if is_agent(c["cmd"])]
    if agent_containers and not hardened_installed:
        alerts.append({
            "event":    "NO_HARDENED_RUNTIME_AVAILABLE",
            "severity": "CRITICAL",
            "agent_containers": len(agent_containers),
            "installed_runtimes": sorted(installed.keys()),
            "confidence": 0.75,
            "note": (f"{len(agent_containers)} agent workload containers are "
                     "running and no hardened runtime (gVisor or Kata) is "
                     "installed on this node. Every one shares the host "
                     "kernel — a single kernel escape breaks the machine. "
                     "This is the containment gap category behind the July "
                     "2026 evaluation escape"),
            "action": ("Install runsc (gVisor) or kata-runtime and route agent "
                        "workloads to it via RuntimeClass"),
        })

    # ── 5. Runtime config drift ──
    known = state.setdefault("runtime_config_hash", {})
    for path in CONTAINERD_CONFIGS + [DOCKER_CONFIG]:
        if not os.path.isfile(path):
            continue
        try:
            h = hashlib.sha256(open(path, "rb").read()).hexdigest()
        except Exception:
            continue
        prev = known.get(path)
        if prev and prev != h:
            alerts.append({
                "event":    "RUNTIME_CONFIG_MODIFIED",
                "severity": "CRITICAL",
                "config":   path,
                "confidence": 0.80,
                "note": ("Container runtime configuration changed. Verify no "
                         "runtime handler was removed, redirected, or "
                         "downgraded to runc"),
            })
        known[path] = h

    return alerts, state

def main():
    log = open(f"module82_{stamp()}.jsonl", "a")

    def emit(event):
        event.setdefault("ts", now_iso())
        log.write(json.dumps(event) + "\n")
        log.flush()

    installed = detect_installed_runtimes()

    emit({
        "event":  "RUN_START",
        "module": "82_container_runtime_isolation",
        "status": "FUNCTIONAL — no special hardware required",
        "problem": ("A RuntimeClass that does not apply is worse than none. "
                     "The manifest declares gVisor or Kata, the pod schedules, "
                     "and the handler silently falls back to runc because the "
                     "binary is missing or the handler name does not match. "
                     "The workload runs unisolated while the operator believes "
                     "it is sandboxed"),
        "hardened_runtimes": HARDENED_RUNTIMES,
        "verifies": [
            "Actual runtime per container, read from the process tree",
            "gVisor and Kata installation and version",
            "containerd / CRI-O handler configuration",
            "RuntimeClass declared vs handler present vs binary present",
            "Seccomp filter applied per process",
            "AppArmor / SELinux confinement",
            "Effective capability set",
            "Host namespace sharing (pid, net, ipc, user)",
            "Writable /proc and /sys inside containers",
            "Runtime configuration drift",
        ],
        "installed_runtimes": {k: v.get("version", v.get("path"))
                                for k, v in installed.items()},
        "mode": "detection only — runtime configuration is an operator action",
    })

    state = load_state()
    host_ns = get_host_namespaces()

    while True:
        installed  = detect_installed_runtimes()
        containers = find_containerized_processes()
        handlers   = parse_containerd_runtimes()
        handlers.update(parse_crio_runtimes())
        declared   = find_runtimeclass_declarations()

        emit({"event": "RUNTIME_SCAN",
              "installed_runtimes": sorted(installed.keys()),
              "containers":         len(containers),
              "configured_handlers": sorted(handlers.keys()),
              "runtimeclass_declarations": len(declared),
              "declared_classes": sorted(set(declared.values()))})

        if not containers and not handlers:
            emit({"event": "NO_CONTAINER_RUNTIME",
                  "note": ("No containers or runtime configuration found on "
                           "this host. This module activates on a container "
                           "host or Kubernetes node.")})
            time.sleep(POLL_INTERVAL)
            continue

        alerts, state = analyse(installed, containers, handlers,
                                declared, host_ns, state)
        for a in alerts:
            emit(a)

        if not alerts:
            emit({"event": "RUNTIME_ISOLATION_OK",
                  "containers": len(containers),
                  "hardened_available": [k for k in installed
                                          if k in ("runsc", "kata-runtime")]})

        save_state(state)
        time.sleep(POLL_INTERVAL)

if __name__ == "__main__":
    main()
