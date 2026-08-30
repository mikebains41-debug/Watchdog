#!/usr/bin/env python3
"""
Watchdog — Module 58: Control-Plane Zero-Trust Interceptor
Status: FUNCTIONAL — no special hardware required

Attack vector: a quantum control host is not one program. It is a set of
services talking to each other — a job scheduler, a calibration daemon, a
pulse-sequence compiler, an instrument control service, a telemetry
collector. They typically communicate over localhost gRPC, REST, or Unix
domain sockets, and they typically trust each other completely because
"it's all on the same box."

That assumption is the attack surface. An adversary with any foothold on
the control host can:
  - Bind a rogue service on a control-plane port and receive job
    submissions intended for the real scheduler
  - Sit between two services as a transparent proxy, passing traffic
    through while logging or modifying it
  - Issue calibration or setpoint commands directly to the instrument
    control daemon, which has no way to distinguish them from the
    scheduler's own commands
  - Read every circuit submitted by every tenant off an unauthenticated
    localhost socket

Zero trust means: no service is trusted because of where it sits. Every
listener is inventoried, every process binding a control port is
identified, every socket permission is checked, and any change is an event.

WHAT THIS DOES (all functional now):
  - Inventory every listening TCP/UDP socket with its owning process
  - Inventory every Unix domain socket in the filesystem with permissions
  - Flag control-plane ports bound by an unexpected binary
  - Flag world-writable Unix sockets — any local process can command them
  - Flag plaintext (non-TLS) listeners on control-plane ports
  - Detect a second process binding a port the baseline owner held
  - Detect proxy/tunnel tooling positioned between services
  - Baseline the entire service topology and alert on any drift
  - Verify the binary behind each listener still matches its baseline hash

No fabricated data. No simulated services. No random().
"""
import json, datetime, os, time, socket, hashlib, subprocess, stat, glob
from collections import defaultdict

POLL_INTERVAL   = 180     # seconds between topology scans
BASELINE_FILE   = "/tmp/watchdog_control_plane_baseline.json"

# Ports commonly used by quantum / HPC control-plane services.
# Not exhaustive — the module inventories everything and compares to baseline.
CONTROL_PLANE_PORTS = {
    50051: "gRPC default",
    50052: "gRPC secondary",
    8080:  "HTTP control API",
    8443:  "HTTPS control API",
    5000:  "Flask/REST control service",
    5555:  "ZeroMQ",
    5556:  "ZeroMQ pub",
    6379:  "Redis (job queue)",
    5672:  "AMQP / RabbitMQ (job queue)",
    9090:  "Prometheus",
    9093:  "Quantum metrics exporter",
    4222:  "NATS",
    2379:  "etcd client",
    2380:  "etcd peer",
    1883:  "MQTT",
    502:   "Modbus TCP (instrument control)",
    5025:  "SCPI raw socket (instrument control)",
    111:   "rpcbind",
}

# Ports where plaintext is a finding — these carry commands or credentials
PLAINTEXT_SENSITIVE = {50051, 8080, 5000, 5555, 6379, 5672, 502, 5025, 2379}

# Tooling used to build a transparent service proxy
PROXY_TOOLS = [
    "socat", "ncat", "nc", "netcat", "stunnel", "haproxy",
    "mitmproxy", "mitmdump", "envoy", "ssh", "chisel",
    "frpc", "frps", "ngrok", "gost", "iptables",
]

# Directories where control-plane Unix sockets typically live
UNIX_SOCKET_GLOBS = [
    "/var/run/*.sock", "/var/run/*/*.sock",
    "/run/*.sock", "/run/*/*.sock",
    "/tmp/*.sock", "/tmp/.*-socket",
    "/var/lib/*/*.sock",
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
        return {"listeners": {}, "unix_sockets": {}, "established": now_iso()}

def save_baseline(b: dict):
    try:
        with open(BASELINE_FILE, "w") as f:
            json.dump(b, f, indent=2)
    except:
        pass

def sha256_file(path: str) -> str | None:
    try:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(1024 * 1024), b""):
                h.update(chunk)
        return h.hexdigest()
    except:
        return None

def parse_proc_net(proto: str) -> list:
    """
    Parse /proc/net/tcp|udp directly — no ss or netstat dependency.
    Returns listening sockets with their inode for owner lookup.
    """
    entries = []
    path = f"/proc/net/{proto}"
    if not os.path.exists(path):
        return entries
    try:
        with open(path) as f:
            lines = f.readlines()[1:]
        for line in lines:
            parts = line.split()
            if len(parts) < 10:
                continue
            local  = parts[1]
            state  = parts[3]
            inode  = parts[9]
            # TCP state 0A = LISTEN. UDP has no listen state.
            if proto == "tcp" and state != "0A":
                continue
            try:
                addr_hex, port_hex = local.split(":")
                port = int(port_hex, 16)
                # Decode little-endian IPv4
                addr = ".".join(str(int(addr_hex[i:i+2], 16))
                                 for i in (6, 4, 2, 0))
            except:
                continue
            entries.append({"proto": proto, "addr": addr,
                             "port": port, "inode": inode})
    except Exception:
        pass
    return entries

def map_inodes_to_processes() -> dict:
    """Build inode -> {pid, cmd, exe, exe_hash} for socket ownership."""
    mapping = {}
    try:
        for pid_dir in os.listdir("/proc"):
            if not pid_dir.isdigit():
                continue
            fd_dir = f"/proc/{pid_dir}/fd"
            try:
                fds = os.listdir(fd_dir)
            except (OSError, PermissionError):
                continue

            cmd, exe, exe_hash = "", "", None
            for fd in fds:
                try:
                    target = os.readlink(os.path.join(fd_dir, fd))
                except (OSError, PermissionError):
                    continue
                if not target.startswith("socket:["):
                    continue
                inode = target[8:-1]
                if not cmd:
                    try:
                        with open(f"/proc/{pid_dir}/cmdline", "rb") as f:
                            cmd = (f.read().replace(b"\x00", b" ")
                                     .decode("utf-8", errors="replace").strip())
                    except:
                        pass
                    try:
                        exe = os.readlink(f"/proc/{pid_dir}/exe")
                        exe_hash = sha256_file(exe)
                    except:
                        pass
                mapping[inode] = {"pid": int(pid_dir), "cmd": cmd[:200],
                                   "exe": exe,
                                   "exe_sha256": exe_hash[:32] + "..." if exe_hash else None,
                                   "_full_hash": exe_hash}
    except Exception:
        pass
    return mapping

def enumerate_listeners() -> list:
    """Every listening TCP and UDP socket with its owning process."""
    inode_map = map_inodes_to_processes()
    listeners = []
    for proto in ("tcp", "udp"):
        for entry in parse_proc_net(proto):
            owner = inode_map.get(entry["inode"], {})
            listeners.append({
                "proto":      entry["proto"],
                "addr":       entry["addr"],
                "port":       entry["port"],
                "pid":        owner.get("pid"),
                "cmd":        owner.get("cmd", ""),
                "exe":        owner.get("exe", ""),
                "exe_sha256": owner.get("exe_sha256"),
                "_full_hash": owner.get("_full_hash"),
                "is_control_plane": entry["port"] in CONTROL_PLANE_PORTS,
                "service_hint": CONTROL_PLANE_PORTS.get(entry["port"], ""),
            })
    return listeners

def enumerate_unix_sockets() -> list:
    """Unix domain sockets on disk with their permissions."""
    sockets = []
    seen = set()
    for pattern in UNIX_SOCKET_GLOBS:
        for path in glob.glob(pattern):
            if path in seen:
                continue
            seen.add(path)
            try:
                st = os.stat(path)
                if not stat.S_ISSOCK(st.st_mode):
                    continue
                sockets.append({
                    "path":        path,
                    "mode":        oct(st.st_mode & 0o777),
                    "uid":         st.st_uid,
                    "gid":         st.st_gid,
                    "world_write": bool(st.st_mode & stat.S_IWOTH),
                    "group_write": bool(st.st_mode & stat.S_IWGRP),
                })
            except (OSError, PermissionError):
                continue
    return sockets

def check_proxy_tools() -> list:
    """Proxy or tunnel tooling that could sit between two services."""
    found = []
    try:
        for pid_dir in os.listdir("/proc"):
            if not pid_dir.isdigit():
                continue
            try:
                with open(f"/proc/{pid_dir}/cmdline", "rb") as f:
                    cmd = (f.read().replace(b"\x00", b" ")
                             .decode("utf-8", errors="replace").strip())
            except:
                continue
            if not cmd:
                continue
            base = os.path.basename(cmd.split()[0]).lower()
            low  = cmd.lower()
            for tool in PROXY_TOOLS:
                if base == tool or base.startswith(tool):
                    # Only flag if it looks like it's proxying something —
                    # a bare `ssh host` is not interesting, `ssh -L` is.
                    interesting = any(k in low for k in
                                      ("listen", "tcp", "fork", "-l", "-l ",
                                       "localhost", "127.0.0.1", "unix",
                                       "-l ", "-r ", "proxy", ":"))
                    if interesting:
                        found.append({"pid": int(pid_dir), "tool": tool,
                                       "cmd": cmd[:200]})
                    break
    except Exception:
        pass
    return found

def probe_tls(port: int, host: str = "127.0.0.1", timeout: float = 1.5) -> bool | None:
    """
    Is this listener speaking TLS? Attempt a TLS handshake.
    Returns True (TLS), False (plaintext), or None (could not determine).
    """
    try:
        import ssl
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((host, port), timeout=timeout) as sock:
            try:
                with ctx.wrap_socket(sock, server_hostname=host) as tls:
                    return True
            except ssl.SSLError:
                return False
            except Exception:
                return None
    except (socket.timeout, ConnectionRefusedError, OSError):
        return None
    except Exception:
        return None

def analyse(listeners: list, unix_socks: list, proxies: list,
            baseline: dict, probe_tls_enabled: bool) -> tuple:
    alerts = []
    known_listeners = baseline.get("listeners", {})
    known_unix      = baseline.get("unix_sockets", {})

    current_listeners = {}

    for l in listeners:
        key = f"{l['proto']}:{l['addr']}:{l['port']}"
        current_listeners[key] = {
            "pid":        l.get("pid"),
            "cmd":        l.get("cmd"),
            "exe":        l.get("exe"),
            "exe_sha256": l.get("_full_hash"),
        }

        # ── 1. Control-plane port bound by a different binary than baseline ──
        if key in known_listeners:
            prev = known_listeners[key]
            prev_hash = prev.get("exe_sha256")
            curr_hash = l.get("_full_hash")
            if prev_hash and curr_hash and prev_hash != curr_hash:
                alerts.append({
                    "event":    "CONTROL_PLANE_BINARY_CHANGED",
                    "severity": "CRITICAL",
                    "listener": key,
                    "service":  l.get("service_hint"),
                    "was_exe":  prev.get("exe"),
                    "now_exe":  l.get("exe"),
                    "was_hash": (prev_hash or "")[:32] + "...",
                    "now_hash": (curr_hash or "")[:32] + "...",
                    "confidence": 0.90,
                    "note": ("The binary bound to this control-plane port has "
                             "changed. Either the service was legitimately "
                             "updated, or a rogue process has taken the port"),
                })
            elif prev.get("exe") and l.get("exe") and prev["exe"] != l["exe"]:
                alerts.append({
                    "event":    "CONTROL_PLANE_OWNER_CHANGED",
                    "severity": "CRITICAL",
                    "listener": key,
                    "was_exe":  prev.get("exe"),
                    "now_exe":  l.get("exe"),
                    "confidence": 0.85,
                    "note": "A different executable now owns this control-plane port",
                })
        else:
            sev = "CRITICAL" if l.get("is_control_plane") else "INFO"
            alerts.append({
                "event":    "NEW_LISTENER",
                "severity": sev,
                "listener": key,
                "service":  l.get("service_hint"),
                "pid":      l.get("pid"),
                "cmd":      l.get("cmd"),
                "exe":      l.get("exe"),
                "confidence": 0.75 if sev == "CRITICAL" else 0.35,
                "note": ("New listening socket since baseline"
                         + (" on a known control-plane port. Verify this is an "
                            "authorised service and not a rogue listener "
                            "intercepting job submissions."
                            if l.get("is_control_plane") else "")),
            })

        # ── 2. Control-plane port bound to a non-loopback address ──
        if l.get("is_control_plane") and l["addr"] not in ("127.0.0.1", "0.0.0.0"):
            alerts.append({
                "event":    "CONTROL_PLANE_EXPOSED",
                "severity": "WARN",
                "listener": key,
                "service":  l.get("service_hint"),
                "confidence": 0.65,
                "note": ("Control-plane service bound to a routable address. "
                         "Inter-service traffic should not leave the host"),
            })
        elif l.get("is_control_plane") and l["addr"] == "0.0.0.0":
            alerts.append({
                "event":    "CONTROL_PLANE_ALL_INTERFACES",
                "severity": "CRITICAL",
                "listener": key,
                "service":  l.get("service_hint"),
                "confidence": 0.80,
                "note": ("Control-plane service listening on all interfaces. "
                         "Any host that can route to this machine can submit "
                         "commands to the control plane"),
            })

        # ── 3. Plaintext on a sensitive control port ──
        if (probe_tls_enabled and l["proto"] == "tcp"
                and l["port"] in PLAINTEXT_SENSITIVE
                and l["addr"] in ("127.0.0.1", "0.0.0.0")):
            tls = probe_tls(l["port"])
            if tls is False:
                alerts.append({
                    "event":    "CONTROL_PLANE_PLAINTEXT",
                    "severity": "WARN",
                    "listener": key,
                    "service":  l.get("service_hint"),
                    "confidence": 0.70,
                    "note": ("Control-plane service is not using TLS. Any "
                             "process that can reach this socket reads every "
                             "circuit and command in the clear"),
                })

    # ── 4. Listener disappeared ──
    for key in known_listeners:
        if key not in current_listeners:
            port = int(key.split(":")[-1])
            sev = "CRITICAL" if port in CONTROL_PLANE_PORTS else "INFO"
            alerts.append({
                "event":    "LISTENER_LOST",
                "severity": sev,
                "listener": key,
                "service":  CONTROL_PLANE_PORTS.get(port, ""),
                "confidence": 0.70 if sev == "CRITICAL" else 0.30,
                "note": ("A control-plane service present at baseline is no "
                         "longer listening. Service down, or replaced"),
            })

    # ── 5. Unix socket permissions ──
    current_unix = {}
    for s in unix_socks:
        current_unix[s["path"]] = {"mode": s["mode"], "uid": s["uid"],
                                    "gid": s["gid"]}
        if s["world_write"]:
            alerts.append({
                "event":    "UNIX_SOCKET_WORLD_WRITABLE",
                "severity": "CRITICAL",
                "path":     s["path"],
                "mode":     s["mode"],
                "confidence": 0.90,
                "note": ("Control-plane Unix socket is world-writable. Any "
                         "local process — including an unprivileged tenant "
                         "workload — can issue commands to this service"),
            })
        if s["path"] not in known_unix:
            alerts.append({
                "event":    "NEW_UNIX_SOCKET",
                "severity": "INFO",
                "path":     s["path"],
                "mode":     s["mode"],
                "confidence": 0.35,
            })
        else:
            prev = known_unix[s["path"]]
            if prev.get("mode") != s["mode"]:
                alerts.append({
                    "event":    "UNIX_SOCKET_PERMISSION_CHANGED",
                    "severity": "WARN",
                    "path":     s["path"],
                    "was":      prev.get("mode"),
                    "now":      s["mode"],
                    "confidence": 0.75,
                })

    # ── 6. Proxy tooling ──
    for p in proxies:
        alerts.append({
            "event":    "SERVICE_PROXY_DETECTED",
            "severity": "WARN",
            "pid":      p["pid"],
            "tool":     p["tool"],
            "cmd":      p["cmd"],
            "confidence": 0.65,
            "note": (f"{p['tool']} is running with forwarding arguments. This "
                     "is how a transparent proxy is inserted between two "
                     "control-plane services"),
        })

    baseline["listeners"]    = current_listeners
    baseline["unix_sockets"] = current_unix
    return alerts, baseline

def main():
    log = open(f"module58_{stamp()}.jsonl", "a")
    probe_tls_enabled = os.environ.get("WD_PROBE_TLS", "false").lower() == "true"

    def emit(event):
        event.setdefault("ts", now_iso())
        log.write(json.dumps(event) + "\n")
        log.flush()

    emit({
        "event":  "RUN_START",
        "module": "58_control_plane_zero_trust",
        "status": "FUNCTIONAL — no special hardware required",
        "control_plane_ports_monitored": len(CONTROL_PLANE_PORTS),
        "tls_probing": ("enabled" if probe_tls_enabled
                        else "disabled — set WD_PROBE_TLS=true to enable "
                             "(opens a connection to each sensitive port)"),
        "checks": [
            "Listening TCP/UDP socket inventory with process ownership",
            "Binary hash verification per control-plane listener",
            "Unix domain socket permission audit",
            "World-writable socket detection",
            "Control-plane exposure on routable addresses",
            "Plaintext detection on sensitive ports (opt-in)",
            "Service proxy / tunnel tooling detection",
            "Full topology baseline and drift alerting",
        ],
    })

    baseline = load_baseline()
    alerts   = 0
    first    = not baseline.get("listeners")

    while True:
        listeners  = enumerate_listeners()
        unix_socks = enumerate_unix_sockets()
        proxies    = check_proxy_tools()

        control_plane = [l for l in listeners if l.get("is_control_plane")]

        emit({"event": "TOPOLOGY_SCAN",
              "listeners":          len(listeners),
              "control_plane_listeners": len(control_plane),
              "unix_sockets":       len(unix_socks),
              "proxy_tools":        len(proxies),
              "control_plane_detail": [
                  {"port": l["port"], "service": l["service_hint"],
                   "addr": l["addr"], "exe": l.get("exe", "")}
                  for l in control_plane
              ]})

        if first:
            emit({"event": "BASELINE_ESTABLISHED",
                  "listeners":    len(listeners),
                  "unix_sockets": len(unix_socks),
                  "note": ("First run — control-plane topology baselined. "
                           "Subsequent runs flag any drift.")})
            baseline["listeners"] = {
                f"{l['proto']}:{l['addr']}:{l['port']}": {
                    "pid": l.get("pid"), "cmd": l.get("cmd"),
                    "exe": l.get("exe"), "exe_sha256": l.get("_full_hash")}
                for l in listeners
            }
            baseline["unix_sockets"] = {
                s["path"]: {"mode": s["mode"], "uid": s["uid"], "gid": s["gid"]}
                for s in unix_socks
            }
            save_baseline(baseline)
            first = False
            time.sleep(POLL_INTERVAL)
            continue

        new_alerts, baseline = analyse(listeners, unix_socks, proxies,
                                        baseline, probe_tls_enabled)
        for a in new_alerts:
            alerts += 1
            emit(a)

        save_baseline(baseline)
        break  # patched: run once and exit instead of infinite monitoring loop
        time.sleep(POLL_INTERVAL)

if __name__ == "__main__":
    main()
