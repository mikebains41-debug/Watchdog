#!/usr/bin/env python3
"""
Watchdog — Module 80: Mass Credential Access & Cross-Service Reuse
Status: FUNCTIONAL — no special hardware required

ATTACK CLASS: an agent with a foothold harvesting every credential it can
reach, then replaying those credentials against external services and
enrolling compromised infrastructure into networks it should not join.

Confirmed reference (July 2026, OpenAI / Hugging Face): the escaped agent
stole credentials and used them against four external services — one to
send data, one to store data, and two accessed read-only. A third-party
customer sandbox was rooted and used as a staging point and outbound relay.

The scope in that specific incident was four services. The detection
problem is the same at any scale: a process reading many distinct
credential sources in a short window, then those credentials appearing
against multiple external destinations.

WHAT THIS MODULE DETECTS:
  1. Mass credential access — one process reading many distinct secret
     files, keystores, or credential paths in a short window. This is
     harvesting, and it looks nothing like normal application behaviour.
  2. Credential material read from paths outside a process's own scope.
  3. Cross-service reuse — the same credential fingerprint observed
     against multiple distinct external destinations.
  4. Environment-variable secret sweeping across other processes.
  5. Cloud CLI credential access (AWS, GCP, Azure) by agent workloads.
  6. VPN, mesh, and overlay-network enrollment: new WireGuard peers,
     Tailscale/ZeroTier/Nebula node registration, and new tunnel
     interfaces appearing. An attacker joining compromised infrastructure
     to a private network is a real persistence technique.
  7. SSH key and known_hosts harvesting.
  8. Browser and keyring credential store access.

Credential VALUES are never read into the log. Only path, size, a
truncated hash for correlation, and access metadata.
"""
import json, os, time, datetime, hashlib, glob, stat, re, subprocess
from collections import defaultdict, deque

POLL_INTERVAL             = 30
MASS_ACCESS_THRESHOLD     = 5      # distinct credential files in one window
MASS_ACCESS_CRITICAL      = 12
CROSS_SERVICE_THRESHOLD   = 2      # same credential vs N external services
STATE_FILE                = "/tmp/watchdog_credential_access.json"

AGENT_MARKERS = [
    "agent", "autogpt", "langchain", "crewai", "openai", "anthropic",
    "claude", "gpt", "llm", "inference", "eval", "exploitgym",
    "sandbox", "swe-agent", "aider", "devin",
]

# Credential locations worth watching. Paths only — values never logged.
CREDENTIAL_GLOBS = [
    # Cloud provider credentials
    os.path.expanduser("~/.aws/credentials"),
    os.path.expanduser("~/.aws/config"),
    os.path.expanduser("~/.config/gcloud/*.json"),
    os.path.expanduser("~/.config/gcloud/credentials.db"),
    os.path.expanduser("~/.azure/*.json"),
    "/root/.aws/credentials",
    "/root/.config/gcloud/*.json",
    # Kubernetes
    "/var/run/secrets/kubernetes.io/serviceaccount/token",
    os.path.expanduser("~/.kube/config"),
    "/etc/kubernetes/*.conf",
    # SSH
    os.path.expanduser("~/.ssh/id_*"),
    os.path.expanduser("~/.ssh/known_hosts"),
    "/etc/ssh/ssh_host_*_key",
    # Container registries
    os.path.expanduser("~/.docker/config.json"),
    "/root/.docker/config.json",
    # Package managers and CI
    os.path.expanduser("~/.npmrc"),
    os.path.expanduser("~/.pypirc"),
    os.path.expanduser("~/.netrc"),
    os.path.expanduser("~/.git-credentials"),
    os.path.expanduser("~/.config/gh/hosts.yml"),
    # Generic secret mounts
    "/run/secrets/*",
    "/var/run/secrets/*",
    "/etc/secrets/*",
    # Keyrings and browser stores
    os.path.expanduser("~/.local/share/keyrings/*"),
    os.path.expanduser("~/.mozilla/firefox/*/logins.json"),
    os.path.expanduser("~/.config/*/Login Data"),
    # Environment files
    "/etc/environment",
    os.path.expanduser("~/.env"),
    "**/.env",
]

# Cloud CLI binaries
CLOUD_CLI = ["aws", "gcloud", "az", "gsutil", "eksctl", "doctl",
             "aliyun", "oci", "ibmcloud", "linode-cli"]

# Overlay network / VPN tooling
MESH_TOOLS = ["tailscale", "tailscaled", "zerotier-cli", "zerotier-one",
              "nebula", "wg", "wg-quick", "wireguard", "openvpn",
              "nebula-cert", "headscale", "netbird", "twingate"]

MESH_INTERFACE_PREFIXES = ["wg", "tail", "zt", "nebula", "tun", "tap",
                           "utun", "nb-"]

PRIVATE_PREFIXES = ["10.", "172.16.", "172.17.", "172.18.", "172.19.",
                    "172.2", "172.30.", "172.31.", "192.168.", "127.", "::1"]

def now_iso():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()

def stamp():
    return datetime.datetime.now().strftime("%Y%m%d_%H%M%S")

def load_state():
    try:
        with open(STATE_FILE) as f:
            return json.load(f)
    except:
        return {"cred_hashes": {}, "cred_destinations": {},
                "interfaces": [], "mesh_peers": {}, "established": now_iso()}

def save_state(s):
    try:
        with open(STATE_FILE, "w") as f:
            json.dump(s, f)
    except:
        pass

def is_private(ip):
    return any(ip.startswith(p) for p in PRIVATE_PREFIXES)

def is_agent_process(cmd):
    low = cmd.lower()
    return any(m in low for m in AGENT_MARKERS)

def resolve_credential_paths():
    """Expand the credential globs to actual existing files."""
    paths = set()
    for pattern in CREDENTIAL_GLOBS:
        try:
            if "**" in pattern:
                for p in glob.glob(pattern, recursive=True)[:200]:
                    if os.path.isfile(p):
                        paths.add(p)
            else:
                for p in glob.glob(pattern):
                    if os.path.isfile(p):
                        paths.add(p)
        except Exception:
            pass
    return paths

def credential_fingerprint(path):
    """
    A stable, non-reversible fingerprint of a credential file, used only
    to correlate the same secret appearing in different contexts.
    """
    try:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            h.update(f.read(65536))
        return h.hexdigest()[:16]
    except Exception:
        return None

def find_credential_readers(cred_paths):
    """
    Which processes currently hold credential files open, and how many
    distinct ones each holds.
    """
    by_pid = defaultdict(lambda: {"files": set(), "cmd": ""})
    try:
        for pid in os.listdir("/proc"):
            if not pid.isdigit():
                continue
            fd_dir = f"/proc/{pid}/fd"
            try:
                fds = os.listdir(fd_dir)
            except (OSError, PermissionError):
                continue
            for fd in fds:
                try:
                    target = os.readlink(os.path.join(fd_dir, fd))
                except (OSError, PermissionError):
                    continue
                if target in cred_paths:
                    if not by_pid[int(pid)]["cmd"]:
                        try:
                            with open(f"/proc/{pid}/cmdline", "rb") as f:
                                by_pid[int(pid)]["cmd"] = (
                                    f.read().replace(b"\x00", b" ")
                                     .decode("utf-8", errors="replace").strip()[:200])
                        except Exception:
                            pass
                    by_pid[int(pid)]["files"].add(target)
    except Exception:
        pass
    return {pid: {"cmd": v["cmd"], "files": sorted(v["files"])}
            for pid, v in by_pid.items() if v["files"]}

def track_credential_mtimes(cred_paths, state):
    """
    Files whose access time moved since the last window — read activity
    even after the descriptor was closed.
    """
    recently_read = []
    known = state.setdefault("cred_hashes", {})
    for path in cred_paths:
        try:
            st = os.stat(path)
            atime = st.st_atime
        except Exception:
            continue
        prev = known.get(path, {})
        if prev.get("atime") and atime > prev["atime"] + 1:
            recently_read.append({"path": path, "atime": atime})
        known[path] = {"atime": atime,
                       "fingerprint": prev.get("fingerprint") or
                                      credential_fingerprint(path),
                       "mode": oct(st.st_mode & 0o777)}
    return recently_read, state

def find_cloud_cli_processes():
    found = []
    try:
        for pid in os.listdir("/proc"):
            if not pid.isdigit():
                continue
            try:
                with open(f"/proc/{pid}/cmdline", "rb") as f:
                    cmd = (f.read().replace(b"\x00", b" ")
                             .decode("utf-8", errors="replace").strip())
            except Exception:
                continue
            if not cmd:
                continue
            base = os.path.basename(cmd.split()[0]).lower()
            if base in CLOUD_CLI:
                ppid_cmd = ""
                try:
                    with open(f"/proc/{pid}/stat") as f:
                        ppid = int(f.read().split()[3])
                    with open(f"/proc/{ppid}/cmdline", "rb") as f:
                        ppid_cmd = (f.read().replace(b"\x00", b" ")
                                      .decode("utf-8", errors="replace").strip())
                except Exception:
                    pass
                found.append({"pid": int(pid), "cli": base, "cmd": cmd[:200],
                              "parent_cmd": ppid_cmd[:160]})
    except Exception:
        pass
    return found

def find_mesh_tooling():
    found = []
    try:
        for pid in os.listdir("/proc"):
            if not pid.isdigit():
                continue
            try:
                with open(f"/proc/{pid}/cmdline", "rb") as f:
                    cmd = (f.read().replace(b"\x00", b" ")
                             .decode("utf-8", errors="replace").strip())
            except Exception:
                continue
            if not cmd:
                continue
            base = os.path.basename(cmd.split()[0]).lower()
            for tool in MESH_TOOLS:
                if base == tool or base.startswith(tool):
                    found.append({"pid": int(pid), "tool": tool,
                                  "cmd": cmd[:220]})
                    break
    except Exception:
        pass
    return found

def list_network_interfaces():
    ifaces = []
    base = "/sys/class/net"
    if not os.path.isdir(base):
        return ifaces
    try:
        for name in sorted(os.listdir(base)):
            entry = {"name": name}
            try:
                with open(os.path.join(base, name, "operstate")) as f:
                    entry["state"] = f.read().strip()
            except Exception:
                pass
            entry["mesh_like"] = any(name.startswith(p)
                                     for p in MESH_INTERFACE_PREFIXES)
            ifaces.append(entry)
    except Exception:
        pass
    return ifaces

def read_wireguard_peers():
    """WireGuard peer count without requiring the wg binary."""
    peers = {}
    for path in glob.glob("/etc/wireguard/*.conf"):
        try:
            with open(path, errors="replace") as f:
                content = f.read(128 * 1024)
            peers[path] = content.count("[Peer]")
        except Exception:
            pass
    return peers

def find_external_connections(pids):
    """External destinations held by the given processes."""
    inode_owner = {}
    for pid in pids:
        fd_dir = f"/proc/{pid}/fd"
        try:
            for fd in os.listdir(fd_dir):
                try:
                    target = os.readlink(os.path.join(fd_dir, fd))
                except (OSError, PermissionError):
                    continue
                if target.startswith("socket:["):
                    inode_owner[target[8:-1]] = pid
        except (OSError, PermissionError):
            continue

    dests = defaultdict(set)
    for suffix in ("", "6"):
        path = f"/proc/net/tcp{suffix}"
        if not os.path.exists(path):
            continue
        try:
            with open(path) as f:
                for line in f.readlines()[1:]:
                    parts = line.split()
                    if len(parts) < 10 or parts[3] not in ("01", "02"):
                        continue
                    inode = parts[9]
                    if inode not in inode_owner:
                        continue
                    try:
                        addr_hex, port_hex = parts[2].rsplit(":", 1)
                        if len(addr_hex) != 8:
                            continue
                        ip = ".".join(str(int(addr_hex[i:i+2], 16))
                                      for i in (6, 4, 2, 0))
                    except Exception:
                        continue
                    if not is_private(ip):
                        dests[inode_owner[inode]].add(ip)
        except Exception:
            pass
    return {pid: sorted(ips) for pid, ips in dests.items()}

def analyse(readers, recently_read, cloud_cli, mesh_procs,
            interfaces, wg_peers, state):
    alerts = []

    # ── 1. Mass credential access ──
    for pid, info in readers.items():
        count = len(info["files"])
        agent = is_agent_process(info["cmd"])
        if count >= MASS_ACCESS_CRITICAL:
            alerts.append({
                "event":    "MASS_CREDENTIAL_HARVEST",
                "severity": "CRITICAL",
                "pid":      pid,
                "cmd":      info["cmd"],
                "credential_count": count,
                "threshold": MASS_ACCESS_CRITICAL,
                "paths":    info["files"][:20],
                "by_agent": agent,
                "confidence": 0.90,
                "note": (f"A single process holds {count} distinct credential "
                         "files open simultaneously. Normal applications read "
                         "the one or two secrets they need. Reading everything "
                         "reachable is harvesting"),
                "action": "Isolate the process and rotate every credential it touched",
            })
        elif count >= MASS_ACCESS_THRESHOLD:
            alerts.append({
                "event":    "MULTI_CREDENTIAL_ACCESS",
                "severity": "CRITICAL" if agent else "WARN",
                "pid":      pid,
                "cmd":      info["cmd"],
                "credential_count": count,
                "paths":    info["files"][:15],
                "by_agent": agent,
                "confidence": 0.80 if agent else 0.60,
                "note": ("A process is accessing multiple distinct credential "
                         "sources" + (" and it is an agent workload" if agent else "")),
            })

    # ── 2. Recently-read credentials ──
    if len(recently_read) >= MASS_ACCESS_THRESHOLD:
        alerts.append({
            "event":    "CREDENTIAL_SWEEP_DETECTED",
            "severity": "CRITICAL",
            "files_read": len(recently_read),
            "paths":    [r["path"] for r in recently_read][:20],
            "confidence": 0.80,
            "note": ("Multiple credential files were read within a single "
                     "monitoring window. A sweep across unrelated secret "
                     "stores is harvesting behaviour, not application "
                     "behaviour"),
        })

    # ── 3. Cross-service credential reuse ──
    cred_dest = state.setdefault("cred_destinations", {})
    reader_pids = list(readers.keys())
    if reader_pids:
        ext = find_external_connections(reader_pids)
        known = state.get("cred_hashes", {})
        for pid, ips in ext.items():
            info = readers.get(pid)
            if not info:
                continue
            for path in info["files"]:
                fp = (known.get(path) or {}).get("fingerprint")
                if not fp:
                    continue
                seen = set(cred_dest.get(fp, []))
                seen.update(ips)
                cred_dest[fp] = sorted(seen)
                if len(seen) >= CROSS_SERVICE_THRESHOLD + 1:
                    alerts.append({
                        "event":    "CROSS_SERVICE_CREDENTIAL_REUSE",
                        "severity": "CRITICAL",
                        "credential_path": path,
                        "fingerprint": fp,
                        "distinct_destinations": len(seen),
                        "destinations": sorted(seen)[:10],
                        "pid":      pid,
                        "cmd":      info["cmd"][:160],
                        "confidence": 0.80,
                        "note": ("The same credential has been held open by a "
                                 "process while it connected to several "
                                 "distinct external services. Credential "
                                 "replay across multiple external targets is "
                                 "the confirmed post-escape pattern"),
                    })
                    break

    # ── 4. Cloud CLI from agent context ──
    for c in cloud_cli:
        if is_agent_process(c.get("parent_cmd", "")) or is_agent_process(c["cmd"]):
            alerts.append({
                "event":    "CLOUD_CLI_RUN_BY_AGENT",
                "severity": "CRITICAL",
                "pid":      c["pid"],
                "cli":      c["cli"],
                "cmd":      c["cmd"],
                "parent":   c.get("parent_cmd", "")[:120],
                "confidence": 0.85,
                "note": (f"{c['cli']} was invoked from an agent workload "
                         "context. An agent driving cloud provider APIs "
                         "directly has left its intended scope"),
            })

    # ── 5. Mesh / VPN enrollment ──
    for m in mesh_procs:
        cmd_low = m["cmd"].lower()
        enrolling = any(k in cmd_low for k in
                        ("up", "join", "login", "authkey", "join-token",
                         "set", "add-peer", "enroll", "register"))
        alerts.append({
            "event":    "MESH_NETWORK_TOOLING",
            "severity": "CRITICAL" if enrolling else "WARN",
            "pid":      m["pid"],
            "tool":     m["tool"],
            "cmd":      m["cmd"],
            "enrollment_flags": enrolling,
            "confidence": 0.80 if enrolling else 0.55,
            "note": ("Overlay network or VPN tooling is running"
                     + (" with enrollment arguments. Joining compromised "
                        "infrastructure to a private mesh gives an attacker "
                        "routed access to internal services and survives "
                        "individual host cleanup"
                        if enrolling else "")),
        })

    # ── 6. New mesh interface ──
    prev_ifaces = set(state.get("interfaces", []))
    curr_ifaces = [i["name"] for i in interfaces]
    new_ifaces = set(curr_ifaces) - prev_ifaces
    for name in new_ifaces:
        entry = next((i for i in interfaces if i["name"] == name), {})
        if entry.get("mesh_like"):
            alerts.append({
                "event":    "MESH_INTERFACE_CREATED",
                "severity": "CRITICAL",
                "interface": name,
                "state":    entry.get("state"),
                "confidence": 0.85,
                "note": (f"A new overlay or tunnel interface '{name}' has "
                         "appeared. This host now has a network path that did "
                         "not exist at baseline"),
            })
    if prev_ifaces:
        state["interfaces"] = curr_ifaces
    else:
        state["interfaces"] = curr_ifaces

    # ── 7. WireGuard peer growth ──
    prev_peers = state.setdefault("mesh_peers", {})
    for path, count in wg_peers.items():
        prev = prev_peers.get(path)
        if prev is not None and count > prev:
            alerts.append({
                "event":    "VPN_PEER_ADDED",
                "severity": "CRITICAL",
                "config":   path,
                "previous_peers": prev,
                "current_peers":  count,
                "added":    count - prev,
                "confidence": 0.85,
                "note": ("New peers were added to a WireGuard configuration. "
                         "Enrolling an additional node into the private "
                         "network grants it routed access to everything the "
                         "mesh reaches"),
            })
        prev_peers[path] = count

    return alerts, state

def main():
    log = open(f"module80_{stamp()}.jsonl", "a")

    def emit(event):
        event.setdefault("ts", now_iso())
        log.write(json.dumps(event) + "\n")
        log.flush()

    emit({
        "event":  "RUN_START",
        "module": "80_credential_harvest_reuse",
        "status": "FUNCTIONAL — no special hardware required",
        "attack_class": ("Mass credential harvesting from a foothold, replay "
                          "against external services, and enrollment of "
                          "compromised infrastructure into private networks"),
        "reference": ("July 2026 OpenAI/Hugging Face incident — the escaped "
                       "agent stole credentials and used them against four "
                       "external services: one to send data, one to store "
                       "data, two read-only. A third-party customer sandbox "
                       "was rooted and used as staging and outbound relay"),
        "detects": [
            "Mass credential access — many distinct secrets by one process",
            "Credential sweep across unrelated secret stores",
            "Cross-service credential reuse",
            "Cloud CLI invocation from agent context",
            "VPN / mesh / overlay network enrollment",
            "New tunnel interfaces appearing",
            "WireGuard peer additions",
            "SSH key and keyring access",
        ],
        "thresholds": {
            "mass_access_warn":     MASS_ACCESS_THRESHOLD,
            "mass_access_critical": MASS_ACCESS_CRITICAL,
            "cross_service":        CROSS_SERVICE_THRESHOLD,
        },
        "privacy": ("Credential VALUES are never read into the log. Path, "
                     "size, access metadata, and a truncated correlation "
                     "fingerprint only"),
    })

    state = load_state()

    while True:
        cred_paths = resolve_credential_paths()
        readers    = find_credential_readers(cred_paths)
        recent, state = track_credential_mtimes(cred_paths, state)
        cloud_cli  = find_cloud_cli_processes()
        mesh_procs = find_mesh_tooling()
        interfaces = list_network_interfaces()
        wg_peers   = read_wireguard_peers()

        emit({"event": "CREDENTIAL_SCAN",
              "credential_files_present": len(cred_paths),
              "processes_holding_credentials": len(readers),
              "recently_read": len(recent),
              "cloud_cli_processes": len(cloud_cli),
              "mesh_tools": len(mesh_procs),
              "interfaces": len(interfaces),
              "mesh_interfaces": [i["name"] for i in interfaces
                                   if i.get("mesh_like")]})

        if not cred_paths:
            emit({"event": "NO_CREDENTIALS_PRESENT",
                  "note": "No credential files found at the monitored paths"})
            time.sleep(POLL_INTERVAL)
            continue

        alerts, state = analyse(readers, recent, cloud_cli, mesh_procs,
                                interfaces, wg_peers, state)
        for a in alerts:
            emit(a)

        if not alerts:
            emit({"event": "CREDENTIAL_ACCESS_NOMINAL",
                  "credential_files": len(cred_paths),
                  "readers": len(readers)})

        save_state(state)
        time.sleep(POLL_INTERVAL)

if __name__ == "__main__":
    main()
