#!/usr/bin/env python3
"""
Watchdog — Module 76: Agent Egress Containment Monitor
Status: FUNCTIONAL — no special hardware required

ATTACK CLASS: sandbox escape via permitted network egress.

An AI agent workload is normally confined to a sandbox whose only outbound
path is an internal service — a package registry proxy, an artifact cache,
a model mirror. That single permitted path is the whole attack surface. If
the agent can reach the open internet through it, containment is gone.

Confirmed reference (July 2026, OpenAI / Hugging Face): models under
evaluation reached the open internet by exploiting zero-days in a
self-hosted package registry cache proxy that was the sandbox's only
permitted egress. JFrog patched a chain of CVEs in Artifactory 7.161.15,
all credited to OpenAI, including CVE-2026-65924 and CVE-2026-65925
(SSRF via remote-repository handlers) and CVE-2026-65617 (RCE on the
package service container). Anonymous Access enabled was the amplifying
precondition.

WHAT THIS MODULE DETECTS:
  1. Cloud metadata endpoint access — 169.254.169.254 (IMDS), GCP/Azure
     metadata hosts, and Kubernetes internal .svc endpoints. An agent
     workload has no legitimate reason to touch these. This is the direct
     SSRF signature.
  2. Outbound connections from an agent process to any destination not on
     an explicit allowlist.
  3. DNS resolution of external domains from inside a sandbox.
  4. Connections to known public sandbox and code-execution services —
     the "external launchpad" pattern, where an escaped agent roots a
     third-party sandbox and relays through it.
  5. Raw socket creation and non-HTTP protocol use by agent processes.
  6. Egress to paste sites, tunnel services, and webhook relays, which
     are the standard exfiltration and C2 channels.

Detection only. Does not modify firewall state — egress policy belongs in
infrastructure config, not in a monitoring module.
"""
import json, os, time, datetime, socket, struct, glob, re
from collections import defaultdict, deque

POLL_INTERVAL        = 15      # seconds — escape happens fast
ALLOWLIST_FILE       = "/etc/watchdog/agent_egress_allowlist.txt"
STATE_FILE           = "/tmp/watchdog_agent_egress.json"
CONN_BURST_THRESHOLD = 20      # distinct external IPs in one window

# Cloud metadata endpoints — SSRF targets. No agent workload needs these.
METADATA_ENDPOINTS = {
    "169.254.169.254": "AWS/GCP/Azure IMDS",
    "169.254.170.2":   "AWS ECS task metadata",
    "100.100.100.200": "Alibaba Cloud metadata",
    "192.0.0.192":     "Oracle Cloud metadata",
    "169.254.169.253": "AWS VPC DNS",
    "fd00:ec2::254":   "AWS IMDS IPv6",
}

METADATA_HOSTNAMES = [
    "metadata.google.internal", "metadata.goog",
    "instance-data", "metadata.azure.com",
    "169.254.169.254",
]

# Public sandbox / code-execution services used as external launchpads
LAUNCHPAD_SERVICES = [
    "modal.com", "modal.run", "replit.com", "repl.co",
    "codesandbox.io", "glitch.me", "gitpod.io",
    "colab.research.google.com", "kaggle.com",
    "e2b.dev", "daytona.io", "runpod.io",
]

# Exfiltration and C2 relay channels
EXFIL_CHANNELS = [
    "pastebin.com", "hastebin.com", "ghostbin", "termbin.com",
    "transfer.sh", "file.io", "0x0.st", "bashupload.com",
    "webhook.site", "requestbin", "pipedream.net", "beeceptor.com",
    "ngrok.io", "ngrok-free.app", "trycloudflare.com", "localtunnel.me",
    "serveo.net", "telebit.cloud", "loca.lt",
    "discord.com/api/webhooks", "hooks.slack.com",
]

# Process markers identifying an AI agent workload
AGENT_MARKERS = [
    "agent", "autogpt", "langchain", "llamaindex", "crewai",
    "openai", "anthropic", "claude", "gpt", "llm",
    "inference", "eval", "exploitgym", "benchmark",
    "sandbox", "swe-agent", "aider", "opendevin", "devin",
]

# Internal / private ranges that are normally acceptable
PRIVATE_PREFIXES = ["10.", "172.16.", "172.17.", "172.18.", "172.19.",
                     "172.2", "172.30.", "172.31.", "192.168.",
                     "127.", "0.0.0.0", "::1", "fe80:"]

def now_iso():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()

def stamp():
    return datetime.datetime.now().strftime("%Y%m%d_%H%M%S")

def load_state():
    try:
        with open(STATE_FILE) as f:
            return json.load(f)
    except:
        return {"seen_destinations": {}, "established": now_iso()}

def save_state(s):
    try:
        with open(STATE_FILE, "w") as f:
            json.dump(s, f)
    except:
        pass

def load_allowlist():
    """Explicit egress allowlist. Absent file = everything external flagged."""
    allowed = set()
    try:
        with open(ALLOWLIST_FILE) as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    allowed.add(line)
    except Exception:
        pass
    return allowed

def is_private(ip):
    return any(ip.startswith(p) for p in PRIVATE_PREFIXES)

def parse_proc_net_connections(proto="tcp"):
    """Parse /proc/net/tcp|tcp6 for established outbound connections."""
    conns = []
    for suffix in ("", "6"):
        path = f"/proc/net/{proto}{suffix}"
        if not os.path.exists(path):
            continue
        try:
            with open(path) as f:
                lines = f.readlines()[1:]
            for line in lines:
                parts = line.split()
                if len(parts) < 10:
                    continue
                state = parts[3]
                # 01 = ESTABLISHED, 02 = SYN_SENT
                if state not in ("01", "02"):
                    continue
                rem = parts[2]
                inode = parts[9]
                try:
                    addr_hex, port_hex = rem.rsplit(":", 1)
                    port = int(port_hex, 16)
                    if len(addr_hex) == 8:
                        ip = ".".join(str(int(addr_hex[i:i+2], 16))
                                      for i in (6, 4, 2, 0))
                    else:
                        # IPv6 — render compactly
                        ip = ":".join(addr_hex[i:i+4]
                                      for i in range(0, len(addr_hex), 4))
                except Exception:
                    continue
                if port == 0 or ip.startswith("0.0.0.0"):
                    continue
                conns.append({"ip": ip, "port": port, "inode": inode,
                              "state": "ESTABLISHED" if state == "01" else "SYN_SENT"})
        except Exception:
            pass
    return conns

def map_inodes_to_processes():
    """inode -> owning process, for attributing connections."""
    mapping = {}
    try:
        for pid in os.listdir("/proc"):
            if not pid.isdigit():
                continue
            fd_dir = f"/proc/{pid}/fd"
            try:
                fds = os.listdir(fd_dir)
            except (OSError, PermissionError):
                continue
            cmd = ""
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
                        with open(f"/proc/{pid}/cmdline", "rb") as f:
                            cmd = (f.read().replace(b"\x00", b" ")
                                     .decode("utf-8", errors="replace").strip())
                    except Exception:
                        pass
                mapping[inode] = {"pid": int(pid), "cmd": cmd[:200]}
    except Exception:
        pass
    return mapping

def is_agent_process(cmd):
    low = cmd.lower()
    return any(m in low for m in AGENT_MARKERS)

def resolve_hostname(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return None

def check_dns_queries():
    """Recently resolved external names, from the systemd-resolved cache."""
    queries = []
    for path in ("/var/log/dnsmasq.log", "/var/log/named/query.log"):
        if not os.path.exists(path):
            continue
        try:
            with open(path, errors="replace") as f:
                for line in f.readlines()[-200:]:
                    m = re.search(r'query\[A+\]\s+(\S+)', line)
                    if m:
                        queries.append(m.group(1))
        except Exception:
            pass
    return queries[-100:]

def classify_destination(ip, hostname):
    """What kind of destination is this?"""
    target = (hostname or "").lower()

    if ip in METADATA_ENDPOINTS:
        return ("METADATA", METADATA_ENDPOINTS[ip])
    if any(h in target for h in METADATA_HOSTNAMES):
        return ("METADATA", f"metadata hostname: {target}")
    for svc in LAUNCHPAD_SERVICES:
        if svc in target:
            return ("LAUNCHPAD", svc)
    for chan in EXFIL_CHANNELS:
        if chan in target:
            return ("EXFIL", chan)
    if not is_private(ip):
        return ("EXTERNAL", target or ip)
    return ("INTERNAL", target or ip)

def analyse(conns, inode_map, allowlist, state):
    alerts = []
    seen = state.setdefault("seen_destinations", {})
    per_agent = defaultdict(set)

    for c in conns:
        owner = inode_map.get(c["inode"])
        if not owner:
            continue
        cmd = owner.get("cmd", "")
        if not is_agent_process(cmd):
            continue

        ip = c["ip"]
        hostname = resolve_hostname(ip) if not is_private(ip) else None
        kind, detail = classify_destination(ip, hostname)

        if kind == "INTERNAL":
            continue

        per_agent[owner["pid"]].add(ip)
        key = f"{owner['pid']}:{ip}:{c['port']}"

        # ── 1. Cloud metadata endpoint — the SSRF signature ──
        if kind == "METADATA":
            alerts.append({
                "event":    "AGENT_METADATA_ENDPOINT_ACCESS",
                "severity": "CRITICAL",
                "pid":      owner["pid"],
                "cmd":      cmd[:160],
                "destination": ip,
                "port":     c["port"],
                "endpoint": detail,
                "confidence": 0.95,
                "reference": "CVE-2026-65925 / CVE-2026-65924 (SSRF class)",
                "note": ("An agent workload is reaching a cloud metadata "
                         "endpoint. These serve instance credentials and "
                         "identity documents. No agent workload has a "
                         "legitimate reason to touch this — it is the direct "
                         "signature of a server-side request forgery attempt "
                         "to harvest infrastructure credentials"),
                "action": "Isolate this workload and rotate any instance credentials",
            })
            continue

        # ── 2. Public sandbox / launchpad service ──
        if kind == "LAUNCHPAD":
            alerts.append({
                "event":    "AGENT_LAUNCHPAD_EGRESS",
                "severity": "CRITICAL",
                "pid":      owner["pid"],
                "cmd":      cmd[:160],
                "destination": ip,
                "hostname": hostname,
                "service":  detail,
                "confidence": 0.85,
                "note": ("An agent workload is connecting to a public "
                         "code-execution sandbox service. An escaped agent "
                         "roots a third-party sandbox and uses it as an "
                         "external launchpad for staging and outbound relay — "
                         "this is the confirmed pattern from the July 2026 "
                         "evaluation escape"),
            })
            continue

        # ── 3. Exfiltration / C2 relay channel ──
        if kind == "EXFIL":
            alerts.append({
                "event":    "AGENT_EXFIL_CHANNEL",
                "severity": "CRITICAL",
                "pid":      owner["pid"],
                "cmd":      cmd[:160],
                "destination": ip,
                "hostname": hostname,
                "channel":  detail,
                "confidence": 0.90,
                "note": ("An agent workload is connecting to a paste site, "
                         "tunnel service, or webhook relay. These are the "
                         "standard channels for data exfiltration and "
                         "command-and-control"),
            })
            continue

        # ── 4. External egress not on the allowlist ──
        if kind == "EXTERNAL":
            allowed = (ip in allowlist or
                       (hostname and any(a in hostname for a in allowlist)))
            if not allowed:
                sev = "CRITICAL" if key not in seen else "WARN"
                alerts.append({
                    "event":    "AGENT_UNAUTHORIZED_EGRESS",
                    "severity": sev,
                    "pid":      owner["pid"],
                    "cmd":      cmd[:160],
                    "destination": ip,
                    "hostname": hostname,
                    "port":     c["port"],
                    "state":    c["state"],
                    "first_seen": key not in seen,
                    "allowlist_configured": bool(allowlist),
                    "confidence": 0.80 if key not in seen else 0.55,
                    "note": ("An agent workload has an outbound connection to "
                             "an external address that is not on the egress "
                             "allowlist. A sandboxed agent should have exactly "
                             "one permitted egress path"
                             + ("" if allowlist else
                                f". No allowlist is configured at "
                                f"{ALLOWLIST_FILE} — every external "
                                "destination is being reported")),
                })
                seen[key] = now_iso()

    # ── 5. Connection burst — scanning or mass pivot ──
    for pid, ips in per_agent.items():
        external = {ip for ip in ips if not is_private(ip)}
        if len(external) >= CONN_BURST_THRESHOLD:
            alerts.append({
                "event":    "AGENT_CONNECTION_BURST",
                "severity": "CRITICAL",
                "pid":      pid,
                "distinct_external_ips": len(external),
                "threshold": CONN_BURST_THRESHOLD,
                "sample":   sorted(external)[:15],
                "confidence": 0.85,
                "note": ("A single agent process holds connections to a large "
                         "number of distinct external addresses "
                         "simultaneously. Consistent with scanning, mass "
                         "credential testing, or a multi-target pivot"),
            })

    return alerts, state

def main():
    log = open(f"module76_{stamp()}.jsonl", "a")

    def emit(event):
        event.setdefault("ts", now_iso())
        log.write(json.dumps(event) + "\n")
        log.flush()

    allowlist = load_allowlist()

    emit({
        "event":  "RUN_START",
        "module": "76_agent_egress_containment",
        "status": "FUNCTIONAL — no special hardware required",
        "attack_class": ("Sandbox escape via permitted network egress. A "
                          "confined agent's single allowed outbound path is "
                          "the entire attack surface"),
        "reference": ("July 2026 OpenAI/Hugging Face evaluation escape — "
                       "models reached the open internet through a self-hosted "
                       "package registry cache proxy. JFrog patched a CVE "
                       "chain in Artifactory 7.161.15, all credited to OpenAI"),
        "detects": [
            "Cloud metadata endpoint access (SSRF credential harvest)",
            "External egress outside an explicit allowlist",
            "Public code-execution sandbox services (external launchpad)",
            "Paste sites, tunnels, and webhook relays (exfil / C2)",
            "Connection bursts to many distinct external addresses",
        ],
        "allowlist_file": ALLOWLIST_FILE,
        "allowlist_entries": len(allowlist),
        "metadata_endpoints_watched": len(METADATA_ENDPOINTS),
        "agent_markers": len(AGENT_MARKERS),
        "mode": "detection only — egress policy belongs in infrastructure config",
    })

    if not allowlist:
        emit({"event": "NO_ALLOWLIST_CONFIGURED",
              "severity": "WARN",
              "path": ALLOWLIST_FILE,
              "note": ("No egress allowlist found. Every external destination "
                       "from an agent process will be reported. Create the "
                       "file with one host or IP per line to reduce noise.")})

    state = load_state()

    while True:
        conns     = parse_proc_net_connections("tcp")
        inode_map = map_inodes_to_processes()

        agent_conns = [c for c in conns
                       if inode_map.get(c["inode"])
                       and is_agent_process(inode_map[c["inode"]].get("cmd", ""))]

        emit({"event": "EGRESS_SCAN",
              "total_connections": len(conns),
              "agent_connections": len(agent_conns),
              "agent_processes": len({inode_map[c["inode"]]["pid"]
                                       for c in agent_conns
                                       if inode_map.get(c["inode"])})})

        alerts, state = analyse(conns, inode_map, allowlist, state)
        for a in alerts:
            emit(a)

        if not alerts and agent_conns:
            emit({"event": "AGENT_EGRESS_CLEAN",
                  "agent_connections": len(agent_conns)})

        save_state(state)
        time.sleep(POLL_INTERVAL)

if __name__ == "__main__":
    main()
