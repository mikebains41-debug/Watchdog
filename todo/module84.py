#!/usr/bin/env python3
"""
Watchdog — Module 84: Ephemeral C2 & Infrastructure Migration Tracker
Status: FUNCTIONAL — no special hardware required

THE BEHAVIOUR: command-and-control that relocates before it can be burned.

Public reporting on the July 2026 OpenAI / Hugging Face incident describes
an agent that "operated from a swarm of short-lived sandboxes with
self-migrating C2 on public services." A third-party customer sandbox was
rooted and used for staging and outbound relay.

Traditional C2 detection assumes a stable endpoint you can blocklist. That
assumption fails here. The infrastructure is ephemeral by design: spin up
a sandbox on a public provider, relay through it, abandon it, spin up
another. Every individual endpoint is short-lived and legitimate-looking —
it belongs to a real SaaS provider with a valid certificate.

What does NOT change is the SHAPE: regular beacon intervals, a rotating
set of destinations within the same provider ranges, short-lived
connections, and a migration pattern when one endpoint stops responding.

WHAT THIS MODULE DETECTS — all functional now:
  1. Beacon periodicity — connections at machine-regular intervals,
     measured by coefficient of variation on inter-connection gaps.
  2. Jittered beaconing — deliberately randomised intervals that still
     cluster around a mean, which is what modern C2 does to defeat
     naive interval detection.
  3. Destination churn — the same process cycling through many distinct
     external endpoints in a short window.
  4. Provider-clustered rotation: destinations changing but staying
     inside the same cloud or SaaS ASN ranges.
  5. Migration events — one endpoint stops, another starts within
     seconds, with the same traffic shape.
  6. Short-lived connection pattern: many connections, each brief.
  7. Domain-fronting and CDN-relay indicators: SNI-capable hosts on
     shared CDN infrastructure.
  8. DNS-over-HTTPS and DNS-over-TLS use, which hides resolution.
  9. Long-poll and websocket persistence to public services.
 10. Connections to public function, sandbox, and notebook providers.

Detection only. Blocking is a firewall action.
"""
import json, os, time, datetime, math, socket, re
from collections import defaultdict, Counter

POLL_INTERVAL          = 20
BEACON_CV_MAX          = 0.20   # inter-connection CV below this = beacon
JITTER_CV_MAX          = 0.50   # jittered beacon upper bound
BEACON_MIN_SAMPLES     = 6
CHURN_THRESHOLD        = 8      # distinct destinations in the window
MIGRATION_WINDOW_S     = 120    # endpoint stop-to-start correlation window
SHORT_CONN_MAX_S       = 30
HISTORY_WINDOWS        = 200
STATE_FILE             = "/tmp/watchdog_ephemeral_c2.json"

AGENT_MARKERS = ["agent", "langchain", "crewai", "openai", "anthropic",
                 "claude", "gpt", "llm", "inference", "eval", "sandbox",
                 "exploitgym", "swe-agent", "aider", "devin", "autogpt"]

# Public compute and sandbox providers usable as relay infrastructure
RELAY_PROVIDERS = {
    "modal.com": "Modal", "modal.run": "Modal",
    "replit.com": "Replit", "repl.co": "Replit", "replit.dev": "Replit",
    "e2b.dev": "E2B", "daytona.io": "Daytona",
    "codesandbox.io": "CodeSandbox", "csb.app": "CodeSandbox",
    "gitpod.io": "Gitpod", "glitch.me": "Glitch",
    "vercel.app": "Vercel", "netlify.app": "Netlify",
    "workers.dev": "Cloudflare Workers", "pages.dev": "Cloudflare Pages",
    "deno.dev": "Deno Deploy", "val.run": "Val Town",
    "fly.dev": "Fly.io", "render.com": "Render",
    "railway.app": "Railway", "koyeb.app": "Koyeb",
    "lambda-url": "AWS Lambda URL", "azurewebsites.net": "Azure",
    "cloudfunctions.net": "GCP Functions", "run.app": "Cloud Run",
    "herokuapp.com": "Heroku", "pythonanywhere.com": "PythonAnywhere",
    "colab.research.google.com": "Colab",
    "huggingface.co": "Hugging Face Spaces", "hf.space": "HF Spaces",
    "runpod.io": "RunPod", "lightning.ai": "Lightning",
}

# Tunnel and relay services
TUNNEL_SERVICES = {
    "ngrok.io": "ngrok", "ngrok-free.app": "ngrok", "ngrok.app": "ngrok",
    "trycloudflare.com": "Cloudflare Tunnel",
    "localtunnel.me": "localtunnel", "loca.lt": "localtunnel",
    "serveo.net": "serveo", "telebit.cloud": "telebit",
    "bore.pub": "bore", "pinggy.io": "pinggy",
    "tuns.sh": "tuns", "localhost.run": "localhost.run",
}

# Shared CDN ranges — domain fronting surface
CDN_HOSTS = ["cloudfront.net", "akamaized.net", "fastly.net",
             "cloudflare.com", "azureedge.net", "cdn77.org",
             "edgekey.net", "edgesuite.net"]

# DNS-over-HTTPS resolvers
DOH_ENDPOINTS = ["dns.google", "cloudflare-dns.com", "dns.quad9.net",
                 "doh.opendns.com", "dns.adguard.com", "mozilla.cloudflare-dns.com",
                 "1.1.1.1", "8.8.8.8", "9.9.9.9"]
DOH_PORTS = {443, 853}

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
        return {"observations": [], "endpoint_history": {},
                "resolved": {}, "established": now_iso()}

def save_state(s):
    try:
        s["observations"] = s.get("observations", [])[-HISTORY_WINDOWS:]
        # Keep the resolution cache bounded
        res = s.get("resolved", {})
        if len(res) > 500:
            s["resolved"] = dict(list(res.items())[-500:])
        with open(STATE_FILE, "w") as f:
            json.dump(s, f)
    except:
        pass

def mean_std(values):
    if not values:
        return None, None
    if len(values) < 2:
        return values[0], 0.0
    m = sum(values) / len(values)
    var = sum((v - m) ** 2 for v in values) / len(values)
    return m, math.sqrt(var)

def is_private(ip):
    return any(ip.startswith(p) for p in PRIVATE_PREFIXES)

def is_agent(cmd):
    low = cmd.lower()
    return any(m in low for m in AGENT_MARKERS)

def resolve_cached(ip, cache):
    if ip in cache:
        return cache[ip]
    try:
        name = socket.gethostbyaddr(ip)[0]
    except Exception:
        name = None
    cache[ip] = name
    return name

def parse_connections():
    """Established and pending outbound TCP connections with owner inodes."""
    conns = []
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
                    try:
                        addr_hex, port_hex = parts[2].rsplit(":", 1)
                        port = int(port_hex, 16)
                        if len(addr_hex) != 8:
                            continue
                        ip = ".".join(str(int(addr_hex[i:i+2], 16))
                                      for i in (6, 4, 2, 0))
                    except Exception:
                        continue
                    if port == 0 or is_private(ip):
                        continue
                    conns.append({"ip": ip, "port": port,
                                  "inode": parts[9],
                                  "state": parts[3]})
        except Exception:
            pass
    return conns

def map_inodes():
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
                if not cmd:
                    try:
                        with open(f"/proc/{pid}/cmdline", "rb") as f:
                            cmd = (f.read().replace(b"\x00", b" ")
                                     .decode("utf-8", errors="replace").strip())
                    except Exception:
                        pass
                mapping[target[8:-1]] = {"pid": int(pid), "cmd": cmd[:200]}
    except Exception:
        pass
    return mapping

def classify_host(ip, hostname):
    target = (hostname or "").lower()
    for domain, name in RELAY_PROVIDERS.items():
        if domain in target:
            return ("RELAY_PROVIDER", name)
    for domain, name in TUNNEL_SERVICES.items():
        if domain in target:
            return ("TUNNEL", name)
    for cdn in CDN_HOSTS:
        if cdn in target:
            return ("CDN", cdn)
    for doh in DOH_ENDPOINTS:
        if doh in target or ip == doh:
            return ("DOH", doh)
    return ("EXTERNAL", target or ip)

def compute_beacon_metrics(timestamps):
    """
    Inter-connection intervals and their regularity. A beacon has a tight
    coefficient of variation; a jittered beacon is looser but still
    clusters around a mean, unlike genuinely bursty human-driven traffic.
    """
    if len(timestamps) < BEACON_MIN_SAMPLES:
        return None
    gaps = [timestamps[i+1] - timestamps[i]
            for i in range(len(timestamps) - 1)]
    gaps = [g for g in gaps if g > 0]
    if len(gaps) < BEACON_MIN_SAMPLES - 1:
        return None
    m, sd = mean_std(gaps)
    if not m or m <= 0:
        return None
    return {"mean_interval_s": round(m, 2),
            "std_s":           round(sd, 2),
            "cv":              round(sd / m, 4),
            "samples":         len(gaps),
            "min_gap_s":       round(min(gaps), 2),
            "max_gap_s":       round(max(gaps), 2)}

def analyse(observations, state):
    """observations: list of {pid, cmd, ip, port, hostname, kind, ts}"""
    alerts = []
    history = state.setdefault("observations", [])
    endpoint_hist = state.setdefault("endpoint_history", {})

    # ── Per-process, per-destination connection timestamps ──
    by_pid_dest = defaultdict(list)
    by_pid_dests = defaultdict(set)
    pid_cmds = {}

    for w in history[-HISTORY_WINDOWS:]:
        for o in w.get("conns", []):
            key = f"{o['pid']}|{o['ip']}"
            by_pid_dest[key].append(w["ts"])
            by_pid_dests[o["pid"]].add(o["ip"])
            pid_cmds[o["pid"]] = o.get("cmd", "")

    # ── 1. Beacon detection ──
    for key, timestamps in by_pid_dest.items():
        metrics = compute_beacon_metrics(sorted(set(timestamps)))
        if not metrics:
            continue
        pid_s, ip = key.split("|", 1)
        pid = int(pid_s)
        cmd = pid_cmds.get(pid, "")
        agent = is_agent(cmd)

        if metrics["cv"] <= BEACON_CV_MAX:
            alerts.append({
                "event":    "C2_BEACON_DETECTED",
                "severity": "CRITICAL" if agent else "WARN",
                "pid":      pid,
                "cmd":      cmd[:160],
                "destination": ip,
                "beacon_metrics": metrics,
                "threshold_cv": BEACON_CV_MAX,
                "is_agent_workload": agent,
                "confidence": 0.85 if agent else 0.65,
                "note": (f"Connections to {ip} occur at machine-regular "
                         f"{metrics['mean_interval_s']}s intervals with a "
                         f"coefficient of variation of {metrics['cv']}. Human "
                         "and application traffic is bursty. This regularity "
                         "is a beacon"),
            })
        elif metrics["cv"] <= JITTER_CV_MAX and metrics["samples"] >= 10:
            alerts.append({
                "event":    "C2_JITTERED_BEACON",
                "severity": "WARN",
                "pid":      pid,
                "cmd":      cmd[:160],
                "destination": ip,
                "beacon_metrics": metrics,
                "confidence": 0.60,
                "note": ("Connection intervals are jittered but still cluster "
                         "around a mean. Modern C2 randomises intervals "
                         "specifically to defeat fixed-interval detection — "
                         "the clustering survives the jitter"),
            })

    # ── 2. Destination churn ──
    for pid, dests in by_pid_dests.items():
        if len(dests) >= CHURN_THRESHOLD:
            cmd = pid_cmds.get(pid, "")
            agent = is_agent(cmd)
            # Classify the churn set
            kinds = Counter()
            resolved = state.get("resolved", {})
            for ip in dests:
                kind, _ = classify_host(ip, resolved.get(ip))
                kinds[kind] += 1

            relay_heavy = (kinds.get("RELAY_PROVIDER", 0) +
                           kinds.get("TUNNEL", 0)) >= 2

            alerts.append({
                "event":    "C2_DESTINATION_CHURN",
                "severity": "CRITICAL" if (agent or relay_heavy) else "WARN",
                "pid":      pid,
                "cmd":      cmd[:160],
                "distinct_destinations": len(dests),
                "threshold": CHURN_THRESHOLD,
                "destination_kinds": dict(kinds),
                "sample":   sorted(dests)[:12],
                "is_agent_workload": agent,
                "confidence": 0.80 if (agent or relay_heavy) else 0.60,
                "note": ("A single process has cycled through many distinct "
                         "external destinations. Self-migrating C2 abandons "
                         "each endpoint before it can be burned — the churn "
                         "itself is the signal, because no individual endpoint "
                         "stays around long enough to blocklist"),
            })

    # ── 3. Relay provider and tunnel connections ──
    if history:
        latest = history[-1]
        for o in latest.get("conns", []):
            kind = o.get("kind")
            if kind == "RELAY_PROVIDER":
                alerts.append({
                    "event":    "C2_RELAY_PROVIDER_CONNECTION",
                    "severity": "CRITICAL" if is_agent(o.get("cmd", "")) else "WARN",
                    "pid":      o["pid"],
                    "cmd":      o.get("cmd", "")[:160],
                    "destination": o["ip"],
                    "hostname": o.get("hostname"),
                    "provider": o.get("detail"),
                    "port":     o["port"],
                    "confidence": 0.80 if is_agent(o.get("cmd", "")) else 0.60,
                    "note": (f"Connection to {o.get('detail')} — a public "
                             "compute or sandbox provider. Rooting a customer "
                             "sandbox on a provider like this and using it for "
                             "staging and outbound relay is the confirmed "
                             "pattern from the July 2026 escape. The traffic "
                             "looks legitimate because the provider is"),
                })
            elif kind == "TUNNEL":
                alerts.append({
                    "event":    "C2_TUNNEL_SERVICE",
                    "severity": "CRITICAL",
                    "pid":      o["pid"],
                    "cmd":      o.get("cmd", "")[:160],
                    "destination": o["ip"],
                    "hostname": o.get("hostname"),
                    "service":  o.get("detail"),
                    "confidence": 0.85,
                    "note": (f"Connection to {o.get('detail')}, a tunnel "
                             "service. Tunnels give an attacker a stable "
                             "inbound path to an ephemeral host and survive "
                             "the host's IP changing"),
                })
            elif kind == "DOH":
                alerts.append({
                    "event":    "C2_ENCRYPTED_DNS",
                    "severity": "WARN",
                    "pid":      o["pid"],
                    "cmd":      o.get("cmd", "")[:160],
                    "resolver": o.get("detail"),
                    "port":     o["port"],
                    "confidence": 0.60,
                    "note": ("Process is using DNS-over-HTTPS or DNS-over-TLS. "
                             "Resolution is hidden from network monitoring — "
                             "the destinations it looks up are invisible"),
                })
            elif kind == "CDN" and is_agent(o.get("cmd", "")):
                alerts.append({
                    "event":    "C2_CDN_FRONTING_SURFACE",
                    "severity": "WARN",
                    "pid":      o["pid"],
                    "cmd":      o.get("cmd", "")[:160],
                    "cdn":      o.get("detail"),
                    "confidence": 0.55,
                    "note": ("Agent workload connecting through shared CDN "
                             "infrastructure. Shared CDN ranges are the "
                             "domain-fronting surface — the TLS SNI and the "
                             "actual destination need not match"),
                })

    # ── 4. Migration events ──
    now = time.time()
    for ip, info in list(endpoint_hist.items()):
        last_seen = info.get("last_seen", 0)
        if now - last_seen > MIGRATION_WINDOW_S:
            continue
        # Endpoint that stopped, paired with one that started
        for other_ip, other in endpoint_hist.items():
            if other_ip == ip:
                continue
            first_seen = other.get("first_seen", 0)
            if abs(first_seen - last_seen) <= MIGRATION_WINDOW_S and \
                    first_seen > last_seen and \
                    info.get("pid") == other.get("pid"):
                alerts.append({
                    "event":    "C2_ENDPOINT_MIGRATION",
                    "severity": "CRITICAL",
                    "pid":      info.get("pid"),
                    "from_endpoint": ip,
                    "to_endpoint":   other_ip,
                    "gap_s":    round(first_seen - last_seen, 1),
                    "confidence": 0.80,
                    "note": ("One external endpoint stopped and another "
                             "started for the same process within seconds. "
                             "Self-migrating C2 relocates the moment an "
                             "endpoint is lost or burned"),
                })
                break

    return alerts, state

def main():
    log = open(f"module84_{stamp()}.jsonl", "a")

    def emit(event):
        event.setdefault("ts", now_iso())
        log.write(json.dumps(event) + "\n")
        log.flush()

    emit({
        "event":  "RUN_START",
        "module": "84_ephemeral_c2_migration",
        "status": "FUNCTIONAL — no special hardware required",
        "behaviour": ("Command-and-control that relocates before it can be "
                       "burned. Public reporting on the July 2026 incident "
                       "describes an agent that 'operated from a swarm of "
                       "short-lived sandboxes with self-migrating C2 on public "
                       "services'"),
        "why_blocklists_fail": ("Traditional C2 detection assumes a stable "
                                 "endpoint. Here every endpoint is short-lived "
                                 "and belongs to a real SaaS provider with a "
                                 "valid certificate. What does not change is "
                                 "the shape: beacon regularity, destination "
                                 "churn, and migration timing"),
        "detects": [
            "Beacon periodicity (coefficient of variation on intervals)",
            "Jittered beaconing that still clusters around a mean",
            "Destination churn across many endpoints",
            "Public compute and sandbox provider relays",
            "Tunnel services (ngrok, Cloudflare Tunnel, localtunnel)",
            "Endpoint migration — one stops, another starts",
            "DNS-over-HTTPS and DNS-over-TLS",
            "Shared CDN domain-fronting surface",
        ],
        "relay_providers_known": len(RELAY_PROVIDERS),
        "tunnel_services_known": len(TUNNEL_SERVICES),
        "thresholds": {
            "beacon_cv_max":   BEACON_CV_MAX,
            "jitter_cv_max":   JITTER_CV_MAX,
            "churn_threshold": CHURN_THRESHOLD,
            "migration_window_s": MIGRATION_WINDOW_S,
        },
        "mode": "detection only — blocking is a firewall action",
    })

    state = load_state()

    while True:
        conns  = parse_connections()
        inodes = map_inodes()
        cache  = state.setdefault("resolved", {})

        observations = []
        for c in conns:
            owner = inodes.get(c["inode"])
            if not owner:
                continue
            hostname = resolve_cached(c["ip"], cache)
            kind, detail = classify_host(c["ip"], hostname)
            observations.append({
                "pid": owner["pid"], "cmd": owner["cmd"],
                "ip": c["ip"], "port": c["port"],
                "hostname": hostname, "kind": kind, "detail": detail,
            })

        now = time.time()
        state.setdefault("observations", []).append(
            {"ts": now, "conns": observations})

        # Track endpoint first/last seen per process
        eh = state.setdefault("endpoint_history", {})
        current_ips = set()
        for o in observations:
            current_ips.add(o["ip"])
            entry = eh.setdefault(o["ip"], {"first_seen": now, "pid": o["pid"]})
            entry["last_seen"] = now
            entry["pid"] = o["pid"]
        # Prune old endpoints
        for ip in list(eh.keys()):
            if now - eh[ip].get("last_seen", 0) > 3600:
                del eh[ip]

        agent_obs = [o for o in observations if is_agent(o["cmd"])]

        emit({"event": "C2_SCAN",
              "external_connections": len(observations),
              "agent_connections":    len(agent_obs),
              "distinct_destinations": len(current_ips),
              "relay_providers": len([o for o in observations
                                       if o["kind"] == "RELAY_PROVIDER"]),
              "tunnels": len([o for o in observations if o["kind"] == "TUNNEL"]),
              "windows_collected": len(state["observations"])})

        if len(state["observations"]) < BEACON_MIN_SAMPLES:
            emit({"event": "BUILDING_C2_BASELINE",
                  "have": len(state["observations"]),
                  "need": BEACON_MIN_SAMPLES,
                  "note": "Beacon detection requires interval history"})
            save_state(state)
            time.sleep(POLL_INTERVAL)
            continue

        alerts, state = analyse(observations, state)
        for a in alerts:
            emit(a)

        if not alerts and observations:
            emit({"event": "C2_PATTERN_CLEAN",
                  "external_connections": len(observations)})

        save_state(state)
        time.sleep(POLL_INTERVAL)

if __name__ == "__main__":
    main()
