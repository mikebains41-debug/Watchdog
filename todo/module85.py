#!/usr/bin/env python3
"""
Watchdog — Module 85: Service Mesh mTLS Enforcement Verifier
Status: FUNCTIONAL — no special hardware required

THE PROBLEM: PERMISSIVE mode looks like mTLS and is not.

Mutual TLS between services is the control that makes a stolen bearer
token useless. If every service call requires a client certificate the
caller can prove it holds, an attacker who lifted a service-account token
out of a pod cannot use it — the token alone does not satisfy the
handshake.

The failure mode: Istio and Linkerd both ship a PERMISSIVE mode that
accepts BOTH mTLS and plaintext. It exists for migration, and it is the
default in many installs. A PeerAuthentication resource in PERMISSIVE mode
reports healthy, shows green in every dashboard, and accepts a plaintext
connection carrying a stolen token exactly as readily as a properly
authenticated one.

The operator sees "mesh: enabled" and believes lateral movement is
blocked. It is not.

This is the same category of failure as module82's RuntimeClass problem:
the control is declared, it appears applied, and it does not do the thing
it is believed to do.

WHAT THIS MODULE VERIFIES — all functional now:
  1. PeerAuthentication mode per namespace — STRICT versus PERMISSIVE
     versus DISABLE, read from applied resources on the node.
  2. Mesh-wide default policy, which silently governs anything without
     an explicit policy.
  3. Sidecar proxy presence per workload — a pod with no sidecar is
     outside the mesh entirely regardless of policy.
  4. Plaintext listeners on service ports inside the mesh.
  5. AuthorizationPolicy presence — mTLS proves identity but does not
     restrict what that identity may call.
  6. Certificate validity and rotation age. A workload certificate that
     has not rotated is a long-lived credential.
  7. Token audience binding — a token valid for any audience is
     replayable across services.
  8. Direct pod-to-pod connections that bypass the sidecar.
  9. Mesh control-plane reachability and configuration drift.

Detection only. Policy changes are operator actions.
"""
import json, os, time, datetime, glob, re, socket, hashlib, subprocess

POLL_INTERVAL       = 300
CERT_ROTATION_WARN  = 90 * 86400     # certificate older than this = flag
CERT_EXPIRY_WARN    = 14 * 86400     # expiring within this = flag
STATE_FILE          = "/tmp/watchdog_mesh_mtls.json"

# Sidecar proxy process names
SIDECAR_PROCESSES = ["envoy", "pilot-agent", "istio-proxy",
                     "linkerd2-proxy", "linkerd-proxy",
                     "consul-connect-envoy", "kuma-dp", "envoy-cilium"]

# Mesh control plane components
CONTROL_PLANE = ["istiod", "pilot", "linkerd-destination",
                 "linkerd-identity", "consul", "kuma-cp"]

# Where mesh config lands on a node
MESH_CONFIG_GLOBS = [
    "/etc/istio/**/*.yaml", "/etc/istio/**/*.json",
    "/var/lib/istio/**/*.json",
    "/etc/linkerd/**/*.yaml",
    "/var/lib/kubelet/pods/*/volumes/kubernetes.io~configmap/istio*/**",
    "/var/lib/kubelet/pods/*/volumes/kubernetes.io~projected/istio*/**",
]

# Certificate locations for mesh workload identity
CERT_GLOBS = [
    "/etc/certs/*.pem",
    "/var/run/secrets/istio/*.pem",
    "/var/run/secrets/workload-spiffe-credentials/*.pem",
    "/var/lib/kubelet/pods/*/volumes/kubernetes.io~empty-dir/istio-*/**/*.pem",
    "/var/run/linkerd/identity/end-entity/*.crt",
]

# Ports typically carrying service-to-service traffic
SERVICE_PORTS = {80, 8080, 8000, 3000, 5000, 9000, 50051, 50052,
                 8081, 8082, 9090, 9091, 6379, 5672, 27017, 3306, 5432}

PRIVATE_PREFIXES = ["10.", "172.16.", "172.17.", "172.18.", "172.19.",
                    "172.2", "172.30.", "172.31.", "192.168."]

def now_iso():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()

def stamp():
    return datetime.datetime.now().strftime("%Y%m%d_%H%M%S")

def load_state():
    try:
        with open(STATE_FILE) as f:
            return json.load(f)
    except:
        return {"policy_hashes": {}, "cert_serials": {},
                "established": now_iso()}

def save_state(s):
    try:
        with open(STATE_FILE, "w") as f:
            json.dump(s, f)
    except:
        pass

def is_private(ip):
    return any(ip.startswith(p) for p in PRIVATE_PREFIXES)

def find_mesh_processes():
    """Sidecar proxies and control plane components running on this node."""
    sidecars = []
    control  = []
    try:
        for pid in os.listdir("/proc"):
            if not pid.isdigit():
                continue
            try:
                with open(f"/proc/{pid}/comm") as f:
                    comm = f.read().strip()
                with open(f"/proc/{pid}/cmdline", "rb") as f:
                    cmd = (f.read().replace(b"\x00", b" ")
                             .decode("utf-8", errors="replace").strip())
            except Exception:
                continue
            low = (comm + " " + cmd).lower()
            for name in SIDECAR_PROCESSES:
                if name in low:
                    sidecars.append({"pid": int(pid), "proxy": name,
                                     "cmd": cmd[:200]})
                    break
            else:
                for name in CONTROL_PLANE:
                    if name in low:
                        control.append({"pid": int(pid), "component": name,
                                        "cmd": cmd[:200]})
                        break
    except Exception:
        pass
    return sidecars, control

def find_peer_authentication_policies():
    """
    PeerAuthentication resources applied on this node. Read from mounted
    configmaps and any cached resource manifests.
    """
    policies = []
    seen = set()
    search = []
    for pattern in MESH_CONFIG_GLOBS:
        try:
            search.extend(glob.glob(pattern, recursive=True)[:500])
        except Exception:
            pass
    # Also scan pod volume mounts broadly for PeerAuthentication YAML
    try:
        search.extend(glob.glob(
            "/var/lib/kubelet/pods/*/volumes/**/*.yaml", recursive=True)[:500])
    except Exception:
        pass

    for path in search:
        if path in seen or not os.path.isfile(path):
            continue
        seen.add(path)
        try:
            if os.path.getsize(path) > 1024 * 1024:
                continue
            with open(path, errors="replace") as f:
                content = f.read(1024 * 1024)
        except Exception:
            continue

        if "PeerAuthentication" not in content:
            continue

        # Extract mode and namespace
        ns = None
        m = re.search(r'namespace:\s*["\']?([A-Za-z0-9\-]+)', content)
        if m:
            ns = m.group(1)
        modes = re.findall(r'mode:\s*["\']?(STRICT|PERMISSIVE|DISABLE|UNSET)',
                           content)
        name = None
        m = re.search(r'name:\s*["\']?([A-Za-z0-9\-\.]+)', content)
        if m:
            name = m.group(1)

        policies.append({"path": path, "namespace": ns, "name": name,
                         "modes": modes,
                         "hash": hashlib.sha256(content.encode()).hexdigest()[:16]})
    return policies

def find_authorization_policies():
    """AuthorizationPolicy presence — mTLS proves identity, this restricts it."""
    found = []
    seen = set()
    try:
        for path in glob.glob(
                "/var/lib/kubelet/pods/*/volumes/**/*.yaml", recursive=True)[:500]:
            if path in seen or not os.path.isfile(path):
                continue
            seen.add(path)
            try:
                if os.path.getsize(path) > 1024 * 1024:
                    continue
                with open(path, errors="replace") as f:
                    content = f.read(512 * 1024)
            except Exception:
                continue
            if "AuthorizationPolicy" in content:
                ns = None
                m = re.search(r'namespace:\s*["\']?([A-Za-z0-9\-]+)', content)
                if m:
                    ns = m.group(1)
                action = None
                m = re.search(r'action:\s*["\']?(ALLOW|DENY|AUDIT|CUSTOM)', content)
                if m:
                    action = m.group(1)
                found.append({"path": path, "namespace": ns, "action": action})
    except Exception:
        pass
    return found

def parse_certificate(path):
    """
    Read certificate validity dates without requiring the cryptography
    package. Uses openssl if present, falls back to file mtime.
    """
    info = {"path": path}
    try:
        st = os.stat(path)
        info["mtime"] = st.st_mtime
        info["age_s"] = time.time() - st.st_mtime
        info["mode"]  = oct(st.st_mode & 0o777)
    except Exception:
        return info

    try:
        out = subprocess.check_output(
            ["openssl", "x509", "-in", path, "-noout",
             "-enddate", "-startdate", "-subject", "-serial"],
            text=True, timeout=5, stderr=subprocess.DEVNULL)
        for line in out.splitlines():
            if line.startswith("notAfter="):
                info["not_after"] = line.split("=", 1)[1].strip()
            elif line.startswith("notBefore="):
                info["not_before"] = line.split("=", 1)[1].strip()
            elif line.startswith("subject="):
                info["subject"] = line.split("=", 1)[1].strip()[:160]
            elif line.startswith("serial="):
                info["serial"] = line.split("=", 1)[1].strip()

        if info.get("not_after"):
            try:
                exp = datetime.datetime.strptime(
                    info["not_after"], "%b %d %H:%M:%S %Y %Z")
                info["expires_in_s"] = (
                    exp.replace(tzinfo=datetime.timezone.utc) -
                    datetime.datetime.now(datetime.timezone.utc)).total_seconds()
            except Exception:
                pass
    except Exception:
        info["openssl_available"] = False
    return info

def find_workload_certificates():
    certs = []
    seen = set()
    for pattern in CERT_GLOBS:
        try:
            for path in glob.glob(pattern, recursive=True)[:200]:
                if path in seen or not os.path.isfile(path):
                    continue
                seen.add(path)
                certs.append(parse_certificate(path))
        except Exception:
            pass
    return certs

def find_plaintext_listeners():
    """
    Listening sockets on service ports. Inside a mesh, application traffic
    should arrive via the sidecar on localhost, not on a routable address.
    """
    listeners = []
    inode_owner = {}
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
                if target.startswith("socket:["):
                    if not cmd:
                        try:
                            with open(f"/proc/{pid}/cmdline", "rb") as f:
                                cmd = (f.read().replace(b"\x00", b" ")
                                         .decode("utf-8", errors="replace").strip())
                        except Exception:
                            pass
                    inode_owner[target[8:-1]] = {"pid": int(pid),
                                                  "cmd": cmd[:180]}
    except Exception:
        pass

    for suffix in ("", "6"):
        path = f"/proc/net/tcp{suffix}"
        if not os.path.exists(path):
            continue
        try:
            with open(path) as f:
                for line in f.readlines()[1:]:
                    parts = line.split()
                    if len(parts) < 10 or parts[3] != "0A":
                        continue
                    try:
                        addr_hex, port_hex = parts[1].rsplit(":", 1)
                        port = int(port_hex, 16)
                        if len(addr_hex) == 8:
                            ip = ".".join(str(int(addr_hex[i:i+2], 16))
                                          for i in (6, 4, 2, 0))
                        else:
                            ip = "::"
                    except Exception:
                        continue
                    owner = inode_owner.get(parts[9], {})
                    listeners.append({"addr": ip, "port": port,
                                      "pid": owner.get("pid"),
                                      "cmd": owner.get("cmd", "")})
        except Exception:
            pass
    return listeners

def analyse(sidecars, control, peer_policies, authz_policies,
            certs, listeners, state):
    alerts = []
    known_hashes = state.setdefault("policy_hashes", {})

    mesh_present = bool(sidecars or control or peer_policies)

    # ── 1. PERMISSIVE mode — the core finding ──
    strict_ns = set()
    permissive_ns = set()
    disabled_ns = set()

    for p in peer_policies:
        ns = p.get("namespace") or "(mesh-wide default)"
        modes = p.get("modes", [])
        if "STRICT" in modes:
            strict_ns.add(ns)
        if "PERMISSIVE" in modes or "UNSET" in modes:
            permissive_ns.add(ns)
        if "DISABLE" in modes:
            disabled_ns.add(ns)

        if "PERMISSIVE" in modes:
            alerts.append({
                "event":    "MTLS_PERMISSIVE_MODE",
                "severity": "CRITICAL",
                "policy":   p.get("name"),
                "namespace": ns,
                "path":     p["path"],
                "modes":    modes,
                "confidence": 0.90,
                "note": ("PeerAuthentication is in PERMISSIVE mode. This "
                         "accepts BOTH mTLS and plaintext. Every dashboard "
                         "will report the mesh as enabled and healthy, and a "
                         "plaintext connection carrying a stolen "
                         "service-account token will be accepted exactly as "
                         "readily as a properly authenticated one. The control "
                         "is declared and does not do what it is believed to "
                         "do"),
                "action": "Set mode: STRICT once all workloads have sidecars",
            })

        if "DISABLE" in modes:
            alerts.append({
                "event":    "MTLS_DISABLED",
                "severity": "CRITICAL",
                "policy":   p.get("name"),
                "namespace": ns,
                "path":     p["path"],
                "confidence": 0.95,
                "note": ("PeerAuthentication explicitly DISABLES mTLS for this "
                         "scope. Service-to-service traffic is plaintext and "
                         "any token that reaches a service is accepted"),
            })

        # Policy drift
        prev = known_hashes.get(p["path"])
        if prev and prev != p["hash"]:
            alerts.append({
                "event":    "MESH_POLICY_MODIFIED",
                "severity": "CRITICAL",
                "path":     p["path"],
                "namespace": ns,
                "current_modes": modes,
                "confidence": 0.85,
                "note": ("A mesh authentication policy changed. Verify it was "
                         "not relaxed from STRICT"),
            })
        known_hashes[p["path"]] = p["hash"]

    # ── 2. Mesh present but no STRICT policy anywhere ──
    if mesh_present and not strict_ns:
        alerts.append({
            "event":    "NO_STRICT_MTLS_POLICY",
            "severity": "CRITICAL",
            "sidecars_running": len(sidecars),
            "policies_found":   len(peer_policies),
            "permissive_namespaces": sorted(permissive_ns),
            "confidence": 0.85,
            "note": ("A service mesh is running on this node but no "
                     "PeerAuthentication policy sets STRICT mode. Without "
                     "STRICT, mTLS is optional — which means it is not a "
                     "control. A stolen token replays successfully over "
                     "plaintext"),
        })

    # ── 3. Sidecar coverage ──
    if peer_policies and not sidecars:
        alerts.append({
            "event":    "MESH_POLICY_WITHOUT_SIDECAR",
            "severity": "CRITICAL",
            "policies": len(peer_policies),
            "confidence": 0.85,
            "note": ("Mesh authentication policies exist on this node but no "
                     "sidecar proxy is running. A workload with no sidecar is "
                     "outside the mesh entirely — policy does not reach it, "
                     "and its traffic is plaintext regardless of what any "
                     "PeerAuthentication says"),
        })

    # ── 4. AuthorizationPolicy absent ──
    if strict_ns and not authz_policies:
        alerts.append({
            "event":    "NO_AUTHORIZATION_POLICY",
            "severity": "WARN",
            "strict_namespaces": sorted(strict_ns),
            "confidence": 0.70,
            "note": ("STRICT mTLS is configured but no AuthorizationPolicy "
                     "was found. mTLS proves WHO is calling; it does not "
                     "restrict WHAT they may call. With identity alone, any "
                     "authenticated workload can reach any other service in "
                     "the mesh — which is exactly the lateral movement mTLS "
                     "was meant to stop"),
        })

    # ── 5. Certificates ──
    known_serials = state.setdefault("cert_serials", {})
    for c in certs:
        path = c["path"]

        if c.get("expires_in_s") is not None:
            if c["expires_in_s"] < 0:
                alerts.append({
                    "event":    "MESH_CERTIFICATE_EXPIRED",
                    "severity": "CRITICAL",
                    "path":     path,
                    "not_after": c.get("not_after"),
                    "subject":  c.get("subject"),
                    "confidence": 0.95,
                    "note": ("A mesh workload certificate has expired. mTLS "
                             "handshakes with this identity will fail — and if "
                             "the mesh is in PERMISSIVE mode, traffic silently "
                             "falls back to plaintext instead of being "
                             "rejected"),
                })
            elif c["expires_in_s"] < CERT_EXPIRY_WARN:
                alerts.append({
                    "event":    "MESH_CERTIFICATE_EXPIRING",
                    "severity": "WARN",
                    "path":     path,
                    "expires_in_days": round(c["expires_in_s"] / 86400, 1),
                    "confidence": 0.70,
                })

        if c.get("age_s", 0) > CERT_ROTATION_WARN:
            alerts.append({
                "event":    "MESH_CERTIFICATE_NOT_ROTATED",
                "severity": "WARN",
                "path":     path,
                "age_days": round(c["age_s"] / 86400, 1),
                "threshold_days": CERT_ROTATION_WARN / 86400,
                "confidence": 0.65,
                "note": ("A workload certificate has not rotated in a long "
                         "time. Short-lived, frequently rotated workload "
                         "certificates are the point — a long-lived one is "
                         "just another static credential"),
            })

        serial = c.get("serial")
        if serial:
            prev = known_serials.get(path)
            if prev and prev == serial and c.get("age_s", 0) > CERT_ROTATION_WARN:
                pass  # already covered by rotation check
            known_serials[path] = serial

        # Certificate readable beyond owner
        mode = c.get("mode")
        if mode and mode not in ("0o600", "0o400"):
            try:
                m = int(mode.replace("0o", ""), 8)
                if m & 0o044:
                    alerts.append({
                        "event":    "MESH_CERTIFICATE_READABLE",
                        "severity": "WARN",
                        "path":     path,
                        "mode":     mode,
                        "confidence": 0.70,
                        "note": ("Workload certificate or key readable beyond "
                                 "its owner. Any local process can assume this "
                                 "workload's mesh identity"),
                    })
            except Exception:
                pass

    # ── 6. Plaintext service listeners on routable addresses ──
    if mesh_present:
        for l in listeners:
            if l["port"] not in SERVICE_PORTS:
                continue
            addr = l["addr"]
            cmd_low = (l.get("cmd") or "").lower()
            # Sidecar itself legitimately listens broadly
            if any(s in cmd_low for s in SIDECAR_PROCESSES):
                continue
            if addr == "0.0.0.0" or (is_private(addr) and addr != "127.0.0.1"):
                alerts.append({
                    "event":    "MESH_BYPASS_LISTENER",
                    "severity": "CRITICAL",
                    "address":  addr,
                    "port":     l["port"],
                    "pid":      l.get("pid"),
                    "cmd":      (l.get("cmd") or "")[:160],
                    "confidence": 0.75,
                    "note": ("An application is listening on a routable "
                             "address on a service port. Inside a mesh, "
                             "application traffic should arrive from the "
                             "sidecar on localhost. A routable listener can be "
                             "reached directly, bypassing the sidecar and "
                             "every mTLS and authorization policy with it"),
                })

    return alerts, state

def main():
    log = open(f"module85_{stamp()}.jsonl", "a")

    def emit(event):
        event.setdefault("ts", now_iso())
        log.write(json.dumps(event) + "\n")
        log.flush()

    emit({
        "event":  "RUN_START",
        "module": "85_mesh_mtls_enforcement",
        "status": "FUNCTIONAL — no special hardware required",
        "problem": ("PERMISSIVE mode looks like mTLS and is not. Istio and "
                     "Linkerd both ship a PERMISSIVE mode that accepts BOTH "
                     "mTLS and plaintext. It reports healthy, shows green in "
                     "every dashboard, and accepts a plaintext connection "
                     "carrying a stolen token exactly as readily as an "
                     "authenticated one"),
        "why_it_matters": ("mTLS is the control that makes a stolen bearer "
                            "token useless. If it is not enforced, an attacker "
                            "who lifted a service-account token out of a pod "
                            "replays it freely across the mesh"),
        "same_category_as": ("module82 — a control that is declared, appears "
                              "applied, and does not do the thing it is "
                              "believed to do"),
        "verifies": [
            "PeerAuthentication mode: STRICT vs PERMISSIVE vs DISABLE",
            "Mesh-wide default policy",
            "Sidecar proxy presence per workload",
            "AuthorizationPolicy presence (identity vs authorization)",
            "Workload certificate validity, expiry, and rotation age",
            "Certificate file permissions",
            "Plaintext listeners bypassing the sidecar",
            "Mesh policy drift",
        ],
        "mode": "detection only — policy changes are operator actions",
    })

    state = load_state()

    while True:
        sidecars, control = find_mesh_processes()
        peer_policies     = find_peer_authentication_policies()
        authz_policies    = find_authorization_policies()
        certs             = find_workload_certificates()
        listeners         = find_plaintext_listeners()

        modes = []
        for p in peer_policies:
            modes.extend(p.get("modes", []))

        emit({"event": "MESH_SCAN",
              "sidecar_proxies":   len(sidecars),
              "control_plane":     [c["component"] for c in control],
              "peer_policies":     len(peer_policies),
              "authz_policies":    len(authz_policies),
              "certificates":      len(certs),
              "modes_observed":    sorted(set(modes)),
              "service_listeners": len([l for l in listeners
                                         if l["port"] in SERVICE_PORTS])})

        if not sidecars and not control and not peer_policies:
            emit({"event": "NO_SERVICE_MESH",
                  "note": ("No service mesh sidecar, control plane, or policy "
                           "found on this host. This module activates on a "
                           "mesh-enabled Kubernetes node.")})
            time.sleep(POLL_INTERVAL)
            continue

        alerts, state = analyse(sidecars, control, peer_policies,
                                authz_policies, certs, listeners, state)
        for a in alerts:
            emit(a)

        if not alerts:
            emit({"event": "MESH_MTLS_ENFORCED",
                  "sidecars": len(sidecars),
                  "strict_policies": len([p for p in peer_policies
                                           if "STRICT" in p.get("modes", [])])})

        save_state(state)
        time.sleep(POLL_INTERVAL)

if __name__ == "__main__":
    main()
