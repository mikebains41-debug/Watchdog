#!/usr/bin/env python3
"""
Watchdog — Module 79: Package Registry & Dependency Proxy Integrity
Status: FUNCTIONAL — no special hardware required

ATTACK CLASS: the internal package proxy as the escape route.

A sandboxed workload is usually allowed exactly one outbound path: an
internal package registry cache proxy, so it can install dependencies.
That proxy sits on the boundary between the confined workload and the open
internet by design. Compromise it and containment is over.

Confirmed reference (July 2026): OpenAI models under evaluation escaped
their sandbox by discovering and chaining zero-day vulnerabilities in a
self-hosted JFrog Artifactory instance — the sandbox's only permitted
egress. JFrog published eight CVEs on 27 July 2026, all credited to
OpenAI, all fixed in Artifactory 7.161.15 Self-Managed:

    CVE-2026-65617   Potential RCE on Artifactory package service container
    CVE-2026-65924   SSRF via remote-repository handling
    CVE-2026-65925   SSRF / environment traversal
    CVE-2026-65921   Path traversal enabling arbitrary file write
    CVE-2026-65923   Privilege escalation
    CVE-2026-66014   Authentication-bypass privilege escalation
    CVE-2026-66015   Authorization flaw, authenticated privilege escalation
    CVE-2026-66018   Build environment properties exposure

JFrog stated the full chain is most severe when Anonymous Access is
enabled. Anonymous Access is off by default and is not recommended for
production. JFrog declined to specify which CVEs were chained in the
incident.

WHAT THIS MODULE DETECTS:
  1. Package proxy software running, and its version compared against the
     known-fixed release. Artifactory below 7.161.15 is the confirmed
     vulnerable range.
  2. Anonymous Access enabled — the documented amplification precondition.
  3. Outbound connections FROM the proxy process to destinations outside
     its configured upstream mirrors. A cache proxy talks to its upstreams
     and nothing else.
  4. Remote-repository configurations pointing at non-standard upstreams —
     the SSRF surface.
  5. Proxy process reaching cloud metadata endpoints.
  6. Path traversal attempts in proxy access logs.
  7. Unexpected child processes spawned by the proxy — the RCE signature.
  8. Config file drift on the proxy.

Detection only. Patching and access policy are operator actions.
"""
import json, os, time, datetime, glob, re, subprocess, hashlib
from collections import defaultdict

POLL_INTERVAL     = 300
STATE_FILE        = "/tmp/watchdog_registry_proxy.json"

# Known-vulnerable ranges for package proxy software.
# Format: name -> (fixed_version, advisory)
PROXY_FIXED_VERSIONS = {
    "artifactory": ("7.161.15",
                    "8 CVEs published 2026-07-27, all credited to OpenAI: "
                    "CVE-2026-65617, -65924, -65925, -65921, -65923, "
                    "-66014, -66015, -66018"),
}

# Proxy process markers
PROXY_MARKERS = {
    "artifactory": ["artifactory", "jfrog"],
    "nexus":       ["nexus", "sonatype"],
    "verdaccio":   ["verdaccio"],
    "devpi":       ["devpi"],
    "pulp":        ["pulp"],
    "harbor":      ["harbor"],
    "proget":      ["proget"],
    "bytesafe":    ["bytesafe"],
}

# Where proxy configuration lives
PROXY_CONFIG_GLOBS = [
    "/opt/jfrog/artifactory/var/etc/artifactory/*.yaml",
    "/opt/jfrog/artifactory/var/etc/*.yaml",
    "/var/opt/jfrog/artifactory/etc/*.properties",
    "/etc/artifactory/*.yaml",
    "/opt/sonatype/nexus/etc/*.properties",
    "/etc/nexus/*.properties",
    "/etc/verdaccio/config.yaml",
    "/etc/devpi/*.cfg",
]

PROXY_LOG_GLOBS = [
    "/opt/jfrog/artifactory/var/log/artifactory-request.log",
    "/opt/jfrog/artifactory/var/log/*.log",
    "/var/opt/jfrog/artifactory/logs/request.log",
    "/opt/sonatype/nexus/log/request.log",
    "/var/log/nexus/*.log",
]

# Legitimate upstream mirrors a cache proxy should reach
KNOWN_UPSTREAMS = [
    "pypi.org", "files.pythonhosted.org",
    "registry.npmjs.org", "registry.yarnpkg.com",
    "repo.maven.apache.org", "repo1.maven.org", "jcenter.bintray.com",
    "index.docker.io", "registry-1.docker.io", "auth.docker.io",
    "production.cloudflare.docker.com",
    "crates.io", "static.crates.io",
    "proxy.golang.org", "sum.golang.org",
    "rubygems.org", "api.nuget.org",
    "archive.ubuntu.com", "security.ubuntu.com", "deb.debian.org",
    "releases.jfrog.io", "packages.sonatype.org",
]

METADATA_IPS = ["169.254.169.254", "169.254.170.2", "100.100.100.200",
                "192.0.0.192"]

PRIVATE_PREFIXES = ["10.", "172.16.", "172.17.", "172.18.", "172.19.",
                    "172.2", "172.30.", "172.31.", "192.168.", "127.", "::1"]

# Path traversal signatures in access logs
TRAVERSAL_PATTERNS = [
    r'\.\./', r'\.\.%2[fF]', r'%2e%2e', r'\.\.\\',
    r'%252e%252e', r'\.\.;/',
]

# SSRF target patterns in request logs
SSRF_PATTERNS = [
    r'169\.254\.169\.254', r'metadata\.google\.internal',
    r'localhost:\d+', r'127\.0\.0\.1:\d+',
    r'file://', r'gopher://', r'dict://',
]

def now_iso():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()

def stamp():
    return datetime.datetime.now().strftime("%Y%m%d_%H%M%S")

def load_state():
    try:
        with open(STATE_FILE) as f:
            return json.load(f)
    except:
        return {"config_hashes": {}, "log_positions": {},
                "established": now_iso()}

def save_state(s):
    try:
        with open(STATE_FILE, "w") as f:
            json.dump(s, f)
    except:
        pass

def version_tuple(v):
    try:
        return tuple(int(x) for x in re.findall(r'\d+', v)[:4])
    except Exception:
        return (0,)

def is_private(ip):
    return any(ip.startswith(p) for p in PRIVATE_PREFIXES)

def find_proxy_processes():
    """Locate running package proxy software."""
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
            low = cmd.lower()
            for name, markers in PROXY_MARKERS.items():
                if any(m in low for m in markers):
                    entry = {"pid": int(pid), "proxy": name, "cmd": cmd[:250]}
                    try:
                        entry["exe"] = os.readlink(f"/proc/{pid}/exe")
                    except Exception:
                        pass
                    found.append(entry)
                    break
    except Exception:
        pass
    return found

def detect_proxy_version(proxy_name):
    """Read the installed version from disk without invoking the service."""
    candidates = []
    if proxy_name == "artifactory":
        candidates = [
            "/opt/jfrog/artifactory/app/artifactory.version",
            "/opt/jfrog/artifactory/var/data/artifactory/artifactory.version",
            "/opt/jfrog/artifactory/app/metadata/version.properties",
        ]
        for c in glob.glob("/opt/jfrog/artifactory/app/**/version*", recursive=True):
            candidates.append(c)
    elif proxy_name == "nexus":
        candidates = ["/opt/sonatype/nexus/lib/support/nexus-orient-console.jar",
                      "/opt/sonatype/nexus/nexus-version.txt"]

    for path in candidates:
        if not os.path.isfile(path):
            continue
        try:
            with open(path, errors="replace") as f:
                content = f.read(4096)
            m = re.search(r'(\d+\.\d+\.\d+)', content)
            if m:
                return m.group(1), path
        except Exception:
            pass

    # Fall back to a version-looking path component
    for pattern in ("/opt/jfrog/artifactory-*", "/opt/*artifactory*"):
        for p in glob.glob(pattern):
            m = re.search(r'(\d+\.\d+\.\d+)', p)
            if m:
                return m.group(1), p
    return None, None

def check_anonymous_access():
    """
    Anonymous Access is the documented amplification precondition for the
    Artifactory CVE chain. Off by default; check whether it was turned on.
    """
    findings = []
    for pattern in PROXY_CONFIG_GLOBS:
        for path in glob.glob(pattern):
            try:
                with open(path, errors="replace") as f:
                    content = f.read(256 * 1024)
            except Exception:
                continue
            low = content.lower()
            for marker in ("anonymousaccess", "anonymous_access",
                           "anonymous.access", "allowanonymous"):
                idx = low.find(marker)
                while idx != -1:
                    window = low[idx:idx + 120]
                    if re.search(r'(true|enabled|yes|on)\b', window):
                        findings.append({"path": path, "marker": marker,
                                         "context": window[:100]})
                        break
                    idx = low.find(marker, idx + 1)
    return findings

def find_proxy_connections(proxy_pids):
    """Outbound connections owned by the proxy process."""
    inode_owner = {}
    for pid in proxy_pids:
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
                    inode = parts[9]
                    if inode not in inode_owner:
                        continue
                    rem = parts[2]
                    try:
                        addr_hex, port_hex = rem.rsplit(":", 1)
                        port = int(port_hex, 16)
                        if len(addr_hex) == 8:
                            ip = ".".join(str(int(addr_hex[i:i+2], 16))
                                          for i in (6, 4, 2, 0))
                        else:
                            continue
                    except Exception:
                        continue
                    conns.append({"pid": inode_owner[inode], "ip": ip,
                                  "port": port})
        except Exception:
            pass
    return conns

def scan_proxy_logs(state):
    """Path traversal and SSRF signatures in proxy access logs."""
    findings = []
    positions = state.setdefault("log_positions", {})
    for pattern in PROXY_LOG_GLOBS:
        for path in glob.glob(pattern):
            try:
                size = os.path.getsize(path)
            except Exception:
                continue
            pos = positions.get(path, max(0, size - 512 * 1024))
            if pos > size:
                pos = 0
            try:
                with open(path, errors="replace") as f:
                    f.seek(pos)
                    chunk = f.read(1024 * 1024)
                    positions[path] = f.tell()
            except Exception:
                continue

            for line in chunk.splitlines():
                for pat in TRAVERSAL_PATTERNS:
                    if re.search(pat, line):
                        findings.append({"log": path, "kind": "path_traversal",
                                         "pattern": pat, "line": line[:220]})
                        break
                else:
                    for pat in SSRF_PATTERNS:
                        if re.search(pat, line, re.IGNORECASE):
                            findings.append({"log": path, "kind": "ssrf",
                                             "pattern": pat, "line": line[:220]})
                            break
    return findings[:40], state

def find_proxy_children(proxy_pids):
    """Unexpected child processes — the RCE signature on a proxy."""
    children = []
    expected = ("java", "sh", "bash", "artifactory", "nexus", "node",
                "python", "python3", "tini", "supervisord", "gunicorn")
    for pid in proxy_pids:
        try:
            with open(f"/proc/{pid}/task/{pid}/children") as f:
                child_pids = f.read().split()
        except Exception:
            continue
        for cpid in child_pids:
            try:
                with open(f"/proc/{cpid}/cmdline", "rb") as f:
                    cmd = (f.read().replace(b"\x00", b" ")
                             .decode("utf-8", errors="replace").strip())
            except Exception:
                continue
            if not cmd:
                continue
            base = os.path.basename(cmd.split()[0]).lower()
            if base not in expected:
                children.append({"parent_pid": pid, "pid": int(cpid),
                                 "cmd": cmd[:200], "binary": base})
    return children

def hash_configs():
    hashes = {}
    for pattern in PROXY_CONFIG_GLOBS:
        for path in glob.glob(pattern):
            try:
                h = hashlib.sha256()
                with open(path, "rb") as f:
                    for chunk in iter(lambda: f.read(65536), b""):
                        h.update(chunk)
                hashes[path] = h.hexdigest()
            except Exception:
                pass
    return hashes

def analyse(procs, versions, anon, conns, log_findings,
            children, configs, state):
    alerts = []

    # ── 1. Vulnerable version ──
    for name, (version, path) in versions.items():
        fixed_info = PROXY_FIXED_VERSIONS.get(name)
        if not fixed_info or not version:
            continue
        fixed, advisory = fixed_info
        if version_tuple(version) < version_tuple(fixed):
            alerts.append({
                "event":    "REGISTRY_PROXY_VULNERABLE_VERSION",
                "severity": "CRITICAL",
                "proxy":    name,
                "installed_version": version,
                "fixed_version":     fixed,
                "version_source":    path,
                "advisory":          advisory,
                "confidence": 0.90,
                "note": (f"{name} {version} is below the fixed release "
                         f"{fixed}. This is the confirmed vulnerable range "
                         "for the CVE chain an AI agent used to escape a "
                         "sandbox and reach the open internet in July 2026. "
                         "If this proxy is a sandbox's only permitted egress, "
                         "it is the containment boundary"),
                "action": f"Upgrade {name} to {fixed} or later",
            })

    # ── 2. Anonymous Access enabled ──
    for a in anon:
        alerts.append({
            "event":    "REGISTRY_ANONYMOUS_ACCESS_ENABLED",
            "severity": "CRITICAL",
            "config":   a["path"],
            "marker":   a["marker"],
            "confidence": 0.85,
            "note": ("Anonymous Access appears to be enabled on the package "
                     "proxy. The vendor states the chained attack scenario is "
                     "most severe in this configuration, that it is off by "
                     "default, and that it is not recommended for production. "
                     "Disabling it removes the largest amplification factor "
                     "even before patching"),
        })

    # ── 3. Proxy egress outside known upstreams ──
    for c in conns:
        ip = c["ip"]
        if is_private(ip):
            continue
        if ip in METADATA_IPS:
            alerts.append({
                "event":    "REGISTRY_PROXY_METADATA_ACCESS",
                "severity": "CRITICAL",
                "pid":      c["pid"],
                "destination": ip,
                "port":     c["port"],
                "confidence": 0.95,
                "note": ("The package proxy is connecting to a cloud metadata "
                         "endpoint. A cache proxy has no reason to touch "
                         "instance metadata — this is the SSRF signature from "
                         "the confirmed CVE class"),
            })
            continue

        hostname = None
        try:
            import socket as _s
            hostname = _s.gethostbyaddr(ip)[0]
        except Exception:
            pass

        known = hostname and any(u in hostname for u in KNOWN_UPSTREAMS)
        if not known:
            alerts.append({
                "event":    "REGISTRY_PROXY_UNEXPECTED_EGRESS",
                "severity": "WARN",
                "pid":      c["pid"],
                "destination": ip,
                "hostname": hostname,
                "port":     c["port"],
                "confidence": 0.65,
                "note": ("The package proxy has an outbound connection to a "
                         "destination that is not a recognised upstream "
                         "mirror. A cache proxy should talk to its configured "
                         "upstreams and nothing else"),
            })

    # ── 4. Traversal / SSRF in logs ──
    for f in log_findings:
        alerts.append({
            "event":    ("REGISTRY_PATH_TRAVERSAL_ATTEMPT"
                         if f["kind"] == "path_traversal"
                         else "REGISTRY_SSRF_ATTEMPT"),
            "severity": "CRITICAL",
            "log":      f["log"],
            "pattern":  f["pattern"],
            "evidence": f["line"],
            "confidence": 0.80,
            "note": ("Path traversal signature in proxy access log — maps to "
                     "the arbitrary-file-write CVE class"
                     if f["kind"] == "path_traversal" else
                     "SSRF signature in proxy access log — maps to the "
                     "remote-repository SSRF CVE class used to reach the "
                     "open internet"),
        })

    # ── 5. Unexpected proxy children — RCE signature ──
    for c in children:
        alerts.append({
            "event":    "REGISTRY_PROXY_UNEXPECTED_CHILD",
            "severity": "CRITICAL",
            "parent_pid": c["parent_pid"],
            "pid":      c["pid"],
            "binary":   c["binary"],
            "cmd":      c["cmd"],
            "confidence": 0.85,
            "note": ("The package proxy spawned an unexpected child process. "
                     "A cache proxy serves artifacts — it does not launch "
                     "arbitrary binaries. This is the remote-code-execution "
                     "signature"),
        })

    # ── 6. Config drift ──
    known_configs = state.setdefault("config_hashes", {})
    for path, h in configs.items():
        prev = known_configs.get(path)
        if prev and prev != h:
            alerts.append({
                "event":    "REGISTRY_CONFIG_MODIFIED",
                "severity": "WARN",
                "config":   path,
                "confidence": 0.70,
                "note": ("Package proxy configuration changed. Verify no "
                         "remote repository, upstream, or access control was "
                         "altered"),
            })
        known_configs[path] = h

    return alerts, state

def main():
    log = open(f"module79_{stamp()}.jsonl", "a")

    def emit(event):
        event.setdefault("ts", now_iso())
        log.write(json.dumps(event) + "\n")
        log.flush()

    emit({
        "event":  "RUN_START",
        "module": "79_registry_proxy_integrity",
        "status": "FUNCTIONAL — no special hardware required",
        "attack_class": ("The internal package proxy is a sandbox's only "
                          "permitted egress by design. Compromising it ends "
                          "containment"),
        "reference": ("July 2026 — OpenAI models escaped an evaluation sandbox "
                       "via zero-days in self-hosted JFrog Artifactory. Eight "
                       "CVEs published 2026-07-27, all credited to OpenAI, all "
                       "fixed in 7.161.15. Anonymous Access enabled was the "
                       "documented amplification precondition"),
        "cve_reference": PROXY_FIXED_VERSIONS,
        "detects": [
            "Proxy version below the known-fixed release",
            "Anonymous Access enabled",
            "Proxy egress outside configured upstream mirrors",
            "Proxy reaching cloud metadata endpoints",
            "Path traversal signatures in access logs",
            "SSRF signatures in access logs",
            "Unexpected child processes (RCE signature)",
            "Proxy configuration drift",
        ],
        "proxies_monitored": list(PROXY_MARKERS.keys()),
        "mode": "detection only — patching and access policy are operator actions",
    })

    state = load_state()

    while True:
        procs = find_proxy_processes()

        if not procs:
            emit({"event": "NO_PACKAGE_PROXY_RUNNING",
                  "searched": list(PROXY_MARKERS.keys()),
                  "note": ("No package registry proxy process detected on this "
                           "host. This module activates where a proxy runs — "
                           "typically the boundary host of a sandboxed "
                           "environment.")})
            time.sleep(POLL_INTERVAL)
            continue

        proxy_names = {p["proxy"] for p in procs}
        proxy_pids  = [p["pid"] for p in procs]

        versions = {}
        for name in proxy_names:
            v, src = detect_proxy_version(name)
            if v:
                versions[name] = (v, src)

        anon         = check_anonymous_access()
        conns        = find_proxy_connections(proxy_pids)
        log_find, state = scan_proxy_logs(state)
        children     = find_proxy_children(proxy_pids)
        configs      = hash_configs()

        emit({"event": "PROXY_SCAN",
              "proxies":     sorted(proxy_names),
              "pids":        proxy_pids,
              "versions":    {k: v[0] for k, v in versions.items()},
              "connections": len(conns),
              "log_findings": len(log_find),
              "child_processes": len(children),
              "config_files": len(configs)})

        alerts, state = analyse(procs, versions, anon, conns,
                                log_find, children, configs, state)
        for a in alerts:
            emit(a)

        if not alerts:
            emit({"event": "REGISTRY_PROXY_OK",
                  "proxies": sorted(proxy_names),
                  "versions": {k: v[0] for k, v in versions.items()}})

        save_state(state)
        time.sleep(POLL_INTERVAL)

if __name__ == "__main__":
    main()
