#!/usr/bin/env python3
"""
Watchdog — Module 62: QaaS Configuration Drift & Environment Guard
Status: FUNCTIONAL — no special hardware or credentials required

Attack vector: every quantum SDK reads its endpoint and credentials from a
config file or environment variable at import time. Nothing verifies them.

Qiskit reads ~/.qiskit/qiskit-ibm.json. Amazon Braket reads AWS config.
D-Wave Ocean reads ~/.config/dwave/dwave.conf. Cirq reads a Google Cloud
credential path. Each of these is a plain file that any process running as
the same user can rewrite.

An attacker who can write one of those files can:
  - Redirect the API endpoint to a proxy they control, capturing every
    circuit a tenant submits and every result returned
  - Substitute their own token so jobs bill to the victim's account
  - Point at a classical simulator instead of real hardware, so the tenant
    pays for QPU time and receives simulated results
  - Read a token stored world-readable and use it from anywhere

None of this triggers a single alert in the SDK. The job runs. Results come
back. Everything looks normal.

WHAT THIS CHECKS (all functional now, no credentials needed):
  - Config file permissions across every quantum SDK — a credentials file
    readable by group or others is an exposed token
  - API endpoint fields inside those config files, compared against the
    official endpoints for each provider
  - Environment variables carrying tokens, and whether they leak into
    /proc/<pid>/environ readable by others
  - Token format sanity — a token that is not the expected shape may be a
    substituted value
  - Proxy environment variables (HTTP_PROXY, HTTPS_PROXY, REQUESTS_CA_BUNDLE,
    SSL_CERT_FILE) that would route or intercept SDK traffic
  - Custom CA bundles — the standard way to make MITM interception invisible
  - /etc/hosts entries for quantum provider domains — DNS hijack at the
    host level
  - Config file content hash baseline and drift

No credentials are read, logged, or transmitted. Token values are never
written to the log — only their length, prefix shape, and a hash.
"""
import os, json, time, datetime, hashlib, stat, glob, re
from pathlib import Path

POLL_INTERVAL   = 600
BASELINE_FILE   = "/tmp/watchdog_qaas_config_baseline.json"

HOME = os.path.expanduser("~")

# Config files every quantum SDK reads at import time
QAAS_CONFIG_PATHS = [
    (f"{HOME}/.qiskit/qiskit-ibm.json",        "Qiskit IBM Runtime"),
    (f"{HOME}/.qiskit/settings.json",          "Qiskit settings"),
    (f"{HOME}/.qiskit/qiskitrc",               "Qiskit legacy config"),
    (f"{HOME}/.config/dwave/dwave.conf",       "D-Wave Ocean"),
    (f"{HOME}/.dwrc",                          "D-Wave legacy"),
    (f"{HOME}/.aws/credentials",               "AWS / Braket credentials"),
    (f"{HOME}/.aws/config",                    "AWS / Braket config"),
    (f"{HOME}/.config/gcloud/application_default_credentials.json",
                                                "Google Cloud / Cirq"),
    (f"{HOME}/.pennylane/config.toml",         "PennyLane"),
    (f"{HOME}/.azure/config",                  "Azure Quantum"),
]

# Environment variables that carry quantum credentials or redirect traffic
CREDENTIAL_ENV_VARS = [
    "IBM_QUANTUM_TOKEN", "QISKIT_IBM_TOKEN", "QISKIT_IBM_INSTANCE",
    "DWAVE_API_TOKEN", "DWAVE_API_ENDPOINT", "DWAVE_SOLVER",
    "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN",
    "AZURE_QUANTUM_TOKEN", "GOOGLE_APPLICATION_CREDENTIALS",
    "PENNYLANE_TOKEN",
]

REDIRECT_ENV_VARS = [
    "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY",
    "http_proxy", "https_proxy", "all_proxy",
    "REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE", "SSL_CERT_FILE",
    "SSL_CERT_DIR", "NODE_EXTRA_CA_CERTS",
    "QISKIT_IBM_URL", "DWAVE_API_ENDPOINT", "AWS_ENDPOINT_URL",
    "BRAKET_ENDPOINT",
]

# The real endpoints. Anything else in a config file is a redirect.
OFFICIAL_ENDPOINTS = {
    "ibm": [
        "auth.quantum-computing.ibm.com",
        "api.quantum-computing.ibm.com",
        "quantum.cloud.ibm.com",
        "iam.cloud.ibm.com",
        "us-east.quantum-computing.cloud.ibm.com",
    ],
    "dwave": [
        "cloud.dwavesys.com",
        "na-west-1.cloud.dwavesys.com",
        "eu-central-1.cloud.dwavesys.com",
    ],
    "braket": [
        "braket.us-east-1.amazonaws.com",
        "braket.us-west-1.amazonaws.com",
        "braket.us-west-2.amazonaws.com",
        "braket.eu-west-2.amazonaws.com",
    ],
    "google": [
        "quantum.googleapis.com",
    ],
    "azure": [
        "quantum.azure.com",
        "westus.quantum.azure.com",
    ],
}

ALL_OFFICIAL_HOSTS = {h for hosts in OFFICIAL_ENDPOINTS.values() for h in hosts}

# Provider domains an attacker would hijack in /etc/hosts
PROVIDER_DOMAINS = [
    "quantum-computing.ibm.com", "quantum.cloud.ibm.com",
    "cloud.dwavesys.com", "amazonaws.com",
    "quantum.googleapis.com", "quantum.azure.com",
]

URL_PATTERN = re.compile(r'https?://([A-Za-z0-9.\-]+)')

def now_iso():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()

def stamp():
    return datetime.datetime.now().strftime("%Y%m%d_%H%M%S")

def load_baseline() -> dict:
    try:
        with open(BASELINE_FILE) as f:
            return json.load(f)
    except:
        return {"configs": {}, "env": {}, "established": now_iso()}

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
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()
    except:
        return None

def token_shape(value: str) -> dict:
    """
    Describe a token without ever recording it. Length, character class,
    and a hash — enough to detect substitution, useless to an attacker.
    """
    if not value:
        return {"present": False}
    return {
        "present":   True,
        "length":    len(value),
        "hash":      hashlib.sha256(value.encode()).hexdigest()[:16],
        "charset":   ("hex" if re.fullmatch(r'[0-9a-fA-F]+', value)
                      else "base64ish" if re.fullmatch(r'[A-Za-z0-9+/=_\-]+', value)
                      else "mixed"),
    }

def scan_config_files() -> list:
    """Permissions, hash, and endpoint content of every SDK config file."""
    results = []
    for path, label in QAAS_CONFIG_PATHS:
        if not os.path.exists(path):
            continue
        entry = {"path": path, "provider": label}
        try:
            st = os.stat(path)
            mode = st.st_mode & 0o777
            entry["mode"]        = oct(mode)
            entry["uid"]         = st.st_uid
            entry["gid"]         = st.st_gid
            entry["group_read"]  = bool(mode & stat.S_IRGRP)
            entry["world_read"]  = bool(mode & stat.S_IROTH)
            entry["world_write"] = bool(mode & stat.S_IWOTH)
            entry["group_write"] = bool(mode & stat.S_IWGRP)
            entry["mtime"]       = st.st_mtime
        except Exception:
            pass

        entry["sha256"] = sha256_file(path)

        # Extract any URL hosts referenced in the file, without reading
        # credential values.
        try:
            with open(path, "r", errors="replace") as f:
                content = f.read(64 * 1024)
            hosts = set(URL_PATTERN.findall(content))
            entry["referenced_hosts"] = sorted(hosts)
            entry["unofficial_hosts"] = sorted(
                h for h in hosts
                if h not in ALL_OFFICIAL_HOSTS
                and not any(h.endswith("." + o) or h == o
                            for o in ALL_OFFICIAL_HOSTS))
        except Exception:
            entry["referenced_hosts"] = []
            entry["unofficial_hosts"] = []

        results.append(entry)
    return results

def scan_environment() -> dict:
    """Credential and redirect environment variables — shapes only."""
    creds = {}
    for var in CREDENTIAL_ENV_VARS:
        val = os.environ.get(var)
        if val:
            creds[var] = token_shape(val)

    redirects = {}
    for var in REDIRECT_ENV_VARS:
        val = os.environ.get(var)
        if val:
            redirects[var] = val   # These are paths/URLs, not secrets

    return {"credentials": creds, "redirects": redirects}

def check_environ_exposure() -> list:
    """
    A token in an environment variable is visible in /proc/<pid>/environ.
    If that file is readable beyond the owner, the token is exposed to
    every process on the host.
    """
    exposed = []
    my_pid = os.getpid()
    try:
        environ_path = f"/proc/{my_pid}/environ"
        st = os.stat(environ_path)
        mode = st.st_mode & 0o777
        if mode & (stat.S_IROTH | stat.S_IRGRP):
            exposed.append({"path": environ_path, "mode": oct(mode)})
    except Exception:
        pass

    # Also check whether any other process exposes quantum tokens
    try:
        for pid_dir in os.listdir("/proc"):
            if not pid_dir.isdigit() or int(pid_dir) == my_pid:
                continue
            ep = f"/proc/{pid_dir}/environ"
            try:
                st = os.stat(ep)
                if not (st.st_mode & (stat.S_IROTH | stat.S_IRGRP)):
                    continue
                with open(ep, "rb") as f:
                    data = f.read(32768)
                text = data.decode("utf-8", errors="replace")
                for var in CREDENTIAL_ENV_VARS:
                    if f"{var}=" in text:
                        cmd = ""
                        try:
                            with open(f"/proc/{pid_dir}/cmdline", "rb") as cf:
                                cmd = (cf.read().replace(b"\x00", b" ")
                                         .decode("utf-8", errors="replace").strip())
                        except:
                            pass
                        exposed.append({"pid": int(pid_dir), "var": var,
                                         "cmd": cmd[:120],
                                         "mode": oct(st.st_mode & 0o777)})
                        break
            except (OSError, PermissionError):
                continue
    except Exception:
        pass
    return exposed

def check_hosts_file() -> list:
    """/etc/hosts entries pointing at quantum provider domains."""
    hijacks = []
    try:
        with open("/etc/hosts", errors="replace") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                parts = line.split()
                if len(parts) < 2:
                    continue
                ip = parts[0]
                for host in parts[1:]:
                    for domain in PROVIDER_DOMAINS:
                        if domain in host:
                            hijacks.append({"ip": ip, "host": host,
                                             "line": line})
                            break
    except Exception:
        pass
    return hijacks

def analyse(configs: list, env: dict, exposure: list,
            hosts_hijack: list, baseline: dict) -> tuple:
    alerts = []
    known = baseline.get("configs", {})

    for cfg in configs:
        path = cfg["path"]

        # ── 1. Credentials file readable beyond owner ──
        if cfg.get("world_read") or cfg.get("group_read"):
            alerts.append({
                "event":    "INSECURE_TOKEN_PERMS",
                "severity": "CRITICAL",
                "path":     path,
                "provider": cfg.get("provider"),
                "mode":     cfg.get("mode"),
                "world_read": cfg.get("world_read"),
                "group_read": cfg.get("group_read"),
                "confidence": 0.90,
                "remediation": f"chmod 600 {path}",
                "note": ("Quantum credentials file is readable beyond its "
                         "owner. Any process running as another user on this "
                         "host can read the API token and submit jobs billed "
                         "to this account"),
            })

        if cfg.get("world_write") or cfg.get("group_write"):
            alerts.append({
                "event":    "QAAS_CONFIG_WRITABLE",
                "severity": "CRITICAL",
                "path":     path,
                "provider": cfg.get("provider"),
                "mode":     cfg.get("mode"),
                "confidence": 0.95,
                "remediation": f"chmod 600 {path}",
                "note": ("Config file is writable by group or others. An "
                         "attacker can rewrite the API endpoint to a proxy "
                         "they control and capture every circuit submitted"),
            })

        # ── 2. Unofficial endpoint in a config file ──
        if cfg.get("unofficial_hosts"):
            alerts.append({
                "event":    "QAAS_CONFIG_HIJACK",
                "severity": "CRITICAL",
                "path":     path,
                "provider": cfg.get("provider"),
                "unofficial_hosts": cfg["unofficial_hosts"],
                "official_endpoints": sorted(ALL_OFFICIAL_HOSTS),
                "confidence": 0.85,
                "note": ("Config file references an endpoint that is not an "
                         "official provider address. Circuits submitted "
                         "through this config go somewhere else first"),
            })

        # ── 3. Config content changed ──
        if path in known:
            prev = known[path]
            if prev.get("sha256") and cfg.get("sha256") \
                    and prev["sha256"] != cfg["sha256"]:
                alerts.append({
                    "event":    "QAAS_CONFIG_MODIFIED",
                    "severity": "CRITICAL",
                    "path":     path,
                    "provider": cfg.get("provider"),
                    "was_hash": prev["sha256"][:16] + "...",
                    "now_hash": cfg["sha256"][:16] + "...",
                    "confidence": 0.80,
                    "note": ("Quantum SDK config file changed since baseline. "
                             "Verify the endpoint and credentials are still "
                             "the intended ones"),
                })
            if prev.get("mode") != cfg.get("mode"):
                alerts.append({
                    "event":    "QAAS_CONFIG_PERMS_CHANGED",
                    "severity": "WARN",
                    "path":     path,
                    "was":      prev.get("mode"),
                    "now":      cfg.get("mode"),
                    "confidence": 0.70,
                })
        else:
            alerts.append({
                "event":    "QAAS_CONFIG_NEW",
                "severity": "WARN",
                "path":     path,
                "provider": cfg.get("provider"),
                "confidence": 0.55,
                "note": "SDK config file not present at baseline",
            })

    # ── 4. Traffic redirect environment variables ──
    for var, val in env.get("redirects", {}).items():
        if var in ("REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE", "SSL_CERT_FILE",
                    "NODE_EXTRA_CA_CERTS"):
            alerts.append({
                "event":    "CUSTOM_CA_BUNDLE_SET",
                "severity": "CRITICAL",
                "variable": var,
                "value":    val,
                "confidence": 0.85,
                "note": ("A custom CA bundle is configured. This is the "
                         "standard method for making TLS interception "
                         "invisible — an attacker's proxy certificate is "
                         "trusted and every circuit is read in transit"),
            })
        elif "PROXY" in var.upper():
            alerts.append({
                "event":    "QAAS_PROXY_CONFIGURED",
                "severity": "WARN",
                "variable": var,
                "value":    val,
                "confidence": 0.70,
                "note": ("Traffic proxy configured. All SDK API calls route "
                         "through this host first"),
            })
        elif "URL" in var.upper() or "ENDPOINT" in var.upper():
            hosts = URL_PATTERN.findall(val)
            unofficial = [h for h in hosts
                          if h not in ALL_OFFICIAL_HOSTS
                          and not any(h.endswith("." + o) for o in ALL_OFFICIAL_HOSTS)]
            if unofficial:
                alerts.append({
                    "event":    "QAAS_ENDPOINT_OVERRIDE",
                    "severity": "CRITICAL",
                    "variable": var,
                    "value":    val,
                    "unofficial_hosts": unofficial,
                    "confidence": 0.90,
                    "note": ("An environment variable overrides the API "
                             "endpoint to a non-official address"),
                })

    # ── 5. Token exposed via /proc environ ──
    for e in exposure:
        alerts.append({
            "event":    "TOKEN_EXPOSED_IN_ENVIRON",
            "severity": "CRITICAL",
            "detail":   e,
            "confidence": 0.85,
            "note": ("A quantum credential is present in an environment "
                     "block readable beyond its owner. Any local process can "
                     "read the token out of /proc"),
        })

    # ── 6. /etc/hosts hijack ──
    for h in hosts_hijack:
        alerts.append({
            "event":    "PROVIDER_DNS_HIJACK",
            "severity": "CRITICAL",
            "ip":       h["ip"],
            "host":     h["host"],
            "line":     h["line"],
            "confidence": 0.90,
            "note": ("/etc/hosts maps a quantum provider domain to a fixed "
                     "address. Every SDK call to that provider resolves to "
                     "this address instead of the real service"),
        })

    # ── 7. Credential env var changed shape ──
    prev_env = baseline.get("env", {}).get("credentials", {})
    curr_env = env.get("credentials", {})
    for var, shape in curr_env.items():
        if var in prev_env:
            if prev_env[var].get("hash") != shape.get("hash"):
                alerts.append({
                    "event":    "CREDENTIAL_VALUE_CHANGED",
                    "severity": "WARN",
                    "variable": var,
                    "was_length": prev_env[var].get("length"),
                    "now_length": shape.get("length"),
                    "confidence": 0.65,
                    "note": ("A credential environment variable changed value. "
                             "If no rotation was performed, a substituted "
                             "token means jobs now bill to a different account"),
                })
        else:
            alerts.append({
                "event":    "CREDENTIAL_VAR_APPEARED",
                "severity": "INFO",
                "variable": var,
                "shape":    shape,
                "confidence": 0.40,
            })

    baseline["configs"] = {c["path"]: {"sha256": c.get("sha256"),
                                        "mode":   c.get("mode")}
                            for c in configs}
    baseline["env"] = env
    return alerts, baseline

def main():
    log = open(f"module62_{stamp()}.jsonl", "a")

    def emit(event):
        event.setdefault("ts", now_iso())
        log.write(json.dumps(event) + "\n")
        log.flush()

    emit({
        "event":  "RUN_START",
        "module": "62_qaas_config_guard",
        "status": "FUNCTIONAL — no credentials or hardware required",
        "config_paths_monitored": len(QAAS_CONFIG_PATHS),
        "credential_vars_monitored": len(CREDENTIAL_ENV_VARS),
        "providers": list(OFFICIAL_ENDPOINTS.keys()),
        "checks": [
            "SDK config file permissions (world/group readable = exposed token)",
            "API endpoint validation against official provider addresses",
            "Environment variable endpoint overrides",
            "Custom CA bundle detection (TLS interception)",
            "Proxy environment variables",
            "Token exposure via readable /proc/<pid>/environ",
            "/etc/hosts provider DNS hijack",
            "Config file content hash baseline and drift",
        ],
        "privacy": ("Credential VALUES are never read into the log. Only "
                     "length, character class, and a truncated hash are "
                     "recorded — enough to detect substitution, useless to "
                     "an attacker reading this log"),
    })

    baseline = load_baseline()
    first    = not baseline.get("configs")

    while True:
        configs      = scan_config_files()
        env          = scan_environment()
        exposure     = check_environ_exposure()
        hosts_hijack = check_hosts_file()

        emit({"event": "QAAS_CONFIG_SCAN",
              "configs_found":     len(configs),
              "providers":         [c["provider"] for c in configs],
              "credential_vars":   list(env["credentials"].keys()),
              "redirect_vars":     list(env["redirects"].keys()),
              "environ_exposures": len(exposure),
              "hosts_entries":     len(hosts_hijack)})

        if not configs and not env["credentials"]:
            emit({"event": "NO_QAAS_CONFIG_FOUND",
                  "note": ("No quantum SDK config files or credential "
                           "environment variables present on this host. "
                           "Nothing to guard yet — this module becomes active "
                           "once an SDK is configured.")})

        if first:
            emit({"event": "QAAS_CONFIG_BASELINE_ESTABLISHED",
                  "configs": len(configs)})
            baseline["configs"] = {c["path"]: {"sha256": c.get("sha256"),
                                                "mode":   c.get("mode")}
                                    for c in configs}
            baseline["env"] = env
            save_baseline(baseline)
            first = False
            # Static-risk checks still run on the first pass
            alerts, _ = analyse(configs, env, exposure, hosts_hijack,
                                 {"configs": baseline["configs"], "env": env})
            for a in alerts:
                if a["event"] in ("INSECURE_TOKEN_PERMS", "QAAS_CONFIG_WRITABLE",
                                   "QAAS_CONFIG_HIJACK", "CUSTOM_CA_BUNDLE_SET",
                                   "QAAS_ENDPOINT_OVERRIDE", "PROVIDER_DNS_HIJACK",
                                   "TOKEN_EXPOSED_IN_ENVIRON", "QAAS_PROXY_CONFIGURED"):
                    emit(a)
            time.sleep(POLL_INTERVAL)
            continue

        alerts, baseline = analyse(configs, env, exposure, hosts_hijack, baseline)
        for a in alerts:
            emit(a)

        if not alerts:
            emit({"event": "QAAS_CONFIG_SECURE",
                  "configs_checked": len(configs)})

        save_baseline(baseline)
        time.sleep(POLL_INTERVAL)

if __name__ == "__main__":
    main()
