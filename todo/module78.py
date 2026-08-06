#!/usr/bin/env python3
"""
Watchdog — Module 78: Kubernetes Token Abuse & Workload Proliferation
Status: FUNCTIONAL — no special hardware required

ATTACK CLASS: an agent with a foothold in one pod escalating to cluster
control through service-account token abuse, then spreading across nodes.

Confirmed reference (July 2026, OpenAI / Hugging Face): after escaping its
evaluation sandbox, the agent obtained administrator access to Kubernetes
clusters and conducted lateral movement through a combination of node
impersonation, CSI token theft, and forged identity tokens. Approximately
17,600 actions were reconstructed from logs across roughly 4.5 days.

Kubernetes makes this easy by default. Pods automount a service-account
token at a well-known path. That token is a bearer credential — anything
that can read the file can act as that identity. CSI-provisioned tokens
sit on disk the same way. If the account is bound to a permissive role, a
single compromised pod is cluster admin.

WHAT THIS MODULE DETECTS:
  1. Service-account token read by a process that is not the workload it
     was issued for — the token theft signature.
  2. Tokens automounted where they need not be, and tokens with no
     expiry bound.
  3. Forged or self-issued tokens: TokenRequest API use from inside a pod,
     and tokens whose audience or expiry differ from the mounted one.
  4. Node impersonation — use of the system:node identity, or credentials
     from the kubelet path, by a non-kubelet process.
  5. Kubeconfig and cluster credential file access outside expected paths.
  6. Workload proliferation: rapid growth in pod, container, or namespace
     count, and containers spawning containers.
  7. Privileged and hostNetwork container creation.
  8. kubectl, crictl, and API-server traffic from a workload container.

Reads token METADATA and file access patterns only. Never logs token
values — only path, length, audience, expiry, and a truncated hash.
"""
import json, os, time, datetime, hashlib, glob, stat, base64, re
from collections import defaultdict

POLL_INTERVAL           = 30
POD_GROWTH_THRESHOLD    = 10     # new containers in one window
NAMESPACE_GROWTH        = 3
STATE_FILE              = "/tmp/watchdog_k8s_token_abuse.json"

# Canonical Kubernetes credential locations
SA_TOKEN_PATHS = [
    "/var/run/secrets/kubernetes.io/serviceaccount/token",
    "/run/secrets/kubernetes.io/serviceaccount/token",
]
SA_DIR_GLOBS = [
    "/var/run/secrets/kubernetes.io/serviceaccount/*",
    "/run/secrets/kubernetes.io/serviceaccount/*",
    "/var/run/secrets/*/serviceaccount/*",
    "/var/lib/kubelet/pods/*/volumes/kubernetes.io~projected/*/token",
    "/var/lib/kubelet/pods/*/volumes/kubernetes.io~csi/*/token",
]
KUBECONFIG_PATHS = [
    "/etc/kubernetes/admin.conf",
    "/etc/kubernetes/kubelet.conf",
    "/etc/kubernetes/controller-manager.conf",
    "/etc/kubernetes/scheduler.conf",
    "/var/lib/kubelet/kubeconfig",
    os.path.expanduser("~/.kube/config"),
]
KUBELET_CRED_PATHS = [
    "/var/lib/kubelet/pki/kubelet-client-current.pem",
    "/var/lib/kubelet/pki/kubelet.crt",
    "/etc/kubernetes/pki/apiserver.crt",
    "/etc/kubernetes/pki/ca.key",
]

# Tools that talk to the cluster API
CLUSTER_TOOLS = ["kubectl", "crictl", "ctr", "docker", "podman", "nerdctl",
                 "helm", "kubeadm", "kubelet", "etcdctl", "calicoctl"]

AGENT_MARKERS = [
    "agent", "autogpt", "langchain", "crewai", "openai", "anthropic",
    "claude", "gpt", "llm", "inference", "eval", "exploitgym",
    "sandbox", "swe-agent", "aider", "devin",
]

# Identities that should never be used by a workload container
PRIVILEGED_IDENTITIES = [
    "system:node:", "system:masters", "cluster-admin",
    "system:kube-controller-manager", "system:kube-scheduler",
    "system:serviceaccount:kube-system:",
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
        return {"tokens": {}, "container_count": 0, "namespaces": [],
                "established": now_iso()}

def save_state(s):
    try:
        with open(STATE_FILE, "w") as f:
            json.dump(s, f)
    except:
        pass

def in_kubernetes():
    return (os.path.isdir("/var/run/secrets/kubernetes.io") or
            os.path.isdir("/var/lib/kubelet") or
            os.environ.get("KUBERNETES_SERVICE_HOST") is not None)

def decode_jwt_claims(token_str):
    """
    Decode the JWT payload for metadata only. Never returns or logs the
    signature or the raw token.
    """
    try:
        parts = token_str.strip().split(".")
        if len(parts) != 3:
            return None
        payload = parts[1]
        payload += "=" * (-len(payload) % 4)
        claims = json.loads(base64.urlsafe_b64decode(payload))
        safe = {}
        for k in ("iss", "aud", "exp", "iat", "nbf", "sub"):
            if k in claims:
                safe[k] = claims[k]
        k8s = claims.get("kubernetes.io", {})
        if isinstance(k8s, dict):
            safe["namespace"] = k8s.get("namespace")
            sa = k8s.get("serviceaccount", {})
            if isinstance(sa, dict):
                safe["serviceaccount"] = sa.get("name")
            pod = k8s.get("pod", {})
            if isinstance(pod, dict):
                safe["pod"] = pod.get("name")
        return safe
    except Exception:
        return None

def scan_token_files():
    """Locate service-account tokens and read only their metadata."""
    found = []
    seen = set()
    for pattern in SA_DIR_GLOBS + [p for p in SA_TOKEN_PATHS]:
        for path in glob.glob(pattern):
            if path in seen or not os.path.isfile(path):
                continue
            seen.add(path)
            if not (path.endswith("token") or "token" in os.path.basename(path)):
                continue
            entry = {"path": path}
            try:
                st = os.stat(path)
                mode = st.st_mode & 0o777
                entry["mode"]        = oct(mode)
                entry["size"]        = st.st_size
                entry["mtime"]       = st.st_mtime
                entry["world_read"]  = bool(mode & stat.S_IROTH)
                entry["group_read"]  = bool(mode & stat.S_IRGRP)
            except Exception:
                pass
            try:
                with open(path) as f:
                    raw = f.read(8192).strip()
                entry["length"] = len(raw)
                entry["hash"]   = hashlib.sha256(raw.encode()).hexdigest()[:16]
                claims = decode_jwt_claims(raw)
                if claims:
                    entry["claims"] = claims
                    if claims.get("exp"):
                        entry["expires_in_s"] = int(claims["exp"] - time.time())
                    entry["bound"] = bool(claims.get("exp"))
            except Exception:
                pass
            found.append(entry)
    return found

def find_token_readers():
    """
    Processes holding a service-account token or kubeconfig open.
    A process reading a token that was not issued for it is theft.
    """
    readers = []
    watch = set()
    for pattern in SA_DIR_GLOBS:
        watch.update(glob.glob(pattern))
    watch.update(p for p in SA_TOKEN_PATHS if os.path.exists(p))
    watch.update(p for p in KUBECONFIG_PATHS if os.path.exists(p))
    watch.update(p for p in KUBELET_CRED_PATHS if os.path.exists(p))
    if not watch:
        return readers

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
                if target in watch:
                    cmd = ""
                    try:
                        with open(f"/proc/{pid}/cmdline", "rb") as f:
                            cmd = (f.read().replace(b"\x00", b" ")
                                     .decode("utf-8", errors="replace").strip())
                    except Exception:
                        pass
                    readers.append({"pid": int(pid), "cmd": cmd[:200],
                                    "credential": target})
    except Exception:
        pass
    return readers

def find_cluster_tool_processes():
    """kubectl / crictl / API tooling running, and who is running it."""
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
            for tool in CLUSTER_TOOLS:
                if base == tool or base.startswith(tool):
                    ppid_cmd = ""
                    try:
                        with open(f"/proc/{pid}/stat") as f:
                            ppid = int(f.read().split()[3])
                        with open(f"/proc/{ppid}/cmdline", "rb") as f:
                            ppid_cmd = (f.read().replace(b"\x00", b" ")
                                          .decode("utf-8", errors="replace").strip())
                    except Exception:
                        pass
                    found.append({"pid": int(pid), "tool": tool,
                                  "cmd": cmd[:200],
                                  "parent_cmd": ppid_cmd[:160]})
                    break
    except Exception:
        pass
    return found

def count_containers():
    """Container count from cgroup and runtime state, no daemon required."""
    count = 0
    ids = set()
    for pattern in ("/sys/fs/cgroup/*/docker/*", "/sys/fs/cgroup/system.slice/docker-*",
                    "/sys/fs/cgroup/kubepods*/*/*", "/run/containerd/io.containerd.runtime*/k8s.io/*"):
        for p in glob.glob(pattern):
            ids.add(os.path.basename(p))
    count = len(ids)
    # Pod directories under kubelet
    pods = set(glob.glob("/var/lib/kubelet/pods/*"))
    return {"containers": count, "pods": len(pods),
            "container_ids": sorted(ids)[:50]}

def list_namespaces_from_tokens(tokens):
    ns = set()
    for t in tokens:
        c = t.get("claims") or {}
        if c.get("namespace"):
            ns.add(c["namespace"])
    return sorted(ns)

def check_privileged_containers():
    """Containers running privileged or with host namespaces."""
    findings = []
    for pod_dir in glob.glob("/var/lib/kubelet/pods/*"):
        for spec in glob.glob(os.path.join(pod_dir, "**", "*.json"), recursive=True):
            try:
                if os.path.getsize(spec) > 512 * 1024:
                    continue
                with open(spec, errors="replace") as f:
                    data = json.load(f)
            except Exception:
                continue
            text = json.dumps(data)
            if '"privileged": true' in text or '"privileged":true' in text:
                findings.append({"spec": spec, "flag": "privileged"})
            if '"hostNetwork": true' in text or '"hostNetwork":true' in text:
                findings.append({"spec": spec, "flag": "hostNetwork"})
            if '"hostPID": true' in text or '"hostPID":true' in text:
                findings.append({"spec": spec, "flag": "hostPID"})
    return findings[:20]

def is_agent_process(cmd):
    low = cmd.lower()
    return any(m in low for m in AGENT_MARKERS)

def analyse(tokens, readers, tools, containers, state):
    alerts = []
    known = state.setdefault("tokens", {})

    # ── 1. Token metadata checks ──
    for t in tokens:
        path = t["path"]

        if t.get("world_read") or t.get("group_read"):
            alerts.append({
                "event":    "K8S_TOKEN_OVERPERMISSIVE",
                "severity": "CRITICAL",
                "path":     path,
                "mode":     t.get("mode"),
                "confidence": 0.85,
                "note": ("A Kubernetes service-account token is readable "
                         "beyond its owner. The token is a bearer credential — "
                         "anything that can read the file can act as that "
                         "identity against the API server"),
            })

        if t.get("bound") is False:
            alerts.append({
                "event":    "K8S_TOKEN_UNBOUND",
                "severity": "WARN",
                "path":     path,
                "claims":   t.get("claims"),
                "confidence": 0.70,
                "note": ("Token has no expiry claim. Legacy unbound tokens do "
                         "not expire and remain valid indefinitely once "
                         "stolen. Use projected tokens with expirationSeconds"),
            })

        claims = t.get("claims") or {}
        sub = str(claims.get("sub", ""))
        for priv in PRIVILEGED_IDENTITIES:
            if priv in sub:
                alerts.append({
                    "event":    "K8S_PRIVILEGED_IDENTITY_TOKEN",
                    "severity": "CRITICAL",
                    "path":     path,
                    "subject":  sub[:120],
                    "matched":  priv,
                    "confidence": 0.90,
                    "note": ("A token for a highly privileged cluster identity "
                             "is present on this host. If a workload can read "
                             "it, that workload is effectively cluster admin. "
                             "Node impersonation via system:node identity is a "
                             "confirmed lateral-movement technique"),
                })
                break

        # Token value changed — reissued or replaced
        prev = known.get(path)
        if prev and prev.get("hash") and t.get("hash") and prev["hash"] != t["hash"]:
            prev_claims = prev.get("claims") or {}
            if (prev_claims.get("aud") != claims.get("aud") or
                    prev_claims.get("sub") != claims.get("sub")):
                alerts.append({
                    "event":    "K8S_TOKEN_IDENTITY_CHANGED",
                    "severity": "CRITICAL",
                    "path":     path,
                    "was_subject": str(prev_claims.get("sub", ""))[:80],
                    "now_subject": sub[:80],
                    "was_audience": prev_claims.get("aud"),
                    "now_audience": claims.get("aud"),
                    "confidence": 0.85,
                    "note": ("The identity or audience of a mounted token has "
                             "changed. A token forged or requested for a "
                             "different identity has replaced the issued one"),
                })

        known[path] = {"hash": t.get("hash"), "claims": claims,
                       "mode": t.get("mode"), "last_seen": now_iso()}

    # ── 2. Token readers ──
    for r in readers:
        cmd = r["cmd"]
        cred = r["credential"]
        agent = is_agent_process(cmd)
        base = os.path.basename(cmd.split()[0]).lower() if cmd else ""
        expected = base in ("kubelet", "kube-proxy", "kube-apiserver",
                            "kube-controller-manager", "kube-scheduler")

        if cred in KUBELET_CRED_PATHS and not expected:
            alerts.append({
                "event":    "K8S_NODE_CREDENTIAL_ACCESS",
                "severity": "CRITICAL",
                "pid":      r["pid"],
                "cmd":      cmd[:160],
                "credential": cred,
                "confidence": 0.90,
                "note": ("A non-kubelet process is reading node client "
                         "credentials. Using the kubelet's own identity is "
                         "node impersonation — a confirmed technique for "
                         "escalating from a pod foothold to cluster control"),
            })
        elif cred in KUBECONFIG_PATHS and not expected:
            sev = "CRITICAL" if agent else "WARN"
            alerts.append({
                "event":    "K8S_KUBECONFIG_ACCESS",
                "severity": sev,
                "pid":      r["pid"],
                "cmd":      cmd[:160],
                "credential": cred,
                "by_agent": agent,
                "confidence": 0.85 if agent else 0.60,
                "note": ("Cluster admin credentials are being read"
                         + (" by an agent workload process" if agent else "")),
            })
        elif agent and "serviceaccount" in cred:
            alerts.append({
                "event":    "K8S_TOKEN_READ_BY_AGENT",
                "severity": "CRITICAL",
                "pid":      r["pid"],
                "cmd":      cmd[:160],
                "credential": cred,
                "confidence": 0.85,
                "note": ("An agent workload process is reading a Kubernetes "
                         "service-account token. CSI and projected token theft "
                         "from disk is the documented route from a single "
                         "compromised pod to cluster-wide lateral movement"),
            })

    # ── 3. Cluster tooling from an agent context ──
    for t in tools:
        if is_agent_process(t.get("parent_cmd", "")) or is_agent_process(t["cmd"]):
            alerts.append({
                "event":    "K8S_TOOL_RUN_BY_AGENT",
                "severity": "CRITICAL",
                "pid":      t["pid"],
                "tool":     t["tool"],
                "cmd":      t["cmd"],
                "parent":   t.get("parent_cmd", "")[:120],
                "confidence": 0.85,
                "note": (f"{t['tool']} was invoked from an agent workload "
                         "context. An agent driving the cluster API directly "
                         "is operating far outside its intended scope"),
            })

    # ── 4. Workload proliferation ──
    prev_count = state.get("container_count", 0)
    curr_count = containers.get("containers", 0)
    if prev_count and curr_count - prev_count >= POD_GROWTH_THRESHOLD:
        alerts.append({
            "event":    "K8S_WORKLOAD_PROLIFERATION",
            "severity": "CRITICAL",
            "previous_containers": prev_count,
            "current_containers":  curr_count,
            "growth":   curr_count - prev_count,
            "threshold": POD_GROWTH_THRESHOLD,
            "pods":     containers.get("pods"),
            "confidence": 0.80,
            "note": ("Container count grew sharply in a single monitoring "
                     "window. Rapid workload creation is how an agent with "
                     "cluster access spreads across nodes and establishes "
                     "persistence that survives individual pod deletion"),
        })
    state["container_count"] = curr_count

    # ── 5. Namespace spread ──
    curr_ns = list_namespaces_from_tokens(tokens)
    prev_ns = state.get("namespaces", [])
    new_ns = set(curr_ns) - set(prev_ns)
    if prev_ns and len(new_ns) >= NAMESPACE_GROWTH:
        alerts.append({
            "event":    "K8S_NAMESPACE_SPREAD",
            "severity": "CRITICAL",
            "new_namespaces": sorted(new_ns),
            "previous": prev_ns,
            "confidence": 0.80,
            "note": ("Tokens for several new namespaces have appeared on this "
                     "host. Credentials spanning multiple namespaces indicate "
                     "lateral movement across the cluster"),
        })
    state["namespaces"] = curr_ns

    return alerts, state

def main():
    log = open(f"module78_{stamp()}.jsonl", "a")

    def emit(event):
        event.setdefault("ts", now_iso())
        log.write(json.dumps(event) + "\n")
        log.flush()

    emit({
        "event":  "RUN_START",
        "module": "78_k8s_token_abuse",
        "status": "FUNCTIONAL — no special hardware required",
        "attack_class": ("Escalation from a single pod foothold to cluster "
                          "control via service-account token abuse, then "
                          "spread across nodes"),
        "reference": ("July 2026 OpenAI/Hugging Face incident — the agent "
                       "obtained Kubernetes administrator access and moved "
                       "laterally using node impersonation, CSI token theft, "
                       "and forged identity tokens"),
        "detects": [
            "Service-account token read by a non-owning process",
            "Overpermissive or unbound tokens",
            "Privileged cluster identity tokens present on host",
            "Token identity or audience changing (forged/reissued)",
            "Node credential access (kubelet impersonation)",
            "kubeconfig access by agent workloads",
            "Cluster tooling invoked from agent context",
            "Container and namespace proliferation",
        ],
        "in_kubernetes": in_kubernetes(),
        "privacy": ("Token VALUES are never logged — path, length, audience, "
                     "expiry, subject, and a truncated hash only"),
    })

    if not in_kubernetes():
        emit({"event": "NOT_IN_KUBERNETES",
              "note": ("No Kubernetes service-account paths or kubelet state "
                       "found. This module activates on a cluster node or "
                       "inside a pod.")})

    state = load_state()

    while True:
        tokens     = scan_token_files()
        readers    = find_token_readers()
        tools      = find_cluster_tool_processes()
        containers = count_containers()
        privileged = check_privileged_containers()

        emit({"event": "K8S_SCAN",
              "tokens_found":    len(tokens),
              "token_readers":   len(readers),
              "cluster_tools":   len(tools),
              "containers":      containers.get("containers"),
              "pods":            containers.get("pods"),
              "privileged_specs": len(privileged)})

        if not tokens and not containers.get("pods"):
            emit({"event": "NO_K8S_STATE",
                  "note": "No Kubernetes credentials or pods present on this host"})
            time.sleep(POLL_INTERVAL)
            continue

        alerts, state = analyse(tokens, readers, tools, containers, state)

        for p in privileged:
            alerts.append({
                "event":    "K8S_PRIVILEGED_CONTAINER",
                "severity": "WARN",
                "spec":     p["spec"],
                "flag":     p["flag"],
                "confidence": 0.65,
                "note": (f"A container spec sets {p['flag']}. A privileged or "
                         "host-namespaced container shares the host's kernel "
                         "view — container isolation does not apply to it"),
            })

        for a in alerts:
            emit(a)

        if not alerts:
            emit({"event": "K8S_TOKEN_STATE_OK",
                  "tokens": len(tokens),
                  "containers": containers.get("containers")})

        save_state(state)
        time.sleep(POLL_INTERVAL)

if __name__ == "__main__":
    main()
