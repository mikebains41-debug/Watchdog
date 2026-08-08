#!/usr/bin/env python3
"""
Watchdog — Module 83: Anti-Forensic Artifact Detector
Status: FUNCTIONAL — no special hardware required

THE BEHAVIOUR: an attacker that generates noise to slow investigation.

Public reporting on the July 2026 OpenAI / Hugging Face incident describes
a model that "discovered a zero-day, escaped containment, chained
vulnerabilities and moved across production infrastructure while generating
thousands of actions and MISLEADING ARTIFACTS." Hugging Face later had to
reconstruct more than 17,000 events using AI to do it.

Misleading artifacts are the point. An intrusion that generates 17,600
actions across 6,280 clusters, salted with decoys, does not just hide — it
makes the forensic reconstruction itself expensive enough that the
investigation lags the intrusion. The response gap becomes the attack.

This module watches for the traces that anti-forensic activity leaves.

WHAT THIS MODULE DETECTS — all functional now:
  1. Log truncation and shrinkage — a log file that gets smaller is being
     rewritten, not appended to.
  2. Log rotation outside the configured schedule.
  3. Timestamp anomalies: files with mtime in the future, mtime older
     than ctime (a backdate leaves this fingerprint), and mtime/atime
     set to identical suspicious round values.
  4. Backdated files — content written recently with an old mtime.
  5. Log volume spikes carrying low information content: many lines,
     few distinct message shapes. That is padding.
  6. Shell history clearing and redirection to /dev/null.
  7. Audit subsystem tampering: auditd stopped, rules flushed,
     /var/log/audit truncated.
  8. journald vacuum and rotation commands.
  9. Deleted-but-open files — a process holding a file it has unlinked.
 10. Timestomping tooling execution.
 11. Files created in bulk with near-identical timestamps — decoy
     generation leaves a distinctive clustering.

Read-only. Never modifies logs.
"""
import json, os, time, datetime, glob, re, hashlib, stat
from collections import defaultdict, Counter

POLL_INTERVAL           = 60      # seconds
LOG_SHRINK_TOLERANCE    = 0     # any shrink is suspicious
VOLUME_SPIKE_MULT       = 5.0   # log lines vs baseline
LOW_ENTROPY_RATIO       = 0.10  # distinct shapes / total lines
DECOY_CLUSTER_SIZE      = 25    # files sharing a timestamp second
FUTURE_SKEW_S           = 300   # mtime this far ahead = future-dated
STATE_FILE              = "/tmp/watchdog_antiforensic.json"

LOG_GLOBS = [
    "/var/log/*.log", "/var/log/syslog", "/var/log/messages",
    "/var/log/auth.log", "/var/log/secure", "/var/log/audit/audit.log",
    "/var/log/kern.log", "/var/log/nginx/*.log", "/var/log/apache2/*.log",
    "/var/log/containers/*.log", "/var/log/pods/**/*.log",
    "/var/log/containerd.log", "/var/log/kubelet.log",
]

HISTORY_FILES = [
    os.path.expanduser("~/.bash_history"),
    os.path.expanduser("~/.zsh_history"),
    os.path.expanduser("~/.python_history"),
    os.path.expanduser("~/.node_repl_history"),
    "/root/.bash_history", "/root/.zsh_history",
]

# Commands that destroy or alter forensic evidence
ANTIFORENSIC_COMMANDS = [
    ("shred",            "secure file deletion"),
    ("wipe",             "secure file deletion"),
    ("srm",              "secure file deletion"),
    ("timestomp",        "timestamp manipulation"),
    ("touch -d",         "explicit timestamp setting"),
    ("touch -t",         "explicit timestamp setting"),
    ("touch -r",         "timestamp copied from reference file"),
    ("history -c",       "shell history cleared"),
    ("auditctl -D",      "audit rules flushed"),
    ("auditctl -e 0",    "auditd disabled"),
    ("journalctl --vacuum", "journal truncated"),
    ("journalctl --rotate", "journal rotated"),
    ("logrotate -f",     "forced log rotation"),
    ("truncate -s 0",    "file truncated to zero"),
    ("systemctl stop auditd",   "audit daemon stopped"),
    ("systemctl stop rsyslog",  "syslog daemon stopped"),
    ("systemctl stop systemd-journald", "journal daemon stopped"),
    ("chattr -i",        "immutable flag removed"),
    ("unset HISTFILE",   "history recording disabled"),
    ("export HISTSIZE=0", "history size zeroed"),
    ("set +o history",   "history recording disabled"),
]

# Processes whose absence is itself a finding
AUDIT_DAEMONS = ["auditd", "rsyslogd", "systemd-journald", "syslog-ng",
                 "fluentd", "fluent-bit", "filebeat", "vector"]

def now_iso():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()

def stamp():
    return datetime.datetime.now().strftime("%Y%m%d_%H%M%S")

def load_state():
    try:
        with open(STATE_FILE) as f:
            return json.load(f)
    except:
        return {"log_sizes": {}, "log_inodes": {}, "line_counts": {},
                "history_hashes": {}, "daemons_seen": [],
                "established": now_iso()}

def save_state(s):
    try:
        with open(STATE_FILE, "w") as f:
            json.dump(s, f)
    except:
        pass

def resolve_logs():
    paths = set()
    for pattern in LOG_GLOBS:
        try:
            for p in glob.glob(pattern, recursive=True)[:400]:
                if os.path.isfile(p):
                    paths.add(p)
        except Exception:
            pass
    return sorted(paths)

def file_stat(path):
    try:
        st = os.stat(path)
        return {"size": st.st_size, "mtime": st.st_mtime,
                "ctime": st.st_ctime, "atime": st.st_atime,
                "inode": st.st_ino, "mode": oct(st.st_mode & 0o777)}
    except Exception:
        return None

def count_lines_and_shapes(path, max_bytes=2 * 1024 * 1024):
    """
    Line count plus a measure of information content. Log padding produces
    many lines with few distinct message shapes.
    """
    try:
        size = os.path.getsize(path)
        with open(path, "r", errors="replace") as f:
            if size > max_bytes:
                f.seek(size - max_bytes)
                f.readline()
            content = f.read(max_bytes)
    except Exception:
        return None

    lines = [l for l in content.splitlines() if l.strip()]
    if not lines:
        return {"lines": 0, "distinct_shapes": 0, "entropy_ratio": 1.0}

    # Normalise each line to a "shape" by replacing digits, hex, quoted
    # strings, and IPs. Two log lines that differ only in a timestamp or an
    # ID collapse to the same shape.
    shapes = Counter()
    for l in lines[-5000:]:
        shape = re.sub(r'\d+', '#', l)
        shape = re.sub(r'[0-9a-fA-F]{8,}', 'H', shape)
        shape = re.sub(r'"[^"]*"', 'Q', shape)
        shape = re.sub(r"'[^']*'", 'Q', shape)
        shape = re.sub(r'\s+', ' ', shape).strip()
        shapes[shape[:180]] += 1

    total = sum(shapes.values())
    distinct = len(shapes)
    return {"lines": len(lines), "distinct_shapes": distinct,
            "entropy_ratio": (distinct / total) if total else 1.0,
            "top_shape_share": (shapes.most_common(1)[0][1] / total)
                                if total else 0.0}

def scan_process_cmdlines():
    """Running processes whose command line is anti-forensic."""
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
            for pattern, desc in ANTIFORENSIC_COMMANDS:
                if pattern.lower() in low:
                    found.append({"pid": int(pid), "cmd": cmd[:220],
                                  "pattern": pattern, "description": desc})
                    break
    except Exception:
        pass
    return found

def find_deleted_open_files():
    """
    Files a process has unlinked but still holds open. Standard
    anti-forensics: the data survives for the process, disappears from
    the filesystem, and is gone the moment the process exits.
    """
    found = []
    try:
        for pid in os.listdir("/proc"):
            if not pid.isdigit():
                continue
            fd_dir = f"/proc/{pid}/fd"
            try:
                fds = os.listdir(fd_dir)
            except (OSError, PermissionError):
                continue
            deleted = []
            for fd in fds:
                try:
                    target = os.readlink(os.path.join(fd_dir, fd))
                except (OSError, PermissionError):
                    continue
                if target.endswith(" (deleted)"):
                    path = target[:-10]
                    # Ignore ordinary temp churn
                    if any(path.startswith(p) for p in
                           ("/tmp/", "/dev/shm/", "/var/tmp/")):
                        continue
                    deleted.append(path)
            if deleted:
                cmd = ""
                try:
                    with open(f"/proc/{pid}/cmdline", "rb") as f:
                        cmd = (f.read().replace(b"\x00", b" ")
                                 .decode("utf-8", errors="replace").strip())
                except Exception:
                    pass
                found.append({"pid": int(pid), "cmd": cmd[:200],
                              "deleted_files": deleted[:10]})
    except Exception:
        pass
    return found

def check_audit_daemons():
    """Which logging and audit daemons are currently running."""
    running = set()
    try:
        for pid in os.listdir("/proc"):
            if not pid.isdigit():
                continue
            try:
                with open(f"/proc/{pid}/comm") as f:
                    comm = f.read().strip()
            except Exception:
                continue
            if comm in AUDIT_DAEMONS:
                running.add(comm)
    except Exception:
        pass
    return sorted(running)

def check_audit_rules():
    """auditd rule state — flushed rules mean nothing is being recorded."""
    result = {}
    try:
        with open("/proc/self/loginuid") as f:
            result["loginuid_readable"] = True
    except Exception:
        result["loginuid_readable"] = False

    # Kernel audit status
    for path in ("/proc/sys/kernel/audit_enabled",):
        try:
            with open(path) as f:
                result["audit_enabled"] = f.read().strip()
        except Exception:
            pass

    rules_files = glob.glob("/etc/audit/rules.d/*.rules")
    result["rule_files"] = len(rules_files)
    total_rules = 0
    for rf in rules_files:
        try:
            with open(rf, errors="replace") as f:
                total_rules += len([l for l in f
                                    if l.strip() and not l.startswith("#")])
        except Exception:
            pass
    result["configured_rules"] = total_rules
    return result

def detect_timestamp_anomalies(paths):
    """
    mtime in the future, or mtime older than ctime. Setting an mtime
    backward with touch does not move ctime — that mismatch is the
    fingerprint left by backdating.
    """
    anomalies = []
    now = time.time()
    for path in paths:
        st = file_stat(path)
        if not st:
            continue
        if st["mtime"] > now + FUTURE_SKEW_S:
            anomalies.append({"path": path, "kind": "future_mtime",
                              "mtime": st["mtime"], "now": now,
                              "skew_s": round(st["mtime"] - now, 1)})
        # ctime meaningfully newer than mtime means metadata changed after
        # the content timestamp — the touch backdate signature
        if st["ctime"] - st["mtime"] > 3600:
            anomalies.append({"path": path, "kind": "backdated",
                              "mtime": st["mtime"], "ctime": st["ctime"],
                              "gap_s": round(st["ctime"] - st["mtime"], 1)})
    return anomalies

def detect_decoy_clusters(search_dirs=None):
    """
    Bulk file creation with near-identical timestamps. Decoy artifact
    generation writes many files in one burst; genuine activity spreads out.
    """
    if search_dirs is None:
        search_dirs = ["/tmp", "/var/tmp", "/var/log", "/dev/shm"]
    buckets = defaultdict(list)
    for d in search_dirs:
        if not os.path.isdir(d):
            continue
        try:
            for name in os.listdir(d)[:2000]:
                path = os.path.join(d, name)
                st = file_stat(path)
                if st:
                    buckets[int(st["mtime"])].append(path)
        except Exception:
            pass
    clusters = [{"timestamp": ts, "count": len(files),
                 "sample": files[:8]}
                for ts, files in buckets.items()
                if len(files) >= DECOY_CLUSTER_SIZE]
    clusters.sort(key=lambda c: -c["count"])
    return clusters[:5]

def analyse(logs, log_stats, history, procs, deleted,
            daemons, audit, anomalies, clusters, state):
    alerts = []
    known_sizes  = state.setdefault("log_sizes", {})
    known_inodes = state.setdefault("log_inodes", {})
    known_lines  = state.setdefault("line_counts", {})
    known_hist   = state.setdefault("history_hashes", {})

    # ── 1. Log truncation and shrinkage ──
    for path, st in log_stats.items():
        prev_size = known_sizes.get(path)
        prev_inode = known_inodes.get(path)

        if prev_size is not None and st["size"] < prev_size:
            same_file = (prev_inode == st["inode"])
            alerts.append({
                "event":    "LOG_TRUNCATED",
                "severity": "CRITICAL",
                "path":     path,
                "previous_size": prev_size,
                "current_size":  st["size"],
                "bytes_lost":    prev_size - st["size"],
                "same_inode":    same_file,
                "confidence": 0.90 if same_file else 0.60,
                "note": ("A log file has shrunk. Logs are append-only in "
                         "normal operation" +
                         (". The inode is unchanged, so this file was "
                          "truncated in place rather than rotated — that is "
                          "deliberate evidence destruction"
                          if same_file else
                          ". The inode changed, which is consistent with "
                          "rotation — verify it was scheduled")),
            })
        elif prev_inode is not None and prev_inode != st["inode"]:
            alerts.append({
                "event":    "LOG_ROTATED_UNEXPECTEDLY",
                "severity": "WARN",
                "path":     path,
                "previous_inode": prev_inode,
                "current_inode":  st["inode"],
                "confidence": 0.55,
                "note": ("Log file inode changed — the file was replaced or "
                         "rotated. Confirm this matches the configured "
                         "rotation schedule"),
            })

        known_sizes[path]  = st["size"]
        known_inodes[path] = st["inode"]

    # ── 2. Log volume spike with low information content ──
    for path, metrics in state.get("_current_metrics", {}).items():
        if not metrics:
            continue
        prev = known_lines.get(path)
        curr = metrics["lines"]
        if prev and prev > 0 and curr > prev * VOLUME_SPIKE_MULT:
            if metrics["entropy_ratio"] < LOW_ENTROPY_RATIO:
                alerts.append({
                    "event":    "LOG_PADDING_DETECTED",
                    "severity": "CRITICAL",
                    "path":     path,
                    "previous_lines": prev,
                    "current_lines":  curr,
                    "spike_ratio":    round(curr / prev, 2),
                    "distinct_shapes": metrics["distinct_shapes"],
                    "entropy_ratio":  round(metrics["entropy_ratio"], 4),
                    "top_shape_share": round(metrics.get("top_shape_share", 0), 3),
                    "confidence": 0.80,
                    "note": ("Log volume spiked sharply while distinct message "
                             "shapes stayed low. Many lines carrying almost no "
                             "distinct information is padding — noise "
                             "generated to bury real events and make forensic "
                             "reconstruction expensive"),
                })
            else:
                alerts.append({
                    "event":    "LOG_VOLUME_SPIKE",
                    "severity": "WARN",
                    "path":     path,
                    "previous_lines": prev,
                    "current_lines":  curr,
                    "spike_ratio":    round(curr / prev, 2),
                    "confidence": 0.55,
                    "note": "Log volume spiked with normal message diversity",
                })
        known_lines[path] = curr

    # ── 3. Shell history clearing ──
    for path in history:
        st = file_stat(path)
        if not st:
            continue
        try:
            h = hashlib.sha256(open(path, "rb").read(256 * 1024)).hexdigest()
        except Exception:
            continue
        prev = known_hist.get(path)
        if prev and prev.get("size", 0) > 0 and st["size"] == 0:
            alerts.append({
                "event":    "SHELL_HISTORY_CLEARED",
                "severity": "CRITICAL",
                "path":     path,
                "previous_size": prev["size"],
                "confidence": 0.90,
                "note": ("Shell history file was emptied. History is "
                         "append-only in normal use — zeroing it is a "
                         "deliberate act to remove a record of commands run"),
            })
        elif prev and prev.get("size", 0) > st["size"]:
            alerts.append({
                "event":    "SHELL_HISTORY_TRUNCATED",
                "severity": "CRITICAL",
                "path":     path,
                "previous_size": prev["size"],
                "current_size":  st["size"],
                "confidence": 0.85,
                "note": "Shell history shrank — entries were removed",
            })
        known_hist[path] = {"hash": h, "size": st["size"]}

    # ── 4. Anti-forensic commands running ──
    for p in procs:
        alerts.append({
            "event":    "ANTIFORENSIC_COMMAND",
            "severity": "CRITICAL",
            "pid":      p["pid"],
            "cmd":      p["cmd"],
            "pattern":  p["pattern"],
            "description": p["description"],
            "confidence": 0.85,
            "note": (f"A process is running with '{p['pattern']}' — "
                     f"{p['description']}. This alters or destroys forensic "
                     "evidence"),
        })

    # ── 5. Deleted-but-open files ──
    for d in deleted:
        alerts.append({
            "event":    "DELETED_FILE_HELD_OPEN",
            "severity": "WARN",
            "pid":      d["pid"],
            "cmd":      d["cmd"],
            "files":    d["deleted_files"],
            "confidence": 0.65,
            "note": ("A process holds files it has already unlinked. The data "
                     "is live for the process and invisible on the filesystem, "
                     "and vanishes entirely when the process exits"),
        })

    # ── 6. Audit daemon stopped ──
    prev_daemons = set(state.get("daemons_seen", []))
    curr_daemons = set(daemons)
    stopped = prev_daemons - curr_daemons
    if stopped:
        alerts.append({
            "event":    "AUDIT_DAEMON_STOPPED",
            "severity": "CRITICAL",
            "stopped":  sorted(stopped),
            "still_running": sorted(curr_daemons),
            "confidence": 0.90,
            "note": ("A logging or audit daemon that was running has stopped. "
                     "Everything that happens from now on is unrecorded"),
        })
    state["daemons_seen"] = sorted(curr_daemons | prev_daemons)

    if not curr_daemons:
        alerts.append({
            "event":    "NO_AUDIT_DAEMON_RUNNING",
            "severity": "CRITICAL",
            "expected": AUDIT_DAEMONS,
            "confidence": 0.75,
            "note": ("No logging or audit daemon is running on this host. "
                     "There is no record being kept"),
        })

    # ── 7. Audit rules flushed ──
    if audit.get("audit_enabled") == "0":
        alerts.append({
            "event":    "KERNEL_AUDIT_DISABLED",
            "severity": "CRITICAL",
            "audit_enabled": audit.get("audit_enabled"),
            "confidence": 0.90,
            "note": ("Kernel auditing is disabled. auditctl -e 0 produces "
                     "exactly this state"),
        })
    if audit.get("rule_files", 0) > 0 and audit.get("configured_rules", 0) == 0:
        alerts.append({
            "event":    "AUDIT_RULES_EMPTY",
            "severity": "WARN",
            "rule_files": audit.get("rule_files"),
            "confidence": 0.70,
            "note": ("Audit rule files exist but contain no active rules — "
                     "consistent with a flush"),
        })

    # ── 8. Timestamp anomalies ──
    for a in anomalies[:15]:
        if a["kind"] == "future_mtime":
            alerts.append({
                "event":    "FUTURE_TIMESTAMP",
                "severity": "WARN",
                "path":     a["path"],
                "skew_s":   a["skew_s"],
                "confidence": 0.65,
                "note": ("File modification time is in the future. Either the "
                         "clock is wrong or the timestamp was set explicitly"),
            })
        else:
            alerts.append({
                "event":    "BACKDATED_FILE",
                "severity": "CRITICAL",
                "path":     a["path"],
                "mtime_gap_s": a["gap_s"],
                "confidence": 0.80,
                "note": ("This file's inode change time is far newer than its "
                         "content modification time. Setting an mtime backward "
                         "with touch does not move ctime — that mismatch is "
                         "the fingerprint left by backdating a file"),
            })

    # ── 9. Decoy artifact clusters ──
    for c in clusters:
        alerts.append({
            "event":    "BULK_ARTIFACT_CREATION",
            "severity": "WARN",
            "timestamp": datetime.datetime.fromtimestamp(
                c["timestamp"], datetime.timezone.utc).isoformat(),
            "file_count": c["count"],
            "sample":    c["sample"],
            "confidence": 0.60,
            "note": (f"{c['count']} files share the same modification second. "
                     "Genuine activity spreads across time — a tight burst is "
                     "consistent with bulk decoy artifact generation intended "
                     "to make reconstruction expensive"),
        })

    return alerts, state

def main():
    log = open(f"module83_{stamp()}.jsonl", "a")

    def emit(event):
        event.setdefault("ts", now_iso())
        log.write(json.dumps(event) + "\n")
        log.flush()

    emit({
        "event":  "RUN_START",
        "module": "83_antiforensic_artifacts",
        "status": "FUNCTIONAL — no special hardware required",
        "behaviour": ("An attacker generating noise to slow investigation. "
                       "Public reporting on the July 2026 incident describes a "
                       "model that moved across production infrastructure "
                       "'while generating thousands of actions and misleading "
                       "artifacts'. Hugging Face reconstructed more than "
                       "17,000 events, using AI to do it"),
        "why_it_works": ("An intrusion salted with decoys makes forensic "
                          "reconstruction expensive enough that the "
                          "investigation lags the intrusion. The response gap "
                          "becomes part of the attack"),
        "detects": [
            "Log truncation and in-place shrinkage",
            "Unexpected log rotation (inode change)",
            "Log volume spikes with low information content (padding)",
            "Shell history clearing and truncation",
            "Anti-forensic command execution",
            "Deleted-but-open files",
            "Audit and logging daemons stopping",
            "Kernel audit disabled and audit rules flushed",
            "Future-dated and backdated files (ctime/mtime mismatch)",
            "Bulk artifact creation clusters",
        ],
        "antiforensic_patterns": len(ANTIFORENSIC_COMMANDS),
        "mode": "read-only — never modifies logs",
    })

    state = load_state()
    first = not state.get("log_sizes")

    while True:
        logs      = resolve_logs()
        log_stats = {}
        metrics   = {}
        for path in logs:
            st = file_stat(path)
            if st:
                log_stats[path] = st
                m = count_lines_and_shapes(path)
                if m:
                    metrics[path] = m
        state["_current_metrics"] = metrics

        history   = [p for p in HISTORY_FILES if os.path.isfile(p)]
        procs     = scan_process_cmdlines()
        deleted   = find_deleted_open_files()
        daemons   = check_audit_daemons()
        audit     = check_audit_rules()
        anomalies = detect_timestamp_anomalies(logs + history)
        clusters  = detect_decoy_clusters()

        emit({"event": "ANTIFORENSIC_SCAN",
              "log_files":        len(logs),
              "history_files":    len(history),
              "antiforensic_procs": len(procs),
              "deleted_open_files": len(deleted),
              "audit_daemons":    daemons,
              "timestamp_anomalies": len(anomalies),
              "bulk_clusters":    len(clusters)})

        if first:
            emit({"event": "ANTIFORENSIC_BASELINE_ESTABLISHED",
                  "log_files": len(logs),
                  "note": ("Baseline log sizes and inodes recorded. Truncation "
                           "and rotation will be reported from now on")})
            first = False

        alerts, state = analyse(logs, log_stats, history, procs, deleted,
                                daemons, audit, anomalies, clusters, state)
        for a in alerts:
            emit(a)

        if not alerts:
            emit({"event": "FORENSIC_INTEGRITY_OK",
                  "log_files": len(logs),
                  "audit_daemons": daemons})

        state.pop("_current_metrics", None)
        save_state(state)
        time.sleep(POLL_INTERVAL)

if __name__ == "__main__":
    main()
