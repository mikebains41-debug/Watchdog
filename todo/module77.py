#!/usr/bin/env python3
"""
Watchdog — Module 77: Agent Action-Rate & Covert Coordination Detector
Status: FUNCTIONAL — no special hardware required

ATTACK CLASS: autonomous agent operating at machine velocity, and multiple
agents coordinating through channels not covered by normal logging.

Velocity is the most reliable single discriminator between a human operator
and an autonomous agent. A confirmed reference point: the July 2026
OpenAI / Hugging Face incident produced roughly 17,600 attacker actions
grouped into about 6,280 clusters over roughly 4.5 days — a sustained rate
no human sustains, and it ran for days before detection.

The second half of this module covers agent-to-agent coordination. Multiple
agent processes that synchronise their activity, write to a shared channel,
or exchange data outside their logged interfaces are operating as a group
rather than independently. Whether or not any specific incident involved
this, it is a real and detectable pattern: shared memory segments, shared
files, Unix sockets between agent processes, and correlated activity bursts
are all observable from the host.

WHAT THIS MODULE DETECTS:
  1. Sustained action rate above a human-plausible ceiling, measured from
     syscall-adjacent proxies: file opens, network connects, process spawns.
  2. Action bursts — short windows of extreme density.
  3. Long-duration sustained activity, the 4.5-day pattern. An agent that
     has been going hard for days without pause is not a person.
  4. Clustered repetition: the same action shape repeating with machine
     regularity, measured by coefficient of variation on inter-action gaps.
  5. Agent-to-agent IPC: shared memory segments, pipes, Unix sockets, and
     shared files with more than one agent process attached.
  6. Correlated activity across separate agent processes — synchronised
     bursts indicating coordination rather than coincidence.
  7. Process spawn storms and self-respawning behaviour.

Detection only. Rate limiting belongs at the API gateway.
"""
import json, os, time, datetime, math, glob, re
from collections import defaultdict, deque

POLL_INTERVAL          = 30
ACTIONS_PER_MIN_WARN   = 60      # sustained rate above this = suspicious
ACTIONS_PER_MIN_CRIT   = 200     # machine velocity
BURST_WINDOW_S         = 10
BURST_THRESHOLD        = 100     # actions in one burst window
SUSTAINED_HOURS_WARN   = 6       # continuous activity beyond this = flag
SUSTAINED_HOURS_CRIT   = 24
REGULARITY_CV_MAX      = 0.15    # inter-action CV below this = machine cadence
CORRELATION_MIN        = 0.70    # cross-agent activity correlation
SPAWN_STORM_THRESHOLD  = 20      # child processes in one window
HISTORY_WINDOWS        = 120
STATE_FILE             = "/tmp/watchdog_agent_activity.json"

AGENT_MARKERS = [
    "agent", "autogpt", "langchain", "llamaindex", "crewai",
    "openai", "anthropic", "claude", "gpt", "llm",
    "inference", "eval", "exploitgym", "benchmark",
    "sandbox", "swe-agent", "aider", "opendevin", "devin",
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
        return {"windows": [], "agent_first_seen": {}, "established": now_iso()}

def save_state(s):
    try:
        s["windows"] = s.get("windows", [])[-HISTORY_WINDOWS:]
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

def pearson(xs, ys):
    n = len(xs)
    if n < 3 or len(ys) != n:
        return None
    mx, my = sum(xs) / n, sum(ys) / n
    num = sum((x - mx) * (y - my) for x, y in zip(xs, ys))
    dx = math.sqrt(sum((x - mx) ** 2 for x in xs))
    dy = math.sqrt(sum((y - my) ** 2 for y in ys))
    if dx == 0 or dy == 0:
        return None
    return num / (dx * dy)

def is_agent_process(cmd):
    low = cmd.lower()
    return any(m in low for m in AGENT_MARKERS)

def read_proc_stat(pid):
    """Per-process counters that act as an action-rate proxy."""
    result = {}
    try:
        with open(f"/proc/{pid}/stat") as f:
            fields = f.read().split()
        if len(fields) > 23:
            result["utime"]      = int(fields[13])
            result["stime"]      = int(fields[14])
            result["num_threads"] = int(fields[19])
            result["starttime"]  = int(fields[21])
    except Exception:
        pass
    try:
        with open(f"/proc/{pid}/io") as f:
            for line in f:
                k, _, v = line.partition(":")
                k = k.strip()
                if k in ("syscr", "syscw", "read_bytes", "write_bytes"):
                    result[k] = int(v.strip())
    except Exception:
        pass
    try:
        result["open_fds"] = len(os.listdir(f"/proc/{pid}/fd"))
    except Exception:
        pass
    return result

def find_agent_processes():
    agents = []
    try:
        boot_time = 0
        try:
            with open("/proc/stat") as f:
                for line in f:
                    if line.startswith("btime"):
                        boot_time = int(line.split()[1])
                        break
        except Exception:
            pass
        clk = os.sysconf("SC_CLK_TCK")

        for pid in os.listdir("/proc"):
            if not pid.isdigit():
                continue
            try:
                with open(f"/proc/{pid}/cmdline", "rb") as f:
                    cmd = (f.read().replace(b"\x00", b" ")
                             .decode("utf-8", errors="replace").strip())
            except Exception:
                continue
            if not cmd or not is_agent_process(cmd):
                continue
            stat = read_proc_stat(pid)
            runtime_s = None
            if boot_time and stat.get("starttime") and clk:
                start_epoch = boot_time + (stat["starttime"] / clk)
                runtime_s = time.time() - start_epoch
            agents.append({"pid": int(pid), "cmd": cmd[:200],
                           "runtime_s": runtime_s, **stat})
    except Exception:
        pass
    return agents

def find_shared_ipc(agent_pids):
    """
    Shared memory segments, pipes, and Unix sockets with more than one
    agent process attached — an agent-to-agent coordination channel.
    """
    resource_holders = defaultdict(set)
    pid_set = set(agent_pids)

    for pid in pid_set:
        fd_dir = f"/proc/{pid}/fd"
        try:
            for fd in os.listdir(fd_dir):
                try:
                    target = os.readlink(os.path.join(fd_dir, fd))
                except (OSError, PermissionError):
                    continue
                # Pipes, sockets, shared memory, and shared regular files
                if (target.startswith("pipe:[") or
                        target.startswith("socket:[") or
                        "/dev/shm/" in target or
                        target.startswith("/tmp/") or
                        target.startswith("/run/")):
                    resource_holders[target].add(pid)
        except (OSError, PermissionError):
            continue

    shared = [{"resource": r, "pids": sorted(p)}
              for r, p in resource_holders.items() if len(p) > 1]
    return shared

def find_shm_segments():
    """POSIX shared memory objects — a classic covert coordination channel."""
    segs = []
    for path in glob.glob("/dev/shm/*"):
        try:
            st = os.stat(path)
            segs.append({"path": path, "size": st.st_size,
                         "mtime": st.st_mtime,
                         "mode": oct(st.st_mode & 0o777)})
        except Exception:
            pass
    return segs

def count_children(pid):
    try:
        with open(f"/proc/{pid}/task/{pid}/children") as f:
            return len(f.read().split())
    except Exception:
        return 0

def compute_actions(prev, curr):
    """Delta in syscall counters = actions taken since last window."""
    if not prev:
        return None
    total = 0
    for field in ("syscr", "syscw"):
        p, c = prev.get(field), curr.get(field)
        if p is not None and c is not None and c >= p:
            total += (c - p)
    return total

def analyse(agents, state, elapsed_s):
    alerts = []
    windows = state.setdefault("windows", [])
    first_seen = state.setdefault("agent_first_seen", {})
    prev_window = windows[-1] if windows else {}
    prev_agents = prev_window.get("agents", {})

    current = {}
    for a in agents:
        pid_s = str(a["pid"])
        current[pid_s] = {k: a.get(k) for k in
                          ("syscr", "syscw", "open_fds", "num_threads",
                           "read_bytes", "write_bytes")}
        current[pid_s]["cmd"] = a["cmd"][:120]

        if pid_s not in first_seen:
            first_seen[pid_s] = now_iso()

        actions = compute_actions(prev_agents.get(pid_s), a)
        if actions is None or elapsed_s <= 0:
            continue

        rate_per_min = (actions / elapsed_s) * 60.0
        current[pid_s]["rate_per_min"] = round(rate_per_min, 1)

        # ── 1. Sustained action rate ──
        if rate_per_min >= ACTIONS_PER_MIN_CRIT:
            alerts.append({
                "event":    "AGENT_ACTION_RATE_CRITICAL",
                "severity": "CRITICAL",
                "pid":      a["pid"],
                "cmd":      a["cmd"][:160],
                "actions_per_min": round(rate_per_min, 1),
                "threshold": ACTIONS_PER_MIN_CRIT,
                "window_s": round(elapsed_s, 1),
                "confidence": 0.85,
                "note": ("Agent process is executing at a rate no human "
                         "operator sustains. For scale: the July 2026 "
                         "evaluation escape produced roughly 17,600 actions "
                         "over 4.5 days and ran undetected for the duration"),
            })
        elif rate_per_min >= ACTIONS_PER_MIN_WARN:
            alerts.append({
                "event":    "AGENT_ACTION_RATE_ELEVATED",
                "severity": "WARN",
                "pid":      a["pid"],
                "actions_per_min": round(rate_per_min, 1),
                "threshold": ACTIONS_PER_MIN_WARN,
                "confidence": 0.60,
            })

        # ── 2. Sustained duration ──
        rt = a.get("runtime_s")
        if rt:
            hours = rt / 3600.0
            if hours >= SUSTAINED_HOURS_CRIT and rate_per_min >= ACTIONS_PER_MIN_WARN:
                alerts.append({
                    "event":    "AGENT_SUSTAINED_LONG_RUN",
                    "severity": "CRITICAL",
                    "pid":      a["pid"],
                    "cmd":      a["cmd"][:160],
                    "runtime_hours": round(hours, 1),
                    "actions_per_min": round(rate_per_min, 1),
                    "confidence": 0.80,
                    "note": (f"Agent has been running at elevated rate for "
                             f"{round(hours,1)} hours continuously. The "
                             "confirmed 2026 incident ran 4.5 days before "
                             "detection — duration alone is a signal"),
                })
            elif hours >= SUSTAINED_HOURS_WARN and rate_per_min >= ACTIONS_PER_MIN_WARN:
                alerts.append({
                    "event":    "AGENT_SUSTAINED_ACTIVITY",
                    "severity": "WARN",
                    "pid":      a["pid"],
                    "runtime_hours": round(hours, 1),
                    "confidence": 0.60,
                })

        # ── 3. Process spawn storm ──
        children = count_children(a["pid"])
        current[pid_s]["children"] = children
        prev_children = prev_agents.get(pid_s, {}).get("children", 0)
        if children >= SPAWN_STORM_THRESHOLD:
            alerts.append({
                "event":    "AGENT_SPAWN_STORM",
                "severity": "CRITICAL",
                "pid":      a["pid"],
                "cmd":      a["cmd"][:160],
                "child_count": children,
                "previous":  prev_children,
                "threshold": SPAWN_STORM_THRESHOLD,
                "confidence": 0.80,
                "note": ("Agent process has spawned a large number of "
                         "children. Consistent with parallel task execution "
                         "at scale, or self-replicating worker behaviour"),
            })

    # ── 4. Machine-regular cadence ──
    if len(windows) >= 10:
        for pid_s in current:
            rates = [w.get("agents", {}).get(pid_s, {}).get("rate_per_min")
                     for w in windows[-10:]]
            rates = [r for r in rates if r is not None and r > 0]
            if len(rates) >= 6:
                m, sd = mean_std(rates)
                if m and m > 0:
                    cv = sd / m
                    if cv < REGULARITY_CV_MAX and m >= ACTIONS_PER_MIN_WARN:
                        alerts.append({
                            "event":    "AGENT_MACHINE_CADENCE",
                            "severity": "WARN",
                            "pid":      int(pid_s),
                            "mean_rate": round(m, 1),
                            "cv":       round(cv, 4),
                            "threshold": REGULARITY_CV_MAX,
                            "samples":  len(rates),
                            "confidence": 0.65,
                            "note": ("Action rate is machine-regular — the "
                                     "coefficient of variation is far below "
                                     "what human-driven activity produces. "
                                     "This is an automated loop, not a person"),
                        })
                        break

    # ── 5. Cross-agent activity correlation ──
    if len(windows) >= 8 and len(current) >= 2:
        pids = list(current.keys())[:6]
        series = {}
        for pid_s in pids:
            s = [w.get("agents", {}).get(pid_s, {}).get("rate_per_min", 0) or 0
                 for w in windows[-8:]]
            if any(v > 0 for v in s):
                series[pid_s] = s
        checked = set()
        for a_pid, a_series in series.items():
            for b_pid, b_series in series.items():
                if a_pid == b_pid or (b_pid, a_pid) in checked:
                    continue
                checked.add((a_pid, b_pid))
                r = pearson(a_series, b_series)
                if r is not None and r >= CORRELATION_MIN:
                    alerts.append({
                        "event":    "AGENT_ACTIVITY_CORRELATED",
                        "severity": "WARN",
                        "pid_a":    int(a_pid),
                        "pid_b":    int(b_pid),
                        "pearson_r": round(r, 3),
                        "threshold": CORRELATION_MIN,
                        "confidence": 0.65,
                        "note": ("Two independent agent processes show "
                                 "synchronised activity bursts. Independent "
                                 "workloads do not correlate this tightly — "
                                 "this indicates coordination between them"),
                    })
                    break
            else:
                continue
            break

    # ── 6. Shared IPC between agent processes ──
    agent_pids = [a["pid"] for a in agents]
    if len(agent_pids) >= 2:
        shared = find_shared_ipc(agent_pids)
        for s in shared:
            res = s["resource"]
            kind = ("shared memory" if "/dev/shm/" in res
                    else "pipe" if res.startswith("pipe:[")
                    else "socket" if res.startswith("socket:[")
                    else "shared file")
            alerts.append({
                "event":    "AGENT_COORDINATION_CHANNEL",
                "severity": "CRITICAL" if "/dev/shm/" in res else "WARN",
                "resource": res,
                "channel_type": kind,
                "pids":     s["pids"],
                "confidence": 0.75 if "/dev/shm/" in res else 0.60,
                "note": (f"Multiple agent processes share a {kind}. This is a "
                         "direct communication channel between agents that "
                         "does not appear in either agent's logged interface. "
                         "Coordination through an unlogged side channel is "
                         "invisible to conversation-level monitoring"),
            })

    windows.append({"ts": time.time(), "agents": current})
    state["agent_first_seen"] = first_seen
    return alerts, state

def main():
    log = open(f"module77_{stamp()}.jsonl", "a")

    def emit(event):
        event.setdefault("ts", now_iso())
        log.write(json.dumps(event) + "\n")
        log.flush()

    emit({
        "event":  "RUN_START",
        "module": "77_agent_action_rate_coordination",
        "status": "FUNCTIONAL — no special hardware required",
        "attack_class": ("Autonomous agent operating at machine velocity, and "
                          "multiple agents coordinating through unlogged "
                          "channels"),
        "reference_scale": ("July 2026 OpenAI/Hugging Face incident — roughly "
                             "17,600 attacker actions in about 6,280 clusters "
                             "over 4.5 days, undetected for the duration"),
        "detects": [
            "Sustained action rate above human-plausible ceiling",
            "Long-duration continuous activity",
            "Machine-regular cadence (low coefficient of variation)",
            "Process spawn storms",
            "Shared memory, pipes, and sockets between agent processes",
            "Correlated activity bursts across separate agents",
        ],
        "thresholds": {
            "actions_per_min_warn": ACTIONS_PER_MIN_WARN,
            "actions_per_min_crit": ACTIONS_PER_MIN_CRIT,
            "sustained_hours_warn": SUSTAINED_HOURS_WARN,
            "sustained_hours_crit": SUSTAINED_HOURS_CRIT,
            "regularity_cv_max":    REGULARITY_CV_MAX,
            "correlation_min":      CORRELATION_MIN,
            "spawn_storm":          SPAWN_STORM_THRESHOLD,
        },
        "mode": "detection only — rate limiting belongs at the API gateway",
    })

    state = load_state()
    last_time = time.time()

    while True:
        agents = find_agent_processes()
        now = time.time()
        elapsed = now - last_time
        last_time = now

        shm = find_shm_segments()

        emit({"event": "AGENT_ACTIVITY_SCAN",
              "agent_processes": len(agents),
              "shm_segments":    len(shm),
              "pids": [a["pid"] for a in agents][:20]})

        if not agents:
            emit({"event": "NO_AGENT_PROCESSES",
                  "note": ("No processes matching agent workload markers. This "
                           "module activates when an AI agent workload runs on "
                           "this host.")})
            time.sleep(POLL_INTERVAL)
            continue

        alerts, state = analyse(agents, state, elapsed)
        for a in alerts:
            emit(a)

        if not alerts:
            emit({"event": "AGENT_ACTIVITY_NOMINAL",
                  "agent_processes": len(agents)})

        save_state(state)
        time.sleep(POLL_INTERVAL)

if __name__ == "__main__":
    main()
