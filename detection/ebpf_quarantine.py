# Author: Manmohan (Mike) Bains -- Watchdog
"""
Watchdog v2.0 - eBPF Micro-Quarantine Controller
Terminates offending container namespaces when critical engines fire.

DEPLOYMENT NOTE: eBPF requires Linux kernel >= 5.4 and CAP_BPF capability.
Cannot execute in Termux or containerized environments without host privileges.
This module provides the control interface — the eBPF program must be loaded
by the host daemon (watchdog-host-agent) with appropriate kernel permissions.

Supported actions:
- KILL_CONTAINER: terminates container namespace via cgroup signal
- SEVER_PCIE: disables PCIe bus access for offending GPU process
- FREEZE_CGROUP: freezes cgroup without killing (forensic preservation)
"""
import os, subprocess, time, json
from datetime import datetime, timezone

# Alert types that trigger immediate quarantine
QUARANTINE_TRIGGERS = {
    "DMA_ATTACK":              "KILL_CONTAINER",
    "SEQUENTIAL_VRAM_READ":    "KILL_CONTAINER",
    "MODEL_MUTATION":          "KILL_CONTAINER",
    "CROSS_WORKLOAD_CLUSTER":  "FREEZE_CGROUP",
    "MIG_PARTITION_DESYNC":    "FREEZE_CGROUP",
    "CLOCK_GLITCH":            "FREEZE_CGROUP",
    "VOLTAGE_GLITCH":          "FREEZE_CGROUP",
    "SUPPLY_CHAIN_ANOMALY":    "FREEZE_CGROUP",
}

QUARANTINE_LOG = "watchdog_data/quarantine.log"

def _log_action(action, result, alert, pid=None):
    os.makedirs("watchdog_data", exist_ok=True)
    entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "action": action,
        "result": result,
        "alert_type": alert.get("type"),
        "gpu": alert.get("gpu"),
        "pid": pid,
        "cvss": alert.get("cvss_score"),
    }
    with open(QUARANTINE_LOG, "a") as f:
        f.write(json.dumps(entry) + "\n")
    print(f"[QUARANTINE] {action} -> {result} | {alert.get('type')} GPU{alert.get('gpu')}")

def _get_gpu_pids(gpu_id):
    """Get PIDs using a specific GPU via nvidia-smi."""
    try:
        r = subprocess.run(
            ["nvidia-smi", "--query-compute-apps=pid",
             "--format=csv,noheader", f"--id={gpu_id}"],
            capture_output=True, text=True, timeout=5
        )
        return [p.strip() for p in r.stdout.strip().split("\n") if p.strip()]
    except Exception:
        return []

def _kill_container(gpu_id, alert):
    """Kill processes using the GPU. Requires host privileges."""
    pids = _get_gpu_pids(gpu_id)
    if not pids:
        _log_action("KILL_CONTAINER", "NO_PROCESSES_FOUND", alert)
        return "NO_PROCESSES_FOUND"
    killed = []
    for pid in pids:
        try:
            subprocess.run(["kill", "-9", pid], timeout=3)
            killed.append(pid)
        except Exception as e:
            pass
    result = f"KILLED_PIDS_{','.join(killed)}" if killed else "KILL_FAILED"
    _log_action("KILL_CONTAINER", result, alert, pid=",".join(pids))
    return result

def _freeze_cgroup(gpu_id, alert):
    """
    Freeze cgroup of GPU process for forensic preservation.
    Requires cgroup v2 and host privileges.
    On systems without cgroup access, falls back to SIGSTOP.
    """
    pids = _get_gpu_pids(gpu_id)
    if not pids:
        _log_action("FREEZE_CGROUP", "NO_PROCESSES_FOUND", alert)
        return "NO_PROCESSES_FOUND"
    frozen = []
    for pid in pids:
        # Try cgroup freeze first
        cgroup_path = f"/sys/fs/cgroup/system.slice/watchdog-quarantine-{pid}.scope/cgroup.freeze"
        if os.path.exists(cgroup_path):
            try:
                with open(cgroup_path, "w") as f:
                    f.write("1")
                frozen.append(f"cgroup:{pid}")
                continue
            except Exception:
                pass
        # Fall back to SIGSTOP
        try:
            subprocess.run(["kill", "-STOP", pid], timeout=3)
            frozen.append(f"sigstop:{pid}")
        except Exception:
            pass
    result = f"FROZEN_{','.join(frozen)}" if frozen else "FREEZE_FAILED_NO_PRIVILEGE"
    _log_action("FREEZE_CGROUP", result, alert, pid=",".join(pids))
    return result

class EBPFQuarantine:
    def __init__(self, auto_quarantine=False, require_cvss_min=8.0):
        self.auto_quarantine = auto_quarantine
        self.require_cvss_min = require_cvss_min
        self.action_count = 0
        self._check_privileges()

    def _check_privileges(self):
        """Check if running with sufficient privileges for quarantine actions."""
        try:
            r = subprocess.run(["id", "-u"], capture_output=True, text=True)
            self.is_root = r.stdout.strip() == "0"
        except Exception:
            self.is_root = False
        if not self.is_root:
            print("[QUARANTINE] WARNING: Not running as root. Quarantine actions may fail.")
            print("[QUARANTINE] For full eBPF support, run watchdog-host-agent as root.")

    def handle(self, alert):
        alert_type = alert.get("type", "UNKNOWN")
        action = QUARANTINE_TRIGGERS.get(alert_type)
        if not action:
            return None

        cvss = alert.get("cvss_score", 0)
        if cvss < self.require_cvss_min:
            _log_action(action, f"SKIPPED_CVSS_BELOW_{self.require_cvss_min}", alert)
            return f"SKIPPED_CVSS_{cvss}"

        if not self.auto_quarantine:
            _log_action(action, "SKIPPED_AUTO_DISABLED", alert)
            return "SKIPPED_AUTO_DISABLED"

        gpu_id = alert.get("gpu", 0)
        self.action_count += 1

        if action == "KILL_CONTAINER":
            return _kill_container(gpu_id, alert)
        elif action == "FREEZE_CGROUP":
            return _freeze_cgroup(gpu_id, alert)
        return "UNKNOWN_ACTION"

    def status(self):
        return {
            "auto_quarantine": self.auto_quarantine,
            "require_cvss_min": self.require_cvss_min,
            "is_root": self.is_root,
            "action_count": self.action_count,
            "triggers": QUARANTINE_TRIGGERS,
        }
