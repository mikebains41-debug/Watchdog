# Author: Manmohan (Mike) Bains -- Watchdog
"""
Watchdog v2.0 - Advanced eBPF Quarantine Core Verifier
Deep structural compatibility check before EBPFQuarantine activation.
Checks cgroup v2 unified hierarchy, kprobes, and perf_event access.
Extends verify_ebpf_compat.py with lower-level kernel structure checks.

FIXED vs. original version (see git history):
  - check_bpf_helpers tested the wrong kernel subsystem. It grepped
    available_filter_functions (kprobe-attachable symbols) for helper
    names like "bpf_map_lookup_elem" -- a coincidental string match, not
    evidence of BPF helper availability, which is enforced by the
    verifier at program-load time and is a different subsystem entirely.
    The function also could never return a failure. It now honestly
    reports that this cannot be checked from userspace without attempting
    an actual BPF_PROG_LOAD, which this script does not do.
  - check_cgroup2_unified confirmed the mount existed and was rw at the
    host level, but never checked whether THIS process actually has write
    access -- the common failure mode on rented multi-tenant containers.
    It now parses /proc/mounts by field (not substring match) and checks
    os.access() on the real mountpoint.
  - Bare except Exception: pass swallowed the actual reason for a failure
    (permission denied vs. not found vs. something else). Exceptions are
    now surfaced in the warning/failure message.

STILL A LIMITATION, stated rather than hidden:
  None of these checks attempt to actually load a BPF program or write to
  a cgroup path. They check necessary preconditions, not sufficiency.
  "APPROVED" means the structural prerequisites this script can observe
  are present -- it does not guarantee EBPFQuarantine will work at runtime.
"""
import os, sys, platform


class AdvancedEBPFVerifier:
    def __init__(self):
        self.min_kernel = (5, 4, 0)
        self.passed = 0
        self.failed = 0
        self.warned = 0

    def _pass(self, msg):
        print(f"  [PASS] {msg}")
        self.passed += 1

    def _fail(self, msg):
        print(f"  [FAIL] {msg}")
        self.failed += 1

    def _warn(self, msg):
        print(f"  [WARN] {msg}")
        self.warned += 1

    def check_kernel_version(self):
        raw = platform.release()
        clean = raw.split("-")[0]
        try:
            ver = tuple(map(int, clean.split(".")[:3]))
            if ver >= self.min_kernel:
                self._pass(f"Kernel {raw} >= {'.'.join(map(str, self.min_kernel))}")
                return True
            else:
                self._fail(f"Kernel {raw} below minimum {'.'.join(map(str, self.min_kernel))}")
                return False
        except ValueError:
            self._fail(f"Kernel version unparseable: {raw}")
            return False

    def check_cgroup2_unified(self):
        try:
            with open("/proc/mounts") as f:
                for line in f:
                    fields = line.split()
                    if len(fields) < 4:
                        continue
                    mountpoint, fstype, options = fields[1], fields[2], fields[3]
                    if fstype != "cgroup2":
                        continue
                    mount_rw = "rw" in options.split(",")
                    process_can_write = os.access(mountpoint, os.W_OK)
                    if mount_rw and process_can_write:
                        self._pass(f"cgroup v2 at {mountpoint}: mounted rw, "
                                    f"this process has write access")
                        return True
                    elif mount_rw and not process_can_write:
                        self._warn(f"cgroup v2 at {mountpoint} mounted rw but "
                                    f"this process lacks write access -- "
                                    f"freeze fallback to SIGSTOP")
                        return False
                    else:
                        self._warn(f"cgroup v2 at {mountpoint} mounted "
                                    f"read-only -- freeze fallback to SIGSTOP")
                        return False
        except Exception as e:
            self._warn(f"cgroup v2 check failed reading /proc/mounts: {e!r}")
            return False
        self._warn("cgroup v2 not found -- freeze fallback to SIGSTOP")
        return False

    def check_kprobes(self):
        kprobes_enabled = "/sys/kernel/debug/kprobes/enabled"
        if os.path.exists(kprobes_enabled):
            try:
                val = open(kprobes_enabled).read().strip()
                if val == "1":
                    self._pass(f"kprobes enabled ({kprobes_enabled}=1)")
                    return True
                else:
                    self._warn(f"kprobes present but disabled "
                                f"({kprobes_enabled}={val!r})")
            except PermissionError:
                self._warn(f"{kprobes_enabled} exists but not readable "
                            f"(permission denied) -- likely a restricted "
                            f"container")
            except Exception as e:
                self._warn(f"{kprobes_enabled} exists but unreadable: {e!r}")

        tracefs = "/sys/kernel/tracing/available_filter_functions"
        if os.path.exists(tracefs) and os.access(tracefs, os.R_OK):
            self._pass(f"Kernel tracing filter functions readable at {tracefs}")
            return True

        self._fail("Kernel tracing/kprobes locked, disabled, or "
                    "inaccessible from this container")
        return False

    def check_bpf_helpers(self):
        self._warn("BPF helper availability cannot be verified from "
                    "userspace without an actual BPF_PROG_LOAD attempt -- "
                    "not implemented here. Do not treat this as a pass.")
        return None

    def check_perf_events(self):
        path = "/proc/sys/kernel/perf_event_paranoid"
        if os.path.exists(path):
            try:
                val = int(open(path).read().strip())
                if val <= 2:
                    self._pass(f"perf_event_paranoid={val} (does not "
                                f"outright block BPF perf events; actual "
                                f"capability also depends on process "
                                f"capabilities, not checked here)")
                else:
                    self._warn(f"perf_event_paranoid={val} (restrictive -- "
                                f"some BPF perf-event-based features likely "
                                f"blocked for unprivileged processes)")
                return True
            except Exception as e:
                self._warn(f"perf_event_paranoid unreadable: {e!r}")
                return True
        self._warn(f"{path} not present")
        return True

    def run_preflight_checks(self):
        print("[WATCHDOG KERNEL] Advanced eBPF Structural Compatibility Check")
        print("=" * 55)
        ok = True
        ok = self.check_kernel_version() and ok
        cg2 = self.check_cgroup2_unified()
        ok = self.check_kprobes() and ok
        self.check_bpf_helpers()
        self.check_perf_events()
        print("=" * 55)
        print(f"[RESULTS] PASS={self.passed} FAIL={self.failed} WARN={self.warned}")
        if not cg2:
            print("[NOTE] cgroup v2 write access missing -- EBPFQuarantine "
                  "will use SIGSTOP fallback")
        if ok:
            print("[WATCHDOG KERNEL] Structural preconditions observed. "
                  "This does not guarantee runtime success -- see module "
                  "docstring.")
        else:
            print("[WATCHDOG KERNEL] Validation FAILED. Safeguards triggered.")
        return ok


if __name__ == "__main__":
    v = AdvancedEBPFVerifier()
    ok = v.run_preflight_checks()
    sys.exit(0 if ok else 1)
