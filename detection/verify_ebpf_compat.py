# Author: Manmohan (Mike) Bains -- Watchdog AIDR
"""
Watchdog AIDR v2.0 - eBPF Kernel Compatibility Verifier
Tests host kernels before deploying EBPFQuarantine driver.
Checks kernel version, BTF presence, required config flags,
cgroup v2, and BPF JIT status.

Run before enabling auto_quarantine=True in EBPFQuarantine.
"""
import os, sys, platform, gzip

class EBPFQuarantineCompatVerifier:
    MIN_KERNEL = (5, 4, 0)
    REQUIRED_FLAGS = [
        "CONFIG_BPF",
        "CONFIG_BPF_SYSCALL",
        "CONFIG_BPF_JIT",
        "CONFIG_HAVE_EBPF_JIT",
        "CONFIG_CGROUPS",
    ]
    RECOMMENDED_FLAGS = [
        "CONFIG_DEBUG_INFO_BTF",   # CO-RE support
        "CONFIG_CGROUP_BPF",       # BPF cgroup hooks
        "CONFIG_BPF_EVENTS",       # Perf event support
    ]

    def __init__(self):
        self.results = {}
        self.passed = 0
        self.failed = 0
        self.warned = 0

    def _check(self, name, result, level="REQUIRED"):
        status = "PASS" if result else ("FAIL" if level == "REQUIRED" else "WARN")
        self.results[name] = {"status": status, "level": level}
        if status == "PASS":
            self.passed += 1
        elif status == "FAIL":
            self.failed += 1
        else:
            self.warned += 1
        print(f"  [{status}] {name}")
        return result

    def check_kernel_version(self):
        release = platform.release().split("-")[0]
        try:
            ver = tuple(map(int, release.split(".")[:3]))
            ok = ver >= self.MIN_KERNEL
            self._check(f"Kernel >= {'.'.join(map(str, self.MIN_KERNEL))} (detected {release})", ok)
            return ok
        except ValueError:
            self._check(f"Kernel version parse ({release})", False)
            return False

    def check_btf(self):
        ok = os.path.exists("/sys/kernel/btf/vmlinux")
        self._check("BTF metadata /sys/kernel/btf/vmlinux", ok, "RECOMMENDED")
        return ok

    def check_bpf_jit(self):
        path = "/proc/sys/net/core/bpf_jit_enable"
        if os.path.exists(path):
            try:
                val = open(path).read().strip()
                ok = val in ("1", "2")
                self._check(f"BPF JIT enabled ({val})", ok)
                return ok
            except Exception:
                pass
        self._check("BPF JIT /proc/sys/net/core/bpf_jit_enable", False, "RECOMMENDED")
        return False

    def check_cgroup_v2(self):
        ok = os.path.exists("/sys/fs/cgroup/cgroup.controllers")
        self._check("cgroup v2 /sys/fs/cgroup/cgroup.controllers", ok)
        return ok

    def check_kernel_config(self):
        release = platform.release()
        paths = [f"/boot/config-{release}", "/proc/config.gz"]
        lines = []
        for path in paths:
            if os.path.exists(path):
                try:
                    if path.endswith(".gz"):
                        with gzip.open(path, "rt") as f:
                            lines = f.readlines()
                    else:
                        with open(path) as f:
                            lines = f.readlines()
                    break
                except Exception:
                    pass

        if not lines:
            self._check("Kernel config readable", False, "RECOMMENDED")
            return True

        found = {}
        for line in lines:
            for flag in self.REQUIRED_FLAGS + self.RECOMMENDED_FLAGS:
                if line.startswith(f"{flag}="):
                    found[flag] = line.strip().split("=")[1]

        all_ok = True
        for flag in self.REQUIRED_FLAGS:
            ok = found.get(flag) == "y"
            self._check(f"Kernel flag {flag}", ok)
            if not ok:
                all_ok = False

        for flag in self.RECOMMENDED_FLAGS:
            ok = found.get(flag) == "y"
            self._check(f"Kernel flag {flag} (recommended)", ok, "RECOMMENDED")

        return all_ok

    def verify_host(self):
        print("[WATCHDOG COMPAT] eBPF Host Compatibility Check")
        print("=" * 50)
        ok = True
        ok = self.check_kernel_version() and ok
        self.check_btf()
        self.check_bpf_jit()
        ok = self.check_cgroup_v2() and ok
        ok = self.check_kernel_config() and ok
        print("=" * 50)
        print(f"[RESULTS] PASS={self.passed} FAIL={self.failed} WARN={self.warned}")
        if ok:
            print("[WATCHDOG COMPAT] Host APPROVED for EBPFQuarantine activation.")
        else:
            print("[WATCHDOG COMPAT] Host UNSAFE for eBPF. Falling back to userspace termination.")
        return ok

    def report(self):
        return {
            "passed": self.passed,
            "failed": self.failed,
            "warned": self.warned,
            "approved": self.failed == 0,
            "results": self.results,
        }

if __name__ == "__main__":
    v = EBPFQuarantineCompatVerifier()
    ok = v.verify_host()
    sys.exit(0 if ok else 1)
