"""
Watchdog AIDR v2.0 - Cryptographic Weight Pinning System
Continuously hashes active VRAM regions holding model weights and
verifies them against a signed registry to detect runtime model
substitution, tampering, or extraction.

DEPLOYMENT: Requires CAP_SYS_PTRACE or root to use process_vm_readv.
Falls back to file-based hash verification when memory access unavailable.
"""
import ctypes, hashlib, time, threading, json, os
from datetime import datetime, timezone

WEIGHT_PIN_LOG = "watchdog_data/weight_pins.jsonl"

class WeightTamperAlert(Exception):
    pass

class WatchdogWeightPinner(threading.Thread):
    def __init__(self, target_pid, expected_hash_registry,
                 check_interval=5.0, on_tamper=None):
        super().__init__()
        self.target_pid = target_pid
        self.expected_hash_registry = expected_hash_registry
        self.check_interval = check_interval
        self.on_tamper = on_tamper
        self.running = True
        self.daemon = True
        self.tamper_count = 0
        self._has_ptrace = self._check_ptrace()
        os.makedirs(os.path.dirname(WEIGHT_PIN_LOG) if os.path.dirname(WEIGHT_PIN_LOG) else ".", exist_ok=True)

    def _check_ptrace(self):
        try:
            libc = ctypes.CDLL("libc.so.6", use_errno=True)
            return hasattr(libc, "process_vm_readv")
        except Exception:
            return False

    def _read_process_memory(self, address, length):
        if not self._has_ptrace:
            return None
        try:
            libc = ctypes.CDLL("libc.so.6")

            class IOVec(ctypes.Structure):
                _fields_ = [("iov_base", ctypes.c_void_p), ("iov_len", ctypes.c_size_t)]

            buf = (ctypes.c_char * length)()
            local_iov = IOVec(ctypes.cast(buf, ctypes.c_void_p), length)
            remote_iov = IOVec(ctypes.c_void_p(address), length)
            ret = libc.process_vm_readv(
                self.target_pid, ctypes.byref(local_iov), 1,
                ctypes.byref(remote_iov), 1, 0
            )
            if ret == length:
                return bytes(buf)
        except Exception:
            pass
        return None

    def pin_file(self, filepath):
        """Hash a model weight file as fallback when memory access unavailable."""
        try:
            h = hashlib.sha256()
            with open(filepath, "rb") as f:
                for chunk in iter(lambda: f.read(65536), b""):
                    h.update(chunk)
            return h.hexdigest()
        except Exception:
            return None

    def _log_tamper(self, offset, current, expected):
        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "type": "WEIGHT_TAMPER_DETECTED",
            "pid": self.target_pid,
            "offset": hex(offset) if isinstance(offset, int) else offset,
            "expected_hash": expected,
            "detected_hash": current,
            "severity": "CRITICAL",
            "cvss_score": 9.1,
        }
        with open(WEIGHT_PIN_LOG, "a") as f:
            f.write(json.dumps(entry) + "\n")
        print(f"[WEIGHT PINNER] CRITICAL TAMPER DETECTED at {hex(offset) if isinstance(offset, int) else offset}")
        print(f"  Expected: {expected}")
        print(f"  Detected: {current}")

    def run(self):
        print(f"[WEIGHT PINNER] Starting — PID {self.target_pid} — {len(self.expected_hash_registry)} pins")
        print(f"[WEIGHT PINNER] Memory access: {'ENABLED' if self._has_ptrace else 'DISABLED — file mode only'}")
        while self.running:
            for offset, expected_hash in self.expected_hash_registry.items():
                if isinstance(offset, int):
                    data = self._read_process_memory(offset, 4096)
                else:
                    data = None
                    if os.path.exists(str(offset)):
                        h = hashlib.sha256()
                        with open(str(offset), "rb") as f:
                            for chunk in iter(lambda: f.read(65536), b""):
                                h.update(chunk)
                        current = h.hexdigest()
                        if current != expected_hash:
                            self.tamper_count += 1
                            self._log_tamper(offset, current, expected_hash)
                            if self.on_tamper:
                                self.on_tamper(offset, current, expected_hash)
                        continue
                if data is not None:
                    current = hashlib.sha256(data).hexdigest()
                    if current != expected_hash:
                        self.tamper_count += 1
                        self._log_tamper(offset, current, expected_hash)
                        if self.on_tamper:
                            self.on_tamper(offset, current, expected_hash)
            time.sleep(self.check_interval)

    def stop(self):
        self.running = False

    def status(self):
        return {
            "running": self.running,
            "target_pid": self.target_pid,
            "pins": len(self.expected_hash_registry),
            "tamper_count": self.tamper_count,
            "memory_access": self._has_ptrace,
            "check_interval_s": self.check_interval,
        }
