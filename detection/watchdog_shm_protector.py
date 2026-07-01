"""
Watchdog AIDR v2.0 - POSIX Shared Memory Read-Only Enforcer
Locks /dev/shm model weight segments to read-only after loading.
Prevents runtime modification of active model layers.

REQUIRES: root or CAP_DAC_OVERRIDE for chmod and chattr.
Test on GPU rental host — /dev/shm not available in Termux.
"""
import os, sys, ctypes

class WatchdogSHMProtector:
    def __init__(self, memory_segment_name):
        self.segment_path = f"/dev/shm/{memory_segment_name.lstrip('/')}"
        try:
            self.libc = ctypes.CDLL(None)
            self.shm_open = self.libc.shm_open
            self.shm_open.argtypes = [ctypes.c_char_p, ctypes.c_int, ctypes.c_uint16]
            self.shm_open.restype = ctypes.c_int
        except Exception as e:
            print(f"[SHM] libc load warning: {e}")
            self.shm_open = None

    def enforce_readonly_context(self):
        print(f"[WATCHDOG SHM] Locking: {self.segment_path}")
        if not os.path.exists(self.segment_path):
            print(f"[SHM] Segment not found: {self.segment_path}")
            return False
        try:
            if self.shm_open:
                fd = self.shm_open(self.segment_path.encode(), 0, 0)
                if fd < 0:
                    print("[SHM] shm_open failed — may need root")
            os.chmod(self.segment_path, 0o444)
            os.system(f"chattr +i {self.segment_path} 2>/dev/null")
            print("[SHM] PASS — segment locked read-only.")
            return True
        except Exception as e:
            print(f"[SHM] FAIL: {e}")
            return False

    def status(self):
        exists = os.path.exists(self.segment_path)
        return {"segment": self.segment_path, "exists": exists, "is_root": os.getuid() == 0}

if __name__ == "__main__":
    if os.getuid() != 0:
        print("[WARN] Not root — some operations may fail.")
    p = WatchdogSHMProtector("model_weights_layer_0")
    print("Status:", p.status())
