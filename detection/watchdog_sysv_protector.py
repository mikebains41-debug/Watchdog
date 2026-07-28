# Author: Manmohan (Mike) Bains -- Watchdog
"""
Watchdog v2.0 - System V IPC Shared Memory Protector
Attaches to System V IPC memory segments read-only and marks
them for deletion to prevent future re-attachment.

Complements WatchdogSHMProtector (POSIX /dev/shm) with
System V IPC region protection.

REQUIRES: root or appropriate IPC permissions.
Test on GPU rental host.
"""
import os, ctypes

class WatchdogSysVProtector:
    IPC_RMID = 0
    SHM_RDONLY = 0o10000

    def __init__(self, key, size):
        self.key = key
        self.size = size
        self.libc = ctypes.CDLL(None)

    def enforce_sysv_readonly_lock(self):
        print(f"[WATCHDOG SYSV] Securing IPC key: {hex(self.key)}")
        shmid = self.libc.shmget(ctypes.c_int(self.key), ctypes.c_size_t(self.size), 0)
        if shmid < 0:
            print(f"[SYSV] shmget failed for key {hex(self.key)} — segment may not exist")
            return False
        self.libc.shmat.restype = ctypes.c_void_p
        addr = self.libc.shmat(shmid, None, self.SHM_RDONLY)
        if addr == ctypes.c_void_p(-1).value or addr is None:
            print("[SYSV] shmat read-only attachment failed")
            return False
        print(f"[SYSV] PASS — attached read-only at {hex(addr)}")
        result = self.libc.shmctl(shmid, self.IPC_RMID, None)
        if result < 0:
            print("[SYSV] WARN — IPC_RMID mark failed")
        else:
            print("[SYSV] PASS — segment marked for deletion")
        return True

    def status(self):
        return {"key": hex(self.key), "size": self.size, "is_root": os.getuid() == 0}

if __name__ == "__main__":
    p = WatchdogSysVProtector(key=0x57444149, size=4096)
    print("Status:", p.status())
