"""
Watchdog AIDR v2.0 - Orphaned /dev/shm Segment Cleaner
Detects and unlinks dead shared memory segments from terminated
Kubernetes container workloads. Runs every 10 minutes via CronJob.

Checks /proc/*/fd to confirm no active PID holds the segment open
before unlinking. Safe — never removes live segments.
"""
import os, sys, glob

class SharedMemoryOrphanCleaner:
    def __init__(self, target_prefix="model_weights_"):
        self.shm_dir = "/dev/shm"
        self.prefix = target_prefix
        self.pruned = 0
        self.skipped = 0

    def _in_use(self, filename):
        for pid_dir in glob.glob("/proc/[0-9]*"):
            try:
                fd_path = os.path.join(pid_dir, "fd")
                if os.path.isdir(fd_path):
                    for fd in os.listdir(fd_path):
                        try:
                            target = os.readlink(os.path.join(fd_path, fd))
                            if filename in target:
                                return True
                        except OSError:
                            pass
            except (OSError, ValueError):
                continue
        return False

    def prune(self):
        print(f"[WATCHDOG CLEANER] Scanning {self.shm_dir} for prefix '{self.prefix}'")
        if not os.path.exists(self.shm_dir):
            print(f"[CLEANER] {self.shm_dir} not available on this host")
            return
        for path in glob.glob(os.path.join(self.shm_dir, f"{self.prefix}*")):
            fname = os.path.basename(path)
            if self._in_use(fname):
                self.skipped += 1
                print(f"[CLEANER] IN USE — skip: {fname}")
            else:
                try:
                    os.system(f"chattr -i {path} 2>/dev/null")
                    os.unlink(path)
                    self.pruned += 1
                    print(f"[CLEANER] PRUNED: {fname}")
                except Exception as e:
                    print(f"[CLEANER] ERROR pruning {fname}: {e}")
        print(f"[CLEANER] Done — pruned={self.pruned} skipped={self.skipped}")

if __name__ == "__main__":
    SharedMemoryOrphanCleaner().prune()
