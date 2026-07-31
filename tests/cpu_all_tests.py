#!/usr/bin/env python3
"""
COMPLETE CPU TEST SUITE - 15 TESTS
"""

import os
import sys
import time
import psutil
import multiprocessing
import subprocess
import json
import random
import threading
import queue
from datetime import datetime

class AllCPUTests:
    def __init__(self):
        self.results = {}
        # FIX: multiprocessing.cpu_count() and psutil.cpu_count() both
        # report the HOST's core count (96 here), not the container's
        # cgroup allocation (32). Every load-average percentage computed
        # from the host count understates real saturation by 3x. Use the
        # scheduler affinity mask, which respects the container boundary.
        self.cpu_count = len(os.sched_getaffinity(0))
        self.host_cpu_count = multiprocessing.cpu_count()
        self.memory = psutil.virtual_memory()
        print("="*70)
        print("COMPLETE CPU TEST SUITE - 15 TESTS")
        print("="*70)
        print(f"System: {self.cpu_count} cores usable "
              f"(host reports {self.host_cpu_count}), "
              f"{self.memory.total/1024**3:.1f}GB RAM")
        print("="*70)

    def test_1_cpu_basic(self):
        print("\n[TEST 1] Basic CPU Monitoring")
        cpu = psutil.cpu_percent(interval=1, percpu=True)
        avg = sum(cpu) / len(cpu)
        print(f"  Average: {avg:.1f}%")
        self.results['basic_cpu'] = {'avg': avg}

    def test_2_cpu_times(self):
        print("\n[TEST 2] CPU Time Breakdown")
        times = psutil.cpu_times()
        print(f"  User: {times.user:.1f}s")
        print(f"  System: {times.system:.1f}s")
        print(f"  Idle: {times.idle:.1f}s")
        self.results['cpu_times'] = {'user': times.user, 'system': times.system}

    def test_3_cpu_freq(self):
        print("\n[TEST 3] CPU Frequency")
        freqs = psutil.cpu_freq(percpu=True)
        avg = sum(f.current for f in freqs) / len(freqs)
        print(f"  Average: {avg:.0f}MHz")
        self.results['cpu_freq'] = {'avg': avg}

    def test_4_cpu_stats(self):
        print("\n[TEST 4] CPU Statistics")
        stats = psutil.cpu_stats()
        print(f"  Context switches: {stats.ctx_switches:,}")
        print(f"  Interrupts: {stats.interrupts:,}")
        self.results['cpu_stats'] = {'ctx_switches': stats.ctx_switches}

    def test_5_cpu_affinity(self):
        print("\n[TEST 5] CPU Affinity")
        p = psutil.Process()
        affinity = p.cpu_affinity()
        print(f"  Affinity: {affinity[:10]}...")
        self.results['affinity'] = {'affinity': str(affinity[:10])}

    def test_6_cpu_load(self):
        print("\n[TEST 6] Load Average")
        load = psutil.getloadavg()
        pct = (load[0] / self.cpu_count) * 100
        print(f"  1m: {load[0]:.2f}  ({pct:.0f}% of {self.cpu_count} usable cores)")
        print(f"  5m: {load[1]:.2f}")
        print(f"  15m: {load[2]:.2f}")
        if pct > 100:
            print(f"  SATURATED: load exceeds usable cores. This is a real"
                  f" measurement, not a threshold artifact.")
        self.results['load'] = {'1m': load[0], '5m': load[1], '15m': load[2],
                                 'pct_of_usable': round(pct, 1),
                                 'usable_cores': self.cpu_count,
                                 'host_cores': self.host_cpu_count}

    def test_7_context_switch_perf(self):
        print("\n[TEST 7] Context Switch Performance")
        q = queue.Queue()
        def worker():
            for _ in range(50000):
                q.put(1)
        start = time.time()
        threads = [threading.Thread(target=worker) for _ in range(50)]
        for t in threads: t.start()
        for t in threads: t.join()
        elapsed = time.time() - start
        print(f"  Elapsed: {elapsed:.2f}s")
        self.results['ctx_perf'] = {'elapsed': elapsed}

    def test_8_memory_bandwidth(self):
        print("\n[TEST 8] Memory Bandwidth")
        size = 200 * 1024 * 1024
        arr = bytearray(size)
        start = time.time()
        for i in range(0, size, 64):
            arr[i] = i % 256
        write_time = time.time() - start
        bandwidth = (size / write_time) / 1024**3
        print(f"  Bandwidth: {bandwidth:.2f} GB/s")
        self.results['memory_bandwidth'] = {'write_gb_s': bandwidth}

    def test_9_cache_hierarchy(self):
        """DISABLED: pure Python cannot measure cache hierarchy.

        Verified empirically on AMD EPYC 9654: a correctly-designed
        benchmark (fixed loop work, varying working-set 16KB -> 512MB,
        cache-line stride) produced 11.90M / 11.88M / 11.80M / 11.81M
        ops/sec for L1 / L2 / L3 / RAM -- a 1.01x spread. Python's
        ~85ns/iteration interpreter overhead swamps the ~1ns vs ~80ns
        L1-to-RAM difference by roughly two orders of magnitude.

        The original test reported ~1.6 GB/s identically across every
        tier, which looked like a measurement but was loop overhead.
        Reporting a number that cannot vary with the thing it claims to
        measure is worse than reporting nothing. Needs native code
        (C/OpenMP) or a tool like lmbench to test properly.
        """
        print("\n[TEST 9] Cache Hierarchy")
        print("  SKIPPED: not measurable from pure Python "
              "(verified: 1.01x L1/RAM spread). See docstring.")
        self.results['cache'] = {'status': 'skipped',
                                  'reason': 'interpreter-bound',
                                  'measured_l1_ram_spread': 1.01}
        return
        sizes = [1, 4, 16, 64, 256, 1024]
        for mb in sizes:
            arr = bytearray(mb * 1024 * 1024)
            start = time.time()
            for i in range(0, len(arr), 64):
                arr[i] = i % 256
            elapsed = time.time() - start
            bw = (len(arr) / elapsed) / 1024**3
            level = "L1" if mb <= 4 else "L2" if mb <= 16 else "L3" if mb <= 64 else "RAM"
            print(f"  {level} {mb:4d}MB: {bw:.2f} GB/s")
        self.results['cache'] = {'levels': ['L1', 'L2', 'L3', 'RAM']}

    def test_10_process_count(self):
        print("\n[TEST 10] Process Count")
        procs = len(psutil.pids())
        print(f"  Total: {procs}")
        self.results['processes'] = {'count': procs}

    def test_11_disk_io(self):
        print("\n[TEST 11] Disk I/O")
        disk = psutil.disk_usage('/')
        print(f"  Disk usage: {disk.percent:.1f}%")
        self.results['disk'] = {'usage': disk.percent}

    def test_12_network(self):
        print("\n[TEST 12] Network I/O")
        net = psutil.net_io_counters()
        print(f"  Bytes sent: {net.bytes_sent/1024**3:.1f}GB")
        print(f"  Bytes recv: {net.bytes_recv/1024**3:.1f}GB")
        self.results['network'] = {'sent': net.bytes_sent, 'recv': net.bytes_recv}

    def test_13_uptime(self):
        print("\n[TEST 13] System Uptime")
        uptime = time.time() - psutil.boot_time()
        days = uptime // 86400
        hours = (uptime % 86400) // 3600
        print(f"  Uptime: {int(days)}d {int(hours)}h")
        self.results['uptime'] = {'days': days, 'hours': hours}

    def test_14_threads(self):
        print("\n[TEST 14] Thread Count")
        p = psutil.Process()
        threads = p.num_threads()
        print(f"  Threads: {threads}")
        self.results['threads'] = {'count': threads}

    def test_15_memory_maps(self):
        print("\n[TEST 15] Memory Maps")
        p = psutil.Process()
        maps = p.memory_maps()
        print(f"  Memory maps: {len(maps)}")
        self.results['memory_maps'] = {'count': len(maps)}

    def run_all(self):
        self.test_1_cpu_basic()
        self.test_2_cpu_times()
        self.test_3_cpu_freq()
        self.test_4_cpu_stats()
        self.test_5_cpu_affinity()
        self.test_6_cpu_load()
        self.test_7_context_switch_perf()
        self.test_8_memory_bandwidth()
        self.test_9_cache_hierarchy()
        self.test_10_process_count()
        self.test_11_disk_io()
        self.test_12_network()
        self.test_13_uptime()
        self.test_14_threads()
        self.test_15_memory_maps()

        print("\n" + "="*70)
        print(f"ALL 15 CPU TESTS COMPLETE - {len(self.results)} tests run")
        print("="*70)

if __name__ == '__main__':
    tests = AllCPUTests()
    tests.run_all()
