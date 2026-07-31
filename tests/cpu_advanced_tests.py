#!/usr/bin/env python3
import psutil
import multiprocessing
import time
import subprocess
import random

def test_numa():
    print("="*60)
    print("NUMA Performance Test")
    print("="*60)
    try:
        result = subprocess.run(['numactl', '--hardware'], capture_output=True, text=True)
        print(result.stdout)
    except:
        print("numactl not available")

def test_context_switching():
    print("="*60)
    print("Context Switching Test")
    print("="*60)
    import threading
    import queue
    q = queue.Queue()
    def worker():
        for i in range(10000):
            q.put(i)
    start = time.time()
    threads = []
    for i in range(100):
        t = threading.Thread(target=worker)
        t.start()
        threads.append(t)
    for t in threads:
        t.join()
    elapsed = time.time() - start
    print(f"100 threads, 10,000 ops each: {elapsed:.2f}s")
    stats = psutil.cpu_stats()
    print(f"Context switches: {stats.ctx_switches}")

def test_memory_latency():
    print("="*60)
    print("Memory Latency Test")
    print("="*60)
    size = 100 * 1024 * 1024
    arr = bytearray(size)
    start = time.time()
    total = 0
    for i in range(0, size, 64):
        total += arr[i]
    seq_time = time.time() - start
    start = time.time()
    total = 0
    indices = list(range(0, size, 64))
    random.shuffle(indices)
    for i in indices[:10000]:
        total += arr[i]
    rand_time = time.time() - start
    print(f"Sequential access: {seq_time:.4f}s")
    print(f"Random access: {rand_time:.4f}s")
    print(f"Latency ratio: {rand_time/seq_time:.2f}x")

if __name__ == '__main__':
    test_numa()
    test_context_switching()
    test_memory_latency()
