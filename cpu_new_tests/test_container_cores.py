#!/usr/bin/env python3
"""Test: Container-Aware Core Counting"""
import os
import psutil

def test_usable_cores():
    try:
        cores = len(os.sched_getaffinity(0))
        print(f"✅ Container-aware cores: {cores}")
    except:
        cores = psutil.cpu_count()
        print(f"⚠️  Fallback: {cores}")
    return cores

if __name__ == '__main__':
    host = psutil.cpu_count()
    container = test_usable_cores()
    print(f"Host: {host}, Container: {container}")
    if host != container:
        print("⚠️  MISMATCH: psutil leaks host core count!")
    else:
        print("✅ Match")
