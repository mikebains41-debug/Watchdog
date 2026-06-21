#!/bin/bash
# Author: Manmohan (Mike) Bains
# Project: GPU Optimizer / Watchdog
# Host Isolation Audit - all non-destructive checks run during the
# Vast.ai 2xH200 session, 2026-06-21

echo "--- CC mode status ---"
sudo nvidia-smi conf-compute -q

echo "--- Network capability check ---"
ip link add dummy0 type dummy 2>/dev/null && echo "VULNERABLE: Container has root network capabilities!" || echo "PASS: Network isolated."

echo "--- Raw device check ---"
ls -l /dev/nvme* /dev/sd* 2>/dev/null || echo "No raw block devices visible"

echo "--- GPU topology ---"
nvidia-smi topo -m

echo "--- Shared memory/temp check ---"
ls -la /dev/shm /tmp

echo "--- Open network ports ---"
ss -tulnp

echo "--- Environment variables ---"
printenv

echo "--- Kernel ring buffer ---"
dmesg 2>&1 | head -n 20

echo "--- GPU device node permissions ---"
ls -la /dev/nvidia*

echo "--- Nvidia/cuda IPC sockets ---"
find /var/run/ -name "*nvidia*" -o -name "*cuda*" 2>/dev/null

echo "--- Metadata server check ---"
GATEWAY_IP=$(ip route | grep default | awk '{print $3}')
curl -m 3 -I http://$GATEWAY_IP/ 2>&1
curl -m 3 -I http://169.254.169.254 2>&1

echo "--- GPU device functional access check (rented indices only expected) ---"
nvidia-smi -i 0,1,2,3,4,5,6,7 --query-gpu=index,gpu_name,power.draw,memory.used,utilization.gpu --format=csv

echo "--- PID Namespace Audit ---"
ps -ef | wc -l
ps -ef | grep -E "containerd|dockerd|libvirtd|kvm"

echo "--- Local Network / DNS Leak Audit ---"
cat /etc/resolv.conf
cat /etc/hosts

echo "--- Sandbox Profile Audit ---"
id
cat /proc/self/attr/current 2>/dev/null || echo "AppArmor: Not enforced/Unavailable"
grep -i "NoNewPrivs" /proc/self/status

echo "--- Advanced Boundary Capability Audit ---"
grep CapBnd /proc/self/status

echo "--- Advanced Real-time IPC Namespace Audit ---"
ipcs -m -s -q

echo "--- Storage Discard Capabilities ---"
lsblk -D 2>/dev/null || echo "lsblk not available"
cat /sys/block/nvme*n1/queue/discard_max_bytes 2>/dev/null || echo "Metrics unavailable"

echo "--- Local Arp / Neighbor Matrix ---"
ip neigh show

echo "--- Group Membership Layout ---"
groups
cat /etc/group | grep -E "docker|render|kvm|wheel"

echo "--- NVIDIA Driver and MPS IPC Audit ---"
ls -la /tmp/.nvidia-mps 2>/dev/null || echo "No global MPS socket leaked in /tmp"
ls -la /dev/shm/cuda_injection_* 2>/dev/null || echo "No active CUDA injection handles visible"
cat /proc/driver/nvidia/gpus/*/information 2>/dev/null || echo "GPU system info files restricted"

echo "--- Storage Mount and UID Mapping Audit ---"
mount | grep -E "workspace|docker|overlay" | head -n 5
cat /proc/self/uid_map 2>/dev/null || echo "UID map file restricted"
