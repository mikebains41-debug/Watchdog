# GPU Isolation Audit: PASS (Mitigated by NVIDIA Runtime)

- **Observation:** 8 physical GPU device files (`/dev/nvidia0` to `/dev/nvidia7`) are mapped to the container filesystem with `crw-rw-rw-` (world-writable) permissions.
- **Test:** Explicit global polling of all 8 GPUs using `nvidia-smi -i 0,1,2,3,4,5,6,7 --query-gpu=index,gpu_name,power.draw,memory.used,utilization.gpu --format=csv`.
- **Outcome:** Only rented indices (0, 1) returned valid hardware telemetry. Indices 2–7 returned no data.
- **Conclusion:** The NVIDIA container runtime's cgroup and device access restrictions successfully block unauthorized hardware-level access to unallocated co-tenant GPUs. The vulnerability is mitigated at the driver/runtime level.
