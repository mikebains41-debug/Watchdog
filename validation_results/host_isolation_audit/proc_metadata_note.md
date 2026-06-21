# Proc Hardware Metadata Note

/proc/driver/nvidia/gpus/*/information exposes basic hardware metadata
(model, UUID, PCIe bus location, firmware version, IRQ) for all 8
physical H200 GPUs on the host, despite this instance being allocated
only 2. This is consistent with the device-node visibility already
documented (/dev/nvidia0-7). Low sensitivity: hardware inventory
metadata only, not tenant workload data, model weights, or any
information about other tenants' actual computations. Functional
access to unallocated GPUs remains blocked (already confirmed via the
nvidia-smi 0-7 query test).
