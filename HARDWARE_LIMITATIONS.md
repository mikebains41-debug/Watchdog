# Watchdog - Hardware Sensor Limitations

The following catalog features require physical sensor hardware not
present in standard cloud GPU VMs (RunPod, GCP, AWS, Azure) and are
NOT implemented as real detection. Building them would require either
bare metal access with sensor wiring, or vendor BMC/IPMI integration.

## Requires external hardware
- EM side-channel detection: needs SDR dongle (HackRF, RTL-SDR) physically near the GPU
- Vibration/acoustic monitoring: needs MEMS accelerometer mounted on chassis
- Optical link health (SNR, BER): needs CPO transceiver direct register access, only on specific rack-scale NVLink switches
- PMBus voltage regulator telemetry: needs I2C/SMBus access to VRM, usually blocked in virtualized/cloud environments

## Requires BMC/IPMI access (cloud VMs do not expose this)
- Remote power cycle: needs PDU or BMC API access
- Liquid cooling telemetry: needs Redfish/IPMI to cooling controller
- Firmware rollback: needs out-of-band management access

## Partially implementable, not yet built
- Memory bandwidth read/write counters: requires DCGM or Nsight Compute, not exposed via nvidia-smi
- Memory controller activation/row-hit counters: requires Nsight profiling, adds significant overhead, not compatible with continuous 100Hz monitoring
- RNG entropy monitoring: feasible via /proc/sys/kernel/random/entropy_avail on Linux host, not GPU-specific

## What Watchdog actually monitors (software-only, nvidia-smi accessible)
Power, temperature, clocks, VRAM usage, utilization, PCIe link generation/width,
driver/VBIOS fingerprint, NVLink status. All 19 detection engines are built
on these accessible fields. This is an honest scope boundary, not a gap to
silently work around.

## _f() default=0.0 audit (August 2026)

`detection/_shared.py`'s `_f()` returns `0.0` for a missing key, not None.
A detector checking `is None` after `_f()` therefore treats an absent
field as a real zero.

Full audit of 64 `_f(row, ...)` call sites across detection/:

- **Fixed** where a false zero contaminates a learned baseline:
  GhostPowerDetector (power.draw), clock/PState detector (clocks.sm),
  ECCAnomalyDetector and PCIeAnomalyDetector (explicit key-presence
  guards). ThermalSideChannelDetector reads temperature.gpu with the
  same guard.
- **Latent, unreachable on target hardware:** ~7 remaining power.draw
  sites in engines.py, advanced.py, llm_attacks.py check `is None`.
  Verified against 1,523 real B200 rows across b200_watchdog/*.csv:
  zero N/A markers, power.draw populated in every row. On real
  NVIDIA datacenter hardware these fields are always present.
- **Direction of failure:** at the remaining sites a spurious 0.0
  produces a MISSED detection (fail-closed), not a false alarm. The
  baseline-contaminating cases (fail-open) are the ones already fixed.

Decision: remaining sites are hardening, not a live-bug fix. If Watchdog
is ever deployed to hardware/configs where power.draw can be absent
(some MIG partitions, some virtualized passthrough), add key-presence
guards to those 7 sites first.
