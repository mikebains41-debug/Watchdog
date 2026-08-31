# Watchdog Detector ID Registry (authoritative)

Generated to fix ID collisions found across modules 1–16. Before this pass,
`D7`, `D8`, and `D12` were each reused by 2–3 unrelated detectors, and modules
9–16 used bare names with no `D#` prefix at all — meaning no central
mapping could exist between module -> detector ID -> severity.

Rule going forward: **every new detector gets the next unused number in this
file before it's written into a module.** Never reuse a number.

| ID  | Name                          | Module | Notes |
|-----|-------------------------------|--------|-------|
| D1  | GHOST_POWER                   | 1      | unchanged |
| D3  | PSTATE                        | 1      | unchanged |
| D4  | ZERO_SYSCALL_MINE             | 1      | unchanged |
| D8  | THERMAL_STRESS                | 1      | unchanged (GPU thermal) |
| D10 | HOST_MEMORY_SPRAWL            | 2      | unchanged |
| D11 | PROCESS_LINEAGE               | 2      | unchanged |
| D12 | CONTAINER_RESOURCE_LIMIT      | 2      | unchanged — kept as canonical D12 |
| D13 | IO_BURST                      | 2      | **renamed** from D12_IO_BURST |
| D14 | CRON_PERSISTENCE              | 2      | unchanged |
| D15 | CREDENTIAL_STORE_ACCESS       | 2      | unchanged |
| D26 | CROSS_SOURCE_CORRELATION      | 5a     | unchanged |
| D32 | PCIE_RESET                    | 3      | unchanged |
| D37 | PCIE_LANE_SPEED               | 3      | unchanged |
| D38 | ASLR_DISABLED                 | 6      | unchanged |
| D45 | LIBRARY_HASH                  | 6      | unchanged |
| D48 | RAPL_DISABLED                 | 6      | unchanged |
| D50 | REGISTRY_PULL                 | 4      | unchanged |
| D51 | VRAM_RESIDUE                  | 5b     | unchanged |
| D59 | IOMMU_ERROR                   | 8      | unchanged |
| D64 | CPU_THERMAL_STRESS             | 8      | unchanged |
| D70 | XID_ERROR                     | 3      | **renamed** from D7_XID_ERROR |
| D71 | GPU_MEM_ATTRIBUTION            | 1      | **renamed** from D7_ATTRIBUTION |
| D72 | CLOCK_GLITCH                  | 7      | **renamed** from D7_CLOCK_GLITCH |
| D73 | POWER_BRAKE                   | 7      | **renamed** from D8_POWER_BRAKE |
| D74 | OUTBOUND_C2                   | 4      | **renamed** from D12_OUTBOUND_C2 |
| D75 | OUTBOUND_PORT                 | 4      | **renamed** from D12_OUTBOUND_PORT |
| D80 | MODEL_EXFILTRATION            | 9      | **new ID** (was unprefixed) |
| D81 | COMPILER_INJECTION            | 9      | **new ID** (was unprefixed) |
| D82 | MMIO_ANOMALY                  | 10     | **new ID** (was unprefixed) |
| D83 | ECC_ACCELERATION              | 11     | **new ID** (was unprefixed) |
| D84 | MEM_CLOCK_DESYNC              | 11     | **new ID** (was unprefixed) |
| D85 | L3_CACHE_THRASHING            | 12     | **new ID** (was unprefixed) |
| D86 | RAPL_SPIKE_NO_COMPUTE         | 12     | **new ID** (was unprefixed) |
| D87 | NVLINK_STATE_CHANGE            | 13     | **new ID** (was unprefixed) |
| D88 | NVLINK_BANDWIDTH_SPIKE        | 13     | **new ID** (was unprefixed) |
| D89 | MEMORY_COVERT_CHANNEL          | 14     | **new ID** (was unprefixed) |
| D90 | GPU_DRIVER_UNLOADED            | 15     | **new ID** (was unprefixed) |
| D91 | GPU_KERNEL_ERROR               | 15     | **new ID** (was unprefixed) |
| D92 | CACHE_MISS_SPIKE               | 16     | **new ID** (was unprefixed) |

Reserved blocks for future modules: D16–D25, D27–D31, D33–D36, D39–D44,
D46–D47, D49, D52–D58, D60–D63, D65–D69, D76–D79, D93–D99.


---

## Scope: modules 1-16 only

This registry and its companion `README_MODULES.md` cover modules 1-16.
That is the ID-governed core.

Modules 17 and above are NOT registered here. A full scan of modules
17-104 (August 2026) confirmed two things:

1. **No detector-ID usage.** None of modules 17-104 emit a registered
   `D#` detector ID. They operate outside this registry's scheme. Do not
   read this file as an inventory of the whole repository -- it governs
   the first 16 modules only.

2. **Detection-only, no destructive actions.** The same scan checked
   every module 17-104 for genuinely destructive calls (process kills,
   file deletion, power-limit changes via nvidia-smi -pl, driver
   unloads, reboots). Zero were found. Every apparent match was a word
   inside a comment, docstring, or string literal (e.g. "no reboot" in a
   comment, "reboots and package updates" in a description string,
   "ED25519" matching a D-number regex by accident). All genuinely gated
   destructive actions live in `remediation/`, not in `todo/`.

If modules 17+ are ever brought under ID governance, assign IDs from the
reserved blocks above, extend README_MODULES.md to match, and update
this scope note. Until then, the honest statement is: 1-16 are
registered and detection-only; 17-104 are unregistered and
detection-only.
