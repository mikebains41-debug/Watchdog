# Fix pass — modules 1–16

## Real bugs fixed
- **Module 3** (`get_lspci`): operator-precedence bug meant the NVIDIA-device
  check never actually gated the LnkSta parse; also assumed device name was
  always exactly one line above LnkSta. Rewritten to track PCI device blocks
  explicitly.
- **Module 4** (`check_pulls`): hardcoded a containerd audit-log path that
  doesn't exist by default, so the check always silently returned empty. Now
  checks multiple candidate paths and logs a WARNING when none are found.
- **Module 9** (outbound check): `subprocess.check_output([...,"|","grep",...], shell=True)`
  does not execute a pipeline when passed as a list — the grep never ran, so
  D80 (model exfiltration) could never fire on the outbound-traffic condition.
  Rewritten without shell=True: fetch connections, filter in Python.
- **Module 11**: `ecc > prev_ecc * 2` could raise TypeError if `prev_ecc` was
  still `None` on an early iteration. Added a None-guard.
- **Module 12** (`check_core_isolation`): defined but never called — isolation
  state wasn't actually being checked despite the module's docstring. Now
  called at startup and logged as context, with the remaining coverage gap
  (per-process violation detection) documented rather than silently implied.
- **Module 16** (`run_perf_stat`): two bugs —
  1. keyed results by `parts[1]` (the unit) instead of the event name under
     `perf stat -x,` output, so baseline/live comparisons likely never matched.
  2. looped `perf stat ... sleep 1` (a 1s window) AND an outer `time.sleep(1.0)`,
     so the intended ~300s run actually took ~600s.
  Rewritten to call perf once per event (unambiguous keys) and removed the
  redundant outer sleep.

## Detector ID collisions resolved
`D7`, `D8`, and `D12` were each reused by 2–3 unrelated detectors across
modules 1/3/7 and 2/4. Modules 9–16 used bare names with no `D#` prefix at
all. Full renumbering is in `DETECTOR_REGISTRY.md`; every module's inline
comments now reference the current ID.

## Standardized
- Run duration: all timed-loop modules now use `DURATION_S = 120` (previously
  ranged from 120s to an effective ~600s in Module 16 and ~600s in Module 11).
- Bare `except:` clauses changed to `except Exception:` throughout (catching
  `SystemExit`/`KeyboardInterrupt` by bare `except:` was accidental and risky
  in a long-running loop).
- Where a module's core dependency is missing (`nvidia-smi`, cgroup v1 paths,
  `perf`, a log source), it now emits a `WARNING` event instead of silently
  returning empty results forever — Module 16 already did this; the pattern
  is now applied to Modules 1, 2, 4, 6, and 15.

## Not changed (flagged, not fixed — confirm before merging)
- **Module 5b** (`probe_vram`): docstring says "allocates VRAM to scan for
  residual data patterns," but the implementation only reads
  `memory.used` before/after a 0.5s sleep — no actual allocation or
  read-back occurs. This isn't a code bug (it runs fine), but it doesn't do
  what the docstring claims. Left as-is since you didn't report it broken;
  flagging because it currently can't detect real VRAM residue.
- **Module 12** (`get_cpu_mem_bandwidth`): parses `vmstat -s` for a line
  containing "K" and "memory" as a bandwidth proxy — this is not actual
  memory bandwidth and may not exist in that form on all `vmstat` builds.
  Same story: not broken, but weak signal. Worth replacing with a real
  bandwidth source (e.g. `/proc/vmstat` pgpgin/pgpgout deltas, or PCM) later.

## Repo hygiene (separate from module logic, seen while reviewing)
- `watchdog_data/api_keys.json` and `auth_log.json` are tracked in-repo —
  confirm they're `.gitignore`d or this needs a history scrub, not just a
  future ignore rule.
- Numerous `.bak`–`.bak15` files at repo root — safe to delete once you've
  confirmed nothing still references them.
