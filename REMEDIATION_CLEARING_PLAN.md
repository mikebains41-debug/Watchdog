# Remediation Clearing Plan - Tenant /tmp and VRAM Residual

Two separate findings, two separate remediation paths. Do not merge them -
they are different mechanisms with different fixability. See EVIDENCE.md
for why these must stay separated in any doc or deck.

---

## PART 1 - Tenant /tmp residual: BUILDABLE NOW, no code exists yet

### What this is
Leftover files from a previous tenant in shared /tmp overlay storage.
Source: CRITICAL_FINDINGS.md, tmp_residual_standalone_report/.
Vast.ai 41986069, 2026-06-21: 5/5 scans dirty, files 16 days old.
RunPod comparison: 2/2 scans clean.

### Why it's fixable
uid_mapping_note.md: /proc/self/uid_map shows "0 0 4294967295" - UID 0 in
container maps directly to host UID 0, no userns-remap. Current-session
root likely has write/delete permission on these files. Real files, real
filesystem, no accounting-vs-reality gap - unlike VRAM below.

### Remediation action to build (new - remediation/response.py has no
tenant-file action today; only log, kill_process, MIG quarantine, and
gpu_memory_reset exist)
1. On session start, scan /tmp and /dev/shm recursively
2. Compare mtime against session start time
3. Flag anything predating session start AND not created by current process
   tree as foreign/stale
4. Write ledger entry BEFORE deleting: path, mtime, size, permissions, owner
   uid if available, detection timestamp
5. Delete (rm -rf) only confirmed-stale foreign items
6. Write second ledger entry confirming deletion (or failure plus reason)

### Test plan
- Build scan and age-check logic
- Fresh Vast.ai rental, tenant A: create test files in /tmp, note
  timestamps, end session without cleanup
- New session same instance, tenant B: run scan, confirm tenant A's
  files correctly flagged as foreign/stale
- Confirm current-session (tenant B) files are NOT flagged
- Run deletion, confirm files actually gone
- Confirm ledger has both entries (detection then deletion) in order

### Pass / fail
PASS = foreign pre-existing files identified, deleted, logged BEFORE
deletion; current-session files untouched.
FAIL = current-session files deleted, deletion before logging, or foreign
files missed.

---

## PART 2 - VRAM residual: action already exists in code, never tested live

### What this is
Real NVML memory-accounting anomaly, confirmed non-recoverable: 527MB
(H200), approximately 1520MB (B200). Every recovery attempt (graceful exit
and SIGKILL, repeated) returned matches=0 nonzero=0 - zero bytes ever
recoverable. Source: EVIDENCE.md, h200_vram_reproduction_log.txt,
B200_VRAM_RESIDUAL_REPORT.md.

### The real code state (correcting earlier drafts of this plan)
remediation/response.py already maps VRAM_RESIDUAL alerts to a real action:
gpu_memory_reset, gated behind human approval by default. The code itself
states no automated path to reclaim orphaned VRAM exists - meaning the
action is wired but its actual effectiveness has never been tested against
a real orphaned-VRAM condition on rented hardware.

An earlier, different bug in this same file was already found and fixed:
a prior clear VRAM action called torch.cuda.empty_cache() in Watchdog's own
process, which cannot affect memory held by a different, already-exited
process, and falsely returned success regardless. That bug is fixed;
gpu_memory_reset is the current, correct-in-principle replacement. What's
missing is a live test proving it actually clears the accounting figure.

### Why SIGKILL leak cleanup (old deck language) is still wrong
EVIDENCE.md already corrected this once: SIGKILL reclaims it, a clean exit
does not - WRONG, no data survives either path. B200 testing confirmed the
approximately 1520MB figure is IDENTICAL regardless of exit path. SIGKILL
is not a remediation for this and must not appear as one in any deck or doc.

### Test plan for gpu_memory_reset (the actual next step)
- On next rented session, after confirming VRAM residual via existing
  detection method, trigger the gpu_memory_reset action (human-approved)
- Record exact result: success, permission denied, or device in use
- If permission denied: log exact error string - useful for a provider
  support ticket requesting reset access
- If it runs: immediately re-check VRAM residual - does the accounting
  figure actually drop to 0
- If it clears the figure: promote from gated-untested to gated-confirmed
  working - update EVIDENCE.md and HARDWARE_LIMITATIONS.md
- If blocked or ineffective: document in HARDWARE_LIMITATIONS.md as a
  confirmed platform limitation; honest deck language becomes detects,
  cannot currently clear

### Pass / fail
PASS = gpu_memory_reset runs successfully AND VRAM figure drops to 0,
logged and reproducible.
FAIL = permission denied, device-in-use error, or figure unchanged. A FAIL
is a real, useful, loggable result.

---

## Deck/doc implications - do not update until tested and logged

- Tenant /tmp: no code exists yet. Safe language: remediation action
  planned, technically supported by confirmed container root access. Not
  clears it until Part 1 is built and its test plan passes.
- VRAM: gpu_memory_reset action exists and is gated behind human approval,
  but has never been confirmed to actually work. Safe language: detected,
  root cause identified, gated remediation action exists, effectiveness
  unconfirmed. Remove SIGKILL leak cleanup from slide 9 regardless of
  outcome - that specific claim is already disproven.
