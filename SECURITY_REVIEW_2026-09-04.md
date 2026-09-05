# Watchdog — Security Code Review

**Date:** 2026-09-04
**Scope:** `mikebains41-debug/Watchdog` at commit `fe3fced`, 1,117 files
**Method:** static review of source. Not a penetration test. Not a certified audit.
**Reviewer note:** findings are ranked by severity. Fix Critical before any deployment.

---

## CRITICAL

### C1. `todo/module24.py` sends a chassis power-off command with no safety gate

`ipmi_lock_psu()` runs `ipmitool raw 0x00 0x02 0x00`. The docstring states it: *"0x00 0x02 = chassis control, 0x00 = power down."* This is IPMI Chassis Control → Power Down. **It turns off the host.** The function name and comment ("hard lock") misdescribe what it does.

It is wired into `main()` at line 156 as "Attempt 2" after a sysfs disable fails, triggered by >3 ACPI power events in a window. No `WD_DRY_RUN`, no `WD_AUTO_REMEDIATION`, no human approval. The bare `except:` on line 91 swallows any error, so a failed attempt is silent and a successful one gives no warning.

On a multi-tenant host this would terminate every tenant's workload.

**Fix:** delete `ipmi_lock_psu()` entirely. There is no scenario in which a monitoring agent should power off a chassis. If PSU isolation is genuinely needed, it belongs in a human-run runbook, not in a detection loop.

---

## HIGH

### H1. Seven modules perform privileged destructive actions with zero gating

| Module | Actions | Gates |
|---|---|---|
| 17 | `nvidia-smi --gpu-reset` | 0 |
| 19 | `os.kill(SIGKILL)` ×2, `--gpu-reset`, driver reload | 0 |
| 20 | `os.kill(SIGKILL)` ×3 | 0 |
| 22 | `setpci` PCIe retrain ×5 | 0 |
| 24 | IPMI chassis power-down (see C1) | 0 |
| 26 | NVMe driver unbind | 0 |
| 30 | `--gpu-reset` on ">5 changes in 30s" | 0 |

`module21.py` has the correct pattern — 18 gate checks: `WD_DRY_RUN` default true, `WD_AUTO_REMEDIATION` must be explicitly enabled, `WD_HUMAN_APPROVAL` for destructive paths. None of the seven above have it.

**Mitigating:** `todo/run_all.sh` does not invoke any of these. They are dormant. But each is one `python3 todo/moduleNN.py` from firing, and nothing in the file warns the operator.

**Fix:** port module21's gating into each. Until then, add a hard `sys.exit("UNGATED — do not run")` at the top of each file.

### H2. `module19.py` `kill_pid()` targets any PID with no ownership check

Line 79: `os.kill(int(pid), signal.SIGKILL)` on PIDs classified as "unknown/miner." Classification is heuristic. A false positive kills a tenant process. Watchdog's own `remediation/response.py` was rewritten to refuse exactly this pattern — it requires a named PID from the alert and will not guess. Module19 reintroduces the bug that was fixed there.

**Fix:** same as H1. Also: require the PID to be owned by the same UID as Watchdog, or explicitly listed in an approved-kill file.

---

## MEDIUM

### M1. `t31_vram_content/t31_100hz.py` reads residual VRAM contents into host memory

Line 41: `raw = probe.cpu().numpy().tobytes()` — the full 256 MB of an uninitialised GPU allocation is copied to host RAM. The script then computes entropy, non-zero count, and marker hits, and prints only those statistics. It never writes the raw bytes to disk.

That is better than storing them. But under HIPAA and similar regimes, reading tenant residual data into process memory is *processing* it, regardless of what is persisted. If a healthcare customer's imaging model ran on that GPU, this script has handled PHI.

**Fix:** compute statistics on-device. `torch.count_nonzero(probe)` and an on-GPU entropy estimate never leave the card. Report *how much* residual exists without ever reading *what* it is. Same detection value, no PHI handling.

### M2. 461 bare `except:` clauses

Across the non-test, non-backup source. Each one silently swallows every exception including `KeyboardInterrupt` and `SystemExit`. In remediation code this means a failed privileged action reports success (module24 line 91, module19 line 82). In detection code it means a broken detector reports "clean."

**Fix:** `except Exception as e:` with logging, at minimum. For the privileged modules, failure must be loud.

### M3. `module139_tls_pin.py` line 40: `shell=True` with interpolated endpoint

`f"echo | openssl s_client -connect {endpoint} ..."` with `shell=True`. If `endpoint` ever comes from config or user input, this is command injection. The line directly above does the same call *without* `shell=True` — the second call exists only to pipe into `openssl x509`.

**Fix:** pass the first call's stdout to a second `subprocess.run(["openssl","x509",...], input=...)`. No shell needed. `module9_model_exfil_compiler.py` already documents this exact refactor.

---

## LOW

### L1. Function names misdescribe destructive actions
`ipmi_lock_psu` powers off the chassis. `reset_gpu` in module19 also reloads the driver. Names should say what the code does.

### L2. Fifteen `watchdog.py.bak*` files on disk
Correctly gitignored, but 15 backups of a 21 KB file is version control done by hand. Delete them; git has the history.

### L3. `module24.py` runs as B200-specific (`"gpu": "B200"` hardcoded line 112)
Architecture is hardcoded in several todo modules. Detectors learn the floor elsewhere; these should too.

---

## CLEAN — verified

- **No secrets in repo.** `.gitignore` excludes `watchdog_data/`, `*.bak*`, `resp*.json`, all `.jsonl`. `api_keys.json` and `auth_log.json` are not tracked.
- **Scanner outputs** (module102/117) were tracked but properly redacted; now untracked, gitignore pattern fixed.
- **Quantum provider credentials** — all four providers read from `os.getenv()`. No hardcoded tokens.
- **Pre-commit hook** lints Python and shell on every commit.
- **`remediation/response.py`** and **`orchestration/cluster_actions.py`** — properly gated (reviewed in prior session, unchanged).
- **`module9`** explicitly avoids `shell=True` and documents why.
- **`detection/dangerous_pattern_scanner.py`** exists and would catch M3 if run against the repo.

---

## Open item outside the code

The credential scanner's own note (module102, 9 Aug): *"this exact session had real OpenQuantum credentials pasted in plaintext multiple times across chat and terminal history."* The `OPENQUANTUM_CLIENT_SECRET` should be rotated if it has not been.

---

## Priority order

1. Delete `ipmi_lock_psu()` from module24 — today
2. Add `sys.exit("UNGATED")` guard to modules 17, 19, 20, 22, 24, 26, 30 — today
3. Rotate OpenQuantum secret
4. Port module21 gating into the seven modules
5. Rewrite t31 to compute on-device
6. Fix module139 shell=True
7. Replace bare excepts in remediation paths

*Static review only. Runtime behaviour, network exposure of the API server, and Kubernetes RBAC were not assessed.*
