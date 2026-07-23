#!/usr/bin/env bash
# Author: Manmohan (Mike) Bains -- Watchdog AIDR
set -euo pipefail

echo "[WATCHDOG BUILD] Running local test suite..."

bash -n ci/verify_kubeconfig.sh
echo "[PASS] verify_kubeconfig.sh syntax valid."

python3 -m py_compile detection/watchdog_shm_protector.py
echo "[PASS] watchdog_shm_protector.py compiled clean."

python3 -m py_compile detection/watchdog_shm_cleaner.py
echo "[PASS] watchdog_shm_cleaner.py compiled clean."

python3 -m py_compile detection/watchdog_sysv_protector.py
echo "[PASS] watchdog_sysv_protector.py compiled clean."

python3 -m py_compile detection/verify_ebpf_quarantine_core.py
echo "[PASS] verify_ebpf_quarantine_core.py compiled clean."

if command -v yamllint &> /dev/null; then
    yamllint kubernetes/watchdog-cleanup-cronjob.yaml
    echo "[PASS] CronJob YAML valid."
else
    echo "[WARN] yamllint not installed — skipping YAML lint."
fi

echo "[SUCCESS] All checks passed."
