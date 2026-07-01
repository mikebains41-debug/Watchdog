#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

verify_target_context() {
    local kubeconfig_path="${1}"
    local cluster_id="${2}"
    echo "[WATCHDOG KUBECONFIG] Inspecting: ${cluster_id}"
    if [[ ! -f "${kubeconfig_path}" ]]; then
        echo "[CRITICAL] Missing: ${kubeconfig_path}" >&2
        return 1
    fi
    local server
    server=$(grep -m 1 "server:" "${kubeconfig_path}" | awk '{print $2}' || true)
    if [[ -z "${server}" ]]; then
        echo "[FAIL] No api-server found in ${kubeconfig_path}" >&2
        return 1
    fi
    echo "[PASS] api-server: ${server}"
    local cert_data
    cert_data=$(grep -m 1 "client-certificate-data:" "${kubeconfig_path}" | awk '{print $2}' || true)
    if [[ -n "${cert_data}" ]]; then
        local expiry
        expiry=$(echo "${cert_data}" | base64 -d 2>/dev/null | openssl x509 -noout -enddate 2>/dev/null | cut -d= -f2 || true)
        if [[ -n "${expiry}" ]]; then
            local expiry_epoch current_epoch
            expiry_epoch=$(date -d "${expiry}" +%s 2>/dev/null || true)
            current_epoch=$(date +%s)
            if [[ -n "${expiry_epoch}" && $((expiry_epoch - current_epoch)) -lt 86400 ]]; then
                echo "[CRITICAL] Certificate expires in < 24h — halting." >&2
                return 1
            fi
            echo "[PASS] Certificate valid."
        fi
    else
        echo "[WARN] No client cert data — assuming token auth."
    fi
    return 0
}

verify_target_context "/root/.kube/config-east" "US-EAST-PROD"
verify_target_context "/root/.kube/config-west" "EU-WEST-SOVEREIGN"
echo "[PASS] All kubeconfig checks passed."
