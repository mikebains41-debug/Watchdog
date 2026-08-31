#!/usr/bin/env python3
"""
gpu_memory_integrity_detector.py -- LeftoverLocals residual, weight
bit-flip canary, and GPUThor/ECC-break detection.
Part of Watchdog AI-Attack Detection Suite.

Three related GPU-memory-integrity detectors, grouped because they all
concern the integrity/confidentiality of data resident in GPU memory.

A4. LeftoverLocals residual read (CVE-2023-4969)
    GPU local/shared memory is not zeroed between kernel invocations, so
    one process can read another's leftover data. This is the named,
    CVE-assigned, cross-process-read version of the same VRAM-residual
    "accounting gap" Watchdog already measures. Detection side: residual
    bytes present after a kernel/process exit on affected vendor+driver
    combos. (The actual cross-tenant READ proof-of-concept remains the
    hardware-gated open item already on the backlog -- this anchors it to
    a CVE.)
    Citation: CVE-2023-4969 (LeftoverLocals, Trail of Bits).

A5. Weight bit-flip / tamper canary
    A single Rowhammer-class bit flip in model weights can drop accuracy
    ~80% -> ~0.1%, silently. Detection: seal a reference fingerprint of a
    known subset of resident weights (or a fixed reference-input ->
    output), then periodically re-check. Drift = possible bit-flip or
    tamper. Extends the at-rest SHA-256 manifest to RESIDENT weights.
    Citations: GPUHammer USENIX Sec 2025; DeepHammer USENIX Sec 2020;
    ProFlip/TrojViT (bit-flip backdoors).

B1. GPUThor / ECC-break signature (Sept 2026)
    GPUThor is the first Rowhammer attack on NVIDIA GPUs to break through
    ECC -- the exact mitigation NVIDIA recommended after GPUHammer.
    Predecessors: GPUHammer (2025, GDDR6 flips), GPUBreach (2026, root
    escalation). Multi-bit flips in one ECC word cause silent
    mis-correction (ECCploit class). A pre-ECC-break detector that only
    watched "ECC corrected fine" would MISS this. This detector watches
    for the ECC-break signature: rising DOUBLE-BIT (uncorrectable) error
    counts, and a rising rate of CORRECTED errors (hammering leaves a
    trail even when ECC holds).
    Citations: GPUThor (U Toronto, Sept 2026); GPUHammer USENIX Sec 2025;
    GPUBreach 2026; NVIDIA Security Notice Rowhammer (Jul 2025);
    ECCploit (multi-bit ECC bypass).

All three take caller-supplied telemetry/samples and are pure logic --
no GPU, no nvidia-smi call inside the module, fully fixture-testable. The
caller wires real nvidia-smi / dmesg readings in.

REMEDIATION
-----------
- A4 residual: auto-safe = trigger the existing tenant_file_cleaner /
  gpu_memory_reset gated action (already in remediation/response.py).
- A5 canary drift: GATED -- weight drift could be legitimate reload;
  block inference + human review + reload from sealed-hash source.
- B1 ECC-break: GATED/urgent -- recommend workload evacuation off the
  affected GPU + escalate; do not auto-reset (may be an active attack,
  preserve state for forensics). Never auto-destructive.
"""

import hashlib
import statistics


# ---------------------------------------------------------------------------
# A4 -- LeftoverLocals residual detector
# ---------------------------------------------------------------------------
# Vendor+driver combos where local/shared mem is known not to be zeroed.
# Conservative default: flag residual on any combo unless explicitly known-clean.
KNOWN_CLEAN_COMBOS = set()  # populate as combos are confirmed clean


def detect_leftover_locals(residual_bytes: int,
                            after_process_exit: bool,
                            vendor: str = "",
                            driver: str = "",
                            threshold_bytes: int = 1) -> dict:
    """
    residual_bytes: bytes still resident/readable after the prior kernel or
                    process has exited (caller measures this).
    after_process_exit: True if measured after the owning process fully exited.
    """
    combo = f"{vendor}:{driver}".strip(":")
    if not after_process_exit:
        return {"status": "SKIPPED",
                "message": "residual only meaningful after owning process exit"}

    if residual_bytes >= threshold_bytes and combo not in KNOWN_CLEAN_COMBOS:
        return {
            "status": "LEFTOVER_LOCALS_RESIDUAL",
            "residual_bytes": residual_bytes,
            "combo": combo or "unknown",
            "cve": "CVE-2023-4969",
            "recommended_action": {
                "action": "invoke_gpu_memory_reset_or_tenant_cleaner",
                "detail": "residual GPU memory readable post-exit; trigger existing gated memory reset",
                "risk": "gated_human_approved",
            },
            "note": ("detection of residual precondition; cross-tenant READ "
                     "proof remains the hardware-gated backlog item"),
        }
    return {"status": "NO_RESIDUAL", "residual_bytes": residual_bytes, "combo": combo}


# ---------------------------------------------------------------------------
# A5 -- weight bit-flip / tamper canary
# ---------------------------------------------------------------------------
def seal_weight_canary(weight_bytes: bytes) -> str:
    """Seal a reference fingerprint of a resident-weight subset."""
    return hashlib.sha256(weight_bytes).hexdigest()


def seal_output_canary(reference_output) -> str:
    """Seal a reference model output for a fixed reference input."""
    return hashlib.sha256(repr(reference_output).encode()).hexdigest()


def check_weight_canary(current_weight_bytes: bytes,
                        sealed_hash: str,
                        auto_remediate: bool = False) -> dict:
    """Re-check a resident-weight subset against its sealed fingerprint."""
    current = seal_weight_canary(current_weight_bytes)
    if current == sealed_hash:
        return {"status": "WEIGHT_CANARY_OK", "hash": current}
    result = {
        "status": "WEIGHT_DRIFT_DETECTED",
        "sealed_hash": sealed_hash,
        "current_hash": current,
        "recommended_action": {
            "action": "block_inference_reload_from_sealed_source",
            "detail": "resident weights differ from sealed fingerprint (possible bit-flip/tamper)",
            "risk": "gated_no_autokill",
        },
        "note": "gated: could be legitimate reload; verify before trusting",
    }
    # Never auto-destructive even with auto_remediate; the safe action is
    # reload-from-trusted, which is a human/orchestrator decision.
    if auto_remediate:
        result["note"] = "auto_remediate ignored: weight reload requires human/orchestrator confirmation"
    return result


def check_output_canary(current_output, sealed_hash: str) -> dict:
    """Re-run a fixed reference input and compare output to sealed value."""
    current = seal_output_canary(current_output)
    if current == sealed_hash:
        return {"status": "OUTPUT_CANARY_OK"}
    return {
        "status": "OUTPUT_DRIFT_DETECTED",
        "note": ("model output for fixed reference input changed; possible "
                 "weight corruption/tamper -- investigate before trusting outputs"),
    }


# ---------------------------------------------------------------------------
# B1 -- GPUThor / ECC-break signature detector
# ---------------------------------------------------------------------------
def detect_ecc_break(corrected_series: list,
                     uncorrectable_series: list,
                     corrected_rate_threshold: float = 5.0,
                     uncorrectable_threshold: int = 1,
                     require_consecutive: int = 2) -> dict:
    """
    corrected_series:     time-ordered CORRECTED (single-bit) ECC error counts.
    uncorrectable_series: time-ordered UNCORRECTABLE (double-bit+) ECC counts.

    GPUThor's signature: hammering produces a RISING corrected-error rate
    (a trail even while ECC still holds), and eventually UNCORRECTABLE /
    mis-corrected events as multi-bit flips defeat ECC. A pre-ECC-break
    detector that only alerted on 'ECC failed to correct' would miss the
    early hammering phase; this watches both.

    Edge-triggered with a consecutive-sample debounce, matching the repo's
    existing detector discipline.
    """
    if len(corrected_series) < 2 and len(uncorrectable_series) < 1:
        return {"status": "SKIPPED", "message": "insufficient ECC telemetry"}

    findings = []

    # Uncorrectable (double-bit) errors are the hard signal: ECC detected
    # but could not correct -> multi-bit flip, the GPUThor endgame.
    recent_uncorrectable = sum(uncorrectable_series[-require_consecutive:]) \
        if uncorrectable_series else 0
    if uncorrectable_series and max(uncorrectable_series) >= uncorrectable_threshold:
        findings.append("UNCORRECTABLE_ECC_ERRORS")

    # Rising corrected-error RATE: sustained increase = active hammering
    # even while ECC still masks the flips.
    if len(corrected_series) >= 2:
        # deltas between consecutive samples
        deltas = [corrected_series[i] - corrected_series[i - 1]
                  for i in range(1, len(corrected_series))]
        recent = deltas[-require_consecutive:]
        if len(recent) >= require_consecutive and all(d >= corrected_rate_threshold for d in recent):
            findings.append("RISING_CORRECTED_ERROR_RATE")

    if findings:
        severity = "CRITICAL" if "UNCORRECTABLE_ECC_ERRORS" in findings else "WARNING"
        return {
            "status": "ECC_BREAK_SUSPECTED",
            "severity": severity,
            "signals": findings,
            "attacks": ["GPUThor", "GPUHammer", "GPUBreach"],
            "recommended_action": {
                "action": "evacuate_workload_and_escalate",
                "detail": ("ECC-break / active-hammering signature; evacuate "
                           "workload off this GPU and escalate. Do NOT auto-reset "
                           "-- preserve state for forensics."),
                "risk": "gated_urgent_no_autoreset",
            },
            "note": ("ECC-event signature, not proof of adversarial intent; "
                     "correlate with access-pattern anomaly. ECC alone no longer "
                     "a complete mitigation post-GPUThor."),
        }
    return {"status": "ECC_NOMINAL"}


if __name__ == "__main__":
    print("[GPU-MEM-INTEGRITY] self-check")
    print(" A4:", detect_leftover_locals(528_000_000, True, "NVIDIA", "550.x")["status"])
    h = seal_weight_canary(b"reference-weights")
    print(" A5:", check_weight_canary(b"tampered-weights", h)["status"])
    print(" B1:", detect_ecc_break([0, 10, 22, 40], [0, 0, 2])["status"])
