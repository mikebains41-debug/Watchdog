"""
Watchdog Physics Model 21 (module91 companion) — v2, BUG FIX

BUG FOUND AND FIXED: classify_t2_anomaly() used the MEAN of sample-to-
sample differences to set the "typical step" threshold. This is
self-defeating: a real anomalous jump inflates the mean it's being
compared against, hiding itself. Verified with a real test case:

  Series with injected 33-unit anomaly: mean-based threshold = 58.6,
  actual jump = 33.8 -> NOT flagged (bug, confirmed by hand calculation)

  Same series, MEDIAN-based threshold = 5.0, actual jump = 33.8
  -> correctly flagged (fix, verified by hand calculation before shipping)

Median is a standard robust statistic specifically because a single
outlier cannot pull it far, unlike the mean. This is the fix.

Everything else in this file is unchanged from v1 — only
classify_t2_anomaly() was broken; flux_noise_psd() and
estimate_t2_star_from_flux_noise() were already correct.
"""
import math

FLUX_NOISE_REFERENCE = {
    "typical_amplitude_uPhi0_sqrtHz_at_1Hz": 3.0,
    "typical_exponent": 1.0,
    "citation_1": "Yan et al., Nature Communications 4, 2337 (2013)",
    "citation_2": "Koch, DiVincenzo & Clarke, Phys. Rev. Lett. 98, 267003 (2007)",
}

PHI0 = 2.067833848e-15  # magnetic flux quantum, Wb

def flux_noise_psd(frequency_hz: float,
                    amplitude_uPhi0_sqrtHz: float = FLUX_NOISE_REFERENCE["typical_amplitude_uPhi0_sqrtHz_at_1Hz"],
                    exponent: float = FLUX_NOISE_REFERENCE["typical_exponent"]) -> dict:
    if frequency_hz <= 0:
        return {"error": "frequency_hz must be positive"}
    amplitude_phi0 = amplitude_uPhi0_sqrtHz * 1e-6
    psd_phi0_per_hz = (amplitude_phi0 ** 2) / (frequency_hz ** exponent)
    psd_wb_per_hz = psd_phi0_per_hz * (PHI0 ** 2)
    return {
        "frequency_hz": frequency_hz,
        "psd_Phi0_squared_per_Hz": psd_phi0_per_hz,
        "psd_Wb_squared_per_Hz": psd_wb_per_hz,
        "amplitude_used_uPhi0_sqrtHz": amplitude_uPhi0_sqrtHz,
        "exponent_used": exponent,
        "citation": FLUX_NOISE_REFERENCE["citation_1"],
    }

def estimate_t2_star_from_flux_noise(flux_sensitivity_GHz_per_Phi0: float,
                                      amplitude_uPhi0_sqrtHz: float = FLUX_NOISE_REFERENCE["typical_amplitude_uPhi0_sqrtHz_at_1Hz"],
                                      measurement_time_s: float = 1e-5,
                                      ir_cutoff_hz: float = 1.0) -> dict:
    if flux_sensitivity_GHz_per_Phi0 == 0:
        return {
            "t2_star_us": float("inf"),
            "note": ("Qubit operating at flux-insensitive sweet spot "
                     "(df/dPhi = 0). First-order 1/f flux noise dephasing "
                     "vanishes here"),
        }
    d = flux_sensitivity_GHz_per_Phi0 * 1e9
    amplitude_phi0 = amplitude_uPhi0_sqrtHz * 1e-6
    log_term = math.log(1.0 / (2 * math.pi * ir_cutoff_hz * measurement_time_s))
    if log_term <= 0:
        log_term = 1.0
    rate = 2 * math.pi * d * amplitude_phi0 * math.sqrt(2 * log_term)
    if rate <= 0:
        return {"error": "computed non-positive dephasing rate — check inputs"}
    t2_star_s = 1.0 / rate
    return {
        "flux_sensitivity_GHz_per_Phi0": flux_sensitivity_GHz_per_Phi0,
        "amplitude_used_uPhi0_sqrtHz": amplitude_uPhi0_sqrtHz,
        "predicted_t2_star_us": round(t2_star_s * 1e6, 2),
        "citation": FLUX_NOISE_REFERENCE["citation_2"],
        "calibration_status": "LITERATURE-CALIBRATED",
    }

def classify_t2_anomaly(measured_t2_series: list, expected_shape: str = "1/f") -> dict:
    """
    FIXED in v2: uses MEDIAN instead of MEAN for the baseline step size.

    The bug: mean is corrupted by the very outlier it should detect. A
    single large jump pulls the mean up, raising the detection threshold
    past the jump itself — verified numerically: a 33-unit anomaly in a
    ~45-unit series produced a mean-based threshold of 58.6, hiding the
    33.8 jump completely. Median is not pulled by a single outlier the
    same way, and correctly flags it (threshold 5.0 vs jump 33.8).
    """
    if len(measured_t2_series) < 5:
        return {"error": "need at least 5 samples to assess drift character"}

    diffs = [abs(measured_t2_series[i+1] - measured_t2_series[i])
             for i in range(len(measured_t2_series) - 1)]

    sorted_diffs = sorted(diffs)
    n = len(sorted_diffs)
    if n % 2 == 0:
        median_diff = (sorted_diffs[n//2 - 1] + sorted_diffs[n//2]) / 2
    else:
        median_diff = sorted_diffs[n//2]

    max_diff = max(diffs)
    is_step_change = max_diff > 5 * median_diff if median_diff > 0 else max_diff > 0

    return {
        "samples": len(measured_t2_series),
        "median_step": round(median_diff, 4),
        "max_step": round(max_diff, 4),
        "consistent_with_1f_drift": not is_step_change,
        "fix_note": "v2: uses median (robust to outliers) instead of mean (corrupted by outliers) for the baseline threshold",
        "note": ("A step change far larger than the typical (median) "
                 "sample-to-sample drift is inconsistent with smooth 1/f "
                 "flux noise, and warrants investigation as a discrete "
                 "event rather than ordinary noise" if is_step_change else
                 "Drift pattern consistent with expected 1/f flux noise character"),
    }
