"""
Watchdog Physics Model 21 (module91 companion): 1/f Flux Noise Model

WHAT THIS MODELS: the second dominant, heavily published source of
dephasing (T2 loss) in superconducting qubits, alongside TLS defects
(module90) — low-frequency magnetic flux noise with a characteristic
1/f power spectral density, believed to arise from fluctuating electron
spins on the surfaces of superconducting circuits.

CITATION: Yan, F. et al. "Rotating-frame relaxation as a noise spectrum
analyser of a superconducting qubit undergoing driven evolution."
Nature Communications 4, 2337 (2013). DOI: 10.1038/ncomms3337
Also: Koch, R.H., DiVincenzo, D.P. & Clarke, J. "Model for 1/f flux
noise in SQUIDs and qubits." Physical Review Letters 98, 267003 (2007).

This is the standard reference pair for the empirical A/f noise
spectrum observed across essentially every superconducting flux-tunable
qubit platform measured in the literature. The noise amplitude A is
material- and geometry-dependent but falls in a well-characterized
range across published devices.

WHAT THIS MODEL COMPUTES:
  Given a qubit's flux sensitivity (df/dPhi, how much its frequency
  shifts per unit flux) and a literature-typical 1/f noise amplitude,
  estimates the flux-noise-limited T2* (Ramsey dephasing time) using
  the standard quasi-static noise approximation:

  T2*_flux = sqrt(2) / (df/dPhi * A_flux * sqrt(2 * ln(1/(omega_ir * t))))

  This is a REFERENCE/LITERATURE-CALIBRATED model, using published noise
  amplitude ranges (typically 1-10 uPhi0/sqrt(Hz) at 1 Hz across
  published flux qubit and tunable transmon literature), not a live
  measurement from any specific chip.

WHY THIS MATTERS FOR SECURITY: T2 drift that tracks flux-noise physics
(1/f spectral shape, correlates with flux-bias line activity) is
expected and benign. T2 drift that does NOT match this signature —
sudden steps, correlation with unrelated system events, or a spectral
shape inconsistent with 1/f — is the kind of anomaly modules 35 and 53
are built to flag. This model gives them the expected baseline shape to
compare against.
"""
import math

# Published reference values from 1/f flux noise literature
FLUX_NOISE_REFERENCE = {
    "typical_amplitude_uPhi0_sqrtHz_at_1Hz": 3.0,  # A, literature range ~1-10
    "typical_exponent": 1.0,  # the "1/f" exponent, literature range 0.7-1.2
    "citation_1": "Yan et al., Nature Communications 4, 2337 (2013)",
    "citation_2": "Koch, DiVincenzo & Clarke, Phys. Rev. Lett. 98, 267003 (2007)",
}

PHI0 = 2.067833848e-15  # magnetic flux quantum, Wb

def flux_noise_psd(frequency_hz: float,
                    amplitude_uPhi0_sqrtHz: float = FLUX_NOISE_REFERENCE["typical_amplitude_uPhi0_sqrtHz_at_1Hz"],
                    exponent: float = FLUX_NOISE_REFERENCE["typical_exponent"]) -> dict:
    """
    Returns the flux noise power spectral density at a given frequency,
    following the standard A/f^alpha empirical form calibrated at 1 Hz.
    """
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
    """
    Estimates T2* (Ramsey dephasing time) limited by 1/f flux noise,
    using the standard quasi-static Gaussian dephasing approximation
    (Ithier et al., PRB 72, 134519 (2005) — the standard formula for
    this regime).

    flux_sensitivity_GHz_per_Phi0 is a REAL DEVICE PARAMETER (df/dPhi
    at the operating point) — this must come from the actual qubit's
    tunability curve, not assumed by this model. At the flux-insensitive
    "sweet spot," this value is zero and 1/f flux noise contributes
    negligibly (to first order) — this model reflects that correctly:
    zero sensitivity gives infinite T2*.
    """
    if flux_sensitivity_GHz_per_Phi0 == 0:
        return {
            "t2_star_us": float("inf"),
            "note": ("Qubit operating at flux-insensitive sweet spot "
                     "(df/dPhi = 0). First-order 1/f flux noise dephasing "
                     "vanishes here — this is the standard reason "
                     "flux-tunable qubits are operated at sweet spots"),
        }

    d = flux_sensitivity_GHz_per_Phi0 * 1e9  # Hz per Phi0
    amplitude_phi0 = amplitude_uPhi0_sqrtHz * 1e-6

    # Standard quasi-static 1/f dephasing formula (Ithier et al. 2005):
    # T2* ~ 1 / (2*pi*d*A * sqrt(2*ln(1/(omega_ir * t))))
    log_term = math.log(1.0 / (2 * math.pi * ir_cutoff_hz * measurement_time_s))
    if log_term <= 0:
        log_term = 1.0  # guard against pathological inputs

    rate = 2 * math.pi * d * amplitude_phi0 * math.sqrt(2 * log_term)
    if rate <= 0:
        return {"error": "computed non-positive dephasing rate — check inputs"}

    t2_star_s = 1.0 / rate

    return {
        "flux_sensitivity_GHz_per_Phi0": flux_sensitivity_GHz_per_Phi0,
        "amplitude_used_uPhi0_sqrtHz": amplitude_uPhi0_sqrtHz,
        "predicted_t2_star_us": round(t2_star_s * 1e6, 2),
        "citation": FLUX_NOISE_REFERENCE["citation_2"],
        "calibration_status": ("LITERATURE-CALIBRATED — uses published 1/f "
                                 "amplitude reference, not a live device "
                                 "measurement"),
    }

def classify_t2_anomaly(measured_t2_series: list, expected_shape: str = "1/f") -> dict:
    """
    A lightweight structural check: does a time series of measured T2*
    values show the gradual, slowly-drifting character expected of 1/f
    flux noise, or does it show step changes / uncorrelated jumps that
    are NOT consistent with this physics?

    This does not do full spectral estimation (that requires many more
    samples than a typical monitoring window provides) — it checks the
    simpler, real signature: 1/f noise produces slow drift, not sudden
    discontinuities.
    """
    if len(measured_t2_series) < 5:
        return {"error": "need at least 5 samples to assess drift character"}

    diffs = [abs(measured_t2_series[i+1] - measured_t2_series[i])
             for i in range(len(measured_t2_series) - 1)]
    mean_diff = sum(diffs) / len(diffs)
    max_diff = max(diffs)

    # A single jump much larger than the typical step is inconsistent
    # with smooth 1/f drift
    is_step_change = max_diff > 5 * mean_diff if mean_diff > 0 else False

    return {
        "samples": len(measured_t2_series),
        "mean_step": round(mean_diff, 4),
        "max_step": round(max_diff, 4),
        "consistent_with_1f_drift": not is_step_change,
        "note": ("A step change far larger than the typical sample-to-sample "
                 "drift is inconsistent with smooth 1/f flux noise, and "
                 "warrants investigation as a discrete event rather than "
                 "ordinary noise" if is_step_change else
                 "Drift pattern consistent with expected 1/f flux noise character"),
    }
