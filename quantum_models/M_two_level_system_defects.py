"""
Watchdog Physics Model 20 (module90 companion): Two-Level-System (TLS)
Defect Density Model

WHAT THIS MODELS: the single most-cited cause of decoherence in
superconducting qubits — parasitic two-level systems (TLS) living in
the amorphous oxide layers of Josephson junctions and on chip surfaces.

CITATION: Müller, C., Cole, J.H. & Lisenfeld, J. "Towards understanding
two-level-systems in amorphous solids: insights from quantum circuits."
Reports on Progress in Physics 82, 124501 (2019).
DOI: 10.1088/1361-6633/ab3a7e

This is the standard review reference for TLS physics in superconducting
qubits — TLS defects are atomic-scale tunneling systems in disordered
dielectrics that couple to the qubit's electric field and cause both
energy relaxation (T1 loss) and dephasing. TLS density and coupling
strength are measurable, material-dependent quantities reported
throughout the literature for real fabricated devices.

WHAT THIS MODEL COMPUTES:
  Given a qubit's operating frequency and the junction's oxide layer
  properties, estimates the expected T1-limiting TLS-induced decoherence
  rate using the standard TLS bath model: a distribution of two-level
  fluctuators with a characteristic density per unit volume per unit
  frequency, each coupling to the qubit via its electric dipole moment.

  Gamma_TLS = (density_of_states) * (coupling_strength^2) * (bath_function)

  This is a REFERENCE/LITERATURE-CALIBRATED model, exactly like the
  other 19 physics models in this suite — it uses published TLS density
  values from real material characterization studies (typically
  Al2O3-based junctions), not a live measurement from any specific
  device. Where real hardware calibration data (measured T1) is
  available, this model's prediction can be compared against it as a
  sanity check — large deviation suggests either non-TLS-dominated loss
  or fabrication quality far from the literature baseline.

WHY THIS MATTERS FOR SECURITY: TLS-induced decoherence is a legitimate
explanation for elevated error rates. Modules that flag anomalous T1/T2
drift (module35, module53) need a physics baseline to distinguish
"normal TLS-driven fluctuation" from "something else is happening" —
this model provides that baseline.
"""
import math

# Published reference values from TLS characterization literature
# (Müller et al. 2019, and references therein for amorphous Al2O3)
TLS_DENSITY_REFERENCE = {
    "material": "amorphous Al2O3 (standard Josephson junction oxide)",
    "density_per_GHz_per_um3": 0.3,   # P0, typical literature range 0.1-1 /GHz/um^3
    "typical_dipole_moment_debye": 4.0,  # d0, typical range 1-8 Debye
    "citation": "Müller, Cole & Lisenfeld, Rep. Prog. Phys. 82, 124501 (2019)",
}

HBAR = 1.0545718e-34   # J*s
KB = 1.380649e-23       # J/K
DEBYE_TO_CM = 3.33564e-30  # C*m per Debye

def tls_loss_tangent(temperature_k: float,
                      density_per_GHz_per_um3: float = TLS_DENSITY_REFERENCE["density_per_GHz_per_um3"],
                      dipole_moment_debye: float = TLS_DENSITY_REFERENCE["typical_dipole_moment_debye"]) -> dict:
    """
    Standard TLS loss tangent formula (saturated, low-power limit):
    tan(delta) proportional to P0 * d0^2 / (3 * epsilon)

    Returns the dimensionless loss tangent contribution from the TLS
    bath at the given temperature, using literature reference values
    unless real device parameters are supplied.
    """
    dipole_cm = dipole_moment_debye * DEBYE_TO_CM
    # Simplified proportionality — full derivation requires participation
    # ratio and dielectric constant, both device-geometry-specific and
    # not assumed here; this returns the material TERM only.
    p0_si = density_per_GHz_per_um3 * 1e9 / 1e-18  # convert to per-J per-m^3
    loss_tangent_material_term = (math.pi * p0_si * dipole_cm**2) / 3

    return {
        "temperature_k": temperature_k,
        "loss_tangent_material_term": loss_tangent_material_term,
        "density_used_per_GHz_per_um3": density_per_GHz_per_um3,
        "dipole_moment_debye": dipole_moment_debye,
        "note": ("Material-term contribution only. Full T1 prediction "
                 "requires the qubit's electric-field participation ratio "
                 "in the lossy dielectric, which is device-geometry "
                 "specific and must be supplied separately — this model "
                 "does not assume a geometry"),
        "citation": TLS_DENSITY_REFERENCE["citation"],
    }

def estimate_t1_from_tls(qubit_freq_ghz: float,
                          participation_ratio: float,
                          temperature_k: float = 0.02,
                          density_per_GHz_per_um3: float = TLS_DENSITY_REFERENCE["density_per_GHz_per_um3"],
                          dipole_moment_debye: float = TLS_DENSITY_REFERENCE["typical_dipole_moment_debye"]) -> dict:
    """
    Estimates T1 from TLS loss, given a real device's participation
    ratio (the fraction of the qubit's electric field energy stored in
    the lossy TLS-hosting dielectric — this is the one parameter that
    genuinely must come from real device geometry/simulation, and is
    NOT assumed or fabricated here).

    T1 = 1 / (omega * tan(delta) * participation_ratio)
    """
    if participation_ratio <= 0 or participation_ratio > 1:
        return {"error": "participation_ratio must be in (0, 1] — this is a real device geometry parameter, not estimated by this model"}

    loss = tls_loss_tangent(temperature_k, density_per_GHz_per_um3,
                            dipole_moment_debye)
    omega = 2 * math.pi * qubit_freq_ghz * 1e9

    # Thermal saturation factor — TLS bath saturates at low T
    thermal_factor = math.tanh(HBAR * omega / (2 * KB * temperature_k))

    effective_loss_tangent = (loss["loss_tangent_material_term"]
                              * participation_ratio * thermal_factor)

    if effective_loss_tangent <= 0:
        return {"error": "computed non-positive loss tangent — check inputs"}

    t1_seconds = 1.0 / (omega * effective_loss_tangent)

    return {
        "qubit_freq_ghz": qubit_freq_ghz,
        "participation_ratio": participation_ratio,
        "temperature_k": temperature_k,
        "predicted_t1_us": round(t1_seconds * 1e6, 2),
        "effective_loss_tangent": effective_loss_tangent,
        "thermal_saturation_factor": round(thermal_factor, 4),
        "citation": TLS_DENSITY_REFERENCE["citation"],
        "calibration_status": ("LITERATURE-CALIBRATED — uses published TLS "
                                 "density/dipole reference values, not a "
                                 "live device measurement"),
    }

def compare_to_measured_t1(predicted_t1_us: float, measured_t1_us: float) -> dict:
    """
    Sanity-check comparison: if a real T1 measurement is available
    (from module35's calibration read, for instance), compare it
    against this model's TLS-only prediction. Large deviation suggests
    either non-TLS loss mechanisms dominate, or device quality differs
    substantially from the literature baseline used here.
    """
    if predicted_t1_us <= 0 or measured_t1_us <= 0:
        return {"error": "both T1 values must be positive"}
    ratio = measured_t1_us / predicted_t1_us
    if ratio < 0.3:
        interpretation = ("Measured T1 far below TLS-only prediction — "
                          "additional non-TLS loss mechanism likely present "
                          "(quasiparticle poisoning, radiation, packaging "
                          "loss, or a fabrication defect)")
    elif ratio > 3.0:
        interpretation = ("Measured T1 far above TLS-only prediction — "
                          "either device quality exceeds the literature "
                          "reference baseline, or the assumed participation "
                          "ratio is too high for this geometry")
    else:
        interpretation = "Measured T1 broadly consistent with TLS-dominated loss"

    return {"predicted_t1_us": predicted_t1_us,
             "measured_t1_us": measured_t1_us,
             "ratio": round(ratio, 3),
             "interpretation": interpretation}
