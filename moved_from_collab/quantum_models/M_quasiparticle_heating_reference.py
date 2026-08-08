#!/usr/bin/env python3
"""
M_quasiparticle_heating_reference.py

Reference constants and the qualitative conclusion from two real papers on
non-equilibrium quasiparticle heating in superconducting qubits, for use as
a sanity-check layer -- NOT a simulator of substrate thermal transients.

Sources:
    Catelani, G. & Basko, D.M. "Non-equilibrium quasiparticles in
    superconducting circuits: photons vs. phonons."
    SciPost Phys. 6, 013 (2019). DOI: 10.21468/SciPostPhys.6.1.013

    Simon, A. et al. "Ab initio modeling of nonequilibrium dynamics in
    superconducting detectors and qubits."
    Phys. Rev. B 112, 174512 (2025). DOI: 10.1103/3m2k-mzr6
    (arXiv:2501.13791)

WHAT THIS MODULE DOES: stores specific numerical values and the central
qualitative conclusion that Catelani & Basko state explicitly in their
paper, for use as a sanity-check reference elsewhere in this repo.

WHAT THIS MODULE DOES NOT DO: it does not simulate phonon transport,
substrate temperature spikes, T1 degradation from drive cycles, or any
other dynamic physical process. Building an actual simulator would require
implementing the kinetic equations in Catelani & Basko Section 2 (Eq. 1-17)
or the ab initio DFT-based approach in Simon et al. -- both are substantial
physics/numerical projects, not something this module attempts.

STATUS: LITERATURE_REFERENCE_ONLY. Real, cited, peer-reviewed constants.
Not a simulation. Not hardware-tested.
"""

# ---------------------------------------------------------------------------
# Catelani & Basko (2019), SciPost Phys. 6, 013 -- Section 4, "Discussion:
# relevance to experiments"
# ---------------------------------------------------------------------------

# For a typical small aluminum-island transmon qubit (~0.02 um^3 island
# volume), the paper estimates the photon absorption/emission rate:
SMALL_ISLAND_VOLUME_UM3 = 0.02
GAMMA_0_HZ = 1e5  # photon absorption/emission rate, Gamma_0 ~ 10^5 Hz

# Phonon relaxation time, estimated from thin-film experimental references
# cited in the paper (their refs [29] and [30]):
TAU_PH_NS = 10.0  # phonon relaxation time ~ 10 ns

# Typical qubit frequency range considered in the paper's estimate:
QUBIT_FREQ_RANGE_GHZ = (4.0, 8.0)

# The paper's computed range for T*/omega_0 (ratio of the "hot quasiparticle"
# temperature scale to the qubit frequency) under strong driving, for this
# island size and phonon relaxation time:
T_STAR_OVER_OMEGA0_RANGE = (0.8, 1.2)

# Central qualitative conclusion, stated explicitly in the paper's
# Discussion section: even under strong driving, a qubit cannot
# significantly heat quasiparticles to energies much above its own
# frequency. This is the paper's own stated conclusion, not our inference.
CENTRAL_CONCLUSION = (
    "Even under strong driving, a qubit cannot significantly heat "
    "quasiparticles to energies much above its own drive frequency "
    "(T*/omega_0 stays within a factor of ~1.2 for realistic small-island "
    "parameters). An undriven qubit (excited-state population below ~0.3, "
    "typically a few percent to ~10%) cannot heat quasiparticles at all."
)

# Threshold excited-state population above which a qubit could, in
# principle, begin heating quasiparticles (n_bar > 1/(1+e) ~ 0.27):
DRIVEN_HEATING_THRESHOLD_POPULATION = 1.0 / (1.0 + 2.71828182845904523536)


# ---------------------------------------------------------------------------
# Simon et al. (2025), Phys. Rev. B 112, 174512 -- ab initio material
# comparison
# ---------------------------------------------------------------------------

# Paper's central materials-science finding: tantalum-based transmon qubits
# show reduced sensitivity to quasiparticle poisoning relative to other
# common qubit materials (e.g. aluminum, niobium), calculated ab initio
# (from first principles, without fitting to experimental data). This is
# offered as a likely partial explanation for tantalum qubits' observed
# longer coherence times.
MATERIAL_COMPARISON_FINDING = (
    "Ab initio (first-principles) modeling shows Ta-based transmon qubits "
    "have reduced sensitivity to quasiparticle poisoning relative to other "
    "common qubit materials, offered as a likely partial explanation for "
    "their longer observed coherence times."
)


def is_qubit_likely_to_heat_quasiparticles(excited_state_population: float) -> bool:
    """
    Plausibility check only, based on Catelani & Basko's stated threshold
    (n_bar > 1/(1+e) ~ 0.27) above which a qubit could, in principle, begin
    heating quasiparticles under strong driving. This is NOT a prediction
    of how much heating occurs -- only whether the qubit is in the regime
    where the paper's analysis says heating becomes possible at all.
    """
    if not (0.0 <= excited_state_population <= 1.0):
        raise ValueError("excited_state_population must be between 0 and 1")
    return excited_state_population > DRIVEN_HEATING_THRESHOLD_POPULATION


def summary() -> dict:
    return {
        "sources": [
            "Catelani & Basko, SciPost Phys. 6, 013 (2019), DOI: 10.21468/SciPostPhys.6.1.013",
            "Simon et al., Phys. Rev. B 112, 174512 (2025), DOI: 10.1103/3m2k-mzr6",
        ],
        "status": "LITERATURE_REFERENCE_ONLY_NOT_A_SIMULATOR",
        "gamma_0_hz": GAMMA_0_HZ,
        "tau_ph_ns": TAU_PH_NS,
        "driven_heating_threshold_population": round(DRIVEN_HEATING_THRESHOLD_POPULATION, 4),
        "central_conclusion": CENTRAL_CONCLUSION,
        "material_comparison_finding": MATERIAL_COMPARISON_FINDING,
        "note": (
            "This module stores specific cited constants and conclusions "
            "from two real papers for reference/sanity-check purposes. It "
            "does not simulate any dynamic physical process. A genuine "
            "simulator would require implementing the kinetic equations "
            "or ab initio methods in the source papers directly."
        ),
    }


if __name__ == "__main__":
    print("=" * 74)
    print("  QUASIPARTICLE HEATING — LITERATURE REFERENCE (not a simulator)")
    print("=" * 74)
    for k, v in summary().items():
        print(f"  {k}: {v}")
    print()
    print("  Plausibility check examples:")
    for pop in [0.01, 0.1, 0.27, 0.3, 0.45]:
        result = is_qubit_likely_to_heat_quasiparticles(pop)
        print(f"    n_bar={pop:.2f} -> heating regime possible: {result}")
