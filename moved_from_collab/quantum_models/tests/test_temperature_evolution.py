#!/usr/bin/env python3
"""
test_temperature_evolution.py

Validates M_qubit_temperature_evolution.py against published values from
Uusnakki et al., Nature Communications 17, 6054 (2026).

Run with: pytest test_temperature_evolution.py -v
"""

import pytest
from M_qubit_temperature_evolution import (
    saturation_model,
    is_near_saturation,
    T_INITIAL_MK,
    T_SATURATION_MK,
    TAU_SAT_US,
    MEASUREMENT_SPAN_US,
    CYCLES_TO_SATURATE,
)


class TestSaturationModelBoundaryConditions:
    def test_at_time_zero_returns_initial_temperature(self):
        temp = saturation_model(0.0)
        assert temp == pytest.approx(T_INITIAL_MK, abs=0.01)

    def test_at_large_time_approaches_saturation_temperature(self):
        temp = saturation_model(100.0)  # far beyond tau_sat
        assert temp == pytest.approx(T_SATURATION_MK, abs=1.0)

    def test_temperature_is_monotonically_increasing(self):
        times = [0.0, 0.5, 1.0, 1.5, 2.0, 3.0, 5.0]
        temps = [saturation_model(t) for t in times]
        for i in range(len(temps) - 1):
            assert temps[i] < temps[i + 1]

    def test_temperature_never_exceeds_saturation_value(self):
        for t in [0.0, 0.5, 1.0, 2.0, 5.0, 20.0]:
            assert saturation_model(t) <= T_SATURATION_MK + 1e-6

    def test_rejects_nonpositive_tau(self):
        with pytest.raises(ValueError):
            saturation_model(1.0, tau_us=0.0)


class TestMeasurementSpanClaim:
    """
    Paper states: "our measurements already span twice the length of the
    saturation time constant, further verifying that we are already
    measuring near the saturated effective temperatures."
    """

    def test_measurement_span_is_twice_tau_sat(self):
        assert MEASUREMENT_SPAN_US == pytest.approx(2.0 * TAU_SAT_US, abs=1e-9)

    def test_temperature_near_saturation_at_measurement_span(self):
        # At 2x tau_sat, should be meaningfully close to saturation,
        # consistent with the paper's claim.
        assert is_near_saturation(MEASUREMENT_SPAN_US, tolerance_mk=70.0)


class TestPublishedTemperatureValues:
    def test_initial_temperature_matches_paper(self):
        assert T_INITIAL_MK == pytest.approx(160.0, abs=0.01)

    def test_saturation_temperature_matches_paper(self):
        assert T_SATURATION_MK == pytest.approx(600.0, abs=0.01)

    def test_cycles_to_saturate_matches_paper(self):
        # Paper's Extended Data Fig. 2: "very accurately saturates after
        # five cycles to a maximum temperature of 600 mK"
        assert CYCLES_TO_SATURATE == 5


if __name__ == "__main__":
    import sys
    sys.exit(pytest.main([__file__, "-v"]))
