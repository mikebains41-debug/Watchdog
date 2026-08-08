#!/usr/bin/env python3
"""Tests for M_wiring_heat_leak.py"""
import pytest
from M_wiring_heat_leak import WiringRun, MATERIALS


class TestWiringRunCalculation:
    def test_heat_leak_scales_linearly_with_wire_count(self):
        run1 = WiringRun("stainless_steel", length_m=1.5, cross_section_mm2=0.05, wire_count=10)
        run2 = WiringRun("stainless_steel", length_m=1.5, cross_section_mm2=0.05, wire_count=20)
        assert run2.heat_leak_watts() == pytest.approx(2 * run1.heat_leak_watts(), rel=1e-9)

    def test_heat_leak_scales_inversely_with_length(self):
        short = WiringRun("stainless_steel", length_m=1.0, cross_section_mm2=0.05, wire_count=10)
        long = WiringRun("stainless_steel", length_m=2.0, cross_section_mm2=0.05, wire_count=10)
        assert long.heat_leak_watts() == pytest.approx(short.heat_leak_watts() / 2, rel=1e-9)

    def test_unknown_material_returns_none(self):
        run = WiringRun("unobtainium", length_m=1.0, cross_section_mm2=0.05, wire_count=10)
        assert run.heat_leak_watts() is None

    def test_zero_length_raises_value_error(self):
        run = WiringRun("stainless_steel", length_m=0.0, cross_section_mm2=0.05, wire_count=10)
        with pytest.raises(ValueError):
            run.heat_leak_watts()

    def test_negative_length_raises_value_error(self):
        run = WiringRun("stainless_steel", length_m=-1.0, cross_section_mm2=0.05, wire_count=10)
        with pytest.raises(ValueError):
            run.heat_leak_watts()

    def test_copper_leaks_more_than_stainless_steel(self):
        """Copper is explicitly noted as high heat leak vs stainless."""
        copper = WiringRun("copper", length_m=1.5, cross_section_mm2=0.05, wire_count=10)
        steel = WiringRun("stainless_steel", length_m=1.5, cross_section_mm2=0.05, wire_count=10)
        assert copper.heat_leak_watts() > steel.heat_leak_watts()

    def test_nbti_leaks_less_than_stainless_steel(self):
        """NbTi superconducting wire should have the lowest heat leak."""
        nbti = WiringRun("nbti_superconducting", length_m=1.5, cross_section_mm2=0.05, wire_count=10)
        steel = WiringRun("stainless_steel", length_m=1.5, cross_section_mm2=0.05, wire_count=10)
        assert nbti.heat_leak_watts() < steel.heat_leak_watts()


class TestTemperatureParametersNowUsed:
    """
    FIXED (previously a documented bug): heat_leak_watts() now scales its
    output by the ratio of the requested temperature span to the reference
    4K-300K span the base constants were calibrated for. This is a linear
    first-order approximation of a physically temperature-dependent
    integral -- flagged as such in the code, not presented as exact.
    """

    def test_temperature_parameters_now_affect_result(self):
        run = WiringRun("stainless_steel", length_m=1.5, cross_section_mm2=0.05, wire_count=10)
        result_default = run.heat_leak_watts()
        result_narrower_span = run.heat_leak_watts(t_hot_kelvin=77.0, t_cold_kelvin=4.0)
        assert result_default != result_narrower_span

    def test_narrower_temperature_span_gives_lower_heat_leak(self):
        run = WiringRun("stainless_steel", length_m=1.5, cross_section_mm2=0.05, wire_count=10)
        full_span = run.heat_leak_watts(t_hot_kelvin=300.0, t_cold_kelvin=0.015)
        narrow_span = run.heat_leak_watts(t_hot_kelvin=77.0, t_cold_kelvin=4.0)
        assert narrow_span < full_span

    def test_invalid_temperature_ordering_raises_value_error(self):
        run = WiringRun("stainless_steel", length_m=1.5, cross_section_mm2=0.05, wire_count=10)
        with pytest.raises(ValueError):
            run.heat_leak_watts(t_hot_kelvin=4.0, t_cold_kelvin=300.0)

    def test_equal_temperatures_raises_value_error(self):
        run = WiringRun("stainless_steel", length_m=1.5, cross_section_mm2=0.05, wire_count=10)
        with pytest.raises(ValueError):
            run.heat_leak_watts(t_hot_kelvin=10.0, t_cold_kelvin=10.0)


class TestMaterialsReference:
    def test_all_expected_materials_present(self):
        expected = {"stainless_steel", "phosphor_bronze", "copper", "nbti_superconducting"}
        assert expected.issubset(set(MATERIALS.keys()))

    def test_nbti_has_lowest_integrated_k(self):
        nbti_k = MATERIALS["nbti_superconducting"].integrated_k_4K_to_300K_W_per_m
        for key, mat in MATERIALS.items():
            if key != "nbti_superconducting":
                assert nbti_k <= mat.integrated_k_4K_to_300K_W_per_m


if __name__ == "__main__":
    import sys
    sys.exit(pytest.main([__file__, "-v"]))
