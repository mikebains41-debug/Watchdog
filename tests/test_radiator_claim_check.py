import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "scripts"))
sys.path.insert(0, ".")
try:
    from radiator_claim_check import check, required_area
except ImportError:
    sys.path.insert(0, "scripts"); from radiator_claim_check import check, required_area
P, F = [], []
def ck(n, c): (P if c else F).append(n); print("[%s] %s" % ("PASS" if c else "FAIL", n))

# reproduce the paper's worked example: 700W @350K @0.9 -> ~0.91 m2
req, flux = required_area(700, 350, 0.9)
ck("worked example ~0.91 m2/chip", abs(req - 0.914) < 0.01)

# impossible claim: 50 chips * 700W = 35kW, claim only 10 m2 (floor ~45.7 m2) -> FAIL
r = check(50, 700, area_m2=10, t_rad_k=350)
ck("under-sized radiator -> FAIL", r["verdict"] == "FAIL")
ck("  FAIL states the shortfall", "short by" in r["detail"])

# adequate with margin: same load, 100 m2 -> PASS
r = check(50, 700, area_m2=100, t_rad_k=350)
ck("well-sized radiator -> PASS", r["verdict"] == "PASS")

# tight margin: floor ~45.7, claim 50 (<20% margin) -> WARN
r = check(50, 700, area_m2=50, t_rad_k=350)
ck("tight margin -> WARN", r["verdict"] == "WARN")

# no claim -> INFO with required area
r = check(10, 700, area_m2=None, t_rad_k=350)
ck("no claim -> INFO with required area", r["verdict"] == "INFO" and r["required_area_m2"] > 0)

# lower chip temp needs FAR more area (T^4): 350K vs 300K
req_hot, _ = required_area(700, 350, 0.9)
req_cool, _ = required_area(700, 300, 0.9)
ck("cooler chip needs more radiator (T^4 law)", req_cool > req_hot * 1.5)

# error: radiator at space temp
r = check(1, 700, area_m2=1, t_rad_k=2.7)
ck("radiator temp <= space -> ERROR", r["verdict"] == "ERROR")

# REAL CLAIM CHECK: a 4000kg Starmind sat. Suppose it runs 40 H100-class chips
# (~28kW). Floor at 350K ~36.6 m2. That's a big deployable panel -- the point is
# the tool QUANTIFIES it, and a small claimed panel would FAIL.
r = check(40, 700, area_m2=5, t_rad_k=350)  # someone claiming a tiny 5 m2 panel
ck("Starmind-style: 28kW on 5 m2 -> FAIL (thermally impossible)", r["verdict"] == "FAIL")
print("   -> 40 H100-class chips need %.1f m2; 5 m2 claimed is impossible" % r["required_area_m2"])

print("\nPASSED: %d FAILED: %d" % (len(P), len(F)))
sys.exit(1 if F else 0)
