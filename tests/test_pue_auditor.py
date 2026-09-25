import sys
sys.path.insert(0, ".")
from pue_auditor import audit
P, F = [], []
def ck(n, c): (P if c else F).append(n); print("[%s] %s" % ("PASS" if c else "FAIL", n))

# implausible claim: subsea_passive floor is 1.03; claiming 1.01 is below floor
r = audit(700, stated_pue=1.01, cls="subsea_passive")
ck("PUE below class floor -> FAIL", r["verdict"] == "FAIL")

# honest claim inside band
r = audit(700, stated_pue=1.07, cls="subsea_passive")
ck("PUE in band -> PASS", r["verdict"] == "PASS")

# inefficient but honest: land_hyperscale tops at 1.4, claim 1.6
r = audit(700, stated_pue=1.6, cls="land_hyperscale")
ck("PUE above band -> WARN (inefficient not dishonest)", r["verdict"] == "WARN")

# measured vs stated disagree by >5% -> FAIL (the real teeth)
r = audit(700, stated_pue=1.10, total_kw=980)  # measured 1.4 vs claimed 1.1
ck("stated PUE contradicted by measured power -> FAIL", r["verdict"] == "FAIL")
ck("  and it reports the measured PUE", abs(r["measured_pue"] - 1.4) < 0.001)

# measured only, no claim -> computes and INFO
r = audit(700, total_kw=770)
ck("measured-only -> INFO with measured_pue 1.1", r["verdict"] == "INFO" and abs(r["measured_pue"]-1.1)<0.001)

# derive overhead correctly
r = audit(1000, stated_pue=1.2, cls="land_hyperscale")
ck("implied overhead 200kW at PUE 1.2 on 1000kW IT", abs(r["implied_overhead_kw"] - 200) < 0.01)

# no class -> INFO, still computes
r = audit(700, stated_pue=1.15)
ck("no class -> INFO, computes overhead", r["verdict"] == "INFO" and "implied_overhead_kw" in r)

# every result carries the citation
ck("citation on every result", all("2609.12511" in audit(700, stated_pue=p).get("citation","") for p in (1.1,1.2)))

print("\nPASSED: %d FAILED: %d" % (len(P), len(F)))
sys.exit(1 if F else 0)
