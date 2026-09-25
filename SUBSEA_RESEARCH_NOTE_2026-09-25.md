# Subsea data centre — verified research note

2026-09-25. Design-stage reference for Watchdog's subsea (UDC) category.
Watchdog has ONE real subsea result (the Belgian cable DAS test). Everything
here is external literature that validates the *market and the need* — not
Watchdog's subsea capability. Cited sources verified by reading the source, not
a summary.

---

## Primary source (VERIFIED)

**Computing at Sea: Floating and Offshore Data Centres as a Pathway to
Sustainable AI Infrastructure.** Chin, Zhang, Venkateshkumar.
arXiv:2609.12511v1 [eess.SY], 11 Sep 2026, CC BY 4.0. Review/position paper.
Confirmed: real paper, real arXiv ID, opened and read.

Second paper referenced but NOT yet independently verified — treat as UNVERIFIED
until opened: "Could Underwater Data Centers Pose a Risk to AI Treaty
Verification?" (ResearchGate 414403438).

---

## The money line — why Watchdog fits the category

The paper states, as a requirement for next-generation subsea data centres
(Section VIII), that they must incorporate:

> "machine learning-driven predictive diagnostics informed by continuous sensor
> telemetry, including large language model-based anomaly interpretation
> pipelines capable of synthesising multi-stream operational data into actionable
> maintenance decisions without requiring direct human intervention at the
> deployment site."

That is a peer-reviewed description of what Watchdog is: predictive, telemetry-
driven, autonomous, human-in-the-loop-optional. Usable as: *the literature says
subsea compute needs self-monitoring like this; here is ours.* NOT as: Watchdog
runs underwater today (it does not — design stage, one cable test).

## The regulatory / attestation angle

Section VIII: within 200-nautical-mile EEZs, coastal-state jurisdiction over IT
infrastructure in the water column is "legally untested in most jurisdictions."
Data-residency law (GDPR, Singapore PDPA) may require regulated data stay in
compliant jurisdictions. This is the case for remote attestation / evidence
ledgers on subsea compute — how do you verify what is running somewhere no
inspector can reach. Watchdog's evidence-ledger work is the answer to that
question. (Same point the treaty-verification paper reportedly makes — verify it.)

---

## Verified facts (citable, from this paper)

- **Project Natick:** 864 Azure servers, 12 racks, 27.6 PB, 35.6 m depth,
  26 months, single power+data cable, passive seawater hull heat exchange,
  nitrogen atmosphere. **~8x lower server failure rate** than land. Est. PUE
  ~1.07. Retrieved July 2020.
- **China / Highlander (Hainan):** first operational offshore floating DC, 2023,
  ~400 racks, PUE <1.15, seawater from ~20 m, returns 3-4C above ambient.
- **Shanghai (HiCloud):** offshore wind-powered UDC off Shanghai (Data Center
  Dynamics, 2025).
- **Subsea Cloud (US):** aluminium capsules ~5 m x 14 m, 8 racks, diver-accessible
  hatch (unlike Natick's sealed design), targeting 2025-26.
- **Cooling energy:** land air-cooled 30-40% of energy; seawater-cooled 3-8%;
  passive capsule floor ~2-3%.
- **Waste heat:** a 100 MW DC dumps ~85-90 MW; thermal effluent typically 3-5C
  above ambient; negligible in open water, a real risk in enclosed water bodies.
- **Latency:** ~0.5-1.0 ms round-trip for 50-100 km offshore; fine for training
  (tolerates up to ~100 ms), not for real-time inference.
- **DC energy scale:** global ~300-380 TWh (2023) -> IEA projects ~945 TWh by
  2030. Cooling is 30-40% of a conventional DC's draw.

---

## How this maps to existing Watchdog subsea modules

- **Section VIII autonomy requirement** -> validates the whole UDC monitoring
  thesis + the predictive swarm.
- **Regulatory/attestation gap** -> validates evidence-ledger / remote-attestation
  work for subsea.
- **Thermal effluent 3-5C, enclosed-water risk** -> U-K category (thermal ecology:
  MarineBoundaryLayerPlumeEquation, LocalizedHypoxiaRiskPredictor).
- **ROV-only maintenance, 5-year target** -> U-F (no-human longevity),
  SparedBladeRedundancyPoolManager, predictive-failure detectors.
- **Gr/Re2 convection criterion** (from the separate fluid-dynamics source, also
  design-stage) -> the quantitative trigger for SlackTideComputeThrottler (U-4):
  Gr/Re2 > 10 = natural convection dominates (stagnant water, worse cooling) =
  throttle; < 0.1 = forced convection (tidal flow, fine).

---

## Honest boundary

- Subsea is DESIGN STAGE. One real Watchdog result (Belgian cable). Nothing built
  or deployed underwater.
- This paper is a review/position paper — cite for landscape and stated need, not
  for experimental data.
- Use to validate the market and Watchdog's direction. Do not imply subsea
  capability that does not exist.
