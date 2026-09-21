# Watchdog Subsea — Research Update, 21 September 2026

Verified against primary and near-primary sources. Every claim from the
AI-generated summary that circulated on LinkedIn was checked before use;
§1 records what held, what was wrong, and what could not be checked.

**Status: design stage.** Zero hardware submerged. Nothing below is built.
§4 is the exception: work that can be done now, free, from public data.

---

## 1. Checking the circulated summary

| Claim | Verdict | Source |
|---|---|---|
| Hainan is the only operational commercial UDC (as of Feb 2026) | **Verified** | SlashGear, Feb 2026 |
| Hainan cabins 35 m deep, 24 racks, 400–500 servers each; plan for 100 cabins | **Verified** | SCMP, Oct 2025 |
| Shanghai UDC: 24 MW total, ~2,000 servers, CNY 1.6 bn (~US$226–228 M) | **Verified** | offshoreWIND.biz; Tom's Hardware, May 2026 |
| Shanghai phase 1 = 2.3 MW, two 35 kV submarine cables | **Verified** | igor'sLAB; offshoreWIND.biz |
| PUE ~1.15; electricity use cut 22.8%; no water; land cut >90% | **Verified — developer's own figures** | offshoreWIND.biz |
| Up to 95% of power from offshore wind | **Verified — developer's figure** | ESG News; TechRadar |
| Cooling via refrigerant in copper pipes rising by buoyancy to a seawater heat exchanger | **Verified** (HiCloud representative quoted) | Interesting Engineering via Brazil Energy Insight |
| Depth "about 10 m" | **Conflicting** — offshoreWIND.biz says 10 m; Tom's Hardware and TechRadar say ~35 m | — |
| "2,000 tons, 32 m high", "15 °C seawater" | **Not verified** in any source checked | — |
| "12 modules, 144 GPU servers each" | **Single low-credibility source** — do not repeat | AgentBear Corps |
| HiCloud plans a 500 MW offshore expansion | **Verified as stated vision** | TechRadar |
| Natick: 1/8 the failure rate of land; dry nitrogen atmosphere | **Verified** | Microsoft; EMEC |
| Natick failures: 6 of 855 underwater vs 8 of 135 on land (0.7% vs 5.9%) | **Verified** (one TechRadar piece misstates "8 of 855") | TechRadar; Global Business Outlook |
| "Vacuum-sealed" | **Wrong word** — Microsoft says sealed and filled with dry nitrogen | Microsoft |
| Natick carried a post-quantum-protected tunnel | **Verified — real (2019)** | Microsoft Research |
| "Microsoft Quantum Telemetry Log" | **Invented name** — the real page is "Post-Quantum Crypto Tunnel to the Underwater Datacenter" | Microsoft Research |
| Baltic Sea surveillance paper (ResearchGate, "June 2026") | **Real, but published Oct 2024** (JITA vol 14 no 2), and a *hypothetical* case study | JITA / APEIRON |
| Dual-purpose evaporation system producing 10,000+ t/day freshwater | **Real, but mis-framed** — it is a coastal land system using seawater, not a subsea plant | Applied Thermal Engineering (2026) |
| Heat-wave resilience (Nature 2022), Bren School/Masanet (Sep 2026), C-SDA (IEEE 2025), "Beneath the Cloud" (Springer), IEEE comprehensive review | **Not checked in this pass** — plausible, unconfirmed | — |

**Takeaway:** the summary's core facts were right; its details were loose,
two dates/framings were wrong, and one source name was invented. Treat
AI-generated research summaries exactly like unvalidated telemetry — useful
signal, checked before use.

---

## 2. What matters for Watchdog

### 2.1 The first subsea data center already proved Watchdog's crypto thesis

Microsoft Research ran a post-quantum-protected VPN tunnel between Natick
and Redmond in 2019, using a hybrid classical + post-quantum key exchange in
a modified OpenVPN. **That tunnel originally used SIKE — an algorithm later
withdrawn after vulnerabilities were found** (ASPI The Strategist, Oct 2025).

So the world's first undersea data center shipped "quantum-safe" crypto that
turned out not to be. That is exactly the gap Watchdog's PQC modules exist
to catch: crypto that is *claimed* safe versus crypto that *is*. WD-089-001
(144/144 certificates quantum-vulnerable with PQC installed) is the same
lesson on land. Subsea backhaul runs over long-lived cables that are
attractive to harvest-now-decrypt-later collection — the case is stronger
there, not weaker.

### 2.2 There is a whole research line on acoustic attacks — and on defending against them

A University of Florida group (Rampazzi, Islam and colleagues) has built a
sustained body of work:

| Year | Paper | What it is |
|---|---|---|
| 2023 | *Deep Note* — ACM HotStorage | Can underwater acoustic interference damage HDD availability in a UDC? |
| 2024 | *AquaSonic* — IEEE S&P | Acoustic manipulation of UDC operations and resource management |
| 2025 | Blow et al. — SPIE Defense & Commercial Sensing | Detecting and localising acoustic vulnerabilities of UDCs |
| 2025 | Abdullah et al. — arXiv 2510.20122 | Active localisation of close-range adversarial acoustic sources for UDC surveillance |
| 2026 | *RepliGuard* — ACM Secure Development Conference | A policy-driven replica-management framework to protect against acoustic attacks |

That arc — **attack → detection → localisation → remediation** — is
Watchdog's own architecture, already worked out in the literature for the
subsea case. RepliGuard in particular is a remediation layer: respond to a
detected acoustic attack by managing where data lives, rather than trying
to stop the sound. Directly relevant to Watchdog modules U-89
(AcousticNoiseFloorEstimator), U-53 (ComponentVibrationIsolationTracker)
and U-13 (AcousticLeakLocalizationEngine).

Honest limit: HDD-targeted attacks matter less as flash replaces spinning
disks, but fans, pumps and structural resonance remain acoustic surfaces.

### 2.3 The cable is the attack surface, and detection is maturing fast

- Dragged anchors cause an estimated **30–40% of offshore cable faults**
  (International Cable Protection Committee, cited in an ECOC 2026 paper).
- **State-of-polarisation (SOP) monitoring** can detect physical contact on
  subsea cables using existing coherent receivers **at no marginal hardware
  cost**, and does not saturate on strong impacts the way DAS can
  (arXiv 2607.01484, accepted ECOC 2026).
- **Finland deployed a distributed-acoustic-sensing early-warning system**
  for its undersea cables in 2026 (Tom's Hardware, June 2026), after at least
  seven major vessel-related infrastructure incidents in the Baltic since 2023.
- Baltic incidents in the literature: Nov 2024 (two cables, Finland–Germany
  and Lithuania links), Dec 2024 (EstLink 2 power cable), Feb 2025 (C-Lion1
  near Gotland), Jan 2026 (vessel allowed to leave Finland after allegedly
  dragging its anchor for kilometres).

A subsea data center is a node on exactly these cables. Its availability is
the cable's availability.

### 2.4 Supply chain and sanctions

Merics reports that subsidiaries of Highlander, the marine engineering firm
behind the Hainan project, are on the US Entity List. For any Western
operator, component and contractor provenance is a compliance question, not
only a security one. Maps to U-65 (ITARSubseaHardwareTracker) and U-138
(MarineSteelBatchTraceabilityTracker).

### 2.5 Thermal discharge is the open environmental question

Developers and reporters alike flag localised warming. HiCloud says it is
monitoring water at the Hainan site. Watchdog's Category U-K
(121–135, thermal ecology) is the relevant set — and currently nothing public
reports measured plume data from either Chinese site.

---

## 3. Module updates

| Module | Change |
|---|---|
| **New: U-151 `CableContactSOPMonitor`** | Physical-contact detection from state-of-polarisation already present in coherent receivers. No new hardware on the cable. Per arXiv 2607.01484. `[BUILD]` against an operator's receiver telemetry |
| **New: U-152 `DASVesselCorrelator`** | Fuse DAS detections with AIS tracks: a vessel on the cable with its AIS off, or loitering, or matching a known anchor-drag profile. `[BUILD]` and `[WHITE-HAT]` — public datasets exist (§4) |
| **New: U-153 `AcousticAttackReplicaPolicy`** | RepliGuard-style remediation: on a detected acoustic attack, move or replicate data away from affected storage rather than acting on the hardware. Human-gated like every other action. `[BUILD]` |
| **New: U-154 `SubseaBackhaulPQCVerifier`** | Point the existing PQC audit (modules 89, 92, 98–104) at the capsule-to-shore link and its tunnels. The Natick SIKE history is the reason. `[BUILD]` |
| U-47 `MarineTrafficAnchorCollisionAvoider` | Now has a concrete public dataset to validate against (§4) |
| U-64 `SubseaCableInterceptionAuditor` | Add SOP-based contact signatures alongside attenuation |
| U-89 `AcousticNoiseFloorEstimator` | Cite the UF research line; the baseline it builds is the precondition for detecting AquaSonic-class attacks |

---

## 4. White-hat programme — free, public data, no hardware

### 4.1 Build and validate a vessel/anchor detector on public DAS + AIS data

The **Marlinks-NS DAS dataset** (Ramirez-Torres et al., 2026) is published
on Zenodo: processed submarine DAS measurements paired with AIS vessel
information, curated specifically for cable-protection research
(arXiv 2607.28306). A separate 2025 study combined public DAS and AIS data to
train a CNN vessel detector.

That means U-152 can be built and **tested to Watchdog's own standard —
positive control, negative control, measured false-positive rate — with no
money and no hardware.** It is the subsea equivalent of the orbital
site-diversity audit.

Before starting: confirm the dataset licence permits this use, and record
its terms in the evidence file. Same discipline as every other dataset.

### 4.2 Write down the Natick SIKE lesson as a Watchdog case study

No code. A short, cited case study: first undersea data center, first
post-quantum tunnel, algorithm later broken. It is the strongest single
public example of why Watchdog verifies crypto instead of trusting labels,
and it belongs next to WD-089-001.

### 4.3 What cannot be done free

Acoustic attack testing needs a water tank and hardware. Thermal plume
measurement needs a real site. SOP monitoring needs access to an operator's
coherent receivers. These stay design-stage.

---

## 5. Stated honestly

- Nothing in this file is built or validated.
- The only commercial underwater data centers are in China; US startups
  (Subsea Cloud, NetworkOcean) have announced plans but, as of late 2025,
  nothing concrete had been deployed.
- Developer performance figures (PUE, energy savings, renewable share) are
  the developer's own and have not been independently measured.
- Five references from the circulated summary were not checked in this pass
  and are listed as unconfirmed in §1.
