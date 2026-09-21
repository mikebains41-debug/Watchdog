# Watchdog Space — Category O
# Optical Link Security & Ground Segment Integrity (Modules 226–250)

**Extends the Space Data Center module set (own namespace, 1–225). Category H
(131–145) covers laser link *quality*. This category covers laser link
*trust*: who else can see it, who else can pretend to be it, and whether the
operator's availability claims survive contact with public weather data.**

Status flags as used throughout the space set:
`[PHYSICS]` derived from a stated physical law ·
`[BUILD]` software logic, buildable now ·
`[SPACE-ONLY]` needs real orbital hardware ·
`[UNVERIFIED]` depends on an unconfirmed claim ·
`[WHITE-HAT]` executable today against public data, no hardware, no access to
anyone's infrastructure.

**Status: design stage. Zero hardware in orbit.** Every module below is
unbuilt. The white-hat programme in §4 is the exception — it is buildable this
week and needs nothing but public data.

---

## 1. What changed since the space set was written

The architecture converged, and it converged on **relay**, not direct
downlink. That matters more than any single technical detail, because it
introduces a third party into the data path.

- SpaceX filed 30 January 2026 for up to one million satellites as the
  "SpaceX Orbital Data Center system"; the FCC Space Bureau accepted it for
  filing on 4 February 2026. The architecture connects the data-center
  satellites to Starlink over optical links, and Starlink's laser mesh
  carries traffic down to ground stations. Current Starlink satellites carry
  three lasers at up to 200 Gbps; a later generation targets 1 Tbps.
- Blue Origin announced TeraWave, a data-center-focused optical satellite
  system supporting up to 6 Tbps.
- Axiom launched its first two orbital data center nodes on 11 January 2026,
  with 2.5 GB/s optical links compatible with SDA Tranche 1 standards,
  alongside Kepler's optical relay constellation.

**The consequence for a security product:** your compute is in orbit, but
your data transits somebody else's constellation. That is the same
tenant-isolation question as a neocloud, moved to orbit, and with one
additional property — you cannot inspect the relay.

The industry's own framing of the bottleneck is worth quoting because it is
an operations problem, not a physics problem: optical inter-satellite links
get most of the attention, but optical downlink is just as critical and
arguably harder to operationalize at scale — the difficulty has been
integrating terminals, coordinating ground stations, managing weather
constraints, and operating the system end to end.

Operations problems are monitoring problems. That is the opening.

---

## 2. Threat model, from the published literature

Six mechanisms, each with a citation, each producing a detectable
precondition or signature.

**T1 — Beaconless PAT spoofing during link acquisition.**
A malicious satellite maneuvers into the *uncertainty area* of a target
satellite during Pointing, Acquisition and Tracking, and completes the
handshake in place of the legitimate peer. Modelled with Clohessy-Wiltshire
relative-motion equations; attack probability is a function of scanning
uncertainty and pointing error.
*Security modelling of laser inter-satellite links establishment*, IOP 2025;
*Securing laser links in LEO satellites: a probability model for attacks on
beaconless PAT*, ScienceDirect, August 2026.

**This is the single most important finding for Watchdog.** Existing research
optimises alignment efficiency and neglects the security of the establishment
phase. The established link is narrow-beam and hard to intercept. The
*acquisition* is a scan across an uncertainty cone, and anything inside that
cone can answer. The attack has a geometric precondition, and geometric
preconditions are observable from public orbital data.

**T2 — Co-orbital or HAPS eavesdropping.**
An attacker positioned close to or above the satellite intercepts the
optical signal. High-altitude platform stations are the demonstrated case
for LEO downlinks.
*Optical Satellite Eavesdropping*; *Securing Satellite Link Segment*, arXiv
2411.12632.

**T3 — Routing-path leakage.**
Laser directivity helps, but traffic still leaks during multi-hop service
routing. The DMSR work defines a *service eavesdropping ratio* to quantify
leakage severity per service and switches paths proactively to reduce it.
*DMSR: Dynamic Multipath Secure Routing*, Photonics 12(10) 1039, 2025.

**T4 — Unencrypted forwarding.**
In broadcast and data-forwarding services, end-to-end encryption is often not
implemented in order to save cost or reduce latency, which is precisely what
an eavesdropper exploits. Same source as T3. This is a configuration
failure, not a cryptographic one, and configuration failures are detectable.

**T5 — Ground-laser QKD disruption.**
A ground-based laser on the order of 1 kW — commercially purchasable — can
significantly disrupt satellite QKD by scattering photons off the satellite
into the receiver, raising the quantum bit error rate. It does not break the
key. It denies it.
*Vulnerability of Satellite QKD to Disruption from Ground-Based Lasers*,
PMC8659886.

Watchdog already has a quantum suite. This is the orbital version of the
same class of finding, and it is a **discrimination** problem: QBER rises
under natural background and under attack alike.

**T6 — ISL availability attacks.**
Broadcast storms from a malicious node compromise the availability of LEO
satellite networks.
*Security Attacks Against the Availability of LEO Satellite Networks*,
ACM 10.1145/3638837.3638847.

---

## 3. The modules

### O-A — Link establishment integrity (226–232)

| # | Module | Function |
|---|---|---|
| 226 | `PATAcquisitionWindowAuditor` | Logs every link-establishment event with its uncertainty-cone geometry, scan duration and the pointing error at lock. The acquisition phase is the attack surface; today it is not recorded as a security event at all. `[BUILD]` |
| 227 | `UncertaintyConeOccupancyChecker` | At each acquisition, enumerates every catalogued object whose propagated position falls inside the scan cone. An uncatalogued or unexpected occupant is the precondition for T1. Uses public TLE/ephemeris; needs no access to the link. `[BUILD][WHITE-HAT]` |
| 228 | `ClohessyWiltshireApproachModeler` | Propagates relative motion of nearby objects against the C-W equations to flag trajectories consistent with deliberate insertion into an acquisition window rather than natural conjunction. `[PHYSICS]` |
| 229 | `PeerIdentityContinuityTracker` | Fingerprints the peer terminal across sessions — pointing bias, Doppler profile, power envelope, lock-time distribution — and flags a peer that authenticates correctly but behaves like a different terminal. Physical-layer continuity as a second factor. `[BUILD]` |
| 230 | `DualLayerAuthenticationValidator` | Confirms the physical-domain plus cryptographic handshake actually executed, rather than falling back to cryptographic-only when acquisition was marginal. Fallbacks under time pressure are where authentication quietly degrades. `[BUILD]` |
| 231 | `AcquisitionRetryAnomalyDetector` | A spoofing attempt that fails still leaves a trace: abnormal retry counts, unusual scan patterns, locks achieved at the edge of the cone. Fires on the *failed* attack, which is the one you want to see. `[BUILD]` |
| 232 | `LinkEstablishmentEvidenceLedger` | Hash-chains every acquisition event into the existing `forensics/audit_ledger.py`. If a link is later found compromised, the establishment record is tamper-evident. `[BUILD]` |

### O-B — Eavesdropping and leakage (233–238)

| # | Module | Function |
|---|---|---|
| 233 | `ServiceEavesdroppingRatioTracker` | Implements the DMSR service-eavesdropping-ratio metric per service, per path. Turns "our links are secure" into a number that changes when the route changes. `[BUILD]` |
| 234 | `CoOrbitalProximityMonitor` | Tracks catalogued objects entering the geometric volume from which a link could be intercepted. States plainly what it cannot distinguish: a proximity operation, a rideshare deployment and a targeted intercept look identical from ephemeris alone. `[BUILD][WHITE-HAT]` |
| 235 | `HAPSInterceptGeometryChecker` | Same for the atmospheric layer — flags when a downlink path crosses altitudes where a high-altitude platform could sit in the beam. `[BUILD]` |
| 236 | `UnencryptedForwardingDetector` | Detects services being forwarded without end-to-end encryption. Per T4 this is a real and cost-motivated practice, which makes it a configuration audit rather than a cryptanalysis problem. `[BUILD]` |
| 237 | `KeyRotationEnforcementAuditor` | Module 144 rotates keys. This one verifies rotation actually occurred across every hop including the relay operator's, and fires when a rotation was scheduled and skipped. `[BUILD]` |
| 238 | `BeamDivergenceAnomalyTracker` | An interception attempt that taps part of the beam changes received power in ways that can mimic atmospheric loss. Fires on the anomaly and explicitly declines to attribute a cause. `[SPACE-ONLY]` |

### O-C — Relay tenancy (239–243) — the new trust boundary

| # | Module | Function |
|---|---|---|
| 239 | `RelayHopTenancyAttestor` | Records every third-party constellation your traffic transits and what cryptographic guarantee applied on each hop. Today this is invisible to the customer. **This is the orbital equivalent of the neocloud tenant-isolation problem.** `[BUILD]` |
| 240 | `CrossOperatorPathDisclosureChecker` | Compares the path the operator says your data took against what the telemetry supports. Same "telemetry lies to itself" pattern as `PStateHonestyDetector`. `[BUILD]` |
| 241 | `RelayOperatorVisibilityScorer` | Scores what a relay operator could see: metadata only, timing and volume, or payload. Answers the question a customer actually has and cannot currently ask. `[BUILD]` |
| 242 | `SovereignRoutingComplianceMonitor` | Flags when a path crosses a jurisdiction the customer's data is not permitted to enter. Orbital data is marketed as operating beyond national jurisdictions, which is a legal claim, not a technical one. `[BUILD]` |
| 243 | `RelayDependencyFailureModeler` | If your only downlink path is one operator's mesh, that operator is a single point of failure for your entire data center. Models the dependency and names it. `[BUILD]` |

### O-D — Ground segment truth (244–250)

| # | Module | Function |
|---|---|---|
| 244 | `CloudFreeLineOfSightPredictor` | All-sky imaging plus nowcasting for minute-scale downlink decisions. Numerical weather prediction and satellite cloud products are too coarse in space and time for individual passes. `[BUILD]` |
| 245 | `SiteDiversityCorrelationAuditor` | Computes pairwise Pearson correlation of cloud cover across a ground-station network. **Low correlation is the entire point of site diversity; correlated sites are not diversity, they are duplication.** `[BUILD][WHITE-HAT]` |
| 246 | `GroundStationAvailabilityVerifier` | Measures delivered availability against the claimed figure. Cloud attenuation can exceed 100 dB/km, far beyond any link margin, so cloud is a blockage rather than a degradation — availability is binary per pass and therefore auditable. `[PHYSICS][WHITE-HAT]` |
| 247 | `ElevationAngleComplianceTracker` | Confirms passes are scheduled above the minimum usable elevation (30° is the standard floor for space-to-ground). Scheduling below it inflates the pass count without delivering data. `[PHYSICS][BUILD]` |
| 248 | `DownlinkDeferralHonestyDetector` | Weather-adaptive scheduling saves the *operator* energy by deferring contacts. This checks whether deferral served the customer's data or the operator's power budget — the orbital analogue of `BillingIntegrityDetector`. `[BUILD]` |
| 249 | `QKDExcessNoiseDiscriminator` | Distinguishes a QBER rise caused by natural background from one caused by an off-axis ground laser (T5). Discloses that it cannot always separate them, and says so in the alert. `[BUILD]` |
| 250 | `GroundSegmentSupplyChainAuditor` | Optical ground stations sit at astronomical observatory sites with existing fibre. That backhaul is a terrestrial attack surface inheriting every terrestrial problem. `[BUILD]` |

---

## 4. The white-hat programme — buildable this week, no hardware

This is the part that can produce a real finding before anything is launched.
Everything below uses public data and touches nobody's infrastructure.

### 4.1 The site-diversity audit — the strongest one

**The claim under test:** every optical downlink operator says site diversity
gives them high availability. Site diversity only works if cloud cover at the
sites is *uncorrelated*. Two stations under the same weather system are one
station with a spare.

**The method:** take an operator's published ground-station locations. Pull
historical cloud-cover data — NOAA, or MODIS cloud fraction from Aqua and
Terra, both public and both already used for exactly this in the literature.
Compute pairwise Pearson correlation of cloud cover across the network.
Simulate availability as the fraction of time at least one site meets the
elevation and cloud-free criteria.

**Why it is a genuine finding:** the method is published and validated. An
Australasian network study did it with Himawari-8 data; an Irish four-station
study found up to 45% availability improvement from diversity. Nobody has
systematically applied it to the *commercial* networks now being marketed for
orbital data centers.

**The possible outcomes are both publishable.** Either a marketed network has
correlated sites and its availability claim is overstated, or it does not and
you have independently verified a vendor claim — which is the same discipline
as `RadiatorClaimVerifier` and `ThroughputPerSatelliteClaimVerifier` already
in the space set.

**Ethics:** public weather data, public station locations, no contact with any
operator's systems. Disclose to the operator before publishing, same as
Vast.ai. This is measurement, not intrusion.

### 4.2 The acquisition-window occupancy check

Public TLE and ephemeris catalogues say what is in orbit. The PAT uncertainty
cone is computable from published terminal specifications. You can therefore
compute, for any pair of satellites that link, *who else was geometrically
positioned to answer that handshake.*

No access to any link required. The output is a precondition, not an
accusation — and the honest alert says so.

### 4.3 The relay-tenancy question, asked publicly

Nobody has published a clear answer to: when an orbital data center's traffic
transits a third-party relay constellation, what can the relay operator see?

You do not need hardware to ask it well. Read the FCC filings — SpaceX's is
public, ICFS File No. SAT-LOA-20260108-00016. Read the SDA Tranche 1 optical
standard. Write down what is specified, what is left to implementation, and
what is unanswered.

**A well-researched gap analysis of a public filing is a credible security
contribution**, and it is squarely on Watchdog's thesis: the customer cannot
see what the infrastructure operator can see.

### 4.4 The downlink-deferral audit

Published work optimises downlink scheduling for spacecraft energy. That
creates a structural incentive to defer a customer's data to a cheaper pass.
Whether any operator does this is unknown and checkable once contact
schedules and delivery timestamps are available.

---

## 5. What is buildable now versus what needs hardware

**Now, no hardware:** 227, 234, 245, 246, 247 and the whole of §4. These are
geometry and public weather data.

**Now, needs an operator relationship:** 226, 229, 231, 232, 236, 237, 239,
240, 241, 244, 248. All software against telemetry an operator already has.

**Needs orbital hardware:** 238 and any real validation of 249.

---

## 6. Stated honestly

Zero hardware in orbit. Nothing in this category has been built or validated.
The threat model is drawn entirely from peer-reviewed and preprint literature
cited inline, not from anything measured here.

Two specific limits worth stating before anyone else states them:

**The acquisition-spoofing modules rest on published probability models, not
on an observed attack.** No public report exists of a beaconless-PAT spoof
being executed. The geometry is real and the papers are real; the attack is
demonstrated in simulation.

**The site-diversity audit measures cloud, which is the dominant but not the
only outage cause.** Turbulence-induced outages are system-specific and
depend on orbit, aperture and adaptive optics. A cloud-based availability
model is a first-order bound, not a complete one, and must be compared
against a real system case by case.

That second caveat is why §4.1 is worth doing carefully rather than quickly.
A vendor whose availability claim is challenged will reach for exactly that
objection, and the analysis should have already conceded it.
