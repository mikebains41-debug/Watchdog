# Watchdog — Optical Interconnect Integrity (OPT category)

**Terrestrial optical networking inside AI data centers: transceivers, linear
pluggable optics, co-packaged optics, and the fibre between them.**

Companion to Space Category O (orbital laser links). That file covers light
between satellites and ground stations. This one covers light between GPUs.

Modules use an `OPT-` prefix rather than a number, deliberately: the repo
already has overlapping numbered namespaces (1–130, Vera/Rubin 131–226, space
1–250, subsea 1–150), and adding another numeric range invites collisions.

Status flags as elsewhere: `[PHYSICS]` `[BUILD]` `[HW-ONLY]` `[UNVERIFIED]`
`[WHITE-HAT]`. **`[BUILT]`** marks the one item in this file that exists as
code: `scripts/optical_transceiver_audit.py`.

---

## 1. Why now, and why it isn't early

Paul's point about the fibre boom is right for orbital. It does not apply to
optics inside the data center, because this part has already arrived.

**NVIDIA.** Spectrum-X Ethernet Photonics — co-packaged optics on the switch
ASIC — moved into full production in August 2026, with NVIDIA claiming 4x
fewer lasers, 5x lower power and 10x higher mean time between incidents, built
across a named five-vendor supply chain, and timed to network Vera Rubin as it
ships this fall (StorageReview, 15 Aug 2026). The InfiniBand version,
Quantum-X Photonics, was deployed in production by Lambda alongside GB300
NVL72 in June 2026 (Glenn Lockwood's notes). The Quantum-X package combines 18
silicon photonics engines — 324 optical connections and 288 data links from 36
laser inputs — using 200 Gb/s micro-ring modulators on TSMC's COUPE process
(optics.org, Mar 2025). Lumentum supplies lasers; Coherent, Corning, Foxconn
and SENKO are named partners.

**AMD.** Acquired silicon-photonics startup Enosemi in May 2025, has invested
in Celestial AI through AMD Ventures, and reportedly set up a ~$280M silicon
photonics hub in Taiwan (Tom's Hardware, Oct 2025, "reportedly"). Forum
rumours say AMD chose micro-ring modulators like NVIDIA; treat that as
unconfirmed.

**Huawei.** CloudMatrix 384 runs its entire scale-up fabric over optics:
roughly 6,912 linear pluggable (LPO) transceivers across 16 racks — 400G each
in SemiAnalysis's accounting, 800G in some reports — joining 384 Ascend 910C
chips all-to-all. It trades efficiency for scale, and optics specialists have
flagged LPO reliability at that volume as a concern.

**The historical warning built into this.** NVIDIA announced a DGX H100
NVL256 "Ranger" platform in 2022 and never shipped it — too expensive, too
power-hungry, and unreliable because of the sheer number of optical
transceivers it needed (SemiAnalysis). Optics at scale is where reliability
goes to die. That is the opening for monitoring.

**Scale of the problem, with honest sourcing:**

- Meta, Llama 3 405B: 419 unexpected interruptions in 54 days on 16,384 H100s;
  network switch and cable issues caused 35 of them, 8.4% (Llama 3 paper,
  reported by DCD/SDxCentral). This is primary data.
- A 2026 arXiv paper (2603.03736) models that at ~3M GPUs and >10M optical
  links, a link flap happens somewhere in the fabric every 48 seconds, and
  argues every existing timeout-based mitigation still produces gray failures.
  Modelled, not measured.
- Transceiver vendors cite Huawei figures claiming the large majority of AI
  cluster failures are optical, and that dirty connectors rather than the
  modules themselves are the primary cause (Naddod, QSFPTEK). **These come
  from companies selling transceivers and conflict with Meta's 8.4%.** Use
  Meta's number externally.

---

## 2. The telemetry gap — Watchdog's thesis, applied to light

Same pattern as ghost power: the instrument reports normal while something
else is true. Four specific gaps.

**G1 — DOM accuracy is too coarse for absolute thresholds.** Pluggable optics
report temperature, voltage, laser bias, Tx power and Rx power (SFF-8472 /
SFF-8636 / CMIS "digital optical monitoring"). Typical datasheet accuracy:
±3 °C, ±2 to ±3 dB on optical power, ±10% on bias. A 1 dB loss is inside the
error bar of a single absolute reading.
**Consequence:** detect change against *this module's own learned baseline*,
never against a fixed number. Repeatability on one module is far better than
accuracy across modules. This is exactly the lesson of GhostPowerDetector's
learned idle floor, and of the context-alive false positive found this week.

**G2 — a failed DOM read looks like dark fibre.** A module whose diagnostics
fail to read can return 0 mW (−inf dBm), 0 °C and 0 V — indistinguishable from
"no light" unless you check whether *everything* went to zero at once. Seen in
the SONiC issue tracker on real hardware.

**G3 — LPO removes the DSP and the diagnostics with it.** Hyperscalers have
said plainly that they are concerned about reduced diagnostic visibility in
LPO compared with DSP-based retimed modules (Lightwave, Jul 2025); vendors
answer with TX/RX LOS, loss-of-modulation and host-side eye monitoring. LPO is
not a drop-in replacement and carries risk in mixed-vendor environments with
limited telemetry (Axiom LPO guide).

**G4 — CPO moves the optics off the faceplate.** In co-packaged optics the
optical engines sit beside the switch silicon and the lasers become separate
pluggable light sources (Quantum-X shows 18 of them). The per-port pluggable
module that `ethtool -m` reads today stops existing in that form. Telemetry
moves into switch management. Micro-ring modulators are thermally sensitive —
packaging engineers describe controlling optical-device temperature to a tenth
of a degree (Semiconductor Engineering). **Where CPO health telemetry is
exposed, and how honestly, is unconfirmed until tested on a CPO switch.**

---

## 3. Threats, with what each one looks like in telemetry

**T1 — Fibre tapping.** Two very different classes, and the difference must be
stated in every alert.
- *Crude taps are power-visible.* Bend couplers introduce up to about 1 dB of
  loss, and power-measuring intrusion detection exists for exactly this
  (multiple fibre-intrusion patents). Commercial passive TAPs quote insertion
  loss as low as 1.3 dB (Network Critical).
- *Skilled taps are not.* A cladding-coupling tap — polishing the cladding and
  coupling evanescent light — can take light 20–30 dB below the core signal,
  a received-power change of only 0.04 or 0.004 dB, "impossible to detect
  reliably by power measurement methods" (same patent family). OTDR and
  polarization monitoring are the tools for that class; DOM is not.
  **Watchdog will catch the first class and must say it cannot catch the
  second.**

**T2 — Dirty or damaged connectors.** Not an attack, but the most common real
cause of the same signature as T1: an Rx power drop. OTDR Fresnel peaks locate
it. Every Rx-drop alert has to name this first.

**T3 — Counterfeit and gray-market modules.** Module identity lives in an
EEPROM that can be programmed to say anything, so identity alone cannot prove
authenticity. Behaviour can hint: one integrator describes failing gray-market
modules whose laser bias climbed ~2% week over week before failure (LINK-PP,
vendor blog — anecdote, not data). Bias drift against a baseline is a real,
cheap signal regardless of cause.

**T4 — In-service transceiver firmware changes.** CMIS 4.0 onward defines a
standard mechanism to update transceiver firmware without removing the module
(Arista), with a start/write-blocks/run/commit sequence (NXP AN15071, Jul
2026). A microcontroller with updatable code sits in the data path of every
link. Whether a given module authenticates images is vendor-specific and not
something this file can assert either way. What Watchdog *can* see is the
firmware version changing on a module whose serial number did not — the same
pattern as `VBIOSIntegrityDetector`.

**T5 — Gray failures and flaps.** A link that degrades without failing — rising
corrected-FEC counts, marginal Rx power — stalls synchronous training without
tripping a hard alarm. That is the ghost-power problem in network form.

---

## 4. Modules

### OPT-A — Transceiver health (pluggables, including LPO)

| Module | Function |
|---|---|
| `OPT-RxPowerBaselineDrop` | Rx power falling against this module's own learned baseline. Names dirty connector first, fibre bend second, inline TAP third, and states that skilled cladding taps are invisible to it. `[BUILT]` |
| `OPT-DomReadFailureDiscriminator` | Separates "no light" from "diagnostics failed to read" by checking whether every DOM field collapsed to zero together. `[BUILT]` |
| `OPT-LaserBiasDrift` | Bias current rising against baseline — laser aging, thermal interface degradation, or a bad batch. Cause not attributed. `[BUILT]` |
| `OPT-TxPowerDecay` | This module's own transmitter weakening. Distinguishes "my laser is fading" from "the light arriving is fading". `[BUILT]` |
| `OPT-ModuleThermalRise` | Module temperature rising against baseline. `[BUILT]` |
| `OPT-ModuleAlarmPassthrough` | Surfaces the module's own threshold alarms, which most monitoring stacks never read. `[BUILT]` |
| `OPT-ModuleIdentityChange` | Serial number changed on a port: a swap. Re-baselines rather than raising a false Rx-drop against the old module. `[BUILT]` |
| `OPT-FirmwareChangeSameSerial` | Firmware version changed while the serial did not: an in-service CMIS update happened. Confirm it against a change record. `[BUILT]` |
| `OPT-BlankIdentity` | Empty vendor/part/serial fields. States that EEPROM contents cannot prove or disprove authenticity. `[BUILT]` |
| `OPT-FecCorrectedTrend` | Corrected-FEC counts rising: the link is working harder to stay up. Uncorrectable increments escalate. Best-effort — counter names vary by NIC. `[BUILT]` |

### OPT-B — Fabric level

| Module | Function |
|---|---|
| `OPT-FlapStormCorrelator` | Correlates flaps across ports sharing a patch panel, trunk or switch — one physical cause, many alerts. Plugs into the existing correlation layer. `[BUILD]` |
| `OPT-GrayFailureToStallCorrelator` | Joins marginal-link telemetry to NCCL stragglers and collective-op slowdowns already measured by the SDC tracer. `[BUILD]` |
| `OPT-BothEndsAgreement` | Compares each end of a link: my Tx against your Rx. A drop visible at one end only localises the fault. Needs both ends' telemetry. `[BUILD]` |

### OPT-C — Co-packaged optics

| Module | Function |
|---|---|
| `OPT-ExternalLaserSourceHealth` | Per-light-source power and bias on CPO switches, where one laser feeds many channels — one failing source is many degraded links. `[HW-ONLY]` |
| `OPT-MicroringThermalLock` | Micro-ring modulators must be held on resonance thermally; drift is a precursor. Depends on what the switch exposes. `[HW-ONLY][UNVERIFIED]` |
| `OPT-CpoTelemetryHonestyCheck` | Whether the switch's reported optical health is internally consistent with delivered link quality. The ghost-power question asked of a CPO switch. `[HW-ONLY]` |

**Remediation for all of OPT:** log and recommend. Clean and inspect both
end-faces, reseat, OTDR the span, confirm a firmware change against the change
log. Nothing disables a port or resets a module automatically. Same human gate
as every other remediation in Watchdog.

---

## 5. White-hat programme

**5.1 — `scripts/optical_transceiver_audit.py` (built).** Read-only. Runs
`ethtool -m` and optionally `ethtool -S` per physical interface, parses DOM
for SFP, QSFP and CMIS modules, keeps a per-module baseline in a local JSON
file, and reports every finding above with what it cannot distinguish. Never
writes to a module. Timeouts on every call, so it cannot hang the way
module56 did. On a phone, cloud VM or container it reports
`NO_OPTICAL_MODULES_FOUND` and says why that is expected.
**Validated against fixtures only.** Not yet run on a host with real optics.

**5.2 — Integrate, don't rebuild.** Existing open-source exporters already
scrape DOM into Prometheus: `wobcom/transceiver-exporter` (Go, ethtool-based,
exports firmware version and date code), `Showmax/prometheus-ethtool-exporter`
(Python), SONiC's `xcvrd` with its `TRANSCEIVER_DOM_THRESHOLD` table and
CMIS/C-CMIS fields, `kamelnetworks/sonic_exporter`, and
`sonix-network/dc908_exporter` for Huawei OptiXtrans DWDM gear over gNMI.
None of them learn a per-module baseline, discriminate read failure from dark
fibre, or state what an alert cannot tell apart. That is the layer Watchdog
adds on top.

**5.3 — What to test first on real hardware.** Any rented bare-metal host with
a pluggable optical NIC: baseline for an hour, then unplug and clean a
connector and confirm the Rx-drop fires and names the connector. Then swap a
module and confirm identity-change fires and the Rx-drop does not. That is a
positive and a negative control, which is the minimum before any number from
this goes in a README.

---

## 6. Stated honestly

- One item here is code, validated on fixtures. Everything else is design.
- DOM accuracy of ±2–3 dB means absolute thresholds are meaningless; the whole
  approach depends on per-module baselines, which need hours of history first.
- Power monitoring catches crude taps and dirty connectors. It cannot catch a
  skilled cladding-coupling tap, and every alert says so.
- EEPROM identity cannot prove authenticity.
- The CPO modules depend on telemetry nobody has confirmed is exposed.
- The most-quoted "optics cause most AI failures" figures come from companies
  that sell optics. Meta's 8.4% is the defensible number.
