# Watchdog — Unimplemented Backlog

Everything researched but not yet built, grouped by what unblocks it.
Nothing here is claimed as working. Items move out of this file only
when they have a real test result and a commit hash.

---

## A. Capability check first — one pod session answers all four

These are detectors that CANNOT be written until we confirm the
telemetry fields actually exist on real hardware. Writing them blind
would be guessing. Run a single rented B200/H200 session, probe for
each field, THEN build only the ones whose data is reachable.

- [ ] **TLB covert channel** — does NVML expose TLB miss counters?
      (AsiaCCS 2021; J. Hardware & Systems Security 2025)
- [ ] **Cache eviction priority side channel** — are those perf
      counters readable? (IEEE/ACM MICRO, October 2025)
- [ ] **GPU.zip compression channel** — likely needs driver
      interception, may be unreachable from NVML entirely
      (IEEE S&P 2024)
- [ ] **Improved micro-architectural covert channel**
      (Baddour et al., J. Hardware & Systems Security, September 2025)

---

## B. Hardware-gated — needs a real GPU

- [ ] **Same-GPU cross-tenant PoC** — demonstrate Process B reading
      Process A's residual data. THE single highest-value open item in
      the project. Turns the confirmed "accounting gap" into a provable
      security finding.
- [ ] **Hypervisor boundary verification** — reproduce the 528MB
      GPU0→GPU1 residual on bare RunPod. Currently one measurement,
      inside a Serial Alice CVM, never reproduced.
- [ ] **Remediation end-to-end test** — kubernetes_taint,
      slurm_evict_job, nvlink_disable are documented and gated but never
      proven to actually execute. Needs a real K8s cluster or SLURM
      scheduler, not a plain pod.
- [ ] **Model weight extraction via inference timing side channel**
- [ ] **NVLink live-fire confirmation on 2× GPU** — three bugs fixed,
      rate math verified (~2.95M KB/s), never confirmed firing
      end-to-end.

---

## C. Adjacent domains — nothing built

All documented in Watchdog-quantum-collab
`results/RESEARCH_FINDINGS_2026_08.md`.

**Quantum**
- [ ] Qubit crosstalk Rowhammer (U. Gdansk, arXiv Mar 2025, demonstrated
      on IBM hardware)
- [ ] Pulse-level circuit tampering (IEEE S&P 2025)
- [ ] SWAP attack (IEEE QCE 2025)
- [ ] Readout crosstalk end-to-end attack (ACM QSP Workshop 2025)

**Subsea**
- [ ] Acoustic injection on HDD resonant frequencies (U. Florida 2024)
- [ ] Distributed acoustic sensing interface (SeaSEC 2025)

**Orbital**
- [ ] SEU monitoring calibrated against Google Trillium 67 MeV proton
      beam results (June 2026)
- [ ] Satellite ransomware detection (SpaceSec 2026)
- [ ] Sensor spoofing via supply-chain implants

**Facility**
- [ ] Neutral-current harmonic PDU detector

---

## D. Already built — do not rebuild

As of August 2026, committed to the main Watchdog repo:

- ECCAnomalyDetector (GPUHammer/Rowhammer)
- ThermalSideChannelDetector (Hot Pixels)
- PCIeAnomalyDetector (Invisible Probe / LockedDown)
- NVIDIAContainerToolkitCVEChecker (CVE-2025-23266)
- ContextSwitchTimingDetector (Leaky DNN)
- BMCExposureDetector (Black Hat USA 2026)
- ShadowInitPackageIntegrityDetector (ShadowInit Dec 2025)
- tenant_file_cleaner (PART 1 of REMEDIATION_CLEARING_PLAN)
- action_switch — the Watchdog Switch (per-action promotion registry)
- SideLink citation added to NVLinkContentionDetector docstring
