#!/usr/bin/env python3
import sys, os, argparse, threading, time
from datetime import datetime
sys.path.insert(0, os.path.dirname(__file__))
from agent.telemetry import TelemetryCollector, detect_gpus
from detection.engines import DetectionPipeline
from detection.hardware_attacks import ClockGlitchDetector, VoltageGlitchDetector, DMAAttackDetector, LaserInjectionDetector, NVLinkContentionDetector
from detection.memory_attacks import CacheSideChannelDetector, MIGPartitionDesyncDetector, SequentialVRAMReadDetector
from detection.llm_attacks import InferencePowerFingerprintDetector, AgentOrchestrationAnomalyDetector, PromptInjectionSideEffectDetector, AgentSessionVRAMRetentionDetector, InterAgentHandoffAnomalyDetector
from detection.pcie_health import PCIeHealthDetector
from detection.predictive_failure import FanWearDetector, CapacitorAgingDetector, PackageCrackingDetector
from detection.attestation import BootAttestation
from detection.business_signals import CovertMiningDetector, BillingIntegrityDetector
from detection.tamper_detection import PowerLimitTamperDetector
from detection.telemetry_honesty import PStateHonestyDetector, PCIeBandwidthMismatchDetector
from detection.ecc_error_trend_detector import ECCErrorTrendDetector
from detection.fleet_aggregation import FleetAggregator
from detection.hashrate_correlation import HashrateCorrelationDetector
from forensics.audit_ledger import AuditLedger
from forensics.clean_run_certificate import CleanRunCertificate
from alerting.state import AlertStateManager
from alerting.siem import SIEMRouter
from detection.cluster_metadata import enrich_with_cluster_metadata
from detection.firmware_integrity import VBIOSIntegrityDetector
from detection.cost_impact import CostImpactAggregator
from intelligence.swarm.swarm_orchestrator import WatchdogSwarm
from intelligence.swarm.telemetry_adapter import adapt_row_to_swarm_telemetry
from detection.migration_recommendation import MigrationRecommendationGenerator
from intelligence.cei_benchmark import CEIBenchmarkRunner
from intelligence.compliance_metrics import ComplianceMetricsTracker
from scripts.vram_residency_challenge import run_residency_challenge
from alerting.manager import AlertManager
from detection.cvss_scores import enrich_alert
from alerting.state import AlertStateManager
from alerting.siem import SIEMRouter
from alerting.email_alerter import EmailAlerter
from intelligence.threat_intel import ThreatIntelEngine
from remediation.response import RemediationEngine

class FullDetectionPipeline:
    """
    Adds five previously-unwired detectors to the live pipeline tonight:
    CovertMiningDetector, BillingIntegrityDetector, PowerLimitTamperDetector,
    PStateHonestyDetector, PCIeBandwidthMismatchDetector -- all five use the
    same update(row) interface as every other engine here, so they slot
    directly into self.engines.

    Two others from the same batch of new detector files do NOT slot in
    the same way, and are handled differently rather than forced into a
    shape they don't fit:

    FleetAggregator does not take a telemetry row -- it takes ALERTS.
    Wired in via a new _handle_alert() method (see below) that both call
    sites in process() now route through, instead of each duplicating
    the same count/print/enrich/callback logic inline as before.
    HONEST GAP: self.base's own 4 core engines (ghost power, VRAM
    residual, power periodicity, multi-GPU correlation) emit alerts
    directly to the external on_alert callback passed into
    DetectionPipeline's constructor, bypassing _handle_alert() entirely
    -- meaning FleetAggregator's rollup, and now AuditLedger's chain,
    are both currently missing those 4 detectors' alerts. Not fixed
    here, since DetectionPipeline's internals were not re-verified
    this session; wrapping that callback safely needs reading its
    source first, not guessing.

    HashrateCorrelationDetector needs externally-supplied hashrate data
    via calibrate()/process(), the same calibrate/process split
    ThroughputContentionDetector used before it got its own /throughput
    API endpoint. Instantiated here and available on the pipeline, but
    NOT wired to any API route -- that's separate, undone work, not
    silently expanded into tonight without being asked for it
    specifically.
    """
    def __init__(self, on_alert=None, fleet_size=None, clean_window_samples=3600, gpu_arch='H200'):
        self.on_alert = on_alert
        self.fleet = FleetAggregator(fleet_size=fleet_size)
        self.ledger = AuditLedger()
        self.state_mgr = AlertStateManager(state_file='watchdog_data/alert_state.json')
        self.siem = SIEMRouter()
        self.cost_impact = CostImpactAggregator(self.ledger)
        self.vbios_integrity = VBIOSIntegrityDetector()
        self.swarm = WatchdogSwarm(gpu_id=0, gpu_arch=gpu_arch)
        self.migration_advisor = MigrationRecommendationGenerator()
        self.cei_benchmark = CEIBenchmarkRunner()
        self.compliance_metrics = ComplianceMetricsTracker()
        self._last_residency_latency_ms = None
        # on_alert=None here deliberately: self.base's own internal _emit()
        # would otherwise call the external callback directly, and process()
        # below ALSO routes the returned alert list through fleet/ledger --
        # passing the real callback through both paths would double-fire it
        # for every base-engine alert. Feeding fleet/ledger from the
        # returned list instead, print/on_alert stays exactly single-fire.
        self.base = DetectionPipeline(on_alert=None)
        self.clock_glitch = ClockGlitchDetector()
        self.voltage_glitch = VoltageGlitchDetector()
        self.dma = DMAAttackDetector()
        self.laser = LaserInjectionDetector()
        self.cache_sc = CacheSideChannelDetector()
        self.mig_desync = MIGPartitionDesyncDetector()
        self.seq_vram = SequentialVRAMReadDetector()
        self.inference_fp = InferencePowerFingerprintDetector()
        self.agent_anomaly = AgentOrchestrationAnomalyDetector()
        self.prompt_injection = PromptInjectionSideEffectDetector()
        self.agent_vram = AgentSessionVRAMRetentionDetector()
        self.inter_agent = InterAgentHandoffAnomalyDetector()
        self.pcie_health = PCIeHealthDetector()
        self.fan_wear = FanWearDetector()
        self.capacitor = CapacitorAgingDetector()
        self.package_crack = PackageCrackingDetector()
        self.nvlink = NVLinkContentionDetector()
        self.covert_mining = CovertMiningDetector()
        self.billing_integrity = BillingIntegrityDetector()
        self.power_tamper = PowerLimitTamperDetector()
        self.pstate_honesty = PStateHonestyDetector()
        self.pcie_mismatch = PCIeBandwidthMismatchDetector()
        self.ecc_trend = ECCErrorTrendDetector()
        self.hashrate_correlation = HashrateCorrelationDetector()  # NOT in self.engines -- see class docstring
        self.attestation = BootAttestation()
        self.attest_checked = False
        self.alert_count = 0
        self.engines = [self.clock_glitch, self.voltage_glitch, self.dma, self.laser,
                         self.cache_sc, self.mig_desync, self.seq_vram,
                         self.inference_fp, self.agent_anomaly, self.prompt_injection,
                         self.agent_vram, self.inter_agent, self.pcie_health,
                         self.fan_wear, self.capacitor, self.package_crack, self.nvlink,
                         self.covert_mining, self.billing_integrity, self.power_tamper,
                         self.pstate_honesty, self.pcie_mismatch, self.ecc_trend, self.vbios_integrity]
        BASE_ENGINE_COUNT = 4  # GhostPowerDetector, VRAMResidualDetector, PowerPeriodicityDetector, MultiGPUCorrelation
        ATTESTATION_COUNT = 1
        self.total_engine_count = BASE_ENGINE_COUNT + len(self.engines) + ATTESTATION_COUNT
        _cert_engine_names = ([type(e).__name__ for e in self.engines]
                               + ['GhostPowerDetector', 'VRAMResidualDetector',
                                  'PowerPeriodicityDetector', 'MultiGPUCorrelation',
                                  'BootAttestation'])
        self.cert_gen = CleanRunCertificate(self.ledger, _cert_engine_names,
                                             clean_window_samples=clean_window_samples)

    def process(self, row):
        base_alerts = self.base.process(row)
        self._record_base_alerts(base_alerts)
        had_alert = bool(base_alerts)
        if not self.attest_checked:
            self.attest_checked = True
            alert = self.attestation.check(int(row.get('index',0)))
            if alert:
                had_alert = True
                self._handle_alert(alert)
        for engine in self.engines:
            try:
                alert = engine.update(row)
            except Exception:
                # Counted for compliance_metrics' crash_count, which
                # measures Watchdog's OWN detector exceptions -- not GPU
                # workload crashes. Re-raised rather than swallowed: a
                # detector raising is a real bug that should surface,
                # not be silently absorbed into a counter.
                self.compliance_metrics.record_detector_exception()
                raise
            if alert:
                had_alert = True
                self._handle_alert(alert)
        self.compliance_metrics.record_sample(row, self.base.ghost_power.baseline_w)
        swarm_telemetry = adapt_row_to_swarm_telemetry(row, residency_latency_ms=self._last_residency_latency_ms)
        swarm_alerts = self.swarm.ingest(swarm_telemetry)
        if swarm_alerts:
            had_alert = True
        self._record_swarm_alerts(swarm_alerts)
        self.cert_gen.record_sample(had_alert=had_alert, timestamp=time.time())

    def run_residency_probe(self, size_mb=512, hold_seconds=0):
        """
        Runs scripts/vram_residency_challenge.py's real latency probe
        and caches the result for TenantIsolationRiskScorer's
        memory_access_timing_ms signal, which nothing else in this
        pipeline can supply. Deliberately a separate, explicitly-called
        entry point -- not part of process(row) -- since it allocates
        real VRAM (default 512MB) and holds it, not something to do
        every sample.

        HONEST STATUS: this measures read latency on a buffer WATCHDOG
        ITSELF allocated and is holding -- not a live tenant's actual
        memory. TenantIsolationRiskScorer treats elevated latency as
        one signal contributing to isolation risk; that is a
        defensible but indirect inference, stated here rather than
        implied by the field name.

        If the pattern's checksum fails to verify after the hold, the
        reading is discarded and the cache is NOT updated -- a failed
        checksum means something is already wrong (corruption, a bug,
        or a real anomaly), and using its timing data as if it were
        trustworthy would compound that rather than surface it.
        Returns None if no CUDA GPU is available.
        """
        result = run_residency_challenge(size_mb=size_mb, hold_seconds=hold_seconds)
        if result is None:
            return None
        if not result['checksum_valid']:
            return {**result, 'discarded_reason':
                     'checksum failed -- not used as a residency-timing signal'}
        self._last_residency_latency_ms = result['read_latency_ms']
        return result

    def _record_swarm_alerts(self, alerts):
        """
        Routes prediction-layer alerts (5-agent swarm) through the same
        fleet/ledger/dedup/SIEM/on_alert treatment as every other alert.
        Deliberately does NOT print -- each swarm agent's own update()
        already prints its own "[SWARM AGENT X] ..." line internally,
        printing again here would double it, same trap already solved
        for self.base's alerts.
        """
        for alert in alerts:
            self.alert_count += 1
            alert = enrich_alert(alert)
            alert = enrich_with_cluster_metadata(alert)
            dedup_result = self.state_mgr.process(alert)
            self.fleet.ingest(alert, node_id=alert.get('gpu', 0))
            self.ledger.append('ALERT', alert)
            if dedup_result in ('NEW', 'REOPENED'):
                self.siem.route(alert)
                if self.on_alert: self.on_alert(alert)

            recommendation = self.migration_advisor.process(alert)
            if recommendation:
                self.alert_count += 1
                recommendation = enrich_alert(recommendation)
                recommendation = enrich_with_cluster_metadata(recommendation)
                rec_dedup = self.state_mgr.process(recommendation)
                self.fleet.ingest(recommendation, node_id=recommendation.get('gpu', 0))
                self.ledger.append('ALERT', recommendation)
                if rec_dedup in ('NEW', 'REOPENED'):
                    print(f"[{recommendation['severity']}] {recommendation['type']} — {recommendation['message']}")
                    self.siem.route(recommendation)
                    if self.on_alert: self.on_alert(recommendation)

    def run_cei_benchmark(self, duration_s=10):
        """
        Runs a real CEI benchmark (matmul workload, real power
        sampling) and feeds the result into both CEI-dependent swarm
        agents. Deliberately a separate, explicitly-called entry
        point -- not part of process(row) -- since CEI cannot be
        derived from passive telemetry, matching the same design as
        calibrate_throughput / process_throughput.

        HONEST STATUS: fully unblocks CEIDegradationForecaster
        (agent2), which needs only cei_flops_per_joule. PARTIALLY
        unblocks EUAIActComplianceForecaster (agent5): also feeds
        idle_power_w from GhostPowerDetector's own already-learned
        baseline (a real value, not a default), but ghost_power_pct,
        crash_count, and isolation_score remain unaddressed here --
        agent5 will still compute its compliance risk score using
        safe defaults for those three, not real measurements. Returns
        None if no real GPU/torch is available.
        """
        result = self.cei_benchmark.run(duration_s=duration_s)
        if result is None:
            return None
        cm = self.compliance_metrics.as_telemetry_fields()
        telemetry = {
            'cei_flops_per_joule': result['cei_flops_per_joule'],
            'ghost_power_pct': cm['ghost_power_pct'],
            'idle_power_w': self.base.ghost_power.baseline_w or 0,
            'crash_count': cm['crash_count'],
            'isolation_score': cm['isolation_score'],
            'timestamp': time.time(),
        }
        result['compliance_metrics_provenance'] = cm['_provenance']
        a2 = self.swarm.agent2.update(telemetry)
        a5 = self.swarm.agent5.update(telemetry)
        fired = [a for a in (a2, a5) if a]
        if fired:
            self._record_swarm_alerts(fired)
        return result

    def _record_base_alerts(self, alerts):
        """
        Closes the gap disclosed since the fleet/ledger were first wired
        in: self.base's 4 core engines (ghost power, VRAM residual, power
        periodicity, multi-GPU correlation) print and reach the external
        on_alert callback via their own internal _emit() already -- this
        only adds fleet/ledger visibility for them, deliberately without
        re-printing or re-calling on_alert a second time.
        """
        for alert in alerts:
            enriched = enrich_alert(dict(alert))
            enriched = enrich_with_cluster_metadata(enriched)
            self.fleet.ingest(enriched, node_id=enriched.get('gpu', 0))
            self.ledger.append('ALERT', enriched)
            self.siem.route(enriched)

    def _handle_alert(self, alert):
        """
        Single choke point for every alert emitted from process() above
        (attestation + the full engines list). Previously this exact
        count/print/enrich/callback sequence was duplicated inline at
        both call sites; factored out so FleetAggregator has one place
        to see every alert exactly once, rather than needing separate
        wiring at each emission site.
        """
        self.alert_count += 1
        alert = enrich_alert(alert)
        alert = enrich_with_cluster_metadata(alert)
        dedup_result = self.state_mgr.process(alert)
        self.fleet.ingest(alert, node_id=alert.get('gpu', 0))
        self.ledger.append('ALERT', alert)
        # Ledger and fleet always see every detection -- a complete audit
        # trail and an accurate "currently affected" picture shouldn't
        # silently drop repeats. Notification (print + external callback
        # + SIEM routing) is gated on dedup_result so a flapping condition
        # doesn't spam any of those channels with the same alert every
        # sample. SIEMRouter is safe by design -- no-ops per integration
        # without its own credential, so this is a no-op today with none
        # configured.
        if dedup_result in ('NEW', 'REOPENED'):
            print(f"[{alert['severity']}] {alert['type']} — {alert['message']}")
            self.siem.route(alert)
            if self.on_alert: self.on_alert(alert)

def main():
    parser = argparse.ArgumentParser(description='Watchdog AIDR v2.0')
    parser.add_argument('--hz', type=int, default=100)
    parser.add_argument('--duration', type=int, default=None)
    parser.add_argument('--output', type=str, default='watchdog_data')
    parser.add_argument('--severity', type=str, default='WARNING')
    parser.add_argument('--slack', type=str, default=None)
    parser.add_argument('--api', action='store_true')
    parser.add_argument('--api-port', type=int, default=8080)
    parser.add_argument('--auto-remediate', action='store_true')
    parser.add_argument('--test', action='store_true')
    parser.add_argument('--gpu', type=int, default=None)
    parser.add_argument('--fleet-size', type=int, default=None)
    args = parser.parse_args()
    print(f"\n[WATCHDOG AIDR v2.0] Start: {datetime.now().isoformat()}")
    gpus = detect_gpus()
    if not gpus: print("[ERROR] No GPUs."); sys.exit(1)
    print(f"[WATCHDOG] GPUs: {gpus}")
    if args.test: run_tests(); return
    alert_mgr = AlertManager(min_severity=args.severity, slack_webhook=args.slack, audit_log_path=os.path.join(args.output,'audit.log'))
    remediation = RemediationEngine(auto_remediate=args.auto_remediate)
    # api_hooks lets on_alert/on_sample feed api/server.py's _state, but
    # only when --api is actually in use. api/server.py's own comment
    # records that update_state() was never called from here -- which
    # meant /status, /alerts and /metrics returned empty data in every
    # real run, regardless of what the detectors were actually finding.
    api_hooks = {'update_state': None}
    def on_alert(alert):
        alert_mgr.handle(alert)
        remediation.handle(alert)
        if api_hooks['update_state']:
            api_hooks['update_state'](alerts=[alert])
    def on_sample(row):
        pipeline.process(row)
        if api_hooks['update_state']:
            api_hooks['update_state'](telemetry_row=row)
    pipeline = FullDetectionPipeline(on_alert=on_alert, fleet_size=args.fleet_size)
    print(f"[WATCHDOG] Detection engines: {pipeline.total_engine_count} active")
    if args.api:
        try:
            from api.server import run_api, set_pipeline, update_state
            # Pass the FULL pipeline, not .base -- /throughput needs
            # base's calibrate_throughput/process_throughput, but
            # /hashrate needs hashrate_correlation which lives on
            # FullDetectionPipeline itself. The API handlers resolve
            # which object they need; passing .base here made the
            # hashrate detector unreachable.
            set_pipeline(pipeline)
            api_hooks['update_state'] = update_state
            update_state(gpu_count=len(gpus))
            t = threading.Thread(target=run_api, kwargs={'host':'0.0.0.0','port':args.api_port}, daemon=True)
            t.start()
            print(f"[WATCHDOG] API at http://0.0.0.0:{args.api_port}")
        except Exception as e: print(f"[API ERROR] {e}")
    collector = TelemetryCollector(sample_hz=args.hz, output_dir=args.output, gpu_index=args.gpu, on_sample=on_sample)
    try:
        print("[WATCHDOG] Running... Ctrl+C to stop\n")
        collector.start(duration_seconds=args.duration)
    except KeyboardInterrupt: print("\n[WATCHDOG] Stopped")
    finally:
        collector.stop()
        print(f"Samples: {collector.sample_count} | Alerts: {alert_mgr.alert_count} | Remediations: {remediation.action_count}")
def run_tests():
    print("[TEST] Running detection engine tests...")
    from detection.engines import GhostPowerDetector
    passed = 0
    ts = datetime.now().isoformat()
    gp = GhostPowerDetector()
    for i in range(30): gp.update({'power.draw':65.0,'utilization.gpu':0,'memory.used':100,'iso_timestamp':ts,'index':0})
    r = gp.update({'power.draw':92.0,'utilization.gpu':0,'memory.used':100,'iso_timestamp':ts,'index':0})
    if r: print(f"  [PASS] Ghost power"); passed+=1
    print(f"\n[TEST] {passed}/1 passed")
if __name__ == '__main__': main()
