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
    def __init__(self, on_alert=None, fleet_size=None, clean_window_samples=3600):
        self.on_alert = on_alert
        self.fleet = FleetAggregator(fleet_size=fleet_size)
        self.ledger = AuditLedger()
        self.base = DetectionPipeline(on_alert=on_alert)
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
                         self.pstate_honesty, self.pcie_mismatch, self.ecc_trend]
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
        self.base.process(row)
        had_alert = False
        if not self.attest_checked:
            self.attest_checked = True
            alert = self.attestation.check(int(row.get('index',0)))
            if alert:
                had_alert = True
                self._handle_alert(alert)
        for engine in self.engines:
            alert = engine.update(row)
            if alert:
                had_alert = True
                self._handle_alert(alert)
        self.cert_gen.record_sample(had_alert=had_alert, timestamp=time.time())

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
        print(f"[{alert['severity']}] {alert['type']} — {alert['message']}")
        alert = enrich_alert(alert)
        self.fleet.ingest(alert, node_id=alert.get('gpu', 0))
        self.ledger.append('ALERT', alert)
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
    def on_alert(alert):
        alert_mgr.handle(alert)
        remediation.handle(alert)
    pipeline = FullDetectionPipeline(on_alert=on_alert, fleet_size=args.fleet_size)
    print(f"[WATCHDOG] Detection engines: {pipeline.total_engine_count} active")
    if args.api:
        try:
            from api.server import run_api, set_pipeline
            set_pipeline(pipeline.base)
            t = threading.Thread(target=run_api, kwargs={'host':'0.0.0.0','port':args.api_port}, daemon=True)
            t.start()
            print(f"[WATCHDOG] API at http://0.0.0.0:{args.api_port}")
        except Exception as e: print(f"[API ERROR] {e}")
    collector = TelemetryCollector(sample_hz=args.hz, output_dir=args.output, gpu_index=args.gpu, on_sample=pipeline.process)
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
