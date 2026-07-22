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
from alerting.manager import AlertManager
from detection.cvss_scores import enrich_alert
from alerting.state import AlertStateManager
from alerting.siem import SIEMRouter
from alerting.email_alerter import EmailAlerter
from intelligence.threat_intel import ThreatIntelEngine
from remediation.response import RemediationEngine

class FullDetectionPipeline:
    """
    FIXED vs. original:
      - The startup print "Detection engines: 17 active" was a hardcoded
        constant that silently went stale every time a detector was
        added or removed (it was already wrong before tonight's NVLink
        addition -- the real count was always 21, since the 4 base-
        pipeline engines in self.base were never counted). Replaced with
        self.total_engine_count, computed once here from the real list,
        so it cannot drift out of sync again.
      - The engines list was previously rebuilt from scratch on every
        single process() call (once per telemetry sample, i.e.
        potentially 100+ times/second) -- wasteful, not incorrect. Now
        built once in __init__ and stored as self.engines.
      - Added NVLinkContentionDetector. It is REAL and ACTIVE in this
        pipeline -- but requires row['nvlink_available'],
        row['nvlink_tx_kbs'], row['nvlink_rx_kbs'], which
        agent/telemetry.py's sample_gpu() does NOT currently populate
        (deliberately -- see sample_nvlink()'s own docstring on the
        subprocess-per-GPU cost of calling it every sample). This
        detector will stay silent, correctly and safely, until NVLink
        telemetry collection is separately wired into the collection
        loop. Counted honestly in total_engine_count, not hidden --
        this gap is real and still open.
    """
    def __init__(self, on_alert=None):
        self.on_alert = on_alert
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
        self.attestation = BootAttestation()
        self.attest_checked = False
        self.alert_count = 0
        self.engines = [self.clock_glitch, self.voltage_glitch, self.dma, self.laser,
                         self.cache_sc, self.mig_desync, self.seq_vram,
                         self.inference_fp, self.agent_anomaly, self.prompt_injection,
                         self.agent_vram, self.inter_agent, self.pcie_health,
                         self.fan_wear, self.capacitor, self.package_crack, self.nvlink]
        BASE_ENGINE_COUNT = 4  # GhostPowerDetector, VRAMResidualDetector, PowerPeriodicityDetector, MultiGPUCorrelation
        ATTESTATION_COUNT = 1
        self.total_engine_count = BASE_ENGINE_COUNT + len(self.engines) + ATTESTATION_COUNT

    def process(self, row):
        self.base.process(row)
        if not self.attest_checked:
            self.attest_checked = True
            alert = self.attestation.check(int(row.get('index',0)))
            if alert:
                self.alert_count += 1
                print(f"[{alert['severity']}] {alert['type']} — {alert['message']}")
                alert = enrich_alert(alert)
                if self.on_alert: self.on_alert(alert)
        for engine in self.engines:
            alert = engine.update(row)
            if alert:
                self.alert_count += 1
                print(f"[{alert['severity']}] {alert['type']} — {alert['message']}")
                alert = enrich_alert(alert)
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
    pipeline = FullDetectionPipeline(on_alert=on_alert)
    print(f"[WATCHDOG] Detection engines: {pipeline.total_engine_count} active")
    if args.api:
        try:
            from api.server import run_api, set_pipeline
            # FIXED: the API previously had no reference to the running
            # pipeline at all -- /throughput could never actually reach
            # ThroughputContentionDetector. set_pipeline() takes the base
            # DetectionPipeline (not FullDetectionPipeline itself -- the
            # throughput methods live on .base), so calibrate/process
            # calls through the API reach the real, live detector.
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
