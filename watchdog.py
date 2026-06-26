#!/usr/bin/env python3
import sys, os, argparse, threading, time
from datetime import datetime
sys.path.insert(0, os.path.dirname(__file__))
from agent.telemetry import TelemetryCollector, detect_gpus
from detection.engines import DetectionPipeline
from detection.hardware_attacks import ClockGlitchDetector, VoltageGlitchDetector, DMAAttackDetector, LaserInjectionDetector
from detection.memory_attacks import CacheSideChannelDetector, MIGPartitionDesyncDetector, SequentialVRAMReadDetector
from detection.llm_attacks import InferencePowerFingerprintDetector, AgentOrchestrationAnomalyDetector, PromptInjectionSideEffectDetector, AgentSessionVRAMRetentionDetector, InterAgentHandoffAnomalyDetector
from detection.pcie_health import PCIeHealthDetector
from detection.predictive_failure import FanWearDetector, CapacitorAgingDetector, PackageCrackingDetector
from detection.attestation import BootAttestation
from alerting.manager import AlertManager
from remediation.response import RemediationEngine

class FullDetectionPipeline:
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
        self.attestation = BootAttestation()
        self.attest_checked = False
        self.alert_count = 0
    def process(self, row):
        self.base.process(row)
        if not self.attest_checked:
            self.attest_checked = True
            alert = self.attestation.check(int(row.get('index',0)))
            if alert:
                self.alert_count += 1
                print(f"[{alert['severity']}] {alert['type']} — {alert['message']}")
                if self.on_alert: self.on_alert(alert)
        engines = [self.clock_glitch, self.voltage_glitch, self.dma, self.laser,
                   self.cache_sc, self.mig_desync, self.seq_vram,
                   self.inference_fp, self.agent_anomaly, self.prompt_injection, self.agent_vram, self.inter_agent,
                   self.pcie_health, self.fan_wear, self.capacitor, self.package_crack]
        for engine in engines:
            alert = engine.update(row)
            if alert:
                self.alert_count += 1
                print(f"[{alert['severity']}] {alert['type']} — {alert['message']}")
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
    print(f"[WATCHDOG] Detection engines: 20 active")
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
    if args.api:
        try:
            from api.server import run_api
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
