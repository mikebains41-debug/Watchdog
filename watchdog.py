#!/usr/bin/env python3
import sys, os, argparse, threading, time
from datetime import datetime
sys.path.insert(0, os.path.dirname(__file__))
from agent.telemetry import TelemetryCollector, detect_gpus
from detection.engines import DetectionPipeline
from alerting.manager import AlertManager
def main():
    parser = argparse.ArgumentParser(description='Watchdog AIDR — GPU Security')
    parser.add_argument('--hz', type=int, default=100)
    parser.add_argument('--duration', type=int, default=None)
    parser.add_argument('--output', type=str, default='watchdog_data')
    parser.add_argument('--severity', type=str, default='WARNING')
    parser.add_argument('--slack', type=str, default=None)
    parser.add_argument('--api', action='store_true')
    parser.add_argument('--api-port', type=int, default=8080)
    parser.add_argument('--test', action='store_true')
    parser.add_argument('--gpu', type=int, default=None)
    args = parser.parse_args()
    print(f"\n[WATCHDOG AIDR v1.0.0] Start: {datetime.now().isoformat()}")
    gpus = detect_gpus()
    if not gpus: print("[ERROR] No GPUs detected."); sys.exit(1)
    print(f"[WATCHDOG] GPUs: {gpus}")
    if args.test: run_tests(); return
    alert_mgr = AlertManager(min_severity=args.severity, slack_webhook=args.slack, audit_log_path=os.path.join(args.output,'audit.log'))
    pipeline = DetectionPipeline(on_alert=alert_mgr.handle)
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
        print(f"Samples: {collector.sample_count} | Alerts: {alert_mgr.alert_count}")
def run_tests():
    print("[TEST] Running detection engine tests...")
    from detection.engines import GhostPowerDetector, VRAMResidualDetector
    from alerting.manager import AuditLog
    passed = 0
    gp = GhostPowerDetector()
    for i in range(30): gp.update({'power.draw':65.0,'utilization.gpu':0,'memory.used':100,'iso_timestamp':datetime.now().isoformat(),'index':0})
    r = gp.update({'power.draw':92.0,'utilization.gpu':0,'memory.used':100,'iso_timestamp':datetime.now().isoformat(),'index':0})
    if r and r['type']=='GHOST_POWER': print(f"  [PASS] Ghost power {r['delta_w']}W"); passed+=1
    else: print("  [FAIL] Ghost power")
    vr = VRAMResidualDetector()
    vr.update({'utilization.gpu':80,'memory.used':8000,'iso_timestamp':datetime.now().isoformat(),'index':0,'utilization.memory':0})
    r = vr.update({'utilization.gpu':0,'memory.used':1102,'iso_timestamp':datetime.now().isoformat(),'index':0,'utilization.memory':0})
    if r and r['type']=='VRAM_RESIDUAL': print(f"  [PASS] VRAM residual {r['memory_used_mb']}MB"); passed+=1
    else: print("  [FAIL] VRAM residual")
    log = AuditLog('/tmp/wd_test.log')
    log.append({'type':'TEST','severity':'INFO'})
    valid, count = log.verify()
    if valid: print(f"  [PASS] Audit log chain valid {count} entries"); passed+=1
    else: print("  [FAIL] Audit log")
    print(f"\n[TEST] {passed}/3 passed")
if __name__ == '__main__': main()
