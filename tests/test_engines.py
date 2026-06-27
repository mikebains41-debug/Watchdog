#!/usr/bin/env python3
import sys, os, time
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from datetime import datetime
PASS = 0
FAIL = 0
ts = datetime.now().isoformat()
def row(power=70.0, util=0, mem=100, temp=45.0, sm=1000, util_mem=0, mem_total=80000, name='H200'):
    return {'power.draw':power,'utilization.gpu':util,'memory.used':mem,'temperature.gpu':temp,'clocks.sm':sm,'utilization.memory':util_mem,'memory.total':mem_total,'name':name,'iso_timestamp':ts,'index':0}
def test(name, result):
    global PASS, FAIL
    if result: print(f"  [PASS] {name}"); PASS += 1
    else: print(f"  [FAIL] {name}"); FAIL += 1
print("\n[TEST SUITE] Watchdog AIDR v2.0 — 24 engines\n")
from detection.engines import GhostPowerDetector, VRAMResidualDetector, PowerSideChannelDetector, ThermalEmanationDetector, CrossTenantBleedingDetector, TimingCovertChannelDetector, CrossWorkloadClusteringDetector
print("Base Engines:")
gp = GhostPowerDetector()
for _ in range(30): gp.update(row(power=67.0,util=0,mem=100))
r = gp.update(row(power=130.0,util=0,mem=100))
test("GhostPowerDetector", r and r['type']=='GHOST_POWER')
vr = VRAMResidualDetector()
vr.update(row(util=50,mem=8000))
r = vr.update(row(util=0,mem=500))
test("VRAMResidualDetector", r and r['type']=='VRAM_RESIDUAL')
ps = PowerSideChannelDetector()
for i in range(200): r = ps.update(row(power=100.0 if i%2==0 else 60.0))
test("PowerSideChannelDetector", r and r['type']=='POWER_SIDE_CHANNEL')
te = ThermalEmanationDetector()
for i in range(10): r = te.update(row(temp=80.0 if i%2==0 else 50.0,util=0))
test("ThermalEmanationDetector", r and r['type']=='THERMAL_EMANATION')
ct = CrossTenantBleedingDetector()
for _ in range(100): ct.update(row(power=67.0,util=0,mem=100))
r = ct.update(row(power=120.0,util=0,mem=100))
test("CrossTenantBleedingDetector", r and r['type']=='CROSS_TENANT_BLEEDING')
tc = TimingCovertChannelDetector()
for i in range(100): r = tc.update(row(power=100.0 if i%2==0 else 60.0))
test("TimingCovertChannelDetector", r and r['type']=='TIMING_COVERT_CHANNEL')
cw = CrossWorkloadClusteringDetector()
cw.add_alert({'type':'GHOST_POWER','gpu':'0'})
r = cw.add_alert({'type':'GHOST_POWER','gpu':'1'})
test("CrossWorkloadClusteringDetector", r and r['type']=='CROSS_WORKLOAD_CLUSTER')
from detection.hardware_attacks import ClockGlitchDetector, VoltageGlitchDetector, DMAAttackDetector, LaserInjectionDetector
print("\nHardware Attack Engines:")
cg = ClockGlitchDetector()
for _ in range(10): cg.update(row(sm=1500,util=80))
r = cg.update(row(sm=100,util=80))
test("ClockGlitchDetector", r and r['type']=='CLOCK_GLITCH')
vg = VoltageGlitchDetector()
for _ in range(85): vg.update(row(power=300.0,util=80))
for _ in range(15): vg.update(row(power=300.0,util=80))
for _ in range(5): vg.update(row(power=10.0,util=80))
vg.last_alert = None
r = vg.update(row(power=10.0,util=80))
test("VoltageGlitchDetector", r and r['type']=='VOLTAGE_GLITCH')
da = DMAAttackDetector()
da.baseline_mem = 100.0
r = da.update(row(util=0,mem=500,util_mem=80))
test("DMAAttackDetector", r and r['type']=='DMA_ATTACK')
li = LaserInjectionDetector()
for _ in range(5): li.update(row(temp=45.0))
r = li.update(row(temp=90.0))
test("LaserInjectionDetector", r and r['type']=='LASER_INJECTION')
from detection.memory_attacks import CacheSideChannelDetector, MIGPartitionDesyncDetector, SequentialVRAMReadDetector
print("\nMemory Attack Engines:")
cc = CacheSideChannelDetector()
for _ in range(200): cc.update(row(util=5,util_mem=70))
cc.last_alert = None
r = cc.update(row(util=5,util_mem=70))
test("CacheSideChannelDetector", r and r['type']=='CACHE_SIDE_CHANNEL')
mg = MIGPartitionDesyncDetector()
r = mg.update(row(util=0,util_mem=50))
test("MIGPartitionDesyncDetector", r and r['type']=='MIG_PARTITION_DESYNC')
sv = SequentialVRAMReadDetector()
sv.baseline_mem = 8000.0
for _ in range(10): sv.update(row(util=2,mem=8000,util_mem=70,mem_total=80000))
sv.last_alert = None
r = sv.update(row(util=2,mem=8000,util_mem=70,mem_total=80000))
test("SequentialVRAMReadDetector", r and r['type']=='SEQUENTIAL_VRAM_READ')
from detection.llm_attacks import InferencePowerFingerprintDetector, AgentOrchestrationAnomalyDetector, PromptInjectionSideEffectDetector, AgentSessionVRAMRetentionDetector, InterAgentHandoffAnomalyDetector
print("\nLLM / Agentic AI Engines:")
ip = InferencePowerFingerprintDetector()
ip.baseline_mean = 300.0
ip.baseline_std = 1.0
for _ in range(20): ip.history.append(600.0)
r = ip.update(row(power=600.0,util=80))
test("InferencePowerFingerprintDetector", r and r['type']=='INFERENCE_POWER_ANOMALY')
ao = AgentOrchestrationAnomalyDetector(power_threshold=100,window=60)
for _ in range(61): ao.update(row(power=150.0,util=3))
ao.last_alert = None
r = ao.update(row(power=150.0,util=3))
test("AgentOrchestrationAnomalyDetector", r and r['type']=='AGENT_ORCHESTRATION_ANOMALY')
pi = PromptInjectionSideEffectDetector()
for _ in range(20): pi.update(row(power=300.0,util=80))
r = pi.update(row(power=400.0,util=80))
test("PromptInjectionSideEffectDetector", r and r['type']=='PROMPT_INJECTION_SIDEEFFECT')
av = AgentSessionVRAMRetentionDetector(retention_threshold_mb=100,idle_window=30)
av.session_active = True
av.session_peak_mem = 8000.0
for _ in range(30): av.history.append({'util':0,'mem':500})
av.last_alert = None
r = av.update(row(util=0,mem=500))
test("AgentSessionVRAMRetentionDetector", r and r['type']=='AGENT_VRAM_RETENTION')
ia = InterAgentHandoffAnomalyDetector()
ia.baseline_mean = 300.0
ia.handoff_detected = True
ia.prev_util = 0
for _ in range(10): r = ia.update(row(util=80,power=500.0))
test("InterAgentHandoffAnomalyDetector", r and r['type']=='INTER_AGENT_HANDOFF_ANOMALY')
from detection.advanced import RowhammerProxyDetector, PerfCounterSideChannelDetector, SupplyChainDetector
print("\nAdvanced Engines:")
rh = RowhammerProxyDetector()
for i in range(50): rh.update(row(util=2,mem=600.0 if i%2==0 else 800.0))
rh.last_alert = None
r = rh.update(row(util=2,mem=600.0))
test("RowhammerProxyDetector", r and r['type']=='ROWHAMMER_PROXY')
pc = PerfCounterSideChannelDetector()
for _ in range(50): pc.update(row(util=2,util_mem=50))
for _ in range(50): pc.update(row(util=2,util_mem=75))
pc.last_alert = None
r = pc.update(row(util=2,util_mem=75))
test("PerfCounterSideChannelDetector", r and r['type']=='PERF_COUNTER_SIDE_CHANNEL')
sc = SupplyChainDetector()
r = sc.check_counterfeit(row(power=850.0,util=80,name='H200'))
test("SupplyChainDetector", r and r['type']=='SUPPLY_CHAIN_ANOMALY')
from detection.pcie_health import PCIeHealthDetector
from detection.predictive_failure import FanWearDetector, CapacitorAgingDetector, PackageCrackingDetector
print("\nInfrastructure Engines:")
ph = PCIeHealthDetector()
r = ph.update(row()); test("PCIeHealthDetector", r is None or 'type' in r)
fw = FanWearDetector()
r = fw.update(row()); test("FanWearDetector", r is None or 'type' in r)
ca = CapacitorAgingDetector()
r = ca.update(row()); test("CapacitorAgingDetector", r is None or 'type' in r)
pk = PackageCrackingDetector()
r = pk.update(row()); test("PackageCrackingDetector", r is None or 'type' in r)
total = PASS + FAIL
print(f"\n{'='*40}")
print(f"[RESULTS] {PASS}/{total} passed | {FAIL} failed")
print(f"{'='*40}\n")
sys.exit(0 if FAIL == 0 else 1)
