# Watchdog AIDR v2.0 - Cap'n Proto Schema for Cross-Cluster Gossip
# Zero-copy binary serialization for vaccine payloads
# Maps to all 24 detection engines, EBPFQuarantine actions, PrecisionAdvisor steps

@0xd2a4b89e3f1c50a1;

enum EngineType {
  ghostPowerDetector @0;
  vramResidualDetector @1;
  powerSideChannelDetector @2;
  thermalEmanationDetector @3;
  crossTenantBleedingDetector @4;
  timingCovertChannelDetector @5;
  crossWorkloadClusteringDetector @6;
  clockGlitchDetector @7;
  voltageGlitchDetector @8;
  dmaAttackDetector @9;
  laserInjectionDetector @10;
  cacheSideChannelDetector @11;
  migPartitionDesyncDetector @12;
  sequentialVramReadDetector @13;
  inferencePowerFingerprintDetector @14;
  agentOrchestrationAnomalyDetector @15;
  promptInjectionSideEffectDetector @16;
  agentSessionVramRetentionDetector @17;
  interAgentHandoffAnomalyDetector @18;
  rowhammerProxyDetector @19;
  perfCounterSideChannelDetector @20;
  supplyChainDetector @21;
  precisionAdvisor @22;
  ebpfQuarantine @23;
}

enum QuarantineAction {
  none @0;
  freezeCgroup @1;
  killContainer @2;
}

enum PrecisionStep {
  noChange @0;
  fp32 @1;
  fp16 @2;
  bf16 @3;
  fp8 @4;
}

struct SwarmVaccinePayload {
  magicBytes @0 :UInt16;          # 0x5744 "WD" Watchdog magic
  version @1 :UInt8;
  epochTimestamp @2 :UInt64;
  sourceNodeHash @3 :Data;        # SHA-256 binary digest (32 bytes)
  signature @4 :Data;             # Ed25519 signature (64 bytes)

  vaccineData :struct {
    targetEngine @5 :EngineType;
    confidenceScore @6 :Float32;
    dynamicPowerThresholdW @7 :Float32;
    slidingWindowSizeSec @8 :UInt16;
    iocSignatureMatch @9 :UInt8;
    enforceQuarantine @10 :QuarantineAction;
    forcePrecisionStep @11 :PrecisionStep;
    signatureBlob @12 :Data;      # Dynamic IOC pattern bytes
    cvssScore @13 :Float32;
    cveReference @14 :Text;
  }
}
