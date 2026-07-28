# Author: Manmohan (Mike) Bains -- Watchdog
import subprocess, hashlib, json, os, time
from datetime import datetime
class BootAttestation:
    def __init__(self, baseline_path='watchdog_data/attestation_baseline.json'):
        self.baseline_path = baseline_path
        os.makedirs(os.path.dirname(baseline_path), exist_ok=True)
    def get_fingerprint(self, gpu_index=0):
        try:
            r = subprocess.run(['nvidia-smi','--query-gpu=driver_version,vbios_version,uuid,name,serial','--format=csv,noheader',f'--id={gpu_index}'],capture_output=True,text=True,timeout=5)
            fields = [f.strip() for f in r.stdout.strip().split(',')]
            data = {'driver':fields[0],'vbios':fields[1],'uuid':fields[2],'name':fields[3],'serial':fields[4] if len(fields)>4 else 'N/A'}
            fingerprint_str = json.dumps(data, sort_keys=True)
            data['hash'] = hashlib.sha256(fingerprint_str.encode()).hexdigest()
            return data
        except Exception as e:
            return None
    def check(self, gpu_index=0):
        current = self.get_fingerprint(gpu_index)
        if not current: return None
        if not os.path.exists(self.baseline_path):
            baseline = {str(gpu_index): current, 'established': datetime.now().isoformat()}
            with open(self.baseline_path,'w') as f: json.dump(baseline, f, indent=2)
            print(f"[ATTEST] Baseline established for GPU {gpu_index}: {current['hash'][:16]}...")
            return None
        with open(self.baseline_path,'r') as f: baseline = json.load(f)
        stored = baseline.get(str(gpu_index))
        if not stored: return None
        if stored['hash'] != current['hash']:
            return {'type':'ATTESTATION_FAILURE','severity':'EMERGENCY','gpu':gpu_index,'expected_hash':stored['hash'][:16],'actual_hash':current['hash'][:16],'expected_driver':stored['driver'],'actual_driver':current['driver'],'timestamp':datetime.now().isoformat(),'message':f"Hardware fingerprint mismatch — firmware/driver changed since baseline. Expected driver {stored['driver']}, got {current['driver']}"}
        return None
