# Author: Manmohan (Mike) Bains -- Watchdog AIDR
import json, os, hashlib, shutil
from datetime import datetime
class ChainOfCustody:
    def __init__(self, evidence_dir='watchdog_data/evidence'):
        self.evidence_dir = evidence_dir
        os.makedirs(evidence_dir, exist_ok=True)
        self.manifest = []
    def collect(self, source_path, description):
        if not os.path.exists(source_path): return None
        fname = os.path.basename(source_path)
        ts = datetime.now().strftime('%Y%m%d_%H%M%S')
        dest = os.path.join(self.evidence_dir, f"{ts}_{fname}")
        shutil.copy2(source_path, dest)
        with open(dest,'rb') as f: file_hash = hashlib.sha256(f.read()).hexdigest()
        entry = {'timestamp':datetime.now().isoformat(),'source':source_path,'sha256':file_hash}
        self.manifest.append(entry)
        return entry
    def collect_all(self, data_dir='watchdog_data'):
        for f in os.listdir(data_dir):
            if f.endswith(('.csv','.log','.json','.txt')):
                self.collect(os.path.join(data_dir,f), f)
    def save_manifest(self):
        path = os.path.join(self.evidence_dir,'MANIFEST.json')
        with open(path,'w') as f: json.dump(self.manifest, f, indent=2)
        return path
