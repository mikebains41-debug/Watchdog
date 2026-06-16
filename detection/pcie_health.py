import subprocess, time, collections
from datetime import datetime
class PCIeHealthDetector:
    def __init__(self):
        self.baseline_gen = None
        self.baseline_width = None
        self.last_alert = None
    def sample(self, gpu_index=0):
        try:
            r = subprocess.run(['nvidia-smi','--query-gpu=pcie.link.gen.current,pcie.link.gen.max,pcie.link.width.current,pcie.link.width.max','--format=csv,noheader,nounits',f'--id={gpu_index}'],capture_output=True,text=True,timeout=5)
            vals = [v.strip() for v in r.stdout.strip().split(',')]
            return {'gen_current':int(vals[0]),'gen_max':int(vals[1]),'width_current':int(vals[2]),'width_max':int(vals[3])}
        except: return None
    def update(self, row):
        gpu = row.get('index',0)
        info = self.sample(gpu)
        if not info: return None
        if self.baseline_gen is None:
            self.baseline_gen = info['gen_max']
            self.baseline_width = info['width_max']
            return None
        if info['gen_current'] < self.baseline_gen or info['width_current'] < self.baseline_width:
            now = time.time()
            if self.last_alert and now-self.last_alert < 60: return None
            self.last_alert = now
            return {'type':'PCIE_LINK_DOWNGRADE','severity':'WARNING','gpu':gpu,'gen_current':info['gen_current'],'gen_expected':self.baseline_gen,'width_current':info['width_current'],'width_expected':self.baseline_width,'timestamp':row.get('iso_timestamp'),'message':f"PCIe link downgraded: Gen{info['gen_current']}x{info['width_current']} vs expected Gen{self.baseline_gen}x{self.baseline_width}"}
        return None
