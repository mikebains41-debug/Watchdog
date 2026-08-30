nvidia-smi --query-gpu=timestamp,index,power.draw,utilization.gpu,utilization.memory,memory.used,clocks.mem,clocks.sm,pstate --format=csv,noheader,nounits -l 1 | tee /root/results/h200_security_tests/t28_timing_attack/t28_raw.csv & python3 -c "
import torch,time
from datetime import datetime
print('=== T-28 TIMING ATTACK H200 ===')
print('Author: Manmohan Mike Bains CVE 2048350')
print('Start:',datetime.now().isoformat())
sizes=[(4096,'SMALL'),(8192,'MEDIUM'),(16384,'LARGE')]
for sz,nm in sizes:
    print(f'PHASE {nm} LOADING {sz}x{sz}')
    t=torch.randn(sz,sz,device='cuda:0',dtype=torch.float16)
    for i in range(50):
        z=torch.mm(t,t)
    torch.cuda.synchronize()
    print(f'COMPUTE DONE {nm} DECAY START',datetime.now().isoformat())
    time.sleep(60)
    del t,z
    import gc; gc.collect()
    torch.cuda.empty_cache()
    print(f'CLEARED {nm}',datetime.now().isoformat())
    time.sleep(30)
print('=== T-28 COMPLETE ===')
print('End:',datetime.now().isoformat())
" && kill %1 && cd /root/results && git add h200_security_tests/t28_timing_attack/ && git commit -m "T-28 timing attack H200 CVE2048350" && git push && echo "T-28 SAVED"
