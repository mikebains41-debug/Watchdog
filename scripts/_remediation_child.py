
import sys, time, json, os
gpu = int(sys.argv[1]); mb = int(sys.argv[2])
import torch
dev = torch.device("cuda:%d" % gpu)
buf = torch.empty(mb * 1024 * 1024, dtype=torch.uint8, device=dev)
buf.fill_(0x5A)
torch.cuda.synchronize(dev)
print(json.dumps({"ok": True, "pid": os.getpid(), "mb": mb}), flush=True)
while True:
    time.sleep(1)
