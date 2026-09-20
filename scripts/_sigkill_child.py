
import sys, time, json
gpu = int(sys.argv[1]); mb = int(sys.argv[2])
import torch
dev = torch.device("cuda:%d" % gpu)
buf = torch.empty(mb * 1024 * 1024, dtype=torch.uint8, device=dev)
buf.fill_(0xA5)
torch.cuda.synchronize(dev)
print(json.dumps({"ok": True, "pid": __import__("os").getpid(), "mb": mb}), flush=True)
while True:
    time.sleep(1)
