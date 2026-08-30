import subprocess,sys

def validate_gpu(architecture,threshold_w=20):
    r=subprocess.run(["nvidia-smi","--query-gpu=power.draw,utilization.gpu","--format=csv,noheader,nounits"],capture_output=True,text=True)
    row=r.stdout.strip()
    power=float(row.split(",")[0].strip())
    util=float(row.split(",")[1].strip())
    baselines={"A100-SXM-80GB":67,"H100-SXM-80GB":69.5,"B200-SXM-180GB":143,"B300-SXM6-288GB":163}
    baseline=baselines.get(architecture,70)
    ghost=util==0 and power>baseline+threshold_w
    if ghost:
        print(f"FAIL: Ghost power detected {power}W on {architecture} baseline {baseline}W")
        sys.exit(1)
    print(f"PASS: {architecture} power {power}W within threshold")
    sys.exit(0)

if __name__=="__main__":
    arch=sys.argv[1] if len(sys.argv)>1 else "A100-SXM-80GB"
    validate_gpu(arch)
