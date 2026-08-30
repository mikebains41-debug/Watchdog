import json,sys

def validate_pod(pod_spec):
    errors=[]
    containers=pod_spec.get("spec",{}).get("containers",[])
    term_period=pod_spec.get("spec",{}).get("terminationGracePeriodSeconds",30)
    if term_period!=0:
        errors.append(f"terminationGracePeriodSeconds must be 0 to enforce SIGKILL. Current: {term_period}")
    for c in containers:
        resources=c.get("resources",{})
        limits=resources.get("limits",{})
        if "nvidia.com/gpu" in limits:
            lifecycle=c.get("lifecycle",{})
            pre_stop=lifecycle.get("preStop",{})
            if pre_stop:
                errors.append(f"Container {c.get('name')} has preStop hook which may delay SIGKILL")
    return errors

if __name__=="__main__":
    example={"spec":{"terminationGracePeriodSeconds":30,"containers":[{"name":"gpu-workload","resources":{"limits":{"nvidia.com/gpu":"1"}}}]}}
    errors=validate_pod(example)
    if errors:
        print("ADMISSION REJECTED:")
        for e in errors: print(f"  - {e}")
        sys.exit(1)
    print("ADMISSION APPROVED")
