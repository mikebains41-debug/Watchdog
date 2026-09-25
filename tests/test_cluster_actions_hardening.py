import os, tempfile, sys
os.environ["WATCHDOG_CLUSTER_AUDIT"] = os.path.join(tempfile.mkdtemp(), "audit.log")
sys.path.insert(0, ".")
from orchestration.cluster_actions import ClusterOrchestration, _valid_target, _AUDIT_PATH
c = ClusterOrchestration()
P, F = [], []
def ck(n, cond):
    (P if cond else F).append(n); print("[%s] %s" % ("PASS" if cond else "FAIL", n))

# F1: malicious key/value refused before kubectl (no shell anyway, but must be caught)
ck("F1 bad taint key refused", c.kubernetes_taint("node1", key="a;rm -rf /", value="true").startswith("REFUSED_BAD_LABEL"))
ck("F1 bad taint value refused", c.kubernetes_taint("node1", key="k", value="v with space").startswith("REFUSED_BAD_LABEL"))
ck("F1 empty value allowed (legal k8s)", not c.kubernetes_taint("node1", key="k", value="").startswith("REFUSED_BAD_LABEL"))
ck("F1 default key/value not refused as label", not c.kubernetes_taint("node1").startswith("REFUSED_BAD_LABEL"))

# F2: length bound
ck("F2 over-long node refused", c.kubernetes_taint("n"*300).startswith("REFUSED_NO_TARGET"))
ck("F2 over-long jobid refused", c.slurm_evict_job("1"*300).startswith("REFUSED_NO_TARGET"))
ck("F2 normal node still ok len-wise", "too long" not in c.kubernetes_taint("gpu-node-01"))

# original protections still hold
ck("None jobid refused", c.slurm_evict_job(None).startswith("REFUSED_NO_TARGET"))
ck("'None' string refused", c.slurm_evict_job("None").startswith("REFUSED_NO_TARGET"))
ck("non-digit jobid refused", c.slurm_evict_job("12;reboot").startswith("REFUSED_NO_TARGET"))
ck("valid jobid reaches tool (no scancel here -> NOT_AVAILABLE)", "SLURM_NOT_AVAILABLE" in c.slurm_evict_job("4231"))
ck("nvlink bad index refused", c.nvlink_disable("0;x","1").startswith("REFUSED_NO_TARGET"))

# F3: audit log written
n = sum(1 for _ in open(_AUDIT_PATH)) if os.path.exists(_AUDIT_PATH) else 0
ck("F3 audit log has entries for every attempt", n >= 12)
sample = open(_AUDIT_PATH).readline()
ck("F3 audit line has timestamp+action+target+result", sample.count("\t") == 3 and "kubernetes_taint" in open(_AUDIT_PATH).read())

print("\nPASSED: %d FAILED: %d" % (len(P), len(F)))
sys.exit(1 if F else 0)
