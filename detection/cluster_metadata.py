# Author: Manmohan (Mike) Bains -- Watchdog
"""
detection/cluster_metadata.py

Attaches cluster-context fields (node_name, job_id) to an alert when
available, so orchestration/cluster_actions.py's Kubernetes taint and
SLURM eviction actions have a real target to act on -- currently, no
alert type supplies either, which is why neither action fires today
regardless of human-approval settings.

HOW THIS WORKS, stated precisely rather than assumed:

- job_id: reads the SLURM_JOB_ID environment variable. This is set
  automatically by SLURM for any process running inside a job -- no
  extra configuration needed if Watchdog itself runs inside the job.

- node_name: reads NODE_NAME first, falling back to
  KUBERNETES_NODE_NAME. Unlike SLURM_JOB_ID, Kubernetes does NOT set
  either of these automatically. The pod spec must explicitly request
  it via the Downward API:
    env:
      - name: NODE_NAME
        valueFrom:
          fieldRef:
            fieldPath: spec.nodeName
  Without that, node_name will be None -- not a bug, a real
  infrastructure prerequisite that has to be set up once per
  deployment.

STILL UNRESOLVED, stated rather than hidden: nvlink_peer_index, the
third target cluster_actions.py's NVLink-disable action needs, is NOT
provided here. It requires mapping a specific detected anomaly to a
specific physical NVLink connection via topology data
(`nvidia-smi topo -m` or similar), which has not been investigated in
this pass. node_name and job_id being available does NOT mean all
three cluster actions are now reachable -- only two of them are.
"""
import os


def enrich_with_cluster_metadata(alert):
    """
    Returns a new dict (does not mutate the input) with node_name and
    job_id added when available in the environment. Both are None,
    not omitted, when unavailable -- so callers can check for their
    presence explicitly rather than using .get() ambiguity.
    """
    enriched = dict(alert)
    enriched['node_name'] = os.environ.get('NODE_NAME') or os.environ.get('KUBERNETES_NODE_NAME')
    enriched['job_id'] = os.environ.get('SLURM_JOB_ID')
    enriched['nvlink_peer_index'] = None  # not yet available -- see module docstring
    return enriched
