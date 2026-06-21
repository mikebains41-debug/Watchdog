# Host Isolation Audit

Five non-destructive checks of container/host isolation boundaries on a
rented Vast.ai 2x H200 instance, run three separate times to confirm
consistency.

## Contents
- attempt1.md, attempt2.md, attempt3.md - individual run results
- SUMMARY.md - condensed findings
- metrics.json - structured key metrics
- evidence.json - structured raw evidence

## Method
Five read-only diagnostic commands were run against the rented
container, checking: network capabilities, raw host device visibility,
GPU interconnect topology, shared temp storage residue, and open
network ports. No exploitation, privilege escalation, or unauthorized
data access was attempted. File contents of any discovered residual
files were not inspected, to avoid accessing another party's data
without authorization.
