# swarm_test.py

**Author:** Manmohan (Mike) Bains
**Status:** Rewritten to match real API endpoints, syntax-valid, NOT
yet run -- requires 2+ real running Watchdog API server instances
reachable over the network.

## What This Is

Tests whether an attack detected on one Watchdog node produces
visible alert data on other nodes when queried, using the REAL
endpoints confirmed in api/server.py: /health, /alerts,
/api/v1/inject/{attack_type}.

## Honest Correction From Original

The original pasted version of this script assumed an endpoint
structure (/api/v1/inject/, /api/v1/alerts) and a gossip-propagation
mechanism that did not exist in the real server code. This version
uses only the endpoints actually present in api/server.py, confirmed
by direct inspection. No gossip/propagation mechanism currently
exists between nodes -- this test currently checks reachability and
before/after alert state per node, not cross-node propagation, since
that capability has not been built yet.

## How To Run

python3 tests/swarm_test.py --nodes host1:8080 host2:8080

## Requirements

2+ real Watchdog API server instances (python api/server.py) running
and network-reachable. Will report 0 reachable nodes and fail cleanly
if none are running -- has not been tested against real running
servers yet.
