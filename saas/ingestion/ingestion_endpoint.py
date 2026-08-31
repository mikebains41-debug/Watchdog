#!/usr/bin/env python3
# Author: Manmohan (Mike) Bains -- Watchdog
"""
saas/ingestion/ingestion_endpoint.py -- Server-Side Telemetry Ingestion

Receives telemetry batches from client agents. For every batch it:
  1. AUTHENTICATES the agent key against the tenant's registered key.
  2. VERIFIES the batch's tenant_id matches the authenticated tenant (an
     agent cannot submit data as another tenant).
  3. ENFORCES data-residency: a batch's region must match the tenant's
     region, and this endpoint's own region -- EU data does not get
     accepted by a non-EU endpoint.
  4. ROUTES accepted samples into that tenant's TenantScopedStore only.
  5. METERS the accepted volume (for billing) per tenant.

This is the trust boundary of the whole SaaS: it is where an untrusted
client agent hands data to your infrastructure, so every check here is a
hard reject on failure, never a warning.

Framework-agnostic: exposes a handle_batch(payload) method that a FastAPI/
Flask route calls. Pure logic, fully testable without a web server.

NOTE: Reference implementation. Production adds TLS termination, rate
limiting, replay protection (nonce/timestamp), and a durable queue in
front of storage.
"""

from datetime import datetime, timezone

from saas.tenancy.tenant_core import (
    TenantStore, TenantScopedStore, TenantError,
)


class AgentKeyRegistry:
    """Maps tenant_id -> the hashed agent key it authenticates with.
    (Reference stores a plain compare; production stores a salted hash.)"""
    def __init__(self):
        self._keys = {}

    def register(self, tenant_id: str, agent_key: str):
        self._keys[tenant_id] = agent_key

    def verify(self, tenant_id: str, agent_key: str) -> bool:
        expected = self._keys.get(tenant_id)
        # constant-ish compare; production uses hmac.compare_digest on hashes
        return expected is not None and expected == agent_key


class Meter:
    """Per-tenant accepted-sample counter for billing."""
    def __init__(self):
        self._counts = {}

    def record(self, tenant_id: str, n: int):
        self._counts[tenant_id] = self._counts.get(tenant_id, 0) + n

    def usage(self, tenant_id: str) -> int:
        return self._counts.get(tenant_id, 0)

    def all_usage(self) -> dict:
        return dict(self._counts)


class IngestionEndpoint:
    def __init__(self, region: str, tenant_store: TenantStore,
                 key_registry: AgentKeyRegistry, storage_backend: dict = None,
                 meter: Meter = None):
        self.region = region
        self.tenants = tenant_store
        self.keys = key_registry
        self.backend = storage_backend if storage_backend is not None else {}
        self.meter = meter or Meter()
        self.accepted_batches = 0
        self.rejected_batches = 0

    def handle_batch(self, payload: dict) -> dict:
        """Process one incoming batch. Returns an accept/reject result.
        Any failed check is a HARD reject -- no partial acceptance."""
        tenant_id = payload.get("tenant_id")
        agent_key = payload.get("agent_key")
        region = payload.get("region")
        samples = payload.get("samples", [])

        # 1. tenant must exist + be active
        try:
            tenant = self.tenants.get(tenant_id)
        except TenantError:
            return self._reject("UNKNOWN_TENANT", tenant_id)
        if tenant.status != "active":
            return self._reject("TENANT_NOT_ACTIVE", tenant_id)

        # 2. authenticate the agent key
        if not self.keys.verify(tenant_id, agent_key):
            return self._reject("AUTH_FAILED", tenant_id)

        # 3. data-residency: batch region must match tenant region AND this
        #    endpoint's region. EU data is only accepted by the EU endpoint.
        if region != tenant.region:
            return self._reject("REGION_MISMATCH_TENANT", tenant_id,
                                detail=f"batch {region} != tenant {tenant.region}")
        if region != self.region:
            return self._reject("REGION_MISMATCH_ENDPOINT", tenant_id,
                                detail=f"batch {region} != endpoint {self.region}")

        # 4. every sample's tenant_id must match (no smuggling foreign rows)
        for s in samples:
            if s.get("tenant_id") != tenant_id:
                return self._reject("SAMPLE_TENANT_MISMATCH", tenant_id)

        # 5. route into the tenant-scoped store ONLY
        scoped = TenantScopedStore(self.backend, tenant_id)
        stored = 0
        for s in samples:
            # key by host+gpu+timestamp so samples don't overwrite
            key = f"telemetry:{s.get('host')}:{s.get('gpu_index')}:{s.get('timestamp')}:{stored}"
            scoped.set(key, s)
            stored += 1

        # 6. meter for billing
        self.meter.record(tenant_id, stored)
        self.accepted_batches += 1
        return {
            "status": "ACCEPTED",
            "tenant_id": tenant_id,
            "stored": stored,
            "endpoint_region": self.region,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

    def _reject(self, reason: str, tenant_id, detail: str = "") -> dict:
        self.rejected_batches += 1
        return {"status": "REJECTED", "reason": reason,
                "tenant_id": tenant_id, "detail": detail}

    def tenant_sample_count(self, tenant_id: str) -> int:
        scoped = TenantScopedStore(self.backend, tenant_id)
        return len([k for k in scoped.keys() if k.startswith("telemetry:")])

    def get_stats(self) -> dict:
        return {
            "component": "IngestionEndpoint",
            "region": self.region,
            "accepted_batches": self.accepted_batches,
            "rejected_batches": self.rejected_batches,
            "usage_by_tenant": self.meter.all_usage(),
        }


if __name__ == "__main__":
    ts = TenantStore()
    ts.create("acme-pharma", "Acme Pharma", "eu-west")
    keys = AgentKeyRegistry()
    keys.register("acme-pharma", "key-acme")

    ep = IngestionEndpoint("eu-west", ts, keys)
    good = {"tenant_id": "acme-pharma", "agent_key": "key-acme", "region": "eu-west",
            "samples": [{"tenant_id": "acme-pharma", "host": "h1", "gpu_index": 0,
                         "timestamp": "t0", "power_watts": 194.0}]}
    print("[INGEST] good batch:", ep.handle_batch(good)["status"])

    wrong_region = dict(good); wrong_region["region"] = "us-east"
    print("[INGEST] wrong region:", ep.handle_batch(wrong_region)["reason"])

    bad_key = dict(good); bad_key["agent_key"] = "nope"
    print("[INGEST] bad key:", ep.handle_batch(bad_key)["reason"])

    print("[INGEST]", ep.get_stats())
