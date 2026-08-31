#!/usr/bin/env python3
# Author: Manmohan (Mike) Bains -- Watchdog
"""
saas/tenancy/tenant_core.py -- Multi-Tenancy Core

The non-negotiable SaaS primitive: every piece of data, every alert, every
query is scoped to a tenant_id, and cross-tenant access is structurally
impossible, not merely discouraged. A single leak of Tenant A's data to
Tenant B is a company-ending event, so isolation is enforced by
construction here, not left to per-callsite discipline.

Design:
- Tenant: an identified client org with a region (for data-residency) and
  a status.
- TenantStore: registry of tenants.
- TenantScopedStore: a key-value store where EVERY read/write is bound to a
  tenant_id at construction; it is impossible to read another tenant's data
  through it. Attempting to pass a foreign tenant_id raises.
- with_tenant(): a context that carries the active tenant and refuses to
  let an operation run without one.

Pure stdlib, in-memory reference implementation (a real deployment backs
this with a database using row-level security on the same tenant_id
contract). Fully testable.

NOTE: Simulation/reference implementation. Production requires a real
database with enforced row-level security + audited access.
"""

import re
import threading
from datetime import datetime, timezone

# Data-residency regions. A tenant's data must stay in its region; the
# ingestion/routing layer uses this. (EU/China residency is a legal
# requirement, not a preference -- see SAAS_READINESS_ROADMAP.)
VALID_REGIONS = {"ca-central", "us-east", "eu-west", "ap-southeast", "cn-north"}

_TENANT_ID_RE = re.compile(r"^[a-z0-9][a-z0-9\-]{2,63}$")


class TenantError(Exception):
    """Raised on any tenant-isolation violation. Never caught-and-ignored."""


class Tenant:
    def __init__(self, tenant_id: str, name: str, region: str,
                 status: str = "active"):
        if not _TENANT_ID_RE.match(tenant_id):
            raise TenantError(f"invalid tenant_id: {tenant_id!r}")
        if region not in VALID_REGIONS:
            raise TenantError(f"invalid region: {region!r}")
        self.tenant_id = tenant_id
        self.name = name
        self.region = region
        self.status = status
        self.created_at = datetime.now(timezone.utc).isoformat()

    def to_dict(self):
        return {"tenant_id": self.tenant_id, "name": self.name,
                "region": self.region, "status": self.status,
                "created_at": self.created_at}


class TenantStore:
    def __init__(self):
        self._tenants = {}
        self._lock = threading.Lock()

    def create(self, tenant_id: str, name: str, region: str) -> Tenant:
        with self._lock:
            if tenant_id in self._tenants:
                raise TenantError(f"tenant already exists: {tenant_id}")
            t = Tenant(tenant_id, name, region)
            self._tenants[tenant_id] = t
            return t

    def get(self, tenant_id: str) -> Tenant:
        t = self._tenants.get(tenant_id)
        if t is None:
            raise TenantError(f"unknown tenant: {tenant_id}")
        return t

    def list_ids(self):
        return sorted(self._tenants.keys())

    def suspend(self, tenant_id: str):
        self.get(tenant_id).status = "suspended"


class TenantScopedStore:
    """A key-value store permanently bound to ONE tenant. Every operation is
    physically namespaced by tenant_id; there is no method that can reach
    another tenant's data. This is the isolation guarantee."""

    def __init__(self, backend: dict, tenant_id: str):
        if not _TENANT_ID_RE.match(tenant_id):
            raise TenantError(f"invalid tenant_id: {tenant_id!r}")
        self._backend = backend            # shared physical store
        self._tenant_id = tenant_id
        self._prefix = f"{tenant_id}::"

    def _k(self, key: str) -> str:
        if "::" in key:
            # prevent a caller from forging a cross-tenant key
            raise TenantError("key may not contain the tenant separator '::'")
        return self._prefix + key

    def set(self, key: str, value):
        self._backend[self._k(key)] = value

    def get(self, key: str, default=None):
        return self._backend.get(self._k(key), default)

    def delete(self, key: str):
        self._backend.pop(self._k(key), None)

    def keys(self):
        # only THIS tenant's keys, prefix stripped
        return [k[len(self._prefix):] for k in self._backend
                if k.startswith(self._prefix)]

    def tenant_id(self):
        return self._tenant_id


class TenantContext:
    """Thread-local active tenant. An operation that needs a tenant but has
    none must fail loudly rather than default to some tenant."""

    def __init__(self):
        self._local = threading.local()

    def set(self, tenant_id: str):
        self._local.tenant_id = tenant_id

    def clear(self):
        self._local.tenant_id = None

    def require(self) -> str:
        tid = getattr(self._local, "tenant_id", None)
        if not tid:
            raise TenantError("no active tenant in context; refusing to proceed")
        return tid


_GLOBAL_CONTEXT = TenantContext()


class with_tenant:
    """Context manager binding an active tenant for the block."""
    def __init__(self, tenant_id: str, context: TenantContext = None):
        if not _TENANT_ID_RE.match(tenant_id):
            raise TenantError(f"invalid tenant_id: {tenant_id!r}")
        self._tid = tenant_id
        self._ctx = context or _GLOBAL_CONTEXT
        self._prev = None

    def __enter__(self):
        self._prev = getattr(self._ctx._local, "tenant_id", None)
        self._ctx.set(self._tid)
        return self._tid

    def __exit__(self, *exc):
        self._ctx.set(self._prev)
        return False


def current_tenant(context: TenantContext = None) -> str:
    return (context or _GLOBAL_CONTEXT).require()


if __name__ == "__main__":
    store = TenantStore()
    store.create("acme-pharma", "Acme Pharma", "eu-west")
    store.create("globex-insure", "Globex Insurance", "us-east")

    backend = {}
    a = TenantScopedStore(backend, "acme-pharma")
    b = TenantScopedStore(backend, "globex-insure")
    a.set("secret", "acme-data")
    b.set("secret", "globex-data")
    print("[TENANCY] acme sees:", a.get("secret"))
    print("[TENANCY] globex sees:", b.get("secret"))
    print("[TENANCY] acme keys only:", a.keys())
    print("[TENANCY] physical backend keys:", sorted(backend.keys()))
    with with_tenant("acme-pharma"):
        print("[TENANCY] active tenant:", current_tenant())
