#!/usr/bin/env python3
# Author: Manmohan (Mike) Bains -- Watchdog
"""
tests/test_saas_scaffold.py

Tests the SaaS foundation: multi-tenancy isolation, the client agent,
the ingestion endpoint (auth + data-residency enforcement), and billing.
The isolation + residency tests are the ones that matter most -- a failure
there is a data-leak or a legal-compliance breach.

Run standalone: python3 tests/test_saas_scaffold.py
Or via suite:   python3 tests/run_all.py (once registered in TEST_FILES).
"""
import os
import sys
from types import SimpleNamespace

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

from saas.tenancy.tenant_core import (
    TenantStore, TenantScopedStore, TenantError, Tenant,
    with_tenant, current_tenant, TenantContext,
)
from saas.agent.watchdog_agent import WatchdogAgent
from saas.ingestion.ingestion_endpoint import (
    IngestionEndpoint, AgentKeyRegistry, Meter,
)
from saas.metering.billing import BillingEngine, compute_invoice, TenantSubscription, PLANS

PASSED = []
FAILED = []


def check(name, condition, detail=""):
    if condition:
        PASSED.append(name)
        print(f"[PASS] {name}")
    else:
        FAILED.append(name)
        print(f"[FAIL] {name} {detail}")


# --------------------------------------------------------------------------
# Tenancy isolation -- the critical tests
# --------------------------------------------------------------------------
def test_scoped_store_isolation():
    backend = {}
    a = TenantScopedStore(backend, "tenant-a")
    b = TenantScopedStore(backend, "tenant-b")
    a.set("secret", "a-data")
    b.set("secret", "b-data")
    check("tenancy: each tenant reads only its own value",
          a.get("secret") == "a-data" and b.get("secret") == "b-data",
          f"a={a.get('secret')} b={b.get('secret')}")
    check("tenancy: tenant A's key list excludes tenant B",
          a.keys() == ["secret"] and b.keys() == ["secret"], "leak in key listing")
    check("tenancy: physical backend namespaces by tenant",
          set(backend.keys()) == {"tenant-a::secret", "tenant-b::secret"},
          f"got {set(backend.keys())}")


def test_scoped_store_rejects_forged_key():
    backend = {}
    a = TenantScopedStore(backend, "tenant-a")
    try:
        a.set("tenant-b::secret", "x")   # try to forge a cross-tenant key
        check("tenancy: forged cross-tenant key rejected", False, "no exception")
    except TenantError:
        check("tenancy: forged cross-tenant key rejected", True)


def test_invalid_tenant_id_rejected():
    try:
        Tenant("BAD ID!", "x", "us-east")
        check("tenancy: invalid tenant_id rejected", False, "no exception")
    except TenantError:
        check("tenancy: invalid tenant_id rejected", True)


def test_invalid_region_rejected():
    try:
        Tenant("valid-id", "x", "mars-west")
        check("tenancy: invalid region rejected", False, "no exception")
    except TenantError:
        check("tenancy: invalid region rejected", True)


def test_context_requires_tenant():
    ctx = TenantContext()
    try:
        current_tenant(ctx)
        check("tenancy: operation without active tenant refuses", False, "no exception")
    except TenantError:
        check("tenancy: operation without active tenant refuses", True)
    with with_tenant("tenant-a", ctx):
        check("tenancy: active tenant available in context",
              current_tenant(ctx) == "tenant-a")


# --------------------------------------------------------------------------
# Agent
# --------------------------------------------------------------------------
def _fake_smi(cmd, **kw):
    # one GPU row matching NVIDIA_SMI_FIELDS order
    return SimpleNamespace(returncode=0,
        stdout="0, 194.0, 65, 0, 629, 1800, 1593, 5, 12, 0\n")


def test_agent_collects_and_normalizes():
    agent = WatchdogAgent("acme", "h1", "eu-west", "k", "https://x/ingest",
                          nvidia_smi_runner=_fake_smi, sender=lambda u, p: True)
    batch = agent.collect_once()
    check("agent: collects one normalized sample per GPU",
          len(batch) == 1 and batch[0]["power_watts"] == 194.0, f"got {batch}")
    check("agent: every sample tagged with tenant + host",
          batch[0]["tenant_id"] == "acme" and batch[0]["host"] == "h1", f"got {batch[0]}")
    check("agent: ECC fields carried through for agent 6",
          "ecc_corrected_total" in batch[0] and batch[0]["ecc_corrected_total"] == 12.0,
          f"got {batch[0]}")


def test_agent_missing_nvidia_smi_is_safe():
    def no_smi(cmd, **kw):
        raise FileNotFoundError("nvidia-smi not found")
    agent = WatchdogAgent("acme", "h1", "eu-west", "k", "https://x",
                          nvidia_smi_runner=no_smi, sender=lambda u, p: True)
    batch = agent.collect_once()
    check("agent: missing nvidia-smi returns empty, does not crash",
          batch == [], f"got {batch}")


def test_agent_buffers_on_send_failure():
    def failing_send(url, payload):
        raise ConnectionError("endpoint down")
    agent = WatchdogAgent("acme", "h1", "eu-west", "k", "https://x",
                          nvidia_smi_runner=_fake_smi, sender=failing_send)
    agent.collect_once()
    r = agent.flush()
    check("agent: send failure keeps samples buffered (fail-safe)",
          r["status"] == "SEND_FAILED" and agent.get_stats()["buffered"] == 1,
          f"got {r}")


def test_agent_flush_clears_on_success():
    agent = WatchdogAgent("acme", "h1", "eu-west", "k", "https://x",
                          nvidia_smi_runner=_fake_smi, sender=lambda u, p: True)
    agent.collect_once()
    r = agent.flush()
    check("agent: successful flush clears the buffer",
          r["status"] == "FLUSHED" and agent.get_stats()["buffered"] == 0, f"got {r}")


# --------------------------------------------------------------------------
# Ingestion endpoint -- auth + residency
# --------------------------------------------------------------------------
def _endpoint(region="eu-west"):
    ts = TenantStore()
    ts.create("acme", "Acme", "eu-west")
    keys = AgentKeyRegistry()
    keys.register("acme", "key-acme")
    return IngestionEndpoint(region, ts, keys), ts, keys


def _batch(tenant="acme", key="key-acme", region="eu-west", stenant=None):
    return {"tenant_id": tenant, "agent_key": key, "region": region,
            "samples": [{"tenant_id": stenant or tenant, "host": "h1",
                         "gpu_index": 0, "timestamp": "t0", "power_watts": 194.0}]}


def test_ingestion_accepts_valid_batch():
    ep, _, _ = _endpoint()
    r = ep.handle_batch(_batch())
    check("ingestion: valid batch accepted + stored",
          r["status"] == "ACCEPTED" and r["stored"] == 1, f"got {r}")


def test_ingestion_rejects_bad_key():
    ep, _, _ = _endpoint()
    r = ep.handle_batch(_batch(key="wrong"))
    check("ingestion: bad agent key rejected (AUTH_FAILED)",
          r["status"] == "REJECTED" and r["reason"] == "AUTH_FAILED", f"got {r}")


def test_ingestion_enforces_residency_tenant():
    ep, _, _ = _endpoint()
    r = ep.handle_batch(_batch(region="us-east"))
    check("ingestion: region != tenant region rejected (residency)",
          r["reason"] == "REGION_MISMATCH_TENANT", f"got {r}")


def test_ingestion_enforces_residency_endpoint():
    # endpoint is us-east but tenant + batch are eu-west
    ep, ts, keys = _endpoint(region="us-east")
    r = ep.handle_batch(_batch(region="eu-west"))
    check("ingestion: EU batch rejected by non-EU endpoint (residency)",
          r["reason"] == "REGION_MISMATCH_TENANT" or r["reason"] == "REGION_MISMATCH_ENDPOINT",
          f"got {r}")


def test_ingestion_rejects_smuggled_sample_tenant():
    ep, _, _ = _endpoint()
    r = ep.handle_batch(_batch(stenant="other-tenant"))
    check("ingestion: sample with foreign tenant_id rejected",
          r["reason"] == "SAMPLE_TENANT_MISMATCH", f"got {r}")


def test_ingestion_rejects_unknown_tenant():
    ep, _, _ = _endpoint()
    r = ep.handle_batch(_batch(tenant="ghost"))
    check("ingestion: unknown tenant rejected",
          r["reason"] == "UNKNOWN_TENANT", f"got {r}")


def test_ingestion_suspended_tenant_rejected():
    ep, ts, _ = _endpoint()
    ts.suspend("acme")
    r = ep.handle_batch(_batch())
    check("ingestion: suspended tenant rejected",
          r["reason"] == "TENANT_NOT_ACTIVE", f"got {r}")


def test_ingestion_meters_accepted_volume():
    ep, _, _ = _endpoint()
    ep.handle_batch(_batch())
    ep.handle_batch(_batch())
    check("ingestion: meters accepted samples per tenant",
          ep.meter.usage("acme") == 2, f"got {ep.meter.usage('acme')}")


def test_ingestion_stored_data_is_tenant_scoped():
    ep, _, _ = _endpoint()
    ep.handle_batch(_batch())
    # a scoped store for a DIFFERENT tenant must not see acme's telemetry
    other = TenantScopedStore(ep.backend, "someone-else")
    check("ingestion: stored telemetry not visible to another tenant's store",
          len([k for k in other.keys() if k.startswith("telemetry:")]) == 0,
          "cross-tenant telemetry leak")


# --------------------------------------------------------------------------
# Billing
# --------------------------------------------------------------------------
def test_billing_base_only_under_allowance():
    sub = TenantSubscription("acme", "growth")
    inv = compute_invoice(sub, samples_used=1_000_000, hosts_active=5)
    check("billing: under allowance bills base only",
          inv["total_usd"] == PLANS["growth"]["base_monthly"], f"got {inv}")


def test_billing_sample_overage():
    sub = TenantSubscription("acme", "growth")
    # 10M over the 50M growth allowance -> 10 * $30 = $300 overage
    inv = compute_invoice(sub, samples_used=60_000_000, hosts_active=5)
    expected = PLANS["growth"]["base_monthly"] + 300
    check("billing: sample overage computed correctly",
          inv["total_usd"] == expected, f"got {inv['total_usd']} expected {expected}")


def test_billing_host_overage():
    sub = TenantSubscription("acme", "growth")
    # 55 hosts, 50 included -> 5 * $40 = $200
    inv = compute_invoice(sub, samples_used=1_000_000, hosts_active=55)
    expected = PLANS["growth"]["base_monthly"] + 200
    check("billing: host overage computed correctly",
          inv["total_usd"] == expected, f"got {inv['total_usd']} expected {expected}")


def test_billing_engine_invoice_all():
    engine = BillingEngine()
    engine.subscribe("acme", "starter")
    engine.subscribe("globex", "enterprise")
    invoices = engine.invoice_all(
        usage_by_tenant={"acme": 1_000_000, "globex": 1_000_000},
        hosts_by_tenant={"acme": 2, "globex": 10})
    check("billing: invoices generated for all subscribed tenants",
          len(invoices) == 2, f"got {len(invoices)}")


if __name__ == "__main__":
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for t in tests:
        try:
            t()
        except Exception as e:
            check(t.__name__, False, f"EXCEPTION {e!r}")
    print("\n" + "=" * 60)
    print(f"PASSED: {len(PASSED)}   FAILED: {len(FAILED)}")
    if FAILED:
        print("\nFailures:")
        for f in FAILED:
            print(f"  - {f}")
    print("=" * 60)
    sys.exit(1 if FAILED else 0)
