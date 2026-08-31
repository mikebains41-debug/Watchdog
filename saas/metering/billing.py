#!/usr/bin/env python3
# Author: Manmohan (Mike) Bains -- Watchdog
"""
saas/metering/billing.py -- Usage Metering & Billing

Turns the ingestion meter's per-tenant sample counts into billable usage
and invoice lines. SaaS needs this to be a business, not just software.

Plan model (reference -- tune to your pricing):
- Per-tenant subscription with a base fee + included sample allowance.
- Overage billed per million samples above the allowance.
- Optional per-GPU-host component (common in infra monitoring).

Pure arithmetic, deterministic, testable. No payment-processor integration
here (that's Stripe/etc. wiring in production) -- this computes the numbers
an invoice is built from.

NOTE: Reference implementation. Real billing adds proration, tax,
currency, dunning, and a payment processor.
"""

from datetime import datetime, timezone

# Reference plans. base_monthly in USD; included samples; overage per 1M.
PLANS = {
    "starter": {"base_monthly": 500, "included_samples": 5_000_000,
                "overage_per_million": 40, "included_hosts": 5,
                "per_host_over": 50},
    "growth": {"base_monthly": 2000, "included_samples": 50_000_000,
               "overage_per_million": 30, "included_hosts": 50,
               "per_host_over": 40},
    "enterprise": {"base_monthly": 8000, "included_samples": 500_000_000,
                   "overage_per_million": 20, "included_hosts": 500,
                   "per_host_over": 30},
}


class TenantSubscription:
    def __init__(self, tenant_id: str, plan: str):
        if plan not in PLANS:
            raise ValueError(f"unknown plan: {plan}")
        self.tenant_id = tenant_id
        self.plan = plan


def compute_invoice(subscription: TenantSubscription,
                    samples_used: int,
                    hosts_active: int,
                    period_label: str = None) -> dict:
    """Compute one billing-period invoice for a tenant."""
    plan = PLANS[subscription.plan]
    lines = []

    # 1. base subscription
    lines.append({"item": f"{subscription.plan} plan base",
                  "amount": plan["base_monthly"]})

    # 2. sample overage
    overage_samples = max(0, samples_used - plan["included_samples"])
    overage_millions = overage_samples / 1_000_000
    overage_cost = round(overage_millions * plan["overage_per_million"], 2)
    if overage_cost > 0:
        lines.append({
            "item": f"sample overage ({overage_millions:.2f}M over "
                    f"{plan['included_samples'] / 1e6:.0f}M included)",
            "amount": overage_cost})

    # 3. host overage
    host_over = max(0, hosts_active - plan["included_hosts"])
    host_cost = host_over * plan["per_host_over"]
    if host_cost > 0:
        lines.append({
            "item": f"host overage ({host_over} over {plan['included_hosts']} included)",
            "amount": host_cost})

    total = round(sum(l["amount"] for l in lines), 2)
    return {
        "tenant_id": subscription.tenant_id,
        "plan": subscription.plan,
        "period": period_label or datetime.now(timezone.utc).strftime("%Y-%m"),
        "samples_used": samples_used,
        "hosts_active": hosts_active,
        "lines": lines,
        "total_usd": total,
        "currency": "USD",
        "note": ("Reference computation. Production adds tax, proration, "
                 "currency conversion, and a payment processor."),
    }


class BillingEngine:
    def __init__(self):
        self._subs = {}

    def subscribe(self, tenant_id: str, plan: str) -> TenantSubscription:
        sub = TenantSubscription(tenant_id, plan)
        self._subs[tenant_id] = sub
        return sub

    def invoice_tenant(self, tenant_id: str, samples_used: int,
                       hosts_active: int, period_label: str = None) -> dict:
        sub = self._subs.get(tenant_id)
        if sub is None:
            raise ValueError(f"no subscription for tenant: {tenant_id}")
        return compute_invoice(sub, samples_used, hosts_active, period_label)

    def invoice_all(self, usage_by_tenant: dict, hosts_by_tenant: dict,
                    period_label: str = None) -> list:
        invoices = []
        for tid in sorted(usage_by_tenant.keys()):
            if tid in self._subs:
                invoices.append(self.invoice_tenant(
                    tid, usage_by_tenant[tid],
                    hosts_by_tenant.get(tid, 0), period_label))
        return invoices


if __name__ == "__main__":
    engine = BillingEngine()
    engine.subscribe("acme-pharma", "growth")
    inv = engine.invoice_tenant("acme-pharma", samples_used=62_000_000,
                                hosts_active=55, period_label="2026-08")
    print(f"[BILLING] {inv['tenant_id']} {inv['period']} plan={inv['plan']}")
    for line in inv["lines"]:
        print(f"   {line['item']}: ${line['amount']}")
    print(f"   TOTAL: ${inv['total_usd']}")
