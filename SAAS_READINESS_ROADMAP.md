# Watchdog — SaaS Readiness Roadmap
**GPU Optimizer Inc. | Mike Bains | August 2026**
**Goal:** Watchdog as a self-sufficient SaaS, run from the lab (North Cowichan/Duncan, BC), used by clients worldwide.

This is the full plan: what's built, what's buildable-and-built-this-session, what's buildable-next, and the hard non-code gates (audits, legal, infrastructure). Researched with 2026 sources (SOC 2 / ISO 27001 / GDPR guidance, multi-tenant SaaS architecture, self-hosted observability, data-residency law).

---

## Where the product stands

The hard part — the IP — is built: detection engines, 8-agent security swarm + correlator, remediation coordinator, LLM investigator, AIBOM with 7-jurisdiction compliance, response pipeline. 227 automated tests. That is the thing most security-SaaS startups do NOT have. Everything below is the delivery shell around that product.

---

## BUILT THIS SESSION — the SaaS foundation (code, tested)

`saas/` package, 27 tests in `tests/test_saas_scaffold.py`, all passing:

| Module | What it does |
|---|---|
| `saas/tenancy/tenant_core.py` | Multi-tenancy core. `TenantScopedStore` makes cross-tenant reads structurally impossible (physical key namespacing + forged-key rejection). `with_tenant`/`current_tenant` refuse to run without an active tenant. Region on every tenant for residency. |
| `saas/agent/watchdog_agent.py` | Client-side collector. Reads nvidia-smi (incl. ECC for agent 6), normalizes to the detector schema, tags every sample with tenant+host, buffers on failure (never crashes the host), ships to the tenant's regional endpoint. |
| `saas/ingestion/ingestion_endpoint.py` | Server-side trust boundary. Per batch: authenticates the agent key, verifies tenant, **enforces data-residency** (EU data refused by non-EU endpoint), rejects smuggled foreign-tenant samples, routes into the tenant-scoped store only, meters volume for billing. Every failed check is a hard reject. |
| `saas/metering/billing.py` | Per-tenant usage → tiered plans (starter/growth/enterprise) → invoice lines with sample + host overage. The numbers a real invoice is built from. |

The critical guarantees are tested: cross-tenant isolation, forged-key rejection, residency enforcement, no telemetry leak between tenants.

**These are reference implementations** — the isolation/residency CONTRACT is real and enforced; production swaps the in-memory backend for a database with row-level security on the same tenant_id contract, and the reference HTTPS transport for TLS-pinned + rate-limited + replay-protected transport.

---

## BUILDABLE NEXT (code, not yet built)

Ordered by dependency. All are real software builds I can do in later sessions.

1. **Detector pipeline wiring to ingestion.** Connect the ingestion store → the existing swarm/detectors/response pipeline, per tenant. The detectors already exist; this feeds them live multi-tenant telemetry instead of local nvidia-smi. Medium.
2. **Web control plane / dashboard (multi-tenant).** The portal clients log into: their alerts, incidents, approve/deny gated remediations, their per-region AIBOM compliance status. Needs a web framework (FastAPI backend + a frontend). Large — the biggest remaining code build.
3. **Auth / identity.** SSO (SAML/OIDC), SCIM provisioning, MFA. Enterprise clients refuse to sign without SSO; MFA is required by every compliance framework. Integrate an identity provider rather than build from scratch. Medium.
4. **Durable ingestion queue.** A real queue (Kafka/Redis Streams/SQS) in front of storage so a spike or a storage blip doesn't drop telemetry. Medium.
5. **Time-series storage backend.** Swap the reference dict for Prometheus/VictoriaMetrics (metrics) + a columnar store (events/alerts), OpenTelemetry-framed. Medium.
6. **Incident-response automation + notification.** Wire the investigator's incidents into per-tenant notification (email/Slack/webhook) with the SOC 2 / GDPR breach-notification timelines baked in. Small-medium.
7. **Rate limiting + replay protection** on the ingestion endpoint. Small.

---

## HARD GATES — non-code, required to actually sell (audits / legal / money / infra)

I cannot build these — they are process, spend, and time. Documented so they're planned, not discovered under pressure.

### Compliance certifications (the sales gates)
- **SOC 2 Type II** — US enterprise clients refuse to sign without it. ~$20–50K audit + tooling; 6–12 months of continuous evidence. (Vanta already scoped in prior notes, ~$30–65K CAD all-in first year.) Do FIRST if North America is the primary market.
- **ISO 27001:2022** — the EU/global equivalent gate. 93 Annex A controls. ~70% overlap with SOC 2, so pursue together — one control library satisfies both.
- Sequence: SOC 2 first if primary market is NA; both if selling globally.

### Privacy / data law (mandatory the moment you touch the data)
- **GDPR** — applies to ANY processing of EU residents' data regardless of where you're based. Lawful basis, data-subject rights, **72-hour breach notification**, Data Processing Agreements (DPAs) with every client. Fines up to 4% of global revenue.
- **HIPAA + BAAs** — if any insurance/health client sends PHI: Business Associate Agreements with the client AND with every subprocessor (cloud, etc.).
- **China (PIPL + data localization)** — the strictest. If serving China clients, data likely cannot leave China; pairs with the GB 45438 AIBOM requirement already built.
- **Canada (PIPEDA / Quebec Law 25)** — your home jurisdiction; Law 25 has demanding automated-decision rules.
- **Incident-response plan** — required by SOC 2, ISO, GDPR, and HIPAA simultaneously. Documented, tested (tabletop), with notification timelines built in.

### Infrastructure / reliability (the "run from my lab" tension)
- **Data residency** is the biggest structural constraint on "one lab, global clients." EU and China clients often **cannot legally let their data leave the region**. A single BC lab cannot satisfy this for everyone. → The residency enforcement is already built into the ingestion endpoint; the deployment answer is **regional ingestion points** (cheap cloud presence in eu-west / ap-southeast / cn-north) feeding back to the lab's control plane, OR regional processing for clients who require it.
- **Reliability / SLA** — enterprise uptime (99.9%+) needs redundancy a single lab can't provide. If the lab loses power, every client goes dark. → At minimum: offsite failover + backups + multi-region replication. "Run from my lab" and "global enterprise SLA" reconcile via a **hybrid**: lab runs the brains + your region; regional cloud points handle ingestion/residency/failover.
- **Backups + business continuity** — tested restore, multi-region replication (also an ISO 27001 requirement).

### Business operations
- **Billing/payments** — wire the metering (built) to a payment processor (Stripe): proration, tax, currency, dunning.
- **Contracts** — MSA, DPA, BAA templates; SLA definitions.
- **Support** — a channel + runbooks for client issues.

---

## The honest strategic read

Two things are in genuine tension with "run entirely from my BC lab, clients all over the globe":

1. **Data residency** — global clients (esp. EU/China) may legally require their data stay in-region. One Canadian lab can't satisfy that alone.
2. **Reliability** — enterprise SLAs need redundancy one lab can't provide.

Neither kills the plan. The resolution is a **hybrid architecture** (already reflected in the built code's region-awareness): the lab runs the control plane, the IP, and the ca-central region; lightweight regional ingestion points in the other regions handle residency + failover and stream back to the lab. This keeps the brains and the IP in your lab while clearing the legal and reliability bar.

**Recommended order to become sellable:**
1. Finish the code path (detector wiring → dashboard → auth) — buildable.
2. Stand up ONE regional cloud ingestion point + the lab control plane — small infra.
3. SOC 2 Type II (parallel-track the 6–12 month evidence period NOW — it's the long pole).
4. GDPR + DPA/BAA templates + incident-response plan.
5. ISO 27001 (reuses most SOC 2 evidence).
6. First design-partner client (pharma or insurance) under the vertical story already scoped.

---

*Everything built this session is a tested reference implementation of the SaaS foundation. It is simulation/reference-grade until deployed on real infrastructure with a real database, real identity provider, and the certifications above. This document is the plan; the certifications and infrastructure are the work that turns it into a live SaaS.*
