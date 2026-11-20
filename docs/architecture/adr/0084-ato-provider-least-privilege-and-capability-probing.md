# ADR-0084: ATO provider least privilege, capability probing and tenant safety

**Status:** Accepted (2026-11-20, after the step 8.5 local verification against the provider simulators: the stack suite `ato-idp` 7/7 on the live api, ato-worker, integration-worker, provider-fake and idp-simulator, the library, worker, api, notification and 8.2 integration suites, the 8.4 contract kit for both adapters, Playwright `ato-providers.spec.ts` 5/5 with the ATO, incident, provider-connection and navigation specs; record [docs/plan/steps/26-ato-provider-adapters.md](../../plan/steps/26-ato-provider-adapters.md) §16 WP6, §17; live verification against real Microsoft and Google tenants (PQ7), CI and a cluster apply not done). Proposed by the step 8.5 architect on 2026-11-17. Design: [docs/plan/steps/26-ato-provider-adapters.md](../../plan/steps/26-ato-provider-adapters.md). Supersedes nothing.

**Context.** The brief requires supported provider APIs, not assuming equal events or permissions across providers, and never bypassing tenant authorization. Provider permissions and licences differ per customer and change over time.

**Decision.**

1. Three permission profiles per provider (`telemetry`, `response_standard`, `response_extended`), published as data and documented; customers grant a profile through 8.2.
2. Effective capabilities = declared by the adapter ∩ proven available by a read-only probe (permissions, licences, configuration) ∩ enabled by tenant settings; probes run periodically and on demand and never write.
3. One directory may be bound to at most one organization platform-wide; a changed directory reference stops the integration.
4. Provider actions run only for identities whose primary address domain is a verified gateway domain of the same organization and a domain of the integration's directory; ingested events of other domains are dropped.
5. Health per integration (`healthy`, `degraded`, `unhealthy`, `unknown`) and per stream (availability, lag, failures, throttling) is stored, shown and alerted.

**Alternatives considered.** One maximal permission set (excess privilege for read-only tenants). Trusting the granted list without probing (licences and roles are invisible in grants). Allowing a directory in several organizations (cross-tenant action risk). Acting on any identity the directory resolves (an alias or guest of another tenant could be acted on).

**Consequences.** Some tenants see partial capabilities and say so; customers must grant and licence; a directory shared by two gateway organizations must be split or merged by the operator.
