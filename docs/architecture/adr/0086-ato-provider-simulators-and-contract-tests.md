# ADR-0086: ATO provider simulators and contract tests

**Status:** Accepted (2026-11-20, after the step 8.5 local verification against the provider simulators: the stack suite `ato-idp` 7/7 on the live api, ato-worker, integration-worker, provider-fake and idp-simulator, the library, worker, api, notification and 8.2 integration suites, the 8.4 contract kit for both adapters, Playwright `ato-providers.spec.ts` 5/5 with the ATO, incident, provider-connection and navigation specs; record [docs/plan/steps/26-ato-provider-adapters.md](../../plan/steps/26-ato-provider-adapters.md) §16 WP6, §17; live verification against real Microsoft and Google tenants (PQ7), CI and a cluster apply not done). Proposed by the step 8.5 architect on 2026-11-17. Design: [docs/plan/steps/26-ato-provider-adapters.md](../../plan/steps/26-ato-provider-adapters.md). Amends ADR-0013 (testing strategy: provider simulators join the local test doubles). Supersedes nothing.

**Context.** No test may call a real provider; the adapters must still be exercised end to end (HTTP, paging, throttling, permissions, licences, eventual consistency) and the 8.4 contract kit must pass against them.

**Decision.**

1. Dependency-free simulators of the used subset of Graph, Office 365 Management Activity, Google Reports, Directory and Gmail settings, and of the token endpoints, driven by synthetic datasets and a script API, enforcing the required permission per endpoint.
2. In-process for unit and integration tests; one Compose service `idp-simulator` in the `smtp-test` profile for stack suites.
3. Endpoint overrides and plain HTTP are accepted only in `local` and `ci`; production origins are code constants.
4. The 8.4 contract kit runs against both adapters on simulators and is a release gate; simulator fidelity is limited to documented behaviour and reviewed when an adapter changes.

**Alternatives considered.** Recorded real responses (needs a real tenant and leaks data). Mocking `fetch` (skips HTTP behaviour). Vendor sandboxes (real endpoints and credentials).

**Consequences.** Simulators can diverge from providers; live verification needs customer test tenants and is recorded as not done until then.
