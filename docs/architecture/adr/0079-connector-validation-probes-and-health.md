# ADR-0079: Connector validation probes and integration health monitoring

**Status:** Accepted (2026-11-19, after the step 8.2 local verification against the provider simulators: the stack suite `provider-integrations` 10/10, the worker, library, api and smtp-adapter integration suites, the regression stack suites, Playwright 112/112, the 3-node RabbitMQ cluster suite on topology v14; record [docs/plan/steps/25-m365-google-connectors.md](../../plan/steps/25-m365-google-connectors.md) §13 WP6, §14; live verification against real Microsoft 365 and Google Workspace tenants, CI and a cluster apply not done). Proposed by the step 8.2 architect on 2026-11-17. Design: 25-m365-google-connectors.md D10, D11, D12, D18.

**Context.** The brief requires connector validation and health monitoring for both providers while the gateway has read-only access to the customer's tenant and must never let a provider outage affect mail flow.

**Decision.**

1. Validation is **observational**: provider API reads (token, permissions, tenant identity, domain verification and Microsoft's MX target), stored gateway DNS results (MX, SPF, DKIM), SMTP reachability probes to the destination hosts (EHLO, STARTTLS with certificate verification, `RCPT TO:<postmaster@domain>`, never DATA), recent delivery statistics, loop evidence, and an **outbound probe**: a single-use probe address on a reserved domain that the customer sends to (Exchange admin center "Validate connector", or any message for Google). The relay accepts probe recipients only on provider-relay sessions; ingestion intercepts them, verifies the proof, records a bounded evidence row and stores no content.
2. What cannot be observed with read-only access (inbound connector restriction, Enhanced Filtering, Gmail "reject non-gateway mail") is **attested** by the administrator and labelled as an attestation.
3. A new deployable `integration-worker` (roles `tasks`, `health`, `maintenance`) runs verifications, validation runs and periodic health checks, with database claims (`FOR UPDATE SKIP LOCKED`, leases) and a leader-elected maintenance role. It uses MySQL and the outbox; no RabbitMQ consumer and no Redis.
4. Health is the worst severity of the latest failing checks, with a grace period for provider-API errors; transitions are stored, audited and published as `integration.connection.health_changed.v1` (topology v14: one binding to `email.webhooks`), projected as the public webhook `integration.health_changed` and the alert `integration_unhealthy`.
5. Health never changes mail flow automatically (I1); outbound suspension is an explicit administrator action.

**Consequences.** One more worker to deploy and monitor; validation needs the administrator to send one probe message. Customer-side lock-down is a statement, not a proof, and the portal says so.

**Alternatives considered.** Exchange configuration reads with `Exchange.ManageAsApp` (write-capable role); test messages with DATA to the customer (puts content into customer mailboxes); health in the api (provider calls on request threads).
