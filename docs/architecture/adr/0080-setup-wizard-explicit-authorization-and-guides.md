# ADR-0080: Setup wizard with explicit authorization; customer-side changes only as customer-specific instructions

**Status:** Accepted (2026-11-19, after the step 8.2 local verification against the provider simulators: the stack suite `provider-integrations` 10/10, the worker, library, api and smtp-adapter integration suites, the regression stack suites, Playwright 112/112, the 3-node RabbitMQ cluster suite on topology v14; record [docs/plan/steps/25-m365-google-connectors.md](../../plan/steps/25-m365-google-connectors.md) §13 WP6, §14; live verification against real Microsoft 365 and Google Workspace tenants, CI and a cluster apply not done). Proposed by the step 8.2 architect on 2026-11-17. Design: 25-m365-google-connectors.md D13, D14.

**Context.** The brief requires setup wizard APIs and frontend workflows, customer-specific setup documentation, and that the customer's mail-flow configuration is never modified without explicit authorization. Gateway-side settings (destinations, relay connector, outbound activation, proof policy) change where the customer's mail goes; customer-side settings (MX, connectors, transport rules, Gmail routing) live in the customer's tenant.

**Decision.**

1. The wizard state (`connect`, `domains`, `inbound`, `outbound`, `validate`, `activate`) is computed by the api from stored rows, never stored as a pointer.
2. Every gateway-side mail-flow change uses **preview → impact token → apply**: the preview returns the concrete change set and an HMAC impact token bound to organization, connection row version, change set, user and a 15-minute expiry; the apply recomputes the change set and refuses a changed or foreign token; it requires `confirm: true`, an `Idempotency-Key`, `integration:manage` **and** the change's own permission (`domain:routing_manage` or `connector:manage`), runs in one writer transaction and is audited with the change set.
3. Outbound activation requires a passed validation and a passed outbound probe within seven days.
4. The gateway **never** changes customer-side configuration (it holds no permission to). Customer-side steps are delivered as a **customer-specific setup guide** (JSON `setup-guide/1` and Markdown) generated from the connection's own values, with attestation codes the administrator records.
5. Disconnecting keeps inbound destinations (removing them would break inbound mail) and returns the provider-side cleanup steps.

**Consequences.** Two clicks and a confirmation for every gateway-side change; impact tokens expire. Customer-side configuration remains the customer's responsibility and is documented per customer.

**Alternatives considered.** Direct PUTs without preview (no explicit authorization of the concrete effect); automated configuration through provider APIs (write permissions, see ADR-0076).
