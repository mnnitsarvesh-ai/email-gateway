# ADR-0081: Loop prevention and failover for provider mail flow

**Status:** Accepted (2026-11-19, after the step 8.2 local verification against the provider simulators: the stack suite `provider-integrations` 10/10, the worker, library, api and smtp-adapter integration suites, the regression stack suites, Playwright 112/112, the 3-node RabbitMQ cluster suite on topology v14; record [docs/plan/steps/25-m365-google-connectors.md](../../plan/steps/25-m365-google-connectors.md) §13 WP6, §14; live verification against real Microsoft 365 and Google Workspace tenants, CI and a cluster apply not done). Proposed by the step 8.2 architect on 2026-11-17. Design: 25-m365-google-connectors.md D9, D15.

**Context.** Routing outbound and internal mail from Exchange Online or Gmail through the gateway and back to the same provider creates loop risks (a transport rule matching the gateway's own internal delivery again) and new availability dependencies in both directions.

**Decision.**

1. The existing loop stops remain authoritative: organization-bound `X-Gateway-Trace`, the ingestion second-pass refusal and `evaluateHops` with `ROUTING_MAX_GATEWAY_PASSES`.
2. **Microsoft 365 internal routing** uses a per-connection **route token** (`X-EG-Route-Token`, HMAC-derived, versioned): the delivery-worker adds it to internal deliveries to domains of a Microsoft 365 connection with internal routing active; the generated transport rule that routes internal mail to the gateway excepts messages carrying the current token, and a second rule removes the header so it never reaches a mailbox. Rotation switches versions only after the administrator attests the updated rules. A database error retries the reinjection instead of sending without the header.
3. **Google Workspace internal routing** applies only to "Internal – sending" mail; the gateway's deliveries arrive as received mail and are not re-routed; no token is needed.
4. Validation and health report loop refusals as a failing required check.
5. **Failover:** inbound uses the provider presets' host lists and Postfix's retry; providers queue and retry towards every gateway relay host listed in the guide; the gateway never configures or recommends an automatic fail-open path to direct delivery; an emergency bypass is a documented customer-side procedure with an explicit warning; provider API outages degrade only health and the wizard.

**Consequences.** Customers apply two transport rules for Microsoft 365 internal routing; the token is a routing marker, not a security credential (the proof of ADR-0078 is the security control), but it is still masked for readers without `integration:manage`.

**Alternatives considered.** Hop limits only (traffic amplification and failures); IP- or connector-based rule exceptions (unreliable with Enhanced Filtering); automatic bypass on gateway outage (uninspected mail without an authorization).
