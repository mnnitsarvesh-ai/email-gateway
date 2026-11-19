# ADR-0075: One security incident model shared by ATO and ATP

**Status:** Accepted (2026-11-18, after the step 8.4 local verification: the stack suites `ato-smtp`, `ato-policy`, `ato-portal`, `ato-resilience`, Playwright and the regression gate; record [docs/plan/steps/24-account-takeover-core.md](../../plan/steps/24-account-takeover-core.md) §13, §14; CI and a cluster apply not done; identity-provider adapters step 8.5). Proposed by the step 8.4 architect on 2026-11-16 (file created by WP1 on 2026-11-18; product-owner decision D15 of the ATP gap analysis, approved 2026-11-16: "one model shared by ATP and ATO, built by whichever of ATP-4 and 8.4 starts first"). Supersedes nothing. Design: [docs/plan/steps/24-account-takeover-core.md](../../plan/steps/24-account-takeover-core.md) §7 (placeholder ADR-ATO-6 before numbering).

**Context.** The ATO brief asks for incidents with six states, assignment, notes, resolution and an audit trail; the ATP brief asks for security incidents created by escalations and late detections. Two incident systems would duplicate state machines, APIs, pages, notifications and audit. No incident lifecycle exists today ("DLP incidents" are a read view over scan results).

**Decision.**

1. Three generic tables: `security_incidents` (category, subject reference, origin, severity, six states, assignment, timestamps, resolution, reason codes, one active incident per category and subject), `security_incident_events` (timeline and audit trail) and `security_incident_links` (typed evidence references). Category detail lives in category tables (`ato_incident_details` first). Enum lists (categories, subject types, link types, origins) are append-only.
2. A shared library `@email-gateway/security-incidents` owns the vocabulary, the transition table, the transactional `IncidentStore` (with outbox events `security.incident.created.v1` / `updated.v1`) and a category-handler registry (subject resolution, detail, transition hooks, feedback schema, report sections, read and manage permissions).
3. A generic `/api/v1/incidents` API with a category filter; access is per category: routes require any registered category permission and the service restricts every query to the caller's readable categories, answering `404` for others. Category-specific evidence and actions live under the category's own routes (`/ato/incidents/{id}/…`).
4. Generic portal list and detail pages with category panels; public webhook types `security.incident.created` / `updated` carrying the category.
5. ATO (8.4) is the first category; ATP-4 adds categories, subject types, link types, origins, handlers, permissions and panels without changing generic columns, states, transitions or routes.

**Alternatives considered.** ATO-specific tables (a second system for ATP). One table with every category's columns (sparse, couples steps). Generic `incident:*` permissions (would grant ATP data to ATO analysts and vice versa). Folding DLP findings in now (no lifecycle requirement in 8.4).

**Consequences.** ATO pays a small indirection (detail table, handler); ATP-4 reuses everything; per-category retention and purge are set by each category (ATO: 730 days in the ato-worker).
