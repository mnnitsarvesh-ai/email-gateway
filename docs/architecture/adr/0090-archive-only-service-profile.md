# ADR-0090: Archive-only service profile

**Status:** Accepted (2026-11-20, local verification: api e2e `/auth/me` serviceProfile and domain refusals (WP5), portal navigation tests for every role and profile, Playwright `archive-only.spec.ts` 2/2; live provider tenants, CI and Kubernetes apply pending). Proposed by the step 8.6 architect, 2026-11-20. Design: [docs/plan/steps/27-journal-intake-and-archive-split.md](../../plan/steps/27-journal-intake-and-archive-split.md) (§2 D13). Amends nothing. Supersedes nothing.

**Context.** PO decision 1: an "archive only" plan for customers who want journaling and archiving without an MX change or mail filtering.

**Decision.**

1. Plan `archive_only` ("Archive only"): features `archiving`, `journal_intake`, `api_access`, `sso`, `webhooks`; `messages_per_day` 0, inbound and outbound recipient limits 0, `quarantine_retention_days` 0, `archive_retention_days` 3 650, `max_domains` 100, `max_users` 10 000, `max_message_size_bytes` 50 MiB, `api_requests_per_minute` 1 200.
2. Feature `journal_intake` (enterprise, dedicated, archive_only; not trial or standard) and the plan limits `journal_intake_messages_per_minute` and `journal_intake_max_message_bytes`.
3. `serviceProfile` = `archive_only` when the effective features have neither `inbound_filtering` nor `outbound_filtering` but have `archiving`, else `gateway`; derived (no column) and returned by `GET /auth/me` and the organization view.
4. The portal hides gateway-only pages for `archive_only`; domains of archive-only organizations are created with inbound off and cannot enable mail flow; existing organizations and domains are unchanged.

**Consequences.** One codebase and data model for both profiles; switching plans later enables the gateway pages without a migration.

**Alternatives considered.** A tenant "mode" column (duplicates features); hiding by role (wrong axis: a role says what a user may do, not what the tenant bought). See the design §5.
