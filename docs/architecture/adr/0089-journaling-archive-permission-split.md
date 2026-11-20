# ADR-0089: Journaling / Archive permission split

**Status:** Accepted (2026-11-20, local verification: grant-preserving migration on the main schema (5 users, 0 lost a permission) and on a clean schema, `seed.test.ts` 8/8, api e2e `archive-split`/`journaling` (WP5), stack case 12, Playwright `archive-split.spec.ts`, `navigation.spec.ts` (6 roles), `archive.spec.ts`, `crud.spec.ts`; open item: user lifecycle actions on archive-role holders need archive access (step 8.6 §13.6); live provider tenants, CI and Kubernetes apply pending). Proposed by the step 8.6 architect, 2026-11-20. Design: [docs/plan/steps/27-journal-intake-and-archive-split.md](../../plan/steps/27-journal-intake-and-archive-split.md) (§2 D12, §3.3). Amends [ADR-0016](0016-authentication-sessions-rbac.md) (ten system roles) and [ADR-0068](0068-archive-search-opensearch-and-authorization.md) (A20 holders, record routes). Supersedes nothing.

**Context.** PO decision 2: organization admins manage journaling but do not read the archive by default; a `compliance_officer` role holds archive access; no tenant loses access silently. Before 8.6 `organization_admin` held every tenant permission, and `archive:read` (in the read set) opened archived record detail.

**Decision.**

1. New permissions `journal:read` (in the read set) and `journal:manage`, category `journaling`.
2. `ARCHIVE_ACCESS_PERMISSIONS` = `archive:search`, `archive:retrieve`, `archive:export`, `archive:legal_hold`, `archive:manage`, `ediscovery:manage`, removed from `organization_admin` (which gains `journal:*`); `domain_admin` gains `journal:*`, `security_analyst` and the read-set holders `journal:read`.
3. New system role `compliance_officer`: `organization:read`, `user:read`, `domain:read`, `journal:read`, `archive:read`, the archive access permissions, `message:reveal`, `audit:read`, `report:read`. Ten system roles.
4. Record-level archive routes (`GET /archive/messages/{id}`, `/journal`, `/security`, `POST …/reveal`) require `archive:search`; `archive:read` is configuration and status only. Archive settings are authorized per changed path (`journal:manage` for capture, `archive:manage` for storage and access).
5. Role assignments that grant or remove archive access are audited (`rbac.archive_access_granted|revoked`).
6. A grant-preserving migration (`journal_intake`) gives every existing `organization_admin` assignment in a customer organization a `compliance_officer` assignment, audited first (`rbac.archive_access_migrated`, actor `system`), idempotent, never deleting an assignment; an effective-permission comparison before and after proves no user loses a permission.

**Amendment (step 8.6 review, 2026-11-20).** The delegation of archive access by `user:manage` holders (role assignment only) is limited to user principals in an MFA-authenticated session and never applies to the caller's own account: an API key, a session without MFA or a self-assignment that would need it is refused (`403`), so no single credential can grant itself the archive. Callers that already hold the archive permissions they grant are judged by the ordinary escalation guard. `role-rules.ts` `forAssignment(AssignmentActor, roles)`; unit tests in `role-rules.test.ts` and `users.service.test.ts`, integration in `apps/api/integration/journaling.test.ts`.

**Consequences.** New organizations need an explicit, audited role assignment for archive access; `read_only_user`, `platform_admin` and custom roles with `archive:read` only lose archived-record detail (documented in the release notes).

**Alternatives considered.** Keeping `archive:read` for record detail (admins could still read any record by id); silently removing archive access from existing admins (rejected by PO decision 2). See the design §5.
