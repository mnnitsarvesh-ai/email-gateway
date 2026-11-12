# Roles, permissions and tenant scoping (RBAC)

How the control-plane API (`apps/api`) decides what a caller may do and which organization's data it may touch. Decisions: [ADR-0016](../architecture/adr/0016-authentication-sessions-rbac.md) and the step design [docs/plan/steps/02-tenants-auth-rbac.md](../plan/steps/02-tenants-auth-rbac.md) (D8, D9, D11). Authentication itself (passwords, sessions, MFA, the override token) is in [authentication.md](authentication.md). Code: `apps/api/src/modules/{roles,users,api-keys,login-audit,tenant-data}/`.

All paths below are under `/api/v1`.

## Principles

- **Guards check permission keys, never role names.** Every route declares `@RequirePermissions(...)` (or is `@Public()` / `@AuthenticatedOnly()`); a route without a declaration is denied, and `apps/api/test/route-security.e2e.test.ts` enumerates every route.
- **The tenant comes from the authenticated principal**, never from a header, body or query parameter: a member's home organization, an API key's organization, or the target of a platform override.
- **Another tenant's resource is `404`**, exactly like a resource that does not exist or was deleted. `403` only means "you are authenticated but lack a permission".
- **No escalation:** nobody can grant, revoke, create or edit what they do not hold themselves, and nobody can act on a user who holds permissions they lack (see [Acting on other users](#acting-on-other-users)).

## Permission catalog

The `permissions` table is seeded from `PERMISSIONS` in `packages/database/src/seed/catalog.ts` (the source of truth; `GET /permissions` lists it). Keys starting with `platform:` are **platform permissions** (`PLATFORM_PERMISSIONS`); all others are **tenant permissions** (`TENANT_PERMISSIONS`). `TENANT_READ_PERMISSIONS` is the read-only subset used by several default roles.

| Key                            | Meaning                                                                                                  |
| ------------------------------ | -------------------------------------------------------------------------------------------------------- |
| `organization:read`            | View organization profile, settings and limits                                                           |
| `organization:manage`          | Change organization profile and settings                                                                 |
| `user:read`                    | View users and their roles                                                                               |
| `user:manage`                  | Invite, disable and assign roles to users                                                                |
| `role:read`                    | View roles and the permission catalog                                                                    |
| `role:manage`                  | Create and edit custom roles                                                                             |
| `apikey:read`                  | View API keys (never secrets)                                                                            |
| `apikey:manage`                | Create and revoke API keys                                                                               |
| `session:manage`               | View and revoke other users' sessions                                                                    |
| `domain:read`                  | View domains, DNS records and mail servers                                                               |
| `domain:manage`                | Add, verify and configure domains                                                                        |
| `domain:dkim_rotate`           | Rotate DKIM signing keys of domains (step 2.1)                                                           |
| `policy:read`                  | View email policies and exceptions                                                                       |
| `policy:manage`                | Create and edit draft policies and exceptions                                                            |
| `policy:publish`               | Publish and roll back policy versions                                                                    |
| `message:read`                 | View message metadata, verdicts and delivery status                                                      |
| `message:read_content`         | View message content (body and attachments) from object storage                                          |
| `message:rescan`               | Request a rescan of a message's security pipeline (step 3.3)                                             |
| `quarantine:read`              | View quarantined messages                                                                                |
| `quarantine:release`           | Release quarantined messages                                                                             |
| `quarantine:delete`            | Delete quarantined messages                                                                              |
| `quarantine:request_release`   | Request the release of a quarantined message                                                             |
| `report:read`                  | View dashboards and reports                                                                              |
| `audit:read`                   | View the audit log                                                                                       |
| `archive:read`                 | Search and view archived messages                                                                        |
| `archive:export`               | Export archived messages                                                                                 |
| `archive:legal_hold`           | Create and release legal holds                                                                           |
| `webhook:manage`               | Create and edit webhook subscriptions                                                                    |
| `settings:manage`              | Change notification, quarantine and archive settings                                                     |
| `platform:organizations`       | Platform: create, suspend and manage customer organizations                                              |
| `platform:operations`          | Platform: view operational health, queues and maintenance status                                         |
| `platform:tenant_override`     | Platform: start an audited override into a customer organization                                         |
| `connector:read`               | View SMTP connectors (never secrets) (step 2.2)                                                          |
| `connector:manage`             | Create, rotate and disable SMTP connectors (step 2.2)                                                    |
| `domain:routing_manage`        | Change where a domain's mail is delivered (destination servers) (step 2.3)                               |
| `delivery:read`                | View per-recipient delivery status and the delivery audit trail (step 2.3)                               |
| `platform:dead_letter_replay`  | Platform: replay dead-lettered pipeline messages (step 3.2)                                              |
| `scan:settings_manage`         | Change the organization's security scan thresholds (step 4.1)                                            |
| `platform:scan_training`       | Train the shared spam classifiers (Bayes, fuzzy) from a message (step 4.1)                               |
| `platform:threat_intel_manage` | Manage the platform's known-threat file hashes (step 4.2) and URL/domain/IP threat indicators (step 4.3) |
| `platform:scan_rescan`         | Start and cancel bulk attachment rescans (step 4.2)                                                      |
| `bec:read`                     | View BEC executive/vendor profiles, trusted senders, suppressions and feedback (step 4.4)                |
| `bec:manage`                   | Manage BEC profiles, trusted senders, suppressions and communication history (step 4.4)                  |
| `bec:feedback`                 | Record false-positive/false-negative feedback on BEC verdicts (step 4.4)                                 |
| `bec:feedback_export`          | Export BEC feedback features for model retraining (step 4.4)                                             |
| `dlp:read`                     | View DLP policies, exceptions, patterns, dictionaries, compliance settings and incidents (step 4.5)      |
| `dlp:manage`                   | Manage DLP policies, exceptions, custom patterns and dictionaries; purge DLP evidence (step 4.5)         |
| `dlp:evidence_read`            | Read decrypted DLP evidence (audited; step 4.5)                                                          |
| `dlp:compliance_manage`        | Record the Aadhaar detection compliance basis (step 4.5)                                                 |
| `quarantine:preview`           | View the sanitized, DLP-masked preview of quarantined messages (step 5.3)                                |
| `quarantine:approve`           | Approve or deny quarantine release and review requests (step 5.3)                                        |
| `quarantine:reject`            | Reject quarantined messages (step 5.3)                                                                   |
| `quarantine:manage`            | Manually quarantine held-for-review or policy-rejected messages (step 5.3)                               |
| `quarantine:download`          | Download quarantined messages and attachments through single-use grants (step 5.3)                       |
| `quarantine:self`              | View, preview and request the release of quarantined mail addressed to oneself (step 5.3)                |
| `threat_intel:read`            | Look up platform threat intelligence (hash catalogue, indicators) (step 6.1)                             |
| `billing:read`                 | View the plan, entitlements and metered usage (step 6.1)                                                 |
| `delivery:suppression_manage`  | Add and remove recipient suppressions (step 6.1)                                                         |

The catalog has **58** permissions (55 before step 6.1, 49 before step 5.3).

`GET /permissions` lists `platform:*` keys only to users of the platform organization who are not under an override; customer users and API keys see the tenant permissions only.

## Default roles

System roles are shared by all organizations (`roles.organization_id IS NULL`, `is_system = true`) and are read-only through the API (`PUT`/`DELETE` → `409`). The seed creates exactly these nine (`SYSTEM_ROLE_KEYS`; `mailbox_user` added by step 5.3) and migrates retired step-1.1 keys to them.

| Abbr. | Key                   | Name                | Purpose                                                                                                                               |
| ----- | --------------------- | ------------------- | ------------------------------------------------------------------------------------------------------------------------------------- |
| PA    | `platform_admin`      | Platform Admin      | Platform operator: manages customer organizations and operations, reads tenant data, may start an audited override; no content access |
| OA    | `organization_admin`  | Organization Admin  | Every tenant permission within the organization                                                                                       |
| DA    | `domain_admin`        | Domain Admin        | Adds, verifies and configures the organization's domains                                                                              |
| SAn   | `security_analyst`    | Security Analyst    | Investigates messages, edits draft policies and handles quarantine                                                                    |
| QR    | `quarantine_reviewer` | Quarantine Reviewer | Reviews, releases, approves, rejects and deletes quarantined messages; no content access                                              |
| CA    | `compliance_auditor`  | Compliance Auditor  | Read-only access plus the audit log and archive export                                                                                |
| RO    | `read_only_user`      | Read-only User      | Read-only access to the organization                                                                                                  |
| MU    | `mailbox_user`        | Mailbox User        | End user (step 5.3): sees, previews and requests the release of quarantined mail addressed to their own verified address only         |

### Permission matrix

Generated from the seed catalog (`SYSTEM_ROLES`); if the catalog changes, regenerate this table.

| Permission                     | SA  | PA  | OA  | DA  | SAn | QR  | CA  | RO  | MU  |
| ------------------------------ | :-: | :-: | :-: | :-: | :-: | :-: | :-: | :-: | :-: |
| `organization:read`            |  ✓  |  ✓  |  ✓  |  ✓  |  ✓  |  ✓  |  ✓  |  ✓  |     |
| `organization:manage`          |  ✓  |     |  ✓  |     |     |     |     |     |     |
| `user:read`                    |  ✓  |  ✓  |  ✓  |  ✓  |     |     |  ✓  |  ✓  |     |
| `user:manage`                  |  ✓  |     |  ✓  |     |     |     |     |     |     |
| `role:read`                    |  ✓  |  ✓  |  ✓  |     |     |     |  ✓  |  ✓  |     |
| `role:manage`                  |  ✓  |     |  ✓  |     |     |     |     |     |     |
| `apikey:read`                  |  ✓  |  ✓  |  ✓  |     |     |     |  ✓  |  ✓  |     |
| `apikey:manage`                |  ✓  |     |  ✓  |     |     |     |     |     |     |
| `session:manage`               |  ✓  |     |  ✓  |     |     |     |     |     |     |
| `domain:read`                  |  ✓  |  ✓  |  ✓  |  ✓  |  ✓  |     |  ✓  |  ✓  |     |
| `domain:manage`                |  ✓  |     |  ✓  |  ✓  |     |     |     |     |     |
| `policy:read`                  |  ✓  |  ✓  |  ✓  |  ✓  |  ✓  |     |  ✓  |  ✓  |     |
| `policy:manage`                |  ✓  |     |  ✓  |     |  ✓  |     |     |     |     |
| `policy:publish`               |  ✓  |     |  ✓  |     |     |     |     |     |     |
| `message:read`                 |  ✓  |  ✓  |  ✓  |  ✓  |  ✓  |  ✓  |  ✓  |  ✓  |     |
| `message:read_content`         |  ✓  |     |  ✓  |     |  ✓  |     |     |     |     |
| `message:rescan`               |  ✓  |     |  ✓  |     |  ✓  |     |     |     |     |
| `quarantine:read`              |  ✓  |  ✓  |  ✓  |  ✓  |  ✓  |  ✓  |  ✓  |  ✓  |     |
| `quarantine:release`           |  ✓  |     |  ✓  |     |  ✓  |  ✓  |     |     |     |
| `quarantine:delete`            |  ✓  |     |  ✓  |     |  ✓  |  ✓  |     |     |     |
| `quarantine:request_release`   |  ✓  |     |  ✓  |     |     |  ✓  |     |     |     |
| `report:read`                  |  ✓  |  ✓  |  ✓  |  ✓  |  ✓  |  ✓  |  ✓  |  ✓  |     |
| `audit:read`                   |  ✓  |  ✓  |  ✓  |     |  ✓  |     |  ✓  |     |     |
| `archive:read`                 |  ✓  |  ✓  |  ✓  |     |  ✓  |     |  ✓  |  ✓  |     |
| `archive:export`               |  ✓  |     |  ✓  |     |     |     |  ✓  |     |     |
| `archive:legal_hold`           |  ✓  |     |  ✓  |     |     |     |     |     |     |
| `webhook:manage`               |  ✓  |     |  ✓  |     |     |     |     |     |     |
| `settings:manage`              |  ✓  |     |  ✓  |     |     |     |     |     |     |
| `platform:organizations`       |  ✓  |  ✓  |     |     |     |     |     |     |     |
| `platform:operations`          |  ✓  |  ✓  |     |     |     |     |     |     |     |
| `platform:tenant_override`     |  ✓  |  ✓  |     |     |     |     |     |     |     |
| `domain:dkim_rotate`           |  ✓  |     |  ✓  |  ✓  |     |     |     |     |     |
| `connector:read`               |  ✓  |  ✓  |  ✓  |  ✓  |     |     |  ✓  |  ✓  |     |
| `connector:manage`             |  ✓  |     |  ✓  |  ✓  |     |     |     |     |     |
| `domain:routing_manage`        |  ✓  |     |  ✓  |  ✓  |     |     |     |     |     |
| `delivery:read`                |  ✓  |  ✓  |  ✓  |  ✓  |  ✓  |  ✓  |  ✓  |  ✓  |     |
| `platform:dead_letter_replay`  |  ✓  |  ✓  |     |     |     |     |     |     |     |
| `scan:settings_manage`         |  ✓  |     |  ✓  |     |  ✓  |     |     |     |     |
| `platform:scan_training`       |  ✓  |  ✓  |     |     |     |     |     |     |     |
| `platform:threat_intel_manage` |  ✓  |  ✓  |     |     |     |     |     |     |     |
| `platform:scan_rescan`         |  ✓  |  ✓  |     |     |     |     |     |     |     |
| `bec:read`                     |  ✓  |     |  ✓  |     |  ✓  |     |  ✓  |     |     |
| `bec:manage`                   |  ✓  |     |  ✓  |     |  ✓  |     |     |     |     |
| `bec:feedback`                 |  ✓  |     |  ✓  |     |  ✓  |     |     |     |     |
| `bec:feedback_export`          |  ✓  |     |  ✓  |     |     |     |     |     |     |
| `dlp:read`                     |  ✓  |     |  ✓  |     |  ✓  |     |  ✓  |     |     |
| `dlp:manage`                   |  ✓  |     |  ✓  |     |  ✓  |     |     |     |     |
| `dlp:evidence_read`            |  ✓  |     |  ✓  |     |  ✓  |     |  ✓  |     |     |
| `dlp:compliance_manage`        |  ✓  |     |  ✓  |     |     |     |     |     |     |
| `quarantine:preview`           |  ✓  |     |  ✓  |     |  ✓  |     |     |     |     |
| `quarantine:approve`           |  ✓  |     |  ✓  |     |  ✓  |  ✓  |     |     |     |
| `quarantine:reject`            |  ✓  |     |  ✓  |     |  ✓  |  ✓  |     |     |     |
| `quarantine:manage`            |  ✓  |     |  ✓  |     |  ✓  |     |     |     |     |
| `quarantine:download`          |  ✓  |     |  ✓  |     |     |     |     |     |     |
| `quarantine:self`              |  ✓  |     |  ✓  |     |     |     |     |     |  ✓  |
| `threat_intel:read`            |  ✓  |  ✓  |  ✓  |     |  ✓  |     |     |     |     |
| `billing:read`                 |  ✓  |     |  ✓  |     |     |     |  ✓  |     |     |
| `delivery:suppression_manage`  |  ✓  |     |  ✓  |  ✓  |     |     |     |     |     |

**Platform roles** are the roles that hold any `platform:*` permission: `super_admin` and `platform_admin` (`PLATFORM_ROLE_KEYS`). They can be assigned only to users of the platform organization (`kind = platform`); assigning one in a customer organization is `400`. Customer organizations never see platform roles in `GET /roles` or `GET /roles/{key}` (`404`). Domain Admin is organization-wide; per-domain scoping of roles is out of scope for now.

## Domain permissions (step 2.1)

The domain routes (`/domains`, design [docs/plan/steps/03-domain-onboarding.md](../plan/steps/03-domain-onboarding.md) D14) use three permissions. All of them accept user tokens and API keys (an API key needs the permission in its scopes).

| Permission           | Routes                                                                                             | System roles                                                                                                        |
| -------------------- | -------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------- |
| `domain:read`        | `GET /domains`, `GET /domains/{id}`, `GET /domains/{id}/dns-records`, `GET /domains/{id}/status`   | super admin, platform admin, organization admin, domain admin, security analyst, compliance auditor, read-only user |
| `domain:manage`      | `POST /domains`, `POST /domains/{id}/verify`, `PATCH /domains/{id}/status`, `DELETE /domains/{id}` | super admin, organization admin, domain admin                                                                       |
| `domain:dkim_rotate` | `POST /domains/{id}/dkim/rotate`                                                                   | super admin, organization admin (holds every tenant permission), domain admin                                       |

- `domain:dkim_rotate` is separate from `domain:manage` because a rotation creates a key whose DNS record the customer must publish; misused, it can break outbound signing. A custom role with `domain:manage` but without `domain:dkim_rotate` can add, verify, activate, suspend and delete domains but gets `403` on rotation. The underscore keeps the `resource:action` shape (like `message:read_content`).
- Another tenant's domain, a deleted domain and an unknown id are all `404` on every route; the tenant is the caller's organization (or the override target), never a request field.
- Platform users without an override see only their own (platform) organization's domains. Under an override, `super_admin` can manage the target's domains (every mutation's audit row carries `metadata.override`) and `platform_admin` can only read them (`403` on mutations).
- `apps/api/integration/tenant-isolation-domains.test.ts` proves these rules end to end (tenant A admin and an A API key with every domain scope get `404` on every route of a tenant B domain; read-only `403` on mutations; domain admin manages and rotates; the custom role cannot rotate; override behaviour as above).

## SMTP connector permissions (step 2.2)

Outbound SMTP connectors (SASL credentials, source-IP networks, client-certificate fingerprints; design [docs/plan/steps/04-smtp-gateway.md](../plan/steps/04-smtp-gateway.md) D10 and §4.1) have their own two permissions, because a connector authorizes a server to send mail as the organization.

| Permission         | Routes (§4.1)                                                                                                                      | System roles                                                                                      |
| ------------------ | ---------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------- |
| `connector:read`   | `GET /smtp-connectors`, `GET /smtp-connectors/{id}`                                                                                | super admin, platform admin, organization admin, domain admin, compliance auditor, read-only user |
| `connector:manage` | `POST /smtp-connectors`, `PATCH /smtp-connectors/{id}`, `POST /smtp-connectors/{id}/rotate-secret`, `DELETE /smtp-connectors/{id}` | super admin, organization admin (holds every tenant permission), domain admin                     |

- `connector:read` is part of `TENANT_READ_PERMISSIONS`, so every system role built on the read set (platform admin, compliance auditor, read-only user) can list connectors. Responses never contain the secret hash; a SASL password is returned **once**, by create and rotate, to a caller holding `connector:manage`.
- `connector:manage` is held by the domain admin (who already configures the organization's mail domains), the organization admin and the super admin. Security analysts and quarantine reviewers hold neither key.
- The recipient allow-list routes (`/domains/{id}/recipient-validation`, `/domains/{id}/recipients`) use the existing `domain:read` and `domain:manage`.
- Tenant scoping is unchanged: the organization comes from the principal (or the audited override target), a foreign connector id is `404`.

## Mail routing and delivery permissions (step 2.3)

Two permissions for destination servers and delivery tracking (design [docs/plan/steps/05-routing.md](../plan/steps/05-routing.md) R13; catalog 33 → 35). The routes are designed in R13 and implemented by the api in step 2.3; this section records the permission model the seed grants.

| Permission              | Routes (R13)                                                                                             | System roles                                                                  |
| ----------------------- | -------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------- |
| `domain:read`           | `GET /destination-providers`, `GET /domains/{id}/destinations` (existing key)                            | as above                                                                      |
| `domain:routing_manage` | `PUT /domains/{id}/destinations`, `DELETE /domains/{id}/destinations`                                    | super admin, organization admin (holds every tenant permission), domain admin |
| `delivery:read`         | `GET /messages/{messageId}/deliveries`, `GET /messages/{messageId}/deliveries/events`, `GET /deliveries` | every system role                                                             |

- `domain:routing_manage` is separate from `domain:manage` (like `domain:dkim_rotate`): changing a domain's destination servers redirects **all** of its inbound and internal mail, so a custom role can configure domains without being able to send their mail elsewhere. It is not part of `TENANT_READ_PERMISSIONS`.
- `delivery:read` is part of `TENANT_READ_PERMISSIONS` (platform admin, compliance auditor and read-only user hold it through the read set) and is also granted explicitly to the domain admin, the security analyst and the quarantine reviewer, the roles that already hold `message:read`; so every system role can read delivery status, as R13 states ("every built-in tenant role and `read_only_user`"). Organization admin and super admin hold it through "every tenant permission" / "every permission". Delivery rows show recipient addresses of the caller's organization only; the audit trail never contains message content.
- Tenant scoping as everywhere: another organization's domain or message is `404`; platform users act on a tenant only through the audited override.

## Dead-letter replay permission (step 3.2)

One platform permission for replaying dead-lettered pipeline messages (design [docs/plan/steps/07-rabbitmq.md](../plan/steps/07-rabbitmq.md) Q9, [ADR-0024](../architecture/adr/0024-rabbitmq-topology-retry-dead-letter.md); catalog 35 → 36). Seed data only (`pnpm db:seed`), no migration. The endpoints are designed in Q9 and built by the api in step 3.2 WP4; this section records the permission model the seed grants.

| Permission                    | Routes (Q9)                                                                          | System roles                |
| ----------------------------- | ------------------------------------------------------------------------------------ | --------------------------- |
| `platform:operations`         | `GET /api/v1/platform/dead-letters` (queue depth and consumers; existing key)        | super admin, platform admin |
| `platform:dead_letter_replay` | `POST /api/v1/platform/dead-letters/replay` (also `@RequireMfa()` and `@UserOnly()`) | super admin, platform admin |

- Replay is separate from `platform:operations` (which only reads operational state): it re-runs pipeline stages on events of **every** tenant (platform-wide by nature; an organization filter narrows it), so a custom platform role can watch queues without being able to re-drive mail.
- Users only: API keys and override tokens never replay (`@UserOnly()`); an MFA-authenticated session is required; every replay (also a dry run, an empty match or a broker failure half-way) writes one `audit_logs` row with the operator's reason.
- Like every `platform:*` key it is stripped under a platform override and never assignable to a customer role (`400`).

## Scan permissions (steps 3.3, 4.1, 4.2)

Catalog 36 → 41 (seed data only, `pnpm db:seed`): `message:rescan` (step 3.3, [design](../plan/steps/08-message-lifecycle.md)), `scan:settings_manage` and `platform:scan_training` (step 4.1, [design](../plan/steps/09-rspamd.md) S8, S13, S16), `platform:threat_intel_manage` and `platform:scan_rescan` (step 4.2, [design](../plan/steps/10-attachment-scanning.md) A13, A16, A17).

| Permission                     | Routes                                                                                                                                                                                                                       | System roles                                      |
| ------------------------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------- |
| `message:read`                 | `GET /messages/{messageId}/scans` (existing key)                                                                                                                                                                             | every system role                                 |
| `message:rescan`               | `POST /messages/{messageId}/rescan`                                                                                                                                                                                          | super admin, organization admin, security analyst |
| `policy:read`                  | `GET /scan-settings` (existing key)                                                                                                                                                                                          | as above                                          |
| `scan:settings_manage`         | `PUT /scan-settings/{engine}`, `DELETE /scan-settings/{engine}` (`rspamd`, `attachment`; `url` step 4.3; `bec` step 4.4)                                                                                                     | super admin, organization admin, security analyst |
| `platform:scan_training`       | `POST /platform/organizations/{organizationId}/messages/{messageId}/scan-training` (`@UserOnly()`, `@RequireMfa()`, 60/min)                                                                                                  | super admin, platform admin                       |
| `platform:threat_intel_manage` | `GET`/`POST /platform/threat-hashes`, `DELETE /platform/threat-hashes/{sha256}`; step 4.3: `GET`/`POST /platform/threat-indicators`, `DELETE /platform/threat-indicators/{id}` (`@UserOnly()`, `@RequireMfa()`, 60/min each) | super admin, platform admin                       |
| `platform:scan_rescan`         | `POST`/`GET /platform/attachment-rescans`, `GET /platform/attachment-rescans/{jobId}`, `POST /platform/attachment-rescans/{jobId}/cancel` (`@UserOnly()`, `@RequireMfa()`, 10/min)                                           | super admin, platform admin                       |

- Tenant scan settings are **bounded** by the platform settings: Rspamd thresholds only inside the platform bounds, attachment settings raise-only (verdicts) and tighten-only (limits, denied types); the worker re-validates every stored row at use.
- The three `platform:` scan keys act on **shared** state: the Bayes/fuzzy stores (training one tenant's message changes every tenant's scores), the known-threat hash catalog (a hash changes every tenant's verdicts at once) and bulk rescans (they select messages of every organization unless one is named). They are therefore platform permissions, users only (no API keys or override tokens), MFA-authenticated, rate limited and audited (`scan_training.learn_*`, `threat_hash.added` / `threat_hash.removed` with the before-image, `attachment_rescan.requested` / `.cancelled`).
- The bulk-rescan api only writes the job row; the email-worker's rescan runner executes it as lifecycle role `scanner` (edge E19, reason `signature_rescan`), never as the requesting user.
- What tenants see of attachment results (`GET /messages/{messageId}/scans`) excludes the content-cache outcome and the attachment engine's durations: the cache is shared across organizations, so these would reveal another organization's mail (step 4.2 A16).

## BEC permissions (step 4.4)

Catalog 41 → 45 (seed data only, `pnpm db:seed`; [design](../plan/steps/12-phishing-bec.md) B11, B12, B18). All four are **tenant** permissions; every route takes the organization from the authenticated scope only, and another organization's id is a `404`.

| Permission            | Routes                                                                                                                                                                   | System roles                                                          |
| --------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | --------------------------------------------------------------------- |
| `bec:read`            | `GET /bec/executives`, `GET /bec/executives/{id}`, `GET /bec/vendors`, `GET /bec/vendors/{id}`, `GET /bec/trusted-senders`, `GET /bec/feedback`, `GET /bec/suppressions` | super admin, organization admin, security analyst, compliance auditor |
| `bec:manage`          | `POST`/`PATCH`/`DELETE` of executives, vendors and trusted senders, `DELETE /bec/suppressions/{id}`, `DELETE /bec/history` (`@RequireMfa()`)                             | super admin, organization admin, security analyst                     |
| `bec:feedback`        | `POST /messages/{messageId}/scans/{scanId}/bec-feedback` (`@UserOnly()`: one feedback per scan, user and kind)                                                           | super admin, organization admin, security analyst                     |
| `bec:feedback_export` | `GET /bec/feedback/export` (NDJSON, `@RequireMfa()`, 10 per caller per minute)                                                                                           | super admin, organization admin                                       |

- `platform_admin` holds none of them: its tenant reads are `TENANT_READ_PERMISSIONS`, and adding `bec:read` there would also give it to `read_only_user`, which B18 does not list. Platform operators act through an audited override when needed.
- API keys may hold `bec:read` and `bec:manage` (profiles, trusted senders and suppressions are integration data); feedback needs a user (the idempotency key is the user) and the export and the history purge need an MFA-authenticated user, so API keys are refused there (`403`).
- The `bec` scan settings use the existing keys: `policy:read` (`GET /scan-settings`) and `scan:settings_manage` (`PUT`/`DELETE /scan-settings/bec`).
- Suppressions are a bounded lever: only suppressible codes (never authentication, lookalike, executive impersonation, credential-link or engine codes), ≤ 90 days, never a free-mail domain, at most `BEC_SUPPRESSIONS_MAX_PER_TENANT` active rules, all audited, so a compromised analyst account cannot silence the engine.

## Data loss prevention (step 4.5)

Catalog 45 → 49 (seed data only, `pnpm db:seed`; [design](../plan/steps/13-dlp.md) D16, D17, D20, D21; [ADR-0038](../architecture/adr/0038-dlp-evidence-masking-and-aadhaar-gating.md)). All four are **tenant** permissions; every route takes the organization from the authenticated scope only, and another organization's id is a `404`.

| Permission              | Routes                                                                                                                                                                                                                                                                                                                          | System roles                                                          |
| ----------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------- |
| `dlp:read`              | `GET /dlp/policies`, `GET /dlp/policies/{id}`, `GET /dlp/exceptions`, `GET /dlp/patterns`, `GET /dlp/patterns/{id}`, `GET /dlp/dictionaries`, `GET /dlp/dictionaries/{id}`, `GET /dlp/compliance`, `GET /dlp/incidents`; and the masked `dlp` section of `GET /messages/{messageId}/scans` (the route itself is `message:read`) | super admin, organization admin, security analyst, compliance auditor |
| `dlp:manage`            | `POST`/`PATCH`/`DELETE` of policies, rules, exceptions, custom patterns and dictionaries, `POST /dlp/patterns/test` (30 per caller per minute), `DELETE /messages/{messageId}/scans/{scanId}/dlp-evidence` and `DELETE /dlp/evidence` (both `@RequireMfa()`)                                                                    | super admin, organization admin, security analyst                     |
| `dlp:evidence_read`     | `GET /messages/{messageId}/scans/{scanId}/dlp-evidence` (`@RequireMfa()`, `@UserOnly()`, 30 per user per minute)                                                                                                                                                                                                                | super admin, organization admin, security analyst, compliance auditor |
| `dlp:compliance_manage` | `PUT /dlp/compliance/aadhaar`, `DELETE /dlp/compliance/aadhaar` (`@RequireMfa()`, `@UserOnly()`)                                                                                                                                                                                                                                | super admin, organization admin                                       |

- **Not in `TENANT_READ_PERMISSIONS`:** that set gives `read_only_user`, `quarantine_reviewer`, `domain_admin` and `platform_admin` their tenant reads, and DLP data (policies that reveal what the organization protects, incidents, masked samples) is deliberately kept from them. They hold `message:read`, so the scans read API returns the `dlp` engine entry to them with `dlp: null` (outcome and reason codes only); masked samples, policy/rule/exception ids, coverage detail and the evidence state need `dlp:read`. Platform operators act through an audited override when needed.
- **Evidence access is one audited door.** Decrypted values exist only in the evidence route: `dlp:evidence_read` + an MFA-authenticated **user** (API keys `403`), an audit row `dlp_evidence.read` (actor, message, scan, match count) **committed before the evidence is fetched or decrypted**, `dlp_evidence.read_failed` (reason only) when anything fails afterwards, `Cache-Control: no-store`, purged → `410 evidence_purged`, expired → `410 evidence_expired`. Even there Aadhaar numbers, private keys and secrets are masked, card numbers keep only first 6 + last 4 and card verification codes are never stored. Evidence is envelope-encrypted under the dedicated key `DLP_EVIDENCE_KEY` (api and dlp email-worker only); purging erases the wrapped data key (crypto-shredding) before the object is deleted.
- **Aadhaar compliance.** The Aadhaar detector runs only when the organization has recorded a basis (`regulatory_obligation`, `uidai_authorised_entity`, `data_protection_policy` or `other`), a document reference, an attestation by the recording user and a review date within 365 days that has not passed. Recording and disabling need `dlp:compliance_manage` (organization admin only by default; not the security analyst, so the analyst who investigates cannot also widen detection) and an MFA-authenticated user, and are audited (`dlp_compliance.aadhaar_enabled` / `aadhaar_disabled` with before-images). The platform records the attestation; whether the basis is lawful is the organization's decision.
- **The pattern test never leaks.** `POST /dlp/patterns/test` persists nothing and never logs, audits or echoes the sample or the pattern (an e2e and an integration test capture the log output with marker strings).
- **Audit.** Every DLP change is audited with before-images in the same transaction (`dlp_policy.*`, `dlp_rule.*`, `dlp_exception.*`, `dlp_pattern.*`, `dlp_dictionary.*` with term **counts** only, `dlp_compliance.*`, `dlp_evidence.read` / `read_failed` / `purged`).
- API keys may hold `dlp:read` and `dlp:manage` (configuration is integration data); evidence reads and the Aadhaar basis need a user, and the evidence purges an MFA session, so API keys are refused there (`403`).
- The `dlp` scan settings use the existing keys: `policy:read` (`GET /scan-settings`) and `scan:settings_manage` (`PUT`/`DELETE /scan-settings/dlp`).

## Risk scoring (step 5.1)

No new permission ([design](../plan/steps/15-risk-scoring.md) R15, §7: profiles are policy configuration). Every route takes the organization from the authenticated scope only (another organization's id → `404`); API keys may call them within their scopes.

| Permission                       | Routes                                                                                                                                                    |
| -------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `policy:read`                    | `GET /risk-scoring/platform-profile`, `GET /risk-scoring/profile`, `GET /risk-scoring/profile/versions`, `GET /risk-scoring/profile/versions/{versionId}` |
| `policy:manage`                  | `POST /risk-scoring/profile/versions`, `PUT` and `DELETE /risk-scoring/profile/versions/{versionId}` (drafts only)                                        |
| `policy:publish`                 | `POST /risk-scoring/profile/versions/{versionId}/publish`, `POST /risk-scoring/profile/versions/{versionId}/activate`, `POST /risk-scoring/profile/reset` |
| `policy:manage` + `message:read` | `POST /messages/{messageId}/scans/{scanId}/risk/dry-run` (reads a stored round; writes nothing)                                                           |
| `message:read`                   | The `risk` section of `GET /messages/{messageId}/scans`                                                                                                   |

- With the default roles: `organization_admin` holds all of them; `security_analyst` reads, edits drafts and runs dry-runs but **cannot publish** (no `policy:publish`, verified in the stack suite `risk-smtp`); `platform_admin`, `domain_admin`, `compliance_auditor` and `read_only_user` read profiles (`policy:read`; `quarantine_reviewer` does not); every system role sees the `risk` section (`message:read`).
- **The `risk` section and DLP facts.** A score's `evidence.dlp` carries the round's DLP action, coverage and maximum severity, and its contributions name `dlp:action.*` / `dlp:severity.*` assertions. These are the same facts the `dlp` engine entry already shows to every `message:read` holder (outcome and `dlp.action.*` / detector reason codes); findings, masked samples and policy or rule ids stay behind `dlp:read`. This is deliberate (step 5.1 WP4 §12).
- **Audit.** Every profile change is audited in its transaction (`risk_profile.draft_created`, `draft_updated`, `draft_deleted`, `published`, `activated`, `reset`) with public ids, version numbers, hashes, the base profile and the changed override paths only (never values or the change note). The dry-run is not audited because it writes nothing.

## Policy engine (step 5.2)

No new permission ([design](../plan/steps/16-policy-engine.md) P22): policies and settings use the `policy:*` keys, departments are directory data under `user:*`. Every route takes the organization from the authenticated scope only (another organization's id → `404`); API keys may call them within their scopes.

| Permission                       | Routes                                                                                                                                                                                                                                                         |
| -------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `policy:read`                    | `GET /policies/catalog`, `GET /policies`, `GET /policies/{policyId}`, `GET /policies/{policyId}/versions[/{versionNo}]`, `GET /policy-settings`, `GET /policies/executions`                                                                                    |
| `policy:manage`                  | `POST /policies`, `PATCH /policies/{policyId}`, `POST /policies/{policyId}/versions`, `PUT` and `DELETE /policies/{policyId}/versions/{versionNo}` (drafts only), `POST /policies/test` (writes nothing)                                                       |
| `policy:publish`                 | `POST /policies/{policyId}/versions/{versionNo}/publish`, `POST /policies/{policyId}/versions/{versionNo}/activate` (rollback), `POST /policies/{policyId}/enable`, `POST /policies/{policyId}/disable`, `DELETE /policies/{policyId}`, `PUT /policy-settings` |
| `policy:manage` + `message:read` | `POST /messages/{messageId}/scans/{scanId}/policy/dry-run` (reads a stored round; writes nothing)                                                                                                                                                              |
| `message:read`                   | `GET /messages/{messageId}/policy-evaluations`, the `policy` section of `GET /messages/{messageId}/scans`                                                                                                                                                      |
| `user:read`                      | `GET /departments`, `GET /departments/{departmentId}`, `GET /departments/{departmentId}/members`                                                                                                                                                               |
| `user:manage`                    | `POST /departments`, `PATCH` and `DELETE /departments/{departmentId}`, `POST /departments/{departmentId}/members`, `DELETE /departments/{departmentId}/members/{memberId}`                                                                                     |

- **Default roles.** `organization_admin` (and `super_admin`) hold every key above. `security_analyst` reads, creates and edits drafts, tests and dry-runs but **cannot publish, activate, enable, disable, delete or change settings** (no `policy:publish`) and cannot manage departments (no `user:*`). `platform_admin`, `domain_admin`, `compliance_auditor` and `read_only_user` read policies, settings, the history and departments (`policy:read`, `user:read`); `quarantine_reviewer` reads only the message evaluations (`message:read`).
- **Overrides of the platform recommendation.** A rule may weaken a _level-only_ risk recommendation only when it carries `override: true` **and** the organization's setting `allowRecommendationOverrides` is on (`PUT /policy-settings`, `policy:publish`). Turning it on is audited as `policy.settings_overrides_enabled`; publishing a version with override rules is audited as `policy.override_rules_published` with the rule ids. No setting or rule ever weakens the strictness floor (hard blocks, engine failures, the DLP binding, missing data).
- **Policy alerts** (ALERT action) are mailed by the notification-worker to the organization's active, email-verified users holding `policy:publish` through a role ([runbook](../runbooks/policy-notifications.md)).
- **Audit.** Every change is audited in its transaction (`policy.created`, `policy.updated`, `policy.enabled`, `policy.disabled`, `policy.deleted`, `policy.version_draft_created`, `policy.version_draft_updated`, `policy.version_draft_deleted`, `policy.version_published`, `policy.version_activated`, `policy.override_rules_published`, `policy.settings_updated`, `policy.settings_overrides_enabled`, `department.created`, `department.updated`, `department.deleted`, `department.member_added`, `department.member_removed`) with public ids, version numbers, row versions, hashes, rule counts, override rule ids, generations and changed paths only — never definition values, change notes, settings values or member addresses. Tests and dry-runs write nothing and are not audited.

## Quarantine (step 5.3)

Six new tenant permissions ([design](../plan/steps/17-quarantine.md) Q25, ADR-0047, ADR-0048); the existing ones keep their meaning (`quarantine:read` = metadata only, `quarantine:release`, `quarantine:delete`, `quarantine:request_release`). `quarantine:self` is **not** part of `TENANT_READ_PERMISSIONS`, and `quarantine:download` is held by no system role except `super_admin` and `organization_admin`. Every route is under `/api/v1/quarantine`, takes the organization from the authenticated scope only (another organization's or another user's entry → `404`, never `403`) and is listed in `apps/api/test/route-security.e2e.test.ts`.

| Role                                         | read | preview | release | approve | reject | delete | manage | download | request_release | self |
| -------------------------------------------- | :--: | :-----: | :-----: | :-----: | :----: | :----: | :----: | :------: | :-------------: | :--: |
| super_admin                                  |  ✓   |    ✓    |    ✓    |    ✓    |   ✓    |   ✓    |   ✓    |    ✓     |        ✓        |  ✓   |
| organization_admin                           |  ✓   |    ✓    |    ✓    |    ✓    |   ✓    |   ✓    |   ✓    |    ✓     |        ✓        |  ✓   |
| security_analyst                             |  ✓   |    ✓    |    ✓    |    ✓    |   ✓    |   ✓    |   ✓    |          |                 |      |
| quarantine_reviewer                          |  ✓   |         |    ✓    |    ✓    |   ✓    |   ✓    |        |          |        ✓        |      |
| compliance_auditor                           |  ✓   |         |         |         |        |        |        |          |                 |      |
| domain_admin, read_only_user, platform_admin |  ✓   |         |         |         |        |        |        |          |                 |      |
| **mailbox_user**                             |      |         |         |         |        |        |        |          |                 |  ✓   |

| Permission                                         | Route families (Q26)                                                                                                                                                                                                                        |
| -------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `quarantine:read`                                  | `GET /catalog`, `GET /summary`, `GET /entries`, `GET /entries/{entryId}`, `GET /entries/{entryId}/history`, `GET /releases/{releaseId}`, `GET /approvals`, `GET /approvals/{id}`, `GET /settings` (metadata; `subject` only with `preview`) |
| `quarantine:preview`                               | `GET /entries/{entryId}/preview` (sanitized JSON text, DLP-masked; rate-limited; `no-store`)                                                                                                                                                |
| `quarantine:release`                               | `POST /entries/{entryId}/release` (re-validation; may become an approval request); bulk `release`                                                                                                                                           |
| `quarantine:request_release`                       | `POST /entries/{entryId}/request-release`                                                                                                                                                                                                   |
| `quarantine:approve`                               | `POST /approvals/{id}/approve`, `POST /approvals/{id}/deny` (user session + MFA; never the requester or the entry's recipient; never an API key); bulk `approve` / `deny`                                                                   |
| `quarantine:approve` or the requester              | `POST /approvals/{id}/cancel`                                                                                                                                                                                                               |
| `quarantine:reject`                                | `POST /entries/{entryId}/reject`; bulk `reject`                                                                                                                                                                                             |
| `quarantine:delete`                                | `POST /entries/{entryId}/delete` (refused under legal hold or retention); bulk `delete`                                                                                                                                                     |
| `quarantine:manage`                                | `POST /entries` (manual quarantine of a held-for-review or policy-rejected message)                                                                                                                                                         |
| `quarantine:download`                              | `POST /entries/{entryId}/download-grants` (user + MFA + password/TOTP re-entry, tenant `download.enabled`), `GET /downloads/{token}` (user; single use)                                                                                     |
| `settings:manage`                                  | `PUT /settings`                                                                                                                                                                                                                             |
| `quarantine:self` (user principal, verified email) | `GET /me/entries`, `GET /me/entries/{id}`, `GET /me/entries/{id}/preview`, `POST /me/entries/{id}/release`, `POST /me/entries/{id}/request-release`, `GET` / `PUT /me/preferences` — own address only; API keys and overrides refused       |

- **Separation of duties.** An approver needs `quarantine:approve`, a user session with MFA, and must be neither the requester nor the entry's recipient. For a request made with an API key the requester is the key's creator (`api_keys.created_by_user_id`), so a user cannot approve a release they triggered with their own key; a follow-up request for reasons that appeared after an approval keeps the original requester. The decision records a hash of the decider's permissions, and the release executor re-checks the stored decision (both rules).
- **End users** (`mailbox_user`, or any user holding `quarantine:self`) never approve, deny, reject, delete, bulk-act or download; self-release is allowed only within the tenant's settings (reason subset, maximum risk level, no approval reason, not stale).
- **The step 3.3 operator release** `POST /messages/{messageId}/release` keeps `quarantine:release` but answers `409 quarantine_workflow_required` for every quarantined or held message (Q30).
- **Rescan of held mail.** `POST /messages/{messageId}/rescan` from `quarantined` or `held_for_review` needs `quarantine:release` besides `message:rescan` (`403 quarantine_rescan_forbidden`): the new round supersedes the open entries and a clean verdict delivers the held recipients. Every system role holding `message:rescan` also holds `quarantine:release`; custom roles and API keys with `message:rescan` only can rescan the other source states.
- **Audit.** Every route writes an audit row (`quarantine.*`, Q21) with ids, enums, counts and hashes only; the operator's typed reason is stored in `quarantine_actions.reason`, never in audit metadata. Previews and downloads are audited before content is read.

The routes are implemented by step 5.3 WP4; this section is the authorization contract they follow.

## REST API (step 6.1)

Three new tenant permissions ([design](../plan/steps/18-rest-api.md) §3.6, D7); none is part of `TENANT_READ_PERMISSIONS`, so read-only roles do not gain them implicitly. `organization_admin` holds them through the tenant set and `super_admin` through the full catalog; the other grants are explicit in `SYSTEM_ROLES`. API keys may carry them as scopes (they are tenant permissions).

| Permission                     | Routes                                                                                                                                                       | System roles                                                                          |
| ------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------- |
| `threat_intel:read`            | `GET /threat-intelligence/lookup` (class `expensive`, audited `threat_intel.looked_up`)                                                                      | super_admin, platform_admin, organization_admin, security_analyst                     |
| `billing:read`                 | `GET /billing/plan`, `GET /billing/usage` (`expensive`)                                                                                                      | super_admin, organization_admin, compliance_auditor                                   |
| `delivery:suppression_manage`  | `POST /recipients/suppressions`, `DELETE /recipients/suppressions/{suppressionId}` (Idempotency-Key, class `sensitive`)                                      | super_admin, organization_admin, domain_admin                                         |
| `report:read` (existing)       | `GET /reports/traffic`, `GET /reports/threats`, `GET /reports/url-clicks` (`expensive`) — the first routes gated by it                                       | every system role except mailbox_user                                                 |
| `audit:read` (existing)        | `GET /audit/login-events` (step 1.3), `GET /audit/logs` (step 6.1; audited `audit.searched`)                                                                 | super_admin, platform_admin, organization_admin, security_analyst, compliance_auditor |
| `delivery:read` (existing)     | also `GET /recipients/suppressions`, `GET /recipients/suppressions/{suppressionId}`                                                                          | every system role except mailbox_user                                                 |
| `message:read` (existing)      | also `GET /messages`, `GET /messages/{messageId}`, `…/recipients`, `…/attachments`, `…/urls`, `GET /attachments` (`expensive`), `GET /url-protection/clicks` | every system role except mailbox_user                                                 |
| `organization:read` (existing) | also `GET /usage` (the caller's organization)                                                                                                                | every system role except mailbox_user                                                 |

**Platform audit access.** `GET /platform/audit/logs` requires `platform:operations` **and** `audit:read`, a user principal (`@UserOnly`: API keys are refused) and an MFA session (`@RequireMfa`). Only users of the platform organization can hold `platform:*`; override sessions carry tenant permissions only, so they are refused too. The caller names exactly one target (`organizationId` or `scope=platform`); each search is audited as `platform.audit_searched` in the searched organization's trail (platform rows for `scope=platform`). Every other cross-tenant read stays behind the audited override.

**Self-service routes without a permission** (`@AuthenticatedOnly()`, an explicit allow-list enforced by `test/route-inventory.e2e.test.ts`): `GET /auth/me`, `POST /auth/logout`, `POST /auth/logout-all`, `POST /auth/password/change`, `POST /auth/email/verification`, `GET /auth/sessions`, `DELETE /auth/sessions/{sessionId}`, the four `/auth/mfa/*` enrollment routes and `DELETE /platform/overrides/{overrideId}` (ending one's own override). Every other non-public route names a permission.

## Custom roles

Organizations with `role:manage` can define their own roles (`POST /roles`, `PUT /roles/{key}`, `DELETE /roles/{key}`; user principals only, not API keys):

- They belong to one organization (`roles.organization_id`); other organizations never see them (`404`) and may use the same key for their own role.
- Keys match `^[a-z][a-z0-9_]{2,63}$` and cannot be a system role key (`409`). Duplicate keys in the organization are `409`.
- Permissions must be tenant permissions (`platform:*` or unknown keys → `400`), and the caller must hold every one of them (`403`). Editing requires holding every old **and** new permission of the role.
- `PUT` replaces name, description and the whole permission set, and invalidates the authorization cache of the organization, so users holding the role get the new permissions on their next request.
- `DELETE` is `409` while any user holds the role.
- Removing `user:manage` from a custom role is refused (`409`) when it would leave the organization without an active administrator (below).

`GET /roles` returns system roles (minus platform roles in customer organizations) followed by the organization's custom roles, each with its permission keys. Every change is audited (`role.created`, `role.updated` with added/removed permissions, `role.deleted`).

## Assigning roles

`POST /users/invitations` and `PUT /users/{id}/roles` (`user:manage`) take `roleKeys` (at least one). For every request:

1. Every key must name a system role or a custom role of the organization (`400` otherwise).
2. Platform roles only in the platform organization (`400`).
3. **Escalation guard (`403`):** the caller must hold every permission of every role it **adds or removes**. Removing a role the caller could not grant is escalation too: a user manager cannot demote an organization admin. Super admins hold every permission. API keys are judged by their effective scopes.
4. **Last administrator (`409`):** see below.

Role changes take effect on the user's next request (the principal cache is invalidated after commit); the user keeps their sessions.

## Acting on other users

`user:manage` is not a master key. **Target-side escalation guard (`403 Cannot manage a user who holds permissions you do not hold`):** every action on another user (profile or email change, status change and unlock, deletion, MFA reset, invitation resend, role change, session revocation) requires the caller to hold every permission of every role the target currently has. Without it, a custom role holding only `user:manage`, or an API key with that scope, could change an administrator's email and reset their password, and so take over an account stronger than itself. API keys are judged by their effective scopes; because keys never hold `apikey:manage`, `role:manage` or `session:manage`, no key can act on an organization admin.

The email address is the account-recovery channel, so it is treated more strictly still:

- Only a user session may change another user's email (`403 Email changes require a user session` for API keys), and never under a platform override.
- A changed address is unverified, and `POST /auth/password/forgot` sends reset links only to **verified** addresses. The owner must first confirm the new address with the link sent to it (`POST /auth/email/verify`). Invitation acceptance verifies the address it was sent to.

## Last-administrator rule

An organization that has at least one **active, non-deleted user whose roles grant `user:manage`** must keep one. Disabling (`PATCH /users/{id}/status`), deleting (`DELETE /users/{id}`) or changing the roles of users (`PUT /users/{id}/roles`, or `PUT /roles/{key}` on a custom role) is `409 The organization must keep at least one active administrator` when it would leave none. The check runs in the same transaction as the change with the organization row locked (`SELECT … FOR UPDATE`), so two concurrent changes cannot both remove "the other" administrator. Organizations that have no active administrator yet (for example, only an invited admin) are not blocked.

In addition, users cannot disable or delete themselves (`409`), and an administrator cannot reset their own MFA through the admin endpoint (they use the self-service MFA endpoints instead).

## User lifecycle (summary)

| Change            | Endpoint                                                  | Effects                                                                                                                                                                                                                                                                                                                         |
| ----------------- | --------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Invite            | `POST /users/invitations`                                 | One transaction: lock the organization, `max_users` (non-deleted users) → `409 Organization limit reached: max_users`, roles checked, user `invited` (a soft-deleted user with the same email is reinstated with password, MFA and lockout state cleared), roles, invitation token; email after commit. Existing email → `409`. |
| Resend            | `POST /users/{id}/invitation`                             | Invited users only (`409` otherwise); earlier links stop working. `202 { expiresAt }`.                                                                                                                                                                                                                                          |
| Profile           | `PATCH /users/{id}`                                       | `displayName`, `email`. A new email clears the verification and sends a verification link to it (invited users get a new invitation instead); no reset link goes to it until it is verified. Email changes need a user session and are refused under an override (`403`). Duplicate → `409`.                                    |
| Disable           | `PATCH /users/{id}/status { status: "disabled", reason }` | From `active`, `locked` or `invited` (cancels the invitation). Revokes every session.                                                                                                                                                                                                                                           |
| Activate / unlock | `PATCH /users/{id}/status { status: "active" }`           | From `disabled` (only users who completed their invitation), from `status = locked`, or from a login lockout (`locked_until` in the future): clears `locked_until`, `failed_login_count` and the Redis failure counters.                                                                                                        |
| Delete            | `DELETE /users/{id}`                                      | Soft delete (`deleted_at`), outstanding tokens consumed, sessions revoked. Hidden from lists and lookups (`404`).                                                                                                                                                                                                               |
| MFA reset         | `POST /users/{id}/mfa/reset`                              | User principal with an MFA-authenticated session (`403 MFA required` otherwise). Clears the TOTP secret, replay step and recovery codes; revokes sessions.                                                                                                                                                                      |
| Sessions          | `GET`/`DELETE /users/{id}/sessions[/{sessionId}]`         | `session:manage`. Live sessions from the replica; revocation is immediate (deny-list).                                                                                                                                                                                                                                          |

Every mutation writes an `audit_logs` row (`user.invited`, `user.invitation_resent`, `user.updated`, `user.status_changed`, `user.roles_changed`, `user.deleted`, `user.mfa_reset`, `session.revoked`, `session.revoked_all`). Under a platform override the row carries `metadata.override = { id, reason }`.

## API keys

`POST /api-keys { name, scopes[], expiresAt? }` (`apikey:manage`, user principals only):

- The organization feature `api_access` must be enabled (`403` otherwise; while it is off, existing keys authenticate as `401`).
- `scopes` is non-empty and contains only **tenant permissions the creator holds** (`403` for others, `400` for `platform:*` or unknown keys).
- **Forbidden scopes** (`API_KEY_FORBIDDEN_SCOPES`): `apikey:manage`, `role:manage`, `session:manage` → `400`. Managing credentials, roles and other people's sessions requires a person. The authenticator also strips these from any stored key.
- `expiresAt` defaults to now + 365 days and may be at most now + 730 days.
- The key (`egk_<12 base62>_<secret>`) is returned **once** in `{ apiKey, key }`. The database stores the 16-character prefix and an HMAC-SHA256 (with `AUTH_TOKEN_PEPPER`) of the full key; neither the key nor the hash is ever returned, logged or audited.
- Keys cannot be created under a platform override: a key would outlive the time-boxed, audited override (the same rule covers invitations, role changes and email changes, see [Platform operators](#platform-operators)).

A key's effective permissions are its scopes ∩ tenant permissions minus the forbidden scopes. It can call only routes marked "K" in the API contract; user-only routes (`POST /api-keys`, role management, MFA reset, self-service) are `403`. `DELETE /api-keys/{id}` revokes idempotently (`204`), and the key stops working immediately. `GET /api-keys` (`apikey:read`) lists keys with `prefix`, `scopes`, `createdBy`, `lastUsedAt`, `expiresAt` and `revokedAt`. Audit actions: `apikey.created`, `apikey.revoked` (metadata: name, prefix, scopes).

## Login events

`GET /audit/login-events` (`audit:read`) lists the organization's `login_audit_logs` rows from the replica: newest first, cursor-paginated, window `[from, to)` defaulting to the last 7 days and at most 90 days, filters `outcome` and `userId` (a user of the organization; a user of another organization matches nothing). Attempts that could not be attributed to an organization (unknown email without an organization slug) belong to no tenant and are never listed. The general `audit_logs` query API arrives with step 6.1.

## Platform operators

Platform users (organization `kind = platform`, MFA mandatory) act in two ways:

- **Platform functions** (`platform:*` permissions, e.g. the organization catalog) in their own organization.
- **Platform override** into one customer organization (`platform:tenant_override`, MFA session, reason, time-boxed; see [authentication.md](authentication.md)). Under the override the tenant scope is the target organization, `platform:*` permissions are stripped, every request is audited as `platform.override_request`, and mutations carry `metadata.override`. A `platform_admin` is read-only in tenants (no `user:manage`); a `super_admin` holds every tenant permission there but still cannot assign platform roles in the customer organization. **Nothing that creates standing access can be done under an override** (`403 … is not allowed under a platform override`): creating API keys, inviting users or resending invitations, changing user roles, and changing a user's email. Each of these would outlive the time-boxed override; they belong to the customer's own administrators. Operational support (status changes and unlocks, display-name fixes, MFA resets, session revocation, domain and policy work) stays possible and audited.

## Tenant-scoped data access (repository rule)

Every query on a tenant-owned table goes through a repository (`*.repository.ts`, the only files under `apps/api/src/modules/**` allowed to use Prisma — enforced by ESLint) whose methods take a `TenantScope` as their first parameter:

- The scope is built only by `scopeFromPrincipal` (requests) or `systemScope` (CLI, jobs, test fixtures). It is a branded, frozen object, so a raw organization id cannot be passed by mistake.
- `where` clauses are built with `tenantWhere(scope, …)`, which adds `organization_id` and throws if a conflicting `organizationId` is present.
- Lookups by public id are `findFirst({ where: { publicId, organizationId } })`, never `findUnique({ publicId })` followed by a check. Writes by internal id are `updateMany`/`deleteMany` with the organization in the filter.
- Partitioned message data is reached through the `message_identities` registry (by public id and organization), then `email_messages` by `(id, received_at)` **and** the organization.
- Lists read the replica (`PrismaReadService.client`); mutations, read-after-write and authorization lookups use the writer.

The only unscoped identity lookups are the authentication paths in `modules/auth/repositories/` (login by email/slug, token hashes, API-key prefix, principal snapshot). `TenantDataModule` exports read-only scoped repositories for later steps: `DomainsRepository`, `PoliciesRepository` (soft-deleted policies excluded), `MessagesRepository` and `QuarantineRepository`.

Coverage: unit tests assert that every query of these repositories and of the identity repositories carries the scope's organization (`tenant-data.repositories.test.ts`, `identity-repositories.test.ts`); `apps/api/integration/tenant-isolation-identity.test.ts` proves end to end that an administrator of tenant A holding every tenant permission, an A API key and a platform operator overriding into B never reach the other tenant's users, roles, sessions, API keys, login events, domains, policies, messages or quarantine.
