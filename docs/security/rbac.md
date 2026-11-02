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

| Key                          | Meaning                                                          |
| ---------------------------- | ---------------------------------------------------------------- |
| `organization:manage`        | Change organization profile and settings                         |
| `user:read`                  | View users and their roles                                       |
| `user:manage`                | Invite, disable and assign roles to users                        |
| `role:read`                  | View roles and the permission catalog                            |
| `role:manage`                | Create and edit custom roles                                     |
| `apikey:read`                | View API keys (never secrets)                                    |
| `apikey:manage`              | Create and revoke API keys                                       |
| `session:manage`             | View and revoke other users' sessions                            |
| `domain:read`                | View domains, DNS records and mail servers                       |
| `domain:manage`              | Add, verify and configure domains                                |
| `policy:read`                | View email policies and exceptions                               |
| `policy:manage`              | Create and edit draft policies and exceptions                    |
| `policy:publish`             | Publish and roll back policy versions                            |
| `message:read`               | View message metadata, verdicts and delivery status              |
| `message:read_content`       | View message content (body and attachments) from object storage  |
| `quarantine:read`            | View quarantined messages                                        |
| `quarantine:release`         | Release quarantined messages                                     |
| `quarantine:delete`          | Delete quarantined messages                                      |
| `quarantine:request_release` | Request the release of a quarantined message                     |
| `report:read`                | View dashboards and reports                                      |
| `audit:read`                 | View the audit log                                               |
| `archive:read`               | Search and view archived messages                                |
| `archive:export`             | Export archived messages                                         |
| `archive:legal_hold`         | Create and release legal holds                                   |
| `webhook:manage`             | Create and edit webhook subscriptions                            |
| `settings:manage`            | Change notification, quarantine and archive settings             |
| `platform:organizations`     | Platform: create, suspend and manage customer organizations      |
| `platform:operations`        | Platform: view operational health, queues and maintenance status |
| `platform:tenant_override`   | Platform: start an audited override into a customer organization |

`GET /permissions` lists `platform:*` keys only to users of the platform organization who are not under an override; customer users and API keys see the tenant permissions only.

## Default roles

System roles are shared by all organizations (`roles.organization_id IS NULL`, `is_system = true`) and are read-only through the API (`PUT`/`DELETE` → `409`). The seed creates exactly these eight (`SYSTEM_ROLE_KEYS`) and migrates retired step-1.1 keys to them.

| Abbr. | Key                   | Name                | Purpose                                                                                                                               |
| ----- | --------------------- | ------------------- | ------------------------------------------------------------------------------------------------------------------------------------- |
| PA    | `platform_admin`      | Platform Admin      | Platform operator: manages customer organizations and operations, reads tenant data, may start an audited override; no content access |
| OA    | `organization_admin`  | Organization Admin  | Every tenant permission within the organization                                                                                       |
| DA    | `domain_admin`        | Domain Admin        | Adds, verifies and configures the organization's domains                                                                              |
| SAn   | `security_analyst`    | Security Analyst    | Investigates messages, edits draft policies and handles quarantine                                                                    |
| QR    | `quarantine_reviewer` | Quarantine Reviewer | Reviews, releases and deletes quarantined messages; no content access                                                                 |
| CA    | `compliance_auditor`  | Compliance Auditor  | Read-only access plus the audit log and archive export                                                                                |
| RO    | `read_only_user`      | Read-only User      | Read-only access to the organization                                                                                                  |

### Permission matrix

Generated from the seed catalog (`SYSTEM_ROLES`); if the catalog changes, regenerate this table.

| Permission                   | SA  | PA  | OA  | DA  | SAn | QR  | CA  | RO  |
| ---------------------------- | :-: | :-: | :-: | :-: | :-: | :-: | :-: | :-: |
| `organization:read`          |  ✓  |  ✓  |  ✓  |  ✓  |  ✓  |  ✓  |  ✓  |  ✓  |
| `organization:manage`        |  ✓  |     |  ✓  |     |     |     |     |     |
| `user:read`                  |  ✓  |  ✓  |  ✓  |  ✓  |     |     |  ✓  |  ✓  |
| `user:manage`                |  ✓  |     |  ✓  |     |     |     |     |     |
| `role:read`                  |  ✓  |  ✓  |  ✓  |     |     |     |  ✓  |  ✓  |
| `role:manage`                |  ✓  |     |  ✓  |     |     |     |     |     |
| `apikey:read`                |  ✓  |  ✓  |  ✓  |     |     |     |  ✓  |  ✓  |
| `apikey:manage`              |  ✓  |     |  ✓  |     |     |     |     |     |
| `session:manage`             |  ✓  |     |  ✓  |     |     |     |     |     |
| `domain:read`                |  ✓  |  ✓  |  ✓  |  ✓  |  ✓  |     |  ✓  |  ✓  |
| `domain:manage`              |  ✓  |     |  ✓  |  ✓  |     |     |     |     |
| `policy:read`                |  ✓  |  ✓  |  ✓  |  ✓  |  ✓  |     |  ✓  |  ✓  |
| `policy:manage`              |  ✓  |     |  ✓  |     |  ✓  |     |     |     |
| `policy:publish`             |  ✓  |     |  ✓  |     |     |     |     |     |
| `message:read`               |  ✓  |  ✓  |  ✓  |  ✓  |  ✓  |  ✓  |  ✓  |  ✓  |
| `message:read_content`       |  ✓  |     |  ✓  |     |  ✓  |     |     |     |
| `quarantine:read`            |  ✓  |  ✓  |  ✓  |  ✓  |  ✓  |  ✓  |  ✓  |  ✓  |
| `quarantine:release`         |  ✓  |     |  ✓  |     |  ✓  |  ✓  |     |     |
| `quarantine:delete`          |  ✓  |     |  ✓  |     |  ✓  |  ✓  |     |     |
| `quarantine:request_release` |  ✓  |     |  ✓  |     |     |  ✓  |     |     |
| `report:read`                |  ✓  |  ✓  |  ✓  |  ✓  |  ✓  |  ✓  |  ✓  |  ✓  |
| `audit:read`                 |  ✓  |  ✓  |  ✓  |     |  ✓  |     |  ✓  |     |
| `archive:read`               |  ✓  |  ✓  |  ✓  |     |  ✓  |     |  ✓  |  ✓  |
| `archive:export`             |  ✓  |     |  ✓  |     |     |     |  ✓  |     |
| `archive:legal_hold`         |  ✓  |     |  ✓  |     |     |     |     |     |
| `webhook:manage`             |  ✓  |     |  ✓  |     |     |     |     |     |
| `settings:manage`            |  ✓  |     |  ✓  |     |     |     |     |     |
| `platform:organizations`     |  ✓  |  ✓  |     |     |     |     |     |     |
| `platform:operations`        |  ✓  |  ✓  |     |     |     |     |     |     |
| `platform:tenant_override`   |  ✓  |  ✓  |     |     |     |     |     |     |

**Platform roles** are the roles that hold any `platform:*` permission: `super_admin` and `platform_admin` (`PLATFORM_ROLE_KEYS`). They can be assigned only to users of the platform organization (`kind = platform`); assigning one in a customer organization is `400`. Customer organizations never see platform roles in `GET /roles` or `GET /roles/{key}` (`404`). Domain Admin is organization-wide; per-domain scoping of roles is out of scope for now.

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
