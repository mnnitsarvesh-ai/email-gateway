# API conventions and endpoints

The control-plane REST API (`apps/api`). Decisions: [ADR-0015](../architecture/adr/0015-api-base-path.md) (base path), [ADR-0016](../architecture/adr/0016-authentication-sessions-rbac.md) (authentication, sessions, RBAC, platform override) and the step design [docs/plan/steps/02-tenants-auth-rbac.md](../plan/steps/02-tenants-auth-rbac.md). Details of authentication: [docs/security/authentication.md](../security/authentication.md); roles and permissions: [docs/security/rbac.md](../security/rbac.md).

## Versioning and the OpenAPI document

- Business routes live under the `/api` prefix and are versioned in the URI: `/api/v1/...` ([ADR-0015](../architecture/adr/0015-api-base-path.md)). Breaking changes ship as `/api/v2` alongside `/api/v1` until clients migrate. The old unprefixed `/v1/...` paths return `404`.
- Operational routes stay unprefixed and unversioned: `GET /health/live`, `GET /health/ready` (probes and Compose health checks do not change). `/api/health/*` is a `404`.
- In non-production environments, OpenAPI is served at `/docs` (Swagger UI) and `/docs-json`. The document declares two security schemes: `access-token` (HTTP bearer, JWT) and `api-key` (`X-API-Key` header). Every protected operation names the schemes it accepts and carries a tag; every request and response schema is generated from the zod schemas that validate it.
- A snapshot of the document is committed as [docs/api/openapi.json](openapi.json). `apps/api/test/openapi.test.ts` fails when the running API and the snapshot differ; after an intended change regenerate it with `UPDATE_OPENAPI=1 pnpm --filter @email-gateway/api test:e2e -- openapi` and review the diff.
- `API_INTERNAL_URL` (portal → api) is the api **origin**; callers append `/api/v1/...`.

## Authentication

Every route except the health probes, `GET /api/v1/meta` and the public authentication routes (marked **P** below) requires exactly one credential. Both credentials at once, or neither, is a `401`.

| Credential   | Header                          | Who                                           | Notes                                                                                                                                                                                                                                  |
| ------------ | ------------------------------- | --------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Access token | `Authorization: Bearer <jwt>`   | users (portal, CLI)                           | From login, MFA verification or refresh. HS256, 10 min by default (`AUTH_ACCESS_TOKEN_TTL_SECONDS`, max 15 min). Revocation (logout, suspension, password change, …) is effective on the next request                                  |
| API key      | `X-API-Key: egk_<prefix>_<key>` | automation of one organization (**K** routes) | Created by an organization administrator, shown once. Effective permissions = the key's scopes ∩ tenant permissions; never `platform:*`, `apikey:manage`, `role:manage`, `session:manage`. Needs the organization feature `api_access` |

**Login and MFA.** `POST /auth/login { email, password, organization? }` (organization = slug; only needed when the same email exists in several organizations). With MFA enabled the answer is `{ mfaRequired: true, mfaToken, expiresIn }`; finish with `POST /auth/mfa/verify { mfaToken, code }` (or `recoveryCode`). Every failure is `401 Invalid credentials`, whatever the reason.

**Refresh rotation.** `POST /auth/refresh { refreshToken }` returns a new token pair; the presented refresh token is spent. Presenting a spent token again (or two concurrent refreshes with the same token) is treated as theft: the whole session is revoked. **Clients must serialize refreshes.** Refresh tokens travel in JSON bodies only.

**Enrollment-restricted sessions.** When the organization requires MFA (`settings.mfaRequired`; always for the platform organization) and the user has not enrolled, login succeeds with `mfaEnrollmentRequired: true`. That session may only call `GET /auth/me`, `GET /auth/sessions`, logout, logout-all and the TOTP setup/enable routes; everything else is `403 MFA enrollment required`.

**Step-up (MFA session).** Routes marked **MFA** require a session that completed a second factor (`403 MFA required` otherwise): the platform override, the organization deletion steps and `POST /users/{id}/mfa/reset`.

**Platform override.** Platform staff reach a customer organization only through `POST /platform/overrides { organizationId, reason, durationMinutes }` (permission `platform:tenant_override`, MFA session). The returned access token is scoped to that one organization, carries tenant permissions only (all `platform:*` permissions are stripped), cannot be refreshed, expires with the override, ends on `DELETE /platform/overrides/{id}`, and every request made with it is written to `audit_logs` as `platform.override_request`. Mutations made under an override also carry `metadata.override = { id, reason }` in their own audit rows.

**Organization catalog.** Users of the platform organization holding `platform:organizations` (without an override) manage the organization catalog (`/organizations`): create, plan, status, features, limits, deletion. This is a platform function, not an override: no reason is required and every mutation is audited.

## Tenancy

The tenant of a request is always derived from the authenticated principal: the user's organization, the API key's organization, or the override target. No endpoint accepts a tenant id from a header or query. A resource of another tenant is answered exactly like a missing one (`404`), so existence is never disclosed.

## Endpoints

All paths are under `/api/v1`. Access: **P** = public (no credentials); **U** = users only (API keys get `403`); **K** = API keys accepted; **MFA** = MFA session required; **enroll** = reachable during MFA enrollment; **RL** = rate limited (`429` with `Retry-After`). Permission keys are listed in [docs/security/rbac.md](../security/rbac.md).

### Operational

| Method | Path            | Access | Description                                                  |
| ------ | --------------- | ------ | ------------------------------------------------------------ |
| GET    | `/health/live`  | P      | Process liveness (unprefixed). No dependency checks          |
| GET    | `/health/ready` | P      | Dependency readiness (unprefixed). `200` when ok, else `503` |
| GET    | `/api/v1/meta`  | P      | API build/version information                                |

### Authentication and self-service (`auth`, `platform` tags)

| Method | Path                               | Access                              | Body → result                                                                                                               |
| ------ | ---------------------------------- | ----------------------------------- | --------------------------------------------------------------------------------------------------------------------------- |
| POST   | `/auth/login`                      | P, RL                               | `{ email, password, organization? }` → token response, or `{ mfaRequired: true, mfaToken, expiresIn }`                      |
| POST   | `/auth/mfa/verify`                 | P, RL                               | `{ mfaToken, code? , recoveryCode? }` (exactly one) → token response                                                        |
| POST   | `/auth/refresh`                    | P, RL                               | `{ refreshToken }` → token response (rotated)                                                                               |
| POST   | `/auth/logout`                     | U, enroll                           | → `204`, current session revoked                                                                                            |
| POST   | `/auth/logout-all`                 | U, enroll                           | → `204`, every own session revoked                                                                                          |
| GET    | `/auth/me`                         | U, enroll                           | user, organization, roles, permissions, `mfaEnabled`, `emailVerified`, session `{ id, mfaAuthenticated }`, `override`       |
| GET    | `/auth/sessions`                   | U, enroll                           | own live sessions                                                                                                           |
| DELETE | `/auth/sessions/{sessionId}`       | U                                   | `204`; `404` if not an own live session                                                                                     |
| POST   | `/auth/password/forgot`            | P, RL                               | `{ email, organization? }` → always `202`; links only to verified addresses                                                 |
| POST   | `/auth/password/reset`             | P, RL                               | `{ token, newPassword }` → `204`, all sessions revoked                                                                      |
| POST   | `/auth/password/change`            | U, RL                               | `{ currentPassword, newPassword }` → `204`, other sessions revoked                                                          |
| POST   | `/auth/email/verification`         | U, RL                               | sends a verification email if unverified → `202`                                                                            |
| POST   | `/auth/email/verify`               | P, RL                               | `{ token }` → `204`                                                                                                         |
| POST   | `/auth/invitations/inspect`        | P, RL                               | `{ token }` → `{ email, organizationName, expiresAt }` (does not consume the token)                                         |
| POST   | `/auth/invitations/accept`         | P, RL                               | `{ token, password, displayName? }` → `204`; the user becomes active with a verified email                                  |
| POST   | `/auth/mfa/totp/setup`             | U, enroll                           | → `{ secret, otpauthUri }` (`409` if already enabled)                                                                       |
| POST   | `/auth/mfa/totp/enable`            | U, enroll, RL                       | `{ code }` → `{ recoveryCodes: string[10] }` (shown once)                                                                   |
| POST   | `/auth/mfa/totp/disable`           | U, RL                               | `{ password, code }` → `204` (`409` while the organization requires MFA)                                                    |
| POST   | `/auth/mfa/recovery-codes`         | U, RL                               | `{ code }` → `{ recoveryCodes }` (replaces all)                                                                             |
| POST   | `/platform/overrides`              | U, `platform:tenant_override`, MFA  | `{ organizationId, reason (10–500), durationMinutes? }` → `{ overrideId, accessToken, tokenType, expiresAt, organization }` |
| DELETE | `/platform/overrides/{overrideId}` | U (owner, normal or override token) | `204`; the override token stops working                                                                                     |

Token response: `{ accessToken, tokenType: "Bearer", expiresIn, refreshToken, refreshTokenExpiresAt, sessionId, mfaEnrollmentRequired, user: { id, email, displayName }, organization: { id, slug, name, kind } }`.

### Identity administration (`users`, `roles`, `api-keys`, `audit` tags)

Scoped to the caller's organization (or the override target). Rules (no privilege escalation, including on the target user of every action: the caller must hold every permission of the target's roles; platform roles only in the platform organization; last-administrator protection; no invitations, role or email changes under a platform override) are described in [docs/security/rbac.md](../security/rbac.md).

| Method | Path                               | Access                | Notes                                                                                         |
| ------ | ---------------------------------- | --------------------- | --------------------------------------------------------------------------------------------- |
| GET    | `/users`                           | `user:read`, K        | reader; filters `status`, `q` (email/name prefix), `role`; paginated                          |
| GET    | `/users/{id}`                      | `user:read`, K        | includes roles, `mfaEnabled`, `emailVerified`, `lockedUntil`                                  |
| POST   | `/users/invitations`               | `user:manage`, K      | `{ email, displayName, roleKeys[≥1] }` → `201`; enforces `max_users`; email sent after commit |
| POST   | `/users/{id}/invitation`           | `user:manage`, K      | resend → `202` (invited users only)                                                           |
| PATCH  | `/users/{id}`                      | `user:manage`, K      | `{ displayName?, email? }`; an email change (U only) clears verification and sends a new one  |
| PATCH  | `/users/{id}/status`               | `user:manage`, K      | `{ status: active \| disabled, reason }`; `active` also unlocks; disabling revokes sessions   |
| PUT    | `/users/{id}/roles`                | `user:manage`, K      | `{ roleKeys[≥1] }`                                                                            |
| DELETE | `/users/{id}`                      | `user:manage`, K      | soft delete, revokes sessions, `204`                                                          |
| POST   | `/users/{id}/mfa/reset`            | `user:manage`, U, MFA | clears TOTP and recovery codes, revokes sessions                                              |
| GET    | `/users/{id}/sessions`             | `session:manage`      | live sessions                                                                                 |
| DELETE | `/users/{id}/sessions`             | `session:manage`      | revoke all, `204`                                                                             |
| DELETE | `/users/{id}/sessions/{sessionId}` | `session:manage`      | `204`                                                                                         |
| GET    | `/permissions`                     | `role:read`, K        | permission catalog (platform keys only for platform-organization principals)                  |
| GET    | `/roles`                           | `role:read`, K        | system roles (no platform roles for customers) + custom roles                                 |
| GET    | `/roles/{key}`                     | `role:read`, K        |                                                                                               |
| POST   | `/roles`                           | `role:manage`, U      | custom role (tenant permissions only)                                                         |
| PUT    | `/roles/{key}`                     | `role:manage`, U      | custom roles only (`409` for system roles)                                                    |
| DELETE | `/roles/{key}`                     | `role:manage`, U      | custom roles only, `409` while assigned                                                       |
| GET    | `/api-keys`                        | `apikey:read`, K      | never returns secrets                                                                         |
| POST   | `/api-keys`                        | `apikey:manage`, U    | `{ name, scopes[], expiresAt? }` → `201 { apiKey, key }` (key shown once)                     |
| DELETE | `/api-keys/{id}`                   | `apikey:manage`, U    | revoke, `204` (idempotent)                                                                    |
| GET    | `/audit/login-events`              | `audit:read`, K       | reader; `from`, `to` (default 7 days, max 90), `outcome`, `userId`; paginated                 |

### Organizations (`organizations` tag)

"Platform" below means a user of the platform organization holding `platform:organizations`, without an override. Everybody else (members, API keys, override sessions) sees only their own scope organization; any other organization id is `404`.

| Method | Path                                        | Access                                                     | Notes                                                                                                                                                                                                              |
| ------ | ------------------------------------------- | ---------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| POST   | `/organizations`                            | `platform:organizations`, U                                | create (below) → `201`; duplicate slug `409`; unknown/inactive plan `400`                                                                                                                                          |
| GET    | `/organizations`                            | `organization:read` or `platform:organizations`, K         | reader; platform: all, filters `status`, `kind`, `planCode`, `deploymentMode`, `q` (slug/name prefix), deleted only with `status=deleted`; others: a page with their own organization                              |
| GET    | `/organizations/{id}`                       | same                                                       | platform: any; others: only their own (`404` otherwise)                                                                                                                                                            |
| PUT    | `/organizations/{id}`                       | `organization:manage` (own) or `platform:organizations`, K | `{ name, planCode? }`; `planCode` needs `platform:organizations` (`403`); slug, kind, deploymentMode, dataRegion are immutable (`400`); `409` while pending deletion/deleted                                       |
| PATCH  | `/organizations/{id}/status`                | `platform:organizations`, U                                | `{ status: active \| suspended, reason }` (reason required to suspend); only active ↔ suspended (`409` otherwise); never the platform organization. Suspension revokes all sessions and stops API keys immediately |
| GET    | `/organizations/{id}/usage`                 | `organization:read` or `platform:organizations`, K         | reader; `?from&to` (ISO 8601; default last 30 days; at most 31 days; `from < to`)                                                                                                                                  |
| GET    | `/organizations/{id}/settings`              | `organization:read` or `platform:organizations`, K         | includes `quarantineRetentionMaxDays`, the current upper bound                                                                                                                                                     |
| PUT    | `/organizations/{id}/settings`              | `organization:manage` (own) or `platform:organizations`, K | changes the given fields (at least one; rules below)                                                                                                                                                               |
| GET    | `/organizations/{id}/features`              | `organization:read` or `platform:organizations`, K         | `{ organizationId, data: [{ key, enabled, config, source, updatedAt }] }`                                                                                                                                          |
| PUT    | `/organizations/{id}/features/{featureKey}` | `platform:organizations`, U                                | `{ enabled, config? }` → `source: override` (kept across plan changes)                                                                                                                                             |
| DELETE | `/organizations/{id}/features/{featureKey}` | `platform:organizations`, U                                | back to the plan value (`source: plan`) → `204`                                                                                                                                                                    |
| GET    | `/organizations/{id}/limits`                | `organization:read` or `platform:organizations`, K         | `{ organizationId, data: [{ key, value, source, updatedAt }] }`                                                                                                                                                    |
| PUT    | `/organizations/{id}/limits/{limitKey}`     | `platform:organizations`, U                                | `{ value }` (non-negative integer) → `source: override`                                                                                                                                                            |
| DELETE | `/organizations/{id}/limits/{limitKey}`     | `platform:organizations`, U                                | back to the plan value → `204`                                                                                                                                                                                     |
| GET    | `/organizations/{id}/deletion`              | `platform:organizations`, U                                | deletion request state                                                                                                                                                                                             |
| POST   | `/organizations/{id}/deletion`              | `platform:organizations`, U, MFA                           | `{ reason (10–512), confirmSlug }` → `200` state; see [the runbook](../runbooks/organization-deletion.md)                                                                                                          |
| POST   | `/organizations/{id}/deletion/confirm`      | `platform:organizations`, U, MFA                           | `{ confirmSlug }`; a different platform user (`403`), within `ORG_DELETION_CONFIRM_WINDOW_HOURS` (`409`)                                                                                                           |
| POST   | `/organizations/{id}/deletion/cancel`       | `platform:organizations`, U, MFA                           | `{ reason (10–512) }`; from `pending_deletion`, or `deleted` before `purge_after` → `suspended`                                                                                                                    |

**Create.** `{ name, slug, planCode, deploymentMode: saas | dedicated, dataRegion, deployment?, settings?, initialAdmin? }`. `slug`: `^[a-z0-9](?:[a-z0-9-]{1,61}[a-z0-9])$`, not `platform`, `admin`, `api`, `www`, `system`. `dataRegion` and `deployment.region`: `^[a-z]{2}-[a-z]+-\d$` (e.g. `ap-south-1`). `deployment { region, environment }` is required for `dedicated` and refused for `saas`. One transaction creates the organization (`kind customer`, `status active`), its settings (defaults, then `settings`), the plan's limits and features (`source plan`), a deployment row (SaaS: `active` in `APP_ENV`; dedicated: `provisioning`; real provisioning is step 8.3) and, with `initialAdmin { email, displayName }`, an invited user with `organization_admin` whose invitation email is sent after commit. The `201` body is the organization plus `initialAdmin { id, email, status, invitationExpiresAt, invitationSent }` (or `null`).

**Organization response.** `{ id, slug, name, kind, status, statusReason, statusChangedAt, plan { code, name }, deploymentMode, dataRegion, deployments [{ deploymentMode, region, environment, status, endpointHostname, mxHostname, releaseVersion, provisionedAt, createdAt }], deletion { state, requestedAt, reason, confirmedAt, purgeAfter } | null, createdAt, updatedAt }`.

**Plan change.** Rewrites every `source = plan` limit and feature with the new plan's values, removes plan-sourced keys the new plan does not define, and keeps every override.

**Settings rules.** `timezone`: an IANA zone (`Intl.supportedValuesOf('timeZone')`, plus IANA aliases the runtime resolves such as `UTC` and `Asia/Kolkata`). `locale`: BCP 47, 2–16 characters. `quarantineRetentionDays`: 1 … min(the organization's `quarantine_retention_days` limit, the platform setting `quarantine.max_retention_days`). `digestEnabled`. `digestSchedule`: 5-field cron (`minute hour day-of-month month day-of-week`; numbers, names, ranges, steps, lists; no seconds, macros or Quartz extensions). `notificationEmail`: email or `null`. `mfaRequired`: cannot be turned off for the platform organization (`409`); changing it applies to existing sessions immediately. `preferences`: a JSON object of at most 16 KiB. Feature and limit keys must be catalog keys (`400` otherwise): limits `messages_per_day`, `max_domains`, `max_users`, `max_message_size_bytes`, `api_requests_per_minute`, `quarantine_retention_days`, `archive_retention_days`; features `inbound_filtering`, `outbound_filtering`, `internal_inspection`, `url_rewriting`, `attachment_sandbox`, `dlp`, `bec_detection`, `archiving`, `api_access`, `sso`, `webhooks`. Disabling `api_access` stops the organization's API keys on the next request.

**Usage response.** `{ organizationId, period { from, to }, users { total, active, invited, disabled, locked }, domains { total, verified, pendingVerification }, messages { total, inbound, outbound, internal, today }, quarantine { active }, apiKeys { active }, sessions { active }, limits [{ key, value, source, used }] }`. `users` counts non-deleted users by status. `messages` counts `email_messages` received in `[from, to)`; `today` counts since midnight UTC. `used` is filled for `max_users` (non-deleted users), `max_domains` and `messages_per_day` (today), else `null`. Usage is served from the read replica, so very recent changes can appear after a short delay; windows longer than 31 days will come from the ClickHouse rollups (steps 9–10).

**Deletion state.** `{ organizationId, status, state: none | pending_deletion | deleted, requestedAt, requestedBy, reason, confirmationDeadline, confirmedAt, confirmedBy, purgeAfter, cancellable }` (`requestedBy`/`confirmedBy` are platform user public ids).

### Domains (`domains` tag, step 2.1)

Domain onboarding: add a domain, prove ownership with a DNS TXT record, publish the gateway's MX, SPF, DKIM and DMARC records, then activate. Design: [docs/plan/steps/03-domain-onboarding.md](../plan/steps/03-domain-onboarding.md) (§4); DNS resolution: [ADR-0017](../architecture/adr/0017-dns-resolution-strategy.md); DKIM key custody: [ADR-0018](../architecture/adr/0018-dkim-key-custody.md). Customer guide: [docs/domains/onboarding.md](../domains/onboarding.md); operators: [docs/runbooks/domain-verification.md](../runbooks/domain-verification.md).

Every route is scoped to the caller's organization (or the override target) and accepts user tokens and API keys. Another tenant's domain, a **deleted** domain and an unknown id are all `404`; `{id}` must be a UUID (`400`).

| Method | Path                        | Access                      | Body → result                                                                                                                                                                    |
| ------ | --------------------------- | --------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| POST   | `/domains`                  | `domain:manage`, K, RL      | `{ name (1–253), inboundEnabled? = true, dkim?: { ed25519? = false } }` → `201` domain detail + `dnsRecords`; `400` invalid/reserved/too long name; `409` (below); `429`; `503`  |
| GET    | `/domains`                  | `domain:read`, K            | reader; `?limit&cursor&status&q` (`status`: any non-deleted status; `q`: ASCII name prefix) → `{ data: DomainSummary[], nextCursor }`, newest first                              |
| GET    | `/domains/{id}`             | `domain:read`, K            | domain detail (writer): verification challenge, DKIM keys (non-retired, plus retired in the last 30 days)                                                                        |
| POST   | `/domains/{id}/verify`      | `domain:manage`, K, RL      | no body → `200` status view after a fresh DNS check (cache bypassed). A `failed` domain restarts verification first. `409` while another check runs; `429`; `503`                |
| GET    | `/domains/{id}/dns-records` | `domain:read`, K            | `{ domainId, records: DnsRecord[], cleanup: [{ type: TXT, host, reason: retired_dkim_selector, retiredAt }] }`                                                                   |
| GET    | `/domains/{id}/status`      | `domain:read`, K            | status view from stored state (no DNS lookups)                                                                                                                                   |
| POST   | `/domains/{id}/dkim/rotate` | `domain:dkim_rotate`, K, RL | `{ algorithm?: rsa_2048 (default) \| ed25519 }` (body optional) → `201 { domainId, key, previous, dnsRecord, overlapDays }`; `409` while a rotation is in progress; `429`; `503` |
| PATCH  | `/domains/{id}/status`      | `domain:manage`, K          | `{ status: active \| suspended, reason? (1–512, required to suspend) }` → `200` domain detail; `409` for any other transition                                                    |
| DELETE | `/domains/{id}`             | `domain:manage`, K          | `204` soft delete; `409 Suspend the domain before deleting it` for an active domain                                                                                              |

**Lifecycle.** `pending_verification` → (ownership TXT found) → `verified` → (`PATCH {status: active}`) → `active` ⇄ `suspended` → (`DELETE`) → `deleted`. A pending domain becomes `failed` when its verification expires (`statusReason: verification_expired`, after `DOMAIN_VERIFICATION_TTL_DAYS`, default 7) or when another organization proves ownership first (`claimed_by_another_organization`); `POST /verify` on a failed domain restarts verification with the same token. `pending_verification`, `verified`, `failed` and `suspended` domains can be deleted. **Activation needs ownership only**, not MX: activate first, then switch MX, so mail arriving during DNS propagation is accepted. Any other transition is `409 Domain is <status>`.

**Ownership and uniqueness.** A name can be claimed (pending) by several organizations; the first to prove ownership wins and the other claims fail. Once a name is owned (`verified`, `active` or `suspended`) nobody else can add it (`409 Domain is already registered with another organization`, without owner details). The same organization cannot hold a name twice (`409 Domain already exists`); after deleting a domain it can add the name again (a new domain id). `max_domains` counts non-deleted domains (`409 Organization limit reached: max_domains`).

**Names.** Trimmed, one trailing dot ignored, IDN converted to punycode (`name`; `unicodeName` for display), lower case; at least two labels of `[a-z0-9-]` (no `_`, `*`, IP literals); at most 253 characters, and short enough that every record host derived from it (`<selector>._domainkey.<name>`, `<verification label>.<name>`, `_dmarc.<name>`) stays within 253 characters: **226** characters with the default verification label (`400 … (too_long)` otherwise). Always reserved: `localhost` and names under `local`, `invalid`, `arpa`, `onion`, `internal`, `alt`; outside `APP_ENV=local|ci` also `test`, `example`, `example.com|net|org`; plus `DOMAIN_RESERVED_SUFFIXES` and the gateway's own MX and SPF hosts. The `400` message carries the reason code (`invalid`, `reserved`, `too_long`).

**DNS records** (`DnsRecord`): `key` (`verification`, `mx:<gateway host>`, `spf`, `dkim:<selector>`, `dmarc`), `purpose`, `requirement` (`activation`, `inbound`, `outbound`, `recommended`), `type` (`TXT`/`MX`), `host` (FQDN), `name` (relative: `@`, `_dmarc`, `<selector>._domainkey`, `_emailgateway-verify`), `value`, `priority` (MX only), `status` (`pending`, `valid`, `invalid`, `missing`), `lastOutcome` (adds `indeterminate`), `observedValue`, `lastCheckedAt`, `lastError`, `warnings[]`, `instructions`. SPF and DMARC values are recommendations recomputed after each check (merged with the customer's current record). Responses never contain private keys; the verification value is the only token returned (it is public by design).

**Status view.** `{ domainId, name, status, statusReason, readyForActivation (status = verified), mailFlowReady (active and MX valid), lastCheckedAt, nextCheckAt, checkFailures, checks: { ownership, mx, spf, dkim, dmarc } }`; each check has `status` (worst of its records), `lastOutcome`, `lastCheckedAt`, `warnings`, plus `mx.observed[{ priority, host, pointsToGateway }]`, `mx.propagation[{ upstream, outcome }]`, `spf.lookupCount`, `spf.recommendedValue`, `dkim.selectors[{ selector, algorithm, keyStatus, recordStatus }]`, `dmarc.stage` (`missing`, `none`, `quarantine`, `reject`), `dmarc.recommendedValue`, `dmarc.nextStep`.

**DNS failures are not errors.** When a lookup times out, gets SERVFAIL/REFUSED or no definitive answer, the record's `lastOutcome` is `indeterminate`, its `status` and the domain status do not change, `checkFailures` grows and the retry is scheduled with exponential backoff (`nextCheckAt`). `POST /verify` then still answers `200`.

**Rate limits.** `POST /verify`: at most 6 per domain per minute (`429` with `Retry-After`) and 30 per client IP per minute; one check per domain at a time (`409 Verification already in progress`); `503` when Redis is unavailable (fails closed). `POST /domains`: at most 60 per caller (user or API key) per minute. `POST /dkim/rotate`: at most 10 per domain per 24 hours and 30 per caller per minute. Refused requests (unknown or foreign domain, `409`s, limits) are answered before any DKIM key is generated. Background checks run on their own schedule (pending: 1, 2, 4 … minutes up to hourly until expiry; owned domains: every 30 minutes while a record is not valid, daily when everything is valid).

**DKIM rotation.** The first key of each domain is RSA 2048 (`dkim.ed25519: true` on create adds an Ed25519 key). Rotation creates a new pending key whose TXT record must be published; when the check finds it valid (on an owned domain) it becomes `active` and the previous key `rotating` for `DKIM_ROTATION_OVERLAP_DAYS` (default 7), after which the background job retires it and lists its selector under `cleanup`. If the family's only key is still pending (never published) it is replaced (`previous.status: revoked`). A second rotation while one is pending next to an active key is `409 A DKIM rotation is already in progress`.

**Audit and events.** Transitions write `audit_logs` rows (`domain.created`, `domain.verified`, `domain.verification_expired`, `domain.verification_restarted`, `domain.claim_superseded`, `domain.status_changed`, `domain.deleted`, `domain.dkim_rotation_started`, `domain.dkim_key_activated`, `domain.dkim_key_retired`, `domain.ownership_record_missing`) and status transitions write a `domain.status.changed.v1` event to `message_outbox` in the same transaction ([contracts](../architecture/contracts.md)). Checks without a transition write neither.

## Errors

Every error uses one shape, produced by the global exception filter:

```json
{
  "statusCode": 404,
  "error": "NOT_FOUND",
  "message": "Organization not found",
  "correlationId": "..."
}
```

| Status | Meaning                                                                                                                                                                                                        |
| ------ | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `400`  | Validation failed: `message` lists every issue as `"<path>: <issue>"` (input values are never echoed). Also malformed ids, unknown feature/limit keys, invalid or used tokens                                  |
| `401`  | Missing, invalid, expired or revoked credentials (`Invalid credentials` on login, `Unauthorized` elsewhere). Also: user or organization no longer active, override ended                                       |
| `403`  | Authenticated but not allowed: missing permission, user-only route called with an API key, `MFA required`, `MFA enrollment required`, four-eyes violation                                                      |
| `404`  | Not found, **including resources of another tenant** and soft-deleted resources                                                                                                                                |
| `409`  | Conflicts with the current state: duplicates (slug, email, domain), limit reached (`Organization limit reached: <key>`), invalid state transitions, active legal hold, a check or rotation already in progress |
| `429`  | Rate limited, with `Retry-After` (seconds)                                                                                                                                                                     |
| `503`  | Authentication, rate-limit or domain-verification backend (Redis) unavailable: these paths fail closed                                                                                                         |

Unexpected errors return a generic `500` message. Details go to the logs only, and can be found there by `correlationId`.

### Validation errors

Request bodies, queries and params are validated with zod schemas (the same schemas generate the OpenAPI shapes). Unknown body fields are rejected where the schema is strict (all organization bodies):

```json
{
  "statusCode": 400,
  "error": "BAD_REQUEST",
  "message": ["slug: is reserved", "deployment: is required for a dedicated deployment"],
  "correlationId": "..."
}
```

## Pagination

List endpoints use cursor pagination, ordered newest first:

- `?limit=`: 1–100, default 25. `?cursor=`: the opaque `nextCursor` from the previous page. An invalid cursor is a `400`.
- The response is `{ "data": [...], "nextCursor": "..." | null }`. `nextCursor` is `null` on the last page.
- Lists and usage read the replica (ADR-0014): a row created a moment ago can appear after a short delay. Every create endpoint returns the created resource from the writer.

Ids in responses are strings (public ids or decimal strings), never JSON numbers. Timestamps are ISO 8601 UTC strings.

## Correlation

Send `x-correlation-id` (8–128 chars of `[A-Za-z0-9._:-]`) to trace a request across services. If it is missing or invalid, a new id is generated. Either way, the id is returned in the response header and stored in the `audit_logs` rows the request writes.

## Readiness response

```json
{
  "service": "api",
  "status": "ok",
  "version": "0.1.0-local",
  "uptimeSeconds": 42,
  "checks": [
    { "name": "mysql", "status": "ok", "latencyMs": 2 },
    { "name": "mysql-reader", "status": "ok", "latencyMs": 2 },
    { "name": "redis", "status": "ok", "latencyMs": 1 },
    { "name": "s3", "status": "ok", "latencyMs": 6 }
  ]
}
```

Every Node service exposes the same two health endpoints on its own port (see the root README).
