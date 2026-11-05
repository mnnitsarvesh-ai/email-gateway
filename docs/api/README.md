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

| Method | Path            | Access | Description                                                                                                                                                                                                                                                |
| ------ | --------------- | ------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| GET    | `/health/live`  | P      | Process liveness (unprefixed). No dependency checks                                                                                                                                                                                                        |
| GET    | `/health/ready` | P      | Dependency readiness (unprefixed). `200` when ok, else `503`                                                                                                                                                                                               |
| GET    | `/api/v1/meta`  | P      | API build/version information                                                                                                                                                                                                                              |
| GET    | `/metrics`      | P      | Prometheus series (unprefixed, step 3.2 §5.3, e.g. `dead_letter_replay_total{source_queue,outcome}`, step 3.3 `api_message_lifecycle_operations_total{operation,outcome}`). Internal port only: the ingress must not route it. Not in the OpenAPI document |

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

### Inbound recipient validation (`domains` tag, step 2.2)

Per-domain recipient checks at SMTP `RCPT` time, stored in the existing `domain_settings` columns, and the domain's recipient allow-list (`domain_recipient_addresses`). Design: [docs/plan/steps/04-smtp-gateway.md](../plan/steps/04-smtp-gateway.md) (D3, §4.1). Same scoping as the other domain routes: another tenant's domain, a deleted domain and an unknown id are `404`. Changes reach the mail path within about 60 seconds (smtp-adapter cache).

| Method | Path                                 | Access             | Body → result                                                                                                                                                          |
| ------ | ------------------------------------ | ------------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| GET    | `/domains/{id}/recipient-validation` | `domain:read`, K   | `{ domainId, mode: accept_all \| allow_list \| smtp_callout \| ldap, enforcement: reject \| monitor, implemented, addressCount }`                                      |
| PUT    | `/domains/{id}/recipient-validation` | `domain:manage`, K | `{ mode: accept_all }` or `{ mode: allow_list, enforcement: reject \| monitor }` → `200` as GET; `422 Not implemented` (`smtp_callout`, `ldap`); `409` (below)         |
| GET    | `/domains/{id}/recipients`           | `domain:read`, K   | reader; `?limit&cursor&q` (`q`: local-part prefix, normalized like the entries) → `{ data: [{ localPart, createdAt }], nextCursor }`, newest first                     |
| POST   | `/domains/{id}/recipients`           | `domain:manage`, K | `{ localParts: string[1..1000] }` → `200 { added, existing }` (idempotent); `409 Recipient limit reached: at most <n> per domain` (`DOMAIN_RECIPIENTS_MAX_PER_DOMAIN`) |
| POST   | `/domains/{id}/recipients/remove`    | `domain:manage`, K | `{ localParts: string[1..1000] }` → `200 { removed }`; unknown local parts are ignored                                                                                 |

**Modes.** `accept_all` (column `none`, the default) accepts every local part. `allow_list` (column `list`) checks the list: `enforcement: reject` (`reject_unknown_recipients = true`) refuses unknown recipients with `550 5.1.1`; `monitor` accepts them and only counts would-be rejections (onboarding shadow mode). `enforcement` is required with `allow_list` and not allowed with `accept_all`. Enforcing an empty list is `409 Add recipients before enforcing the allow-list`. `smtp_callout` and `ldap` exist in the schema but are not implemented: the API refuses to set them (`422`) and reports `implemented: false` if a row holds one (the mail path then accepts everyone).

**Local parts.** The part before `@` only (the domain is implied). Stored Unicode-NFC-normalized and lower-cased; 1–64 bytes of UTF-8; `@`, whitespace, control and format characters are refused (`400 localParts.<i>: …`). Duplicates in one request count once. The column collation is case- and accent-insensitive, so entries that differ only by accents are treated as the same address. A request that would exceed the per-domain cap adds nothing.

**Audit.** `domain.recipient_validation_changed` (`from`/`to` mode and enforcement), `domain.recipients_added` (`added`, `existing`), `domain.recipients_removed` (`removed`, `requested`); counts only, never the local parts. A request that changes nothing writes no audit row.

```bash
curl -X PUT "$API/api/v1/domains/$DOMAIN_ID/recipient-validation" -H "X-API-Key: $KEY" \
  -H 'Content-Type: application/json' -d '{"mode":"allow_list","enforcement":"monitor"}'
curl -X POST "$API/api/v1/domains/$DOMAIN_ID/recipients" -H "X-API-Key: $KEY" \
  -H 'Content-Type: application/json' -d '{"localParts":["sales","support","jane.doe"]}'
# → {"added":3,"existing":0}
```

### SMTP connectors (`smtp-connectors` tag, step 2.2)

Organization-level outbound connectors that let a tenant's mail servers relay through the gateway's outbound MTA (`postfix-outbound`). Design: [docs/plan/steps/04-smtp-gateway.md](../plan/steps/04-smtp-gateway.md) (D10, §4.1). Every route is scoped to the caller's organization (or the override target) and accepts user tokens and API keys; another tenant's connector is `404`. Responses never contain a secret hash.

| Method | Path                                  | Access                    | Body → result                                                                                                                                                                            |
| ------ | ------------------------------------- | ------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| POST   | `/smtp-connectors`                    | `connector:manage`, K, RL | `{ name (1–128), authType: sasl \| source_ip \| client_certificate, networks?, certificateFingerprintSha256?, requireTls? = true }` → `201` connector (+ `credentials` for `sasl`, once) |
| GET    | `/smtp-connectors`                    | `connector:read`, K       | reader; `?limit&cursor&status&authType` → `{ data: Connector[], nextCursor }`, newest first                                                                                              |
| GET    | `/smtp-connectors/{id}`               | `connector:read`, K       | connector (writer)                                                                                                                                                                       |
| PATCH  | `/smtp-connectors/{id}`               | `connector:manage`, K     | `{ name?, status?: active \| disabled, networks?, requireTls? }` (at least one) → `200` connector; networks are replaced atomically with the create rules                                |
| POST   | `/smtp-connectors/{id}/rotate-secret` | `connector:manage`, K, RL | no body → `200 { id, credentials: { username, password }, secretSetAt }`; `409 Only sasl connectors have a secret`                                                                       |
| DELETE | `/smtp-connectors/{id}`               | `connector:manage`, K     | `204` hard delete; its networks are freed                                                                                                                                                |

**Connector** (`Connector`): `{ id, name, authType, status, saslUsername, certificateFingerprintSha256, networks: [{ cidr, ipVersion }], requireTls, secretSetAt, createdAt, updatedAt }`.

**Types.**

- `sasl`: SMTP AUTH (PLAIN/LOGIN) after STARTTLS on the submission port (587). The username (`egc-` + 20 lower-case base32 characters) and a random password (32 bytes, base64url) are generated by the API and returned **once** in `credentials`; only an Argon2id hash is stored. Lost passwords are replaced with `rotate-secret` (the old one stops working at once). `networks` are not allowed.
- `source_ip`: 1–20 networks (`a.b.c.d/nn`, IPv6 CIDR, or a bare address for one host) on the port 25 relay listener. IPv4 prefixes must be `/16` or longer, IPv6 `/48` or longer; host bits are cleared (`192.0.2.7/24` is stored as `192.0.2.0/24`); IPv4-mapped IPv6 is refused (use the IPv4 form). Networks must be publicly routable: a network that overlaps a private (RFC 1918, IPv6 ULA), loopback, link-local, shared (100.64.0.0/10), documentation, benchmarking, multicast or reserved range is refused with `400` (`networks.N: must be a publicly routable network …`), so no tenant can claim the gateway's internal ranges or lock others out of them. A dedicated deployment whose customer relays from its own private networks sets `SMTP_CONNECTOR_ALLOW_NON_PUBLIC_NETWORKS=true`. `requireTls: false` lets the servers relay without STARTTLS (only for this type).
- `client_certificate`: the SHA-256 fingerprint of the client certificate presented on port 25 (64 hex characters, colons optional, any case; stored lower-case without colons), optionally restricted to networks (same rules, `[]` clears them).

> **Warning: never use `source_ip` connectors for shared-IP mail platforms such as Microsoft 365 or Google Workspace.** Every customer of such a platform sends from the same addresses and could then send as your organization. Use `sasl` or `client_certificate` connectors there. (The non-overlap rule below stops two tenants from claiming the same range, but cannot know who else sends from it.)

**Global uniqueness.** A network may not overlap any network of any connector in any organization: `409 Network overlaps an existing connector network` (never says whose; the api logs each refusal with the requesting organization, the IP version and the prefix, as a signal of probing or of a disputed range). The check and the insert run in one transaction under the MySQL named lock `smtp_connector_networks` (`503` if it cannot be taken within 5 s), so concurrent claims of the same range cannot both succeed. Fingerprints are globally unique (`409 Certificate fingerprint is already registered`); names are unique per organization (`409 SMTP connector name already exists`). At most `SMTP_CONNECTORS_MAX_PER_ORGANIZATION` (default 50) connectors per organization (`409 SMTP connector limit reached: at most <n> per organization`).

**Status.** A `disabled` connector (and any connector of an organization that is not active) authorizes nothing; the change reaches the mail path within the adapter's cache TTL (about 30 seconds).

**Rate limits and audit.** `POST /smtp-connectors`: 20 per caller (user or API key) per minute; `rotate-secret`: 10 per caller per minute (`429` with `Retry-After`). `smtp_connector.created`, `smtp_connector.updated` (`changes` with `from`/`to`), `smtp_connector.secret_rotated` and `smtp_connector.deleted` are written in the same transaction as the change; their metadata never contains the password or its hash.

```bash
curl -X POST "$API/api/v1/smtp-connectors" -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' -d '{"name":"On-prem Exchange","authType":"sasl"}'
# → 201 { "id": "…", "authType": "sasl", "saslUsername": "egc-…", …,
#         "credentials": { "username": "egc-…", "password": "<shown once>" } }
curl -X POST "$API/api/v1/smtp-connectors" -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"name":"Datacenter relay","authType":"source_ip","networks":["192.0.2.0/27","2001:db8:10::/48"]}'
```

**DKIM signing keys.** Not an HTTP route: the api's `DkimSigningPublisher` copies the active RSA-2048 key of every active, outbound-enabled domain of an active organization into redis-dkim every `DKIM_SIGNING_SYNC_INTERVAL_SECONDS` (default 30; one replica per tick), and on demand with `pnpm --filter @email-gateway/api dkim:sync` (prints counts only: `published removed unchanged skipped pruned`). `REDIS_DKIM_URL` empty disables it with one startup warning ([ADR-0020](../architecture/adr/0020-dkim-signing.md)).

### Destination servers (`domains` tag, step 2.3)

Where a domain's approved inbound and internal mail is delivered: the tenant's own servers or a provider preset (Microsoft 365, Google Workspace). Design: [docs/plan/steps/05-routing.md](../plan/steps/05-routing.md) (R2, R3, R13); customer-side setup: [docs/domains/destination-servers.md](../domains/destination-servers.md). Every route is scoped to the caller's organization (or the override target) and accepts user tokens and API keys; another tenant's domain and an unknown id are `404`. Changing destinations redirects all mail of a domain, so it has its own permission, `domain:routing_manage` (granted to `domain_admin`, `organization_admin`, `super_admin`; **not** implied by `domain:manage`).

| Method | Path                         | Access                         | Body → result                                                                                                                                        |
| ------ | ---------------------------- | ------------------------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------- |
| GET    | `/destination-providers`     | `domain:read`, K               | reader; `{ data: [{ provider, displayName, hostHint, hostPatterns, port, tlsMode, tlsVerifyNames, maxServers, defaultServers, documentationUrl }] }` |
| GET    | `/domains/{id}/destinations` | `domain:read`, K               | reader; `{ provider: custom \| microsoft_365 \| google_workspace \| null, servers: [Server] }` in delivery order (deleted domain → `404`)            |
| PUT    | `/domains/{id}/destinations` | `domain:routing_manage`, K, RL | one of the bodies below → `200` as GET (writer); `422` with `reason`; `409 Domain is deleted`; `400` more than `ROUTING_MAX_DESTINATIONS_PER_DOMAIN` |
| DELETE | `/domains/{id}/destinations` | `domain:routing_manage`, K, RL | `204`; every destination removed (mail for the domain is then held with `no_destination` until destinations are set again); `409 Domain is deleted`  |

**Server** (`Server`): `{ id, host, port, priority, tlsMode: none | opportunistic | required | verify, tlsVerifyNames, enabled, createdAt, updatedAt }` (`id` is the server's public id). Deprecated `outbound_source` rows are never shown or touched.

**Bodies** (a discriminated union on `provider`; unknown fields are `400`):

- `{ "provider": "microsoft_365", "host": "contoso-com.mail.protection.outlook.com" }`: exactly one host matching the preset's patterns (`*.mail.protection.outlook.com`, `*.mx.microsoft`), copied from the Microsoft 365 admin center. Port 25, `verify` and the preset's certificate names are forced.
- `{ "provider": "google_workspace" }`: the preset's five servers (`aspmx.l.google.com` priority 1, `alt1`/`alt2` 5, `alt3`/`alt4` 10), `verify`.
- `{ "provider": "custom", "servers": [{ "host", "port"?: 25, "priority"?: 10, "tlsMode"?: "opportunistic", "tlsVerifyNames"? }] }`: 1–`ROUTING_MAX_DESTINATIONS_PER_DOMAIN` (default 10) servers. `tlsVerifyNames` (a Postfix `match=` list such as `nexthop:.example.com`, `^[A-Za-z0-9.:-]{1,512}$`) only with `tlsMode: verify`; omitted means `nexthop`. Hosts are normalized (lower case, trailing dot removed, IDN to ASCII, canonical IP); a repeated host:port is `422 duplicate_server`.

The replacement is atomic: the rows, the audit entry and the `domain.routing.changed.v1` outbox event commit in one transaction, and the gateway's MTA follows the change within seconds (cache invalidation; otherwise within the 60-second cache TTL). A body equal to the stored destinations writes nothing. Postfix tries the servers in order (priority, then list order) and fails over to the next one; the TLS policy applies per server.

**Refusals (`422`).** The body is the standard error body plus a stable `reason` and the request `field` it applies to (`host`, `servers.<i>.host`, `servers.<i>.port`, `provider`); the input value is never echoed:

```json
{
  "statusCode": 422,
  "error": "UNPROCESSABLE_ENTITY",
  "message": "Destination IP address is not publicly routable",
  "reason": "ip_not_public",
  "field": "servers.0.host",
  "correlationId": "..."
}
```

| `reason`                        | When                                                                                                                                                                                  |
| ------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `ip_not_public`                 | IP literal (v4/v6, with or without brackets) in a non-public range (private, loopback, link-local, CGNAT, documentation, ULA, …), unless `ROUTING_ALLOW_NON_PUBLIC_DESTINATIONS=true` |
| `metadata_address`              | Cloud metadata address or name (`169.254.169.254`, `fd00:ec2::254`, `100.100.100.200`, `169.254.170.2`, `metadata.google.internal`, `instance-data`), even with the flag              |
| `single_label`                  | A name without a dot (`mysql`, `localhost`, any container or service short name)                                                                                                      |
| `internal_suffix`               | A name under `.local`, `.localhost`, `.localdomain`, `.internal`, `.intranet`, `.lan`, `.home.arpa`, `.svc`, `.cluster.local`, `.consul` or `ROUTING_DENIED_DESTINATION_SUFFIXES`     |
| `gateway_host`                  | One of the gateway's own hosts (`GATEWAY_MX_HOSTS`, `POSTFIX_MYHOSTNAME`, `POSTFIX_OUTBOUND_MYHOSTNAME`) or the bounce domain (`POSTFIX_BOUNCE_DOMAIN`) and names under it            |
| `invalid_host`                  | Not a valid host name (LDH labels, ≤ 253 characters) or IP literal                                                                                                                    |
| `port_not_allowed`              | Not the preset's port; for custom servers not one of `ROUTING_ALLOWED_DESTINATION_PORTS` (default 25, 587, 2525); the gateway's internal listener ports are always refused            |
| `host_not_allowed_for_provider` | The host does not match the preset's patterns (e.g. `mail.contoso.com` for `microsoft_365`)                                                                                           |
| `duplicate_server`              | The same host:port twice in one request                                                                                                                                               |
| `provider_unavailable`          | The preset is disabled or its seeded servers fail the rules (a platform configuration problem)                                                                                        |
| `host_reserved_for_provider`    | A custom server on a provider preset's host (e.g. `aspmx.l.google.com`): use that provider; its TLS policy is fixed for every tenant                                                  |
| `destination_tls_conflict`      | The custom `host:port` is already a destination of another organization with a different `tlsMode` (or, for `verify`, other `tlsVerifyNames`); the field is `servers.<i>.tlsMode`     |

Resolved addresses are not checked (DNS can change); production egress rules block private ranges (see [docs/deployment/mail-routing.md](../deployment/mail-routing.md)). The smtp-adapter re-applies the same rules on every Postfix lookup, so a row written directly to the database is skipped (logged), and any gateway host makes the domain defer instead of looping.

**Rate limit and audit.** `PUT` and `DELETE` share one counter: 30 per caller (user or API key) per minute (`429` with `Retry-After`). `domain.destinations_replaced` (`name`, `provider`, `hosts`, `count`, `previous: { provider, hosts }`) and `domain.destinations_removed` (`name`, `provider`, `hosts`, `count`); never secrets. Platform users act only through an audited override (ADR-0016); `platform_admin` can read but not change destinations.

```bash
curl -X PUT "$API/api/v1/domains/$DOMAIN_ID/destinations" -H "X-API-Key: $KEY" \
  -H 'Content-Type: application/json' \
  -d '{"provider":"custom","servers":[{"host":"mx1.example.com","tlsMode":"required"},{"host":"mx2.example.com","priority":20}]}'
curl -X PUT "$API/api/v1/domains/$DOMAIN_ID/destinations" -H "X-API-Key: $KEY" \
  -H 'Content-Type: application/json' -d '{"provider":"microsoft_365","host":"contoso-com.mail.protection.outlook.com"}'
```

### Delivery status (`deliveries` tag, step 2.3)

Per-recipient delivery state of the caller's organization (R9, R13), from the read replica (a few seconds behind the mail path). Permission `delivery:read` (every built-in tenant role, `read_only_user` included). A message is addressed by its public id; another organization's message is `404`. Internal ids never appear: recipients are identified by `rcptSeq` (position in the RCPT list) and deliveries by `rcptSeq` + `deliverySeq` (`0` = the initial delivery; releases use 1, 2, …).

| Method | Path                                      | Access             | Result                                                                                                                                                                                                               |
| ------ | ----------------------------------------- | ------------------ | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| GET    | `/messages/{messageId}/deliveries`        | `delivery:read`, K | `{ message: { id, direction, status, statusReason, receivedAt }, deliveries: [Delivery] }` by `rcptSeq`, then `deliverySeq`                                                                                          |
| GET    | `/messages/{messageId}/deliveries/events` | `delivery:read`, K | `?rcptSeq&limit&cursor` → `{ data: [{ rcptSeq, deliverySeq, source, fromStatus, toStatus, applied, occurredAt, queueId, smtpCode, enhancedStatus, remoteHost, errorClass, detail }], nextCursor }`, **oldest first** |
| GET    | `/deliveries`                             | `delivery:read`, K | `?from&to&status&direction&limit&cursor` → `{ data: [{ messageId, rcptSeq, recipient, direction, status, attemptCount, lastErrorClass, statusChangedAt }], nextCursor }`, newest first                               |

**Delivery** (`Delivery`): `{ rcptSeq, deliverySeq, recipient, direction: inbound | outbound | internal | null, status, attemptCount, lastAttemptAt, deliveredAt, remoteHost, finalSmtpCode, enhancedStatus, finalSmtpResponse, lastErrorClass, failureReason, dsnGenerated, statusChangedAt }`. `dsnGenerated` is true when the gateway's MTA sent a DSN to the original sender (never for inbound mail). `finalSmtpCode`, `enhancedStatus` and `finalSmtpResponse` describe the latest result that explains the status: a remote server's reply or Postfix's own outcome from the delivery log or a DSN, or the gateway's refusal or deferral of its internal hop; the hop's own `250 … queued as` is never shown there (a `queued` recipient has no final code), and a later result without an SMTP code (`connect to …: No route to host`) clears an earlier attempt's code. `lastErrorClass` is cleared when the recipient is delivered. `direction` is null for recipients ingested before step 2.3.

**Statuses.** `pending` (planned), `queued` (accepted by the gateway's outbound MTA), `deferred` (temporary failure, retried by the MTA), `delivered` (only after the remote server's `2xx`, from the MTA's delivery log), `bounced` (permanent failure), `expired` (the MTA gave up after its queue lifetime, or the gateway's own retry window ended), `failed` (refused by the gateway; `failureReason`: `direction_changed`, `recipient_domain_inactive`, `loop_detected`, `reinjection_refused`, `reinjection_expired`, `content_missing`), `suppressed` (address on the organization's suppression list), `unknown` (no status signal for too long, or an ambiguous hand-off to the MTA that no log evidence resolved before the gateway's retry window ended, `failureReason: status_signal_missing`; never guessed; a late real signal still makes it final). `delivered`, `bounced`, `expired`, `failed` and `suppressed` are final.

**Error classes** (`lastErrorClass`, `errorClass`): `connect`, `dns`, `tls`, `timeout`, `remote_4xx`, `remote_5xx`, `no_destination` (the domain has no usable destination server), `loop`, `gateway_rate_limited`, `gateway_rate_limit_unavailable`, `gateway_hold`, `reinjection_4xx`, `reinjection_error`, `other`.

**Audit trail.** Every status signal is kept, applied or not (`applied: false` for stale, conflicting or same-state signals). `source`: `planner`, `reinjection`, `postfix_log` (the MTA delivery log), `bounce_notice` (postmaster DSN copies), `reconciler`. `detail` is the remote reply or the reason text, never message content.

**List range.** `from` (inclusive) and `to` (exclusive) are ISO 8601 date-times; `to` defaults to now and `from` to `to` − 24 h. The range must be at most 31 days and `from` before `to` (`400`). The cursor is opaque (keyset on received-at and id); filters must stay the same between pages.

### Message lifecycle (`messages` tag, step 3.3)

The lifecycle state of a message of the caller's organization ([ADR-0025](../architecture/adr/0025-message-lifecycle-state-machine.md), design [08-message-lifecycle.md](../plan/steps/08-message-lifecycle.md) L10–L12) and the two administrative operations that change it. Every state change goes through the shared transition service `@email-gateway/message-lifecycle` (history row, `email_events` row and `mail.message.state_changed.v1` in the same writer transaction). A message is addressed by its public id; another organization's message (or an unknown id) is `404 message_not_found`, for reads and writes alike. Responses carry ids, states, codes, counts and times only: never subjects, addresses or bodies.

| Method | Path                                      | Access                  | Result                                                                                                                                                                                                                            |
| ------ | ----------------------------------------- | ----------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| GET    | `/messages/{messageId}/lifecycle`         | `message:read`, K       | `{ messageId, receivedAt, direction, state, statusReason, version, lifecycleRound, statusChangedAt, parse: { status, completedAt } \| null, recipients: { total, byStatus }, deliverySeq \| null, actions: { rescan, release } }` |
| GET    | `/messages/{messageId}/lifecycle/history` | `message:read`, K       | `?limit&cursor` → `{ data: [{ version, fromState, toState, reasonCode, lifecycleRound, actor: { role, type, service, id }, causationEventId, correlationId, occurredAt, changedAt }], nextCursor }`, **oldest first**             |
| POST   | `/messages/{messageId}/rescan`            | `message:rescan`, K     | `Idempotency-Key` + `{ expectedVersion, reason }` → `202 { messageId, state: "scanning", version, lifecycleRound, rescanEventId, note }`                                                                                          |
| POST   | `/messages/{messageId}/release`           | `quarantine:release`, K | `Idempotency-Key` + `{ expectedVersion, reason }` → `202 { messageId, state: "approved", version, lifecycleRound, deliverySeq, approvalEventIds, recipientCount }`                                                                |

**States.** `received`, `persisted`, `scanning`, `scanned`, `scan_failed`, `policy_evaluated`, `approved`, `quarantined`, `held_for_review`, `rejected`, `delivery_pending`, `delivery_retry`, `delivered`, `archived`, `expired`. Partial and failed deliveries are reasons, not states: `delivered` with `statusReason: delivery_partial`, `rejected` with `delivery_failed` (per-recipient detail: `GET …/deliveries`). `version` grows by one per applied transition and is the optimistic-concurrency token of the operations; `lifecycleRound` grows by one per rescan or release. `actions` says what the current state allows (from the transition table), not what the caller may do.

**Reads** use the read replica (a few seconds behind; with the replica unusable the writer answers). Right after a rescan or release the previous state may still show; the `202` body carries the new `version`. The history is ordered by `version`; rows written before step 3.3 show `actor.role: "legacy"` and are shown as recorded (they may contain pairs the transition table no longer allows). `actor.id` is the public id of the operator (user or API key), `null` for system actors.

**Rescan** (edge E19, from `scanning`, `scanned`, `scan_failed`, `policy_evaluated`, `quarantined`, `held_for_review` or `expired`): the message moves to `scanning` in a new round and `mail.message.rescan_requested.v1` is published to the scan stages. Since step 4.1 ([09-rspamd.md](../plan/steps/09-rspamd.md) S14) every registered scan engine (Rspamd, queue `scan.spam`) scans the new round and the message ends `scanned` or `scan_failed` with that round; the results of earlier rounds stay unchanged, and the response `note` points at `GET /messages/{messageId}/scans`. Learning (below) does not rescan: rescan after training to see its effect. Audited as `message.rescan_requested`.

**Release** (edges E14 from `quarantined`, E15 from `held_for_review`): the message moves to `approved` in a new round and its `pending` and `quarantined` recipients (by `rcptSeq`) are approved for delivery (the released `quarantined` recipients read as `pending` from then on, until their own delivery result) with `mail.delivery.approved.v1` (`source: quarantine_release`, `deliverySeq` = highest existing + 1, or 1; at most 1000 recipients per approval; one `delivery.approved` timeline event each). The delivery-worker plans and delivers them through the normal path, and the message then moves on to `delivery_pending` and a final state. A message with per-recipient quarantine entries (`quarantine_messages`) is refused with `409 quarantine_workflow_required` (released through the quarantine workflow of step 5.3); no releasable recipient is `409 no_releasable_recipients`. Audited as `message.quarantine_released`.

**Body** (both operations, strict): `expectedVersion` (integer ≥ 0, the `version` the operator saw) and `reason` (10–500 characters, stored in the audit row only, never in the history or events). The audit row (`resource_type: message`, `resource_id: <messageId>`) carries `metadata: { fromState, toState, version, lifecycleRound, reason, idempotencyKeyHash, eventIds, deliverySeq?, recipientCount? }`; the key itself is never stored outside `api_idempotency_keys`.

**Refusals** (coded error body, see [Errors](#errors)):

| Case                                                        | Response                                                   |
| ----------------------------------------------------------- | ---------------------------------------------------------- |
| No permission                                               | `403`                                                      |
| Another organization's message, or an unknown id            | `404 message_not_found`                                    |
| `messageId` not a UUID, invalid body                        | `400` (`message` lists the issues)                         |
| Missing / invalid `Idempotency-Key`                         | `400 idempotency_key_required` / `idempotency_key_invalid` |
| Same key, different request (body, path, operation, caller) | `422 idempotency_key_reused`                               |
| `expectedVersion` is not the current version                | `409 message_version_conflict`                             |
| The current state does not allow the operation              | `409 message_state_conflict`                               |
| Release of a message with per-recipient quarantine entries  | `409 quarantine_workflow_required`                         |
| Release without a `pending` or `quarantined` recipient      | `409 no_releasable_recipients`                             |

`409` bodies add `currentState` and `currentVersion`: read them, decide, and retry with the new `expectedVersion`.

**Idempotency-Key** (required on both operations): 1–128 characters of `[A-Za-z0-9._:-]`, case-sensitive, scoped to the organization. The first `2xx` response is stored for 24 hours in the same writer transaction as the change and its audit row. Repeating the request with the same key (same body, path, operation and caller) returns the stored status and body with the header `Idempotency-Replayed: true` and changes nothing; concurrent repeats are serialized (one applies, the others replay). Errors (`4xx`) are never stored: fix the request and retry with the same key. After 24 hours the key may be reused for a new request on another message; on the same message the earlier transition still holds the key, and the request is `422`.

```bash
curl -X POST "$API/api/v1/messages/$MESSAGE_ID/release" -H "X-API-Key: $KEY" \
  -H "Idempotency-Key: release-$MESSAGE_ID-1" -H 'Content-Type: application/json' \
  -d '{"expectedVersion":5,"reason":"false positive confirmed by the security team"}'
# → 202 {"messageId":"…","state":"approved","version":6,"lifecycleRound":1,"deliverySeq":1,
#        "approvalEventIds":["…"],"recipientCount":2}
```

### Security scan results (`messages` tag, steps 4.1 and 4.2)

The scan rounds of a message of the caller's organization ([ADR-0026](../architecture/adr/0026-security-scan-pipeline.md), design [09-rspamd.md](../plan/steps/09-rspamd.md) S16; per-attachment results [10-attachment-scanning.md](../plan/steps/10-attachment-scanning.md) A16, [ADR-0028](../architecture/adr/0028-attachment-scanning-engine.md)), from the read replica. A round is one lifecycle round (`0` = the initial scan, each rescan adds one); another organization's message is `404 message_not_found`, and every query (rounds, engine rows, per-attachment rows, attachment metadata, sandbox submissions) filters by the caller's organization.

| Method | Path                          | Access            | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| ------ | ----------------------------- | ----------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| GET    | `/messages/{messageId}/scans` | `message:read`, K | `?limit (1–20, default 10)&cursor` → `{ messageId, data: [{ round, scanKind, status, verdict, reasonCodes, requiredEngines, startedAt, completedAt, deadlineAt, auth: { spf, spfDomain, dkim, dkimSignatures, dmarc, dmarcPolicy, dmarcDomain, arc } \| null, engines: [{ engine, final, engineVersion, outcome, score, requiredScore, action, reasonCodes, symbols: [{ name, score, options }], attempts: [{ attempt, outcome, errorCode, durationMs, at }], durationMs, settingsVersion, completedAt }] }], nextCursor }`, **newest round first** |

**Per-attachment results (step 4.2).** The `attachment` engine entry also carries `attachments: [{ partIndex, filename, declaredContentType, sha256, sizeBytes, detectedType, typeFamily, typeMismatch, verdict (clean \| suspicious \| malicious \| unknown), reasonCodes, clamav: { signature \| null, engineVersion, dbVersion } \| null, yara: { bundleId, matches: [{ rule, severity, scope }] } \| null, archive: { format, supported, entries, depthReached, decompressedBytes, maxRatio, encrypted, findings: [{ path, type, reasonCodes }] } \| null, knownHash: { severity, family: null } \| null, cache (hit \| miss \| bypass), durationMs, sandbox: { submissionId, status } \| null }]` (by part index; empty before the final result and for `skipped`). Rows come from `attachment_scan_results` joined with the part's `email_attachments` row on `(message_id, part_index, received_at)` and its `sandbox_submissions` row. `filename` is the sanitized display name (attacker-controlled text); archive entries are addressed by index path (`"2/0/5"`), never by name; no file content is ever stored or returned. `knownHash.family` is null (results store only the severity of the catalog hit).

**Verdicts** (`verdict`, aggregate of the round, null while running): `clean`, `spam`, `suspicious`, `malicious`, `unknown`, `timeout`, `error`. A failed or timed-out engine never counts as `clean`: the round then ends `scan_failed` (`status: failed` or `timed_out`). Per engine, `final: false` means the engine has no final result yet (attempts are retried); `attempts` lists every attempt with its `errorCode`. `symbols` are the Rspamd symbols with their scores (at most 200) and up to five options of at most 200 characters, which **can contain addresses or URLs of the message**; reason codes follow `<category>.<code>` (e.g. `spam.score`, `auth.dmarc_reject`, `phishing.known_bad_url`).

### Scan settings (`scan-settings` tag, steps 4.1 and 4.2)

Per-organization settings of the scan engines (S8, S16; step 4.2 A8) within the platform settings (`SCAN_RSPAMD_*`, `ATTACHMENT_*`). Engines with settings: `rspamd`, `attachment` (catalog order; each with its own `platform`, `bounds`, `override` and `effective` shape). Users and API keys; the organization is always the caller's scope. Reading needs `policy:read` (every built-in tenant role); changing needs the step 4.1 permission `scan:settings_manage` (`organization_admin`, `security_analyst`; grantable to API keys).

| Method | Path                                        | Access                    | Description                                                                                                                                                                                                   |
| ------ | ------------------------------------------- | ------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| GET    | `/scan-settings`                            | `policy:read`, K          | `{ data: [{ engine, required, tenantMayDisable, platform, bounds, override \| null, effective, overrideApplied, violations, version, updatedAt }], note }` (replica)                                          |
| PUT    | `/scan-settings/{engine}`                   | `scan:settings_manage`, K | `{ expectedVersion (0 = no override yet), settings }` → the engine's view + `note`; replaces the override. Audited as `scan_settings.updated` (`metadata: { engine, fromVersion, toVersion, before, after }`) |
| DELETE | `/scan-settings/{engine}?expectedVersion=n` | `scan:settings_manage`, K | back to the platform settings (the row keeps an empty override and a new version, so versions never repeat). Audited as `scan_settings.reset`; nothing to reset is a no-op                                    |

**Rspamd settings** (`engine = rspamd`, all optional, strict): `spamScore` and `suspiciousScore` (at most two decimals, within `[SCAN_RSPAMD_SCORE_MIN, SCAN_RSPAMD_SCORE_MAX]`, `suspiciousScore < spamScore` after merging; a tenant may loosen or tighten scores), `phishingVerdict` (`suspicious` \| `malicious`), `dmarcRejectVerdict` (`suspicious` \| `malicious`) and `authFailureVerdict` (`reason_only` \| `suspicious`), which may only be **raised** above the platform value. Rspamd is a required engine and cannot be disabled. A stored override that no longer fits (the platform bounds were tightened) is listed with `overrideApplied: false` and its `violations`, and the scan stage ignores it. **Workers apply a change within their settings cache TTL** (`SCAN_SETTINGS_CACHE_TTL_MS`, default 30 s); messages already scanned keep their results.

**Attachment settings** (`engine = attachment`, step 4.2 A8, all optional, strict): `deniedTypes` (file type ids added to the platform deny list `ATTACHMENT_DENIED_TYPES`; a platform entry can never be removed; not `unknown`), `allowedTypes` (allow-list mode, at least one type, never a platform-denied type), `deniedTypeVerdict`, `typeMismatchVerdict`, `encryptedArchiveVerdict` (`suspicious` \| `malicious`, **raise-only**) and `maxAttachmentBytes` (tighten-only, `1 048 576 ≤ x ≤ ATTACHMENT_MAX_BYTES`). Archive depth/entries/sizes/ratio and the inspector's CPU and memory limits are platform-only (`platform` shows them). The attachment engine is required and cannot be disabled.

| Case                                                      | Response                                                                                                                                                            |
| --------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Engine not registered                                     | `404 scan_engine_not_found`                                                                                                                                         |
| Out of bounds, wrong order, lowered severity, unknown key | `422 scan_settings_invalid` with `violations: [{ path, code, message }]` (`code`: `invalid`, `unknown_key`, `out_of_bounds`, `threshold_order`, `severity_lowered`) |
| `expectedVersion` is not the current version              | `409 version_conflict` with `currentVersion`                                                                                                                        |

```bash
curl -X PUT "$API/api/v1/scan-settings/rspamd" -H "X-API-Key: $KEY" -H 'Content-Type: application/json' \
  -d '{"expectedVersion":0,"settings":{"spamScore":7,"dmarcRejectVerdict":"malicious"}}'
```

### Scan training (`platform` tag, step 4.1)

Bayes learning and fuzzy hashes are stored once for **all** organizations, so only platform users train them (S13): permission `platform:scan_training` (role `platform_admin`), user sessions with MFA, never API keys or override tokens; 60 calls per caller per minute.

| Method | Path                                                                          | Access                           | Description                                                                                                                                                                                                                                                      |
| ------ | ----------------------------------------------------------------------------- | -------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| POST   | `/platform/organizations/{organizationId}/messages/{messageId}/scan-training` | `platform:scan_training`, U, MFA | `{ operation: learn_spam \| learn_ham \| fuzzy_add \| fuzzy_delete, fuzzyFlag? (spam = flag 11 \| phishing = flag 12; required for fuzzy operations), reason (1–512) }` → `{ operation, result: learned \| already_learned \| added \| deleted, engineVersion }` |

`organizationId` is the organization's public id (as in `/organizations/{id}`); the message is looked up on the writer within that organization only (`404 organization_not_found` / `404 message_not_found`). The api streams the stored EML from S3 (key prefix checked) to the Rspamd controller (`RSPAMD_CONTROLLER_URL`, enable password `RSPAMD_CONTROLLER_ENABLE_PASSWORD`; fuzzy weight `SCAN_FUZZY_WEIGHT`). `409 content_unavailable` when the EML is gone, `422 scan_training_not_applicable` when Rspamd finds nothing to hash, `503 rspamd_unavailable` when the controller is not configured, unreachable or fails. Every call that found its message writes an `audit_logs` row `scan_training.<operation>` (`metadata: { operation, fuzzyFlag?, fuzzyFlagNumber?, outcome, engineVersion, reason }`, never content); a successful call also adds the timeline event `scan.training` (`details: { operation, result }`). Learning does not rescan the message.

### Known-threat file hashes (`platform` tag, step 4.2)

The platform-wide catalog of malicious file hashes (`malware_signatures`, design [10-attachment-scanning.md](../plan/steps/10-attachment-scanning.md) A16, A17). The attachment engine looks every attachment's and archive entry's SHA-256 up on every scan (never cached), so a change applies to the next scan of every organization: `high`/`critical` → `malicious` (`malware.known_hash`), `low`/`medium` → `suspicious` (`hash.known_suspicious`). Permission **`platform:threat_intel_manage`** (new in step 4.2, role `platform_admin`), user sessions with MFA, never API keys or override tokens; 60 calls per caller per minute.

| Method | Path                                       | Access                                 | Description                                                                                                                                                                                                                                                                                                 |
| ------ | ------------------------------------------ | -------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| GET    | `/platform/threat-hashes`                  | `platform:threat_intel_manage`, U, MFA | `?limit&cursor&source (analyst \| sandbox \| feed:<name>)&sha256` → `{ data: [{ sha256, md5, severity, family, source, reason, expiresAt, addedByUserId, firstSeenAt, lastSeenAt, createdAt, updatedAt }], nextCursor }`, newest first (replica)                                                            |
| POST   | `/platform/threat-hashes`                  | `platform:threat_intel_manage`, U, MFA | `{ sha256 (64 lower-case hex), severity (low \| medium \| high \| critical), md5? (32 lower-case hex), family? (≤ 128), reason (1–512), expiresAt? (future) }` → `201` the entry (`source: analyst`, the caller as `addedByUserId`, first/last seen now); `409 hash_exists`. Audited as `threat_hash.added` |
| DELETE | `/platform/threat-hashes/{sha256}?reason=` | `platform:threat_intel_manage`, U, MFA | `204`; `404 threat_hash_not_found`. Hard delete; audited as `threat_hash.removed` with `metadata: { reason, before }` (the entry as it was)                                                                                                                                                                 |

The audit rows (`organization_id` NULL, `resource_type: malware_signature`, `resource_id: <sha256>`) hold hashes and metadata only, never file content.

### Attachment rescan jobs (`platform` tag, step 4.2)

Bulk rescans after a signature update or a newly listed hash (A13). The api only writes and cancels `attachment_rescan_jobs` rows; the email-worker's rescan runner executes a job at a bounded rate (`ATTACHMENT_RESCAN_BATCH_SIZE` per `ATTACHMENT_RESCAN_INTERVAL_MS`), moving each candidate through the existing rescan path (edge E19, role `scanner`, reason `signature_rescan`, a new round on every engine). Permission **`platform:scan_rescan`** (new in step 4.2, role `platform_admin`), user sessions with MFA, never API keys or override tokens; 10 calls per caller per minute.

| Method | Path                                          | Access                         | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| ------ | --------------------------------------------- | ------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| POST   | `/platform/attachment-rescans`                | `platform:scan_rescan`, U, MFA | `{ windowHours (1–168), states? (non-empty subset of scanned, scan_failed, quarantined, held_for_review; default all four), organizationId? (public id; 404 organization_not_found), maxMessages? (1–ATTACHMENT_RESCAN_MAX_MESSAGES, the default), reason (1–512), dryRun? (false) }` → `202 { jobId, status: pending, estimatedMessages }`; dry run `200 { dryRun: true, estimatedMessages, windowStart, windowEnd, states, maxMessages }`, nothing written. Audited as `attachment_rescan.requested` |
| GET    | `/platform/attachment-rescans`                | `platform:scan_rescan`, U, MFA | `?limit&cursor&status` → `{ data: [{ jobId, trigger (admin \| signature_update), status, organizationId, windowStart, windowEnd, states, component, fromVersion, toVersion, maxMessages, selectedCount, requestedCount, skippedCount, requestedByUserId, reason, lastError, startedAt, completedAt, createdAt, updatedAt }], nextCursor }`, newest first (replica)                                                                                                                                     |
| GET    | `/platform/attachment-rescans/{jobId}`        | `platform:scan_rescan`, U, MFA | one job (replica); `404 rescan_job_not_found`                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| POST   | `/platform/attachment-rescans/{jobId}/cancel` | `platform:scan_rescan`, U, MFA | `{ reason? }` (body optional) → the job, `pending`/`running` → `cancelled` (the runner stops at its next batch; messages already requested keep their new round); `409 rescan_job_not_cancellable` with `status` otherwise. Audited as `attachment_rescan.cancelled`                                                                                                                                                                                                                                   |

**Candidates** (the runner's predicate, also used for `estimatedMessages`): messages received in `[now − windowHours, now]` in one of `states`, of `organizationId` if given, with at least one `email_attachments` row, and either `scan_failed` or without a final `malicious` attachment result in their current round. The estimate is counted on the read replica when the job is requested and capped at `maxMessages`; the runner selects on the writer as it goes, so its counts can differ.

### Dead letters (`platform` tag, step 3.2)

Pipeline messages that a consumer could not process end in the RabbitMQ queue `email.dead-letter` (design [07-rabbitmq.md](../plan/steps/07-rabbitmq.md) Q8, Q9; [ADR-0024](../architecture/adr/0024-rabbitmq-topology-retry-dead-letter.md)). Platform users only (API keys and override tokens get `403`). The api connects to the broker per request with `RABBITMQ_OPS_URL` (role user `eg-ops`: read `email.dead-letter`, write the six exchanges) and closes the connection afterwards; without that key both routes answer `503 dead_letter_replay_unavailable`.

| Method | Path                            | Access                                | Description                                                                                                                                                                                                                                                                                                            |
| ------ | ------------------------------- | ------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| GET    | `/platform/dead-letters`        | `platform:operations`, U              | `{ queue: 'email.dead-letter', messages, consumers }` (passive check of the queue)                                                                                                                                                                                                                                     |
| POST   | `/platform/dead-letters/replay` | `platform:dead_letter_replay`, U, MFA | `{ sourceQueue, limit (1–1000), eventType?, organizationId? (public id), failureReason?, dryRun? (false), reason (10–500 characters) }` → `{ replayId, dryRun, scanned, matched, replayed, skipped: { invalid, notMatching }, items: [{ eventId, eventType, organizationId, sourceQueue, failureReason, replayed }] }` |

```bash
curl -s -X POST http://127.0.0.1:${API_HOST_PORT}/api/v1/platform/dead-letters/replay \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"sourceQueue":"email.received","limit":50,"failureReason":"max_attempts_exceeded","dryRun":true,"reason":"after fixing the S3 credentials"}'
```

**What a replay does.** One replay runs at a time platform-wide (Redis lock `dlq:replay:lock`, 5 minutes; otherwise `409 replay_in_progress`). The api fetches dead letters one by one with manual acks and **holds** them until `limit` matched, the queue is empty or `DEAD_LETTER_REPLAY_SCAN_MAX` (default 10 000) were scanned. A message matches when its source queue (`x-eg-source-queue`, or the broker's `x-first-death-queue` for a delivery-limit dead letter) equals `sourceQueue` and every given filter matches (`eventType`; `organizationId`; `failureReason` = `x-eg-failure-reason` or the broker reason such as `delivery_limit`). Each match is decoded against the event registry (schema version, payload schema, tenant agreement of header, routing key and envelope) and passes the content guard; an invalid one stays in the queue (`skipped.invalid`). A valid one is republished **unchanged** (same body, `messageId` = `eventId`, `correlationId`, type, timestamp, appId) to `retry.<sourceQueue>.org.<id>.<eventType>` on the source queue's home exchange with fresh headers (the base headers, `x-eg-attempt: 0`, `x-eg-transient-retries: 0`, `x-eg-replay-id`, `x-eg-replay-count` + 1, `x-eg-replayed-at`; no failure or `x-death` headers), and the dead letter is acked **only after the broker confirmed the copy**. Everything not replayed is returned to the queue at the end (also on a dry run and on errors). `sourceQueue` must be a work queue (`email.received`, `email.delivery.pending`, since step 4.1 `scan.spam`, since step 4.2 `scan.attachment`); a dormant, delay or dead-letter queue is `400` with `sourceQueue: source_queue_not_replayable`. An unknown `organizationId` is `404`.

**Safety.** A replayed event keeps its `eventId`: a consumer that already processed it records a ledger duplicate (`processOnce`), so replaying twice is harmless. A crash between the confirm and the ack leaves a copy in both queues, which is again a duplicate. Replay is cross-tenant by nature; the organization filter narrows it.

**Audit.** Every replay writes one `audit_logs` row (`action: platform.dead_letters_replayed`, `resource_type: queue`, `resource_id: <sourceQueue>`, the platform user as actor) with `metadata: { replayId, dryRun, filters, scanned, matched, replayed, skipped, reason, outcome, eventIds (≤ 100) }`, also when nothing matched. When the broker fails half-way the row says `outcome: partial` and the request answers `503 dead_letter_replay_unavailable`; what was replayed before stays replayed, the rest is back in the queue.

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

| Status | Meaning                                                                                                                                                                                                                                                                            |
| ------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `400`  | Validation failed: `message` lists every issue as `"<path>: <issue>"` (input values are never echoed). Also malformed ids, unknown feature/limit keys, invalid or used tokens                                                                                                      |
| `401`  | Missing, invalid, expired or revoked credentials (`Invalid credentials` on login, `Unauthorized` elsewhere). Also: user or organization no longer active, override ended                                                                                                           |
| `403`  | Authenticated but not allowed: missing permission, user-only route called with an API key, `MFA required`, `MFA enrollment required`, four-eyes violation                                                                                                                          |
| `404`  | Not found, **including resources of another tenant** and soft-deleted resources                                                                                                                                                                                                    |
| `409`  | Conflicts with the current state: duplicates (slug, email, domain), limit reached (`Organization limit reached: <key>`), invalid state transitions, active legal hold, a check or rotation already in progress; message lifecycle conflicts (coded, step 3.3)                      |
| `422`  | A valid request for a feature that is not implemented (`Not implemented`, e.g. `smtp_callout`/`ldap` recipient validation); a refused destination server (with `reason` and `field`, step 2.3); an Idempotency-Key reused for another request (`idempotency_key_reused`, step 3.3) |
| `429`  | Rate limited, with `Retry-After` (seconds)                                                                                                                                                                                                                                         |
| `503`  | Authentication, rate-limit or domain-verification backend (Redis) unavailable: these paths fail closed                                                                                                                                                                             |

**Coded errors (step 3.3, 4.1, 4.2).** The message lifecycle routes, the step 4.1 scan routes (`scan_engine_not_found`, `scan_settings_invalid` with `violations`, `version_conflict` with `currentVersion`, `organization_not_found`, `content_unavailable`, `scan_training_not_applicable`, `rspamd_unavailable`) and the step 4.2 platform routes (`hash_exists`, `threat_hash_not_found`, `rescan_job_not_found`, `rescan_job_not_cancellable` with `status`) add a stable machine-readable `code` to the body (and, for `409`, the message's `currentState` and `currentVersion`); `message` stays human-readable:

```json
{
  "statusCode": 409,
  "error": "CONFLICT",
  "code": "message_version_conflict",
  "message": "The message changed since expectedVersion; read its lifecycle and retry",
  "currentState": "quarantined",
  "currentVersion": 6,
  "correlationId": "..."
}
```

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
