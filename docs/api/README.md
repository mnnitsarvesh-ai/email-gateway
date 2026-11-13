# API conventions and endpoints

The control-plane REST API (`apps/api`). Decisions: [ADR-0015](../architecture/adr/0015-api-base-path.md) (base path), [ADR-0016](../architecture/adr/0016-authentication-sessions-rbac.md) (authentication, sessions, RBAC, platform override), [ADR-0050](../architecture/adr/0050-api-conventions.md)–[ADR-0053](../architecture/adr/0053-public-internal-api-boundary.md) (step 6.1 conventions, pagination, rate limits and idempotency, public/internal boundary; summarized under [Conventions](#conventions-step-61)) and the step design [docs/plan/steps/02-tenants-auth-rbac.md](../plan/steps/02-tenants-auth-rbac.md). Details of authentication: [docs/security/authentication.md](../security/authentication.md); roles and permissions: [docs/security/rbac.md](../security/rbac.md).

## Versioning and the OpenAPI document

- Business routes live under the `/api` prefix and are versioned in the URI: `/api/v1/...` ([ADR-0015](../architecture/adr/0015-api-base-path.md)). Breaking changes ship as `/api/v2` alongside `/api/v1` until clients migrate. The old unprefixed `/v1/...` paths return `404`.
- Operational routes stay unprefixed and unversioned: `GET /health/live`, `GET /health/ready` (probes and Compose health checks do not change) and `GET /metrics`. They are **internal** ([ADR-0053](../architecture/adr/0053-public-internal-api-boundary.md)): never routed by the Ingress (which routes only `Prefix /api/v1/`) and not in the public OpenAPI document. `/api/health/*`, `/api/metrics`, `/api/docs` and `/api/v1/metrics` are `404 route_not_found`.
- In non-production environments, OpenAPI is served at `/docs` (Swagger UI) and `/docs-json`; never in production (`NODE_ENV=production`). The document lists only `/api/v1/*` (249 operations at step 6.1, 266 since step 6.2, 269 since step 7.1), describes every tag (the step that built it and its deferrals) and carries the portal extensions `x-eg-permissions`, `x-eg-rate-class`, `x-eg-idempotency`, `x-eg-cursor`, `x-eg-returns-secret` and (step 6.2) `x-eg-secret-replay: redacted`. The document declares two security schemes: `access-token` (HTTP bearer, JWT) and `api-key` (`X-API-Key` header). Every protected operation names the schemes it accepts and carries a tag; every request and response schema is generated from the zod schemas that validate it.
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

### Clients behind the admin portal (internal)

The admin portal (step 7.1) calls this API from its server-side BFF, so every browser request reaches the api from the portal's address. To keep per-IP limits (login 20/min, MFA verify 20/min, refresh 60/min, the IP failure block) and audit IPs per browser, the BFF sends two **internal** headers ([ADR-0060](../architecture/adr/0060-portal-ingress-and-trusted-client-ip-forwarding.md)):

| Header                 | Value                                                                 |
| ---------------------- | --------------------------------------------------------------------- |
| `X-EG-Client-IP`       | The browser's address (IPv4 or IPv6 literal; `::ffff:a.b.c.d` = IPv4) |
| `X-EG-Forwarder-Token` | The shared secret `API_TRUSTED_FORWARDER_TOKEN` (32–256 characters)   |

When the token matches (SHA-256 digests, constant-time) and the address is valid, the api uses that address as the request's client IP (`login_audit_logs.ip_address`, `audit_logs.source_ip`, session IPs, per-IP limits). Otherwise both headers are ignored and the socket / `HTTP_TRUST_PROXY` address is used; they are removed from every request either way and never reach a handler or a log. They are not part of the public OpenAPI document and not a client feature: API clients send neither (a forged `X-EG-Client-IP` without the token changes nothing). Outcomes are counted in `api_trusted_forwarder_total{outcome}`.

## Tenancy

The tenant of a request is always derived from the authenticated principal: the user's organization, the API key's organization, or the override target. No endpoint accepts a tenant id from a header or query. A resource of another tenant is answered exactly like a missing one (`404`), so existence is never disclosed.

## Endpoints

All paths are under `/api/v1`. Access: **P** = public (no credentials); **U** = users only (API keys get `403`); **K** = API keys accepted; **MFA** = MFA session required; **enroll** = reachable during MFA enrollment; **RL** = rate limited by a route-specific limit (`429` with `Retry-After`). Since step 6.1 every authenticated route is also subject to the [global rate limits](#rate-limits). Permission keys are listed in [docs/security/rbac.md](../security/rbac.md).

### Operational

| Method | Path            | Access | Description                                                                                                                                                                                                                                                                                                                                                     |
| ------ | --------------- | ------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| GET    | `/health/live`  | P      | Process liveness (unprefixed). No dependency checks                                                                                                                                                                                                                                                                                                             |
| GET    | `/health/ready` | P      | Dependency readiness (unprefixed). `200` when ok, else `503`                                                                                                                                                                                                                                                                                                    |
| GET    | `/api/v1/meta`  | P      | API build/version information                                                                                                                                                                                                                                                                                                                                   |
| GET    | `/metrics`      | P      | Prometheus series (unprefixed; e.g. step 3.2 `dead_letter_replay_total`, step 3.3 `api_message_lifecycle_operations_total`, step 6.1 `api_http_requests_total{method,route,status_class}`, `api_rate_limited_total{scope}`, `api_idempotency_total{outcome}`, `api_report_*`). **Internal** port only: never routed by the Ingress. Not in the OpenAPI document |

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
| POST   | `/messages/{messageId}/release`           | `quarantine:release`, K | `Idempotency-Key` + `{ expectedVersion, reason }` → since step 5.3 always `409 quarantine_workflow_required` for a quarantined/held message (release through [Quarantine](#quarantine-quarantine-tag-step-53))                    |

**States.** `received`, `persisted`, `scanning`, `scanned`, `scan_failed`, `policy_evaluated`, `approved`, `quarantined`, `held_for_review`, `rejected`, `delivery_pending`, `delivery_retry`, `delivered`, `archived`, `expired`. Partial and failed deliveries are reasons, not states: `delivered` with `statusReason: delivery_partial`, `rejected` with `delivery_failed` (per-recipient detail: `GET …/deliveries`). `version` grows by one per applied transition and is the optimistic-concurrency token of the operations; `lifecycleRound` grows by one per rescan or release. `actions` says what the current state allows (from the transition table), not what the caller may do.

**Reads** use the read replica (a few seconds behind; with the replica unusable the writer answers). Right after a rescan or release the previous state may still show; the `202` body carries the new `version`. The history is ordered by `version`; rows written before step 3.3 show `actor.role: "legacy"` and are shown as recorded (they may contain pairs the transition table no longer allows). `actor.id` is the public id of the operator (user or API key), `null` for system actors.

**Rescan** (edge E19, from `scanning`, `scanned`, `scan_failed`, `policy_evaluated`, `quarantined`, `held_for_review` or `expired`): the message moves to `scanning` in a new round and `mail.message.rescan_requested.v1` is published to the scan stages. Since step 4.1 ([09-rspamd.md](../plan/steps/09-rspamd.md) S14) every registered scan engine (Rspamd, queue `scan.spam`) scans the new round and the message ends `scanned` or `scan_failed` with that round; the results of earlier rounds stay unchanged, and the response `note` points at `GET /messages/{messageId}/scans`. Learning (below) does not rescan: rescan after training to see its effect. Audited as `message.rescan_requested`.

**Release** (step 5.3 Q30): quarantined and held messages are released **per recipient through the quarantine workflow** ([Quarantine](#quarantine-quarantine-tag-step-53)), which re-validates each entry against the latest scan round and the current policy and needs a second person for hard blocks, engine failures, DLP holds and policy rejections. This route keeps its path and permission and answers `409 quarantine_workflow_required` for every `quarantined` or `held_for_review` message, with `entries` (the message's entry count; 0 for a 5.2-held message the quarantine sweeper has not adopted yet) and `route` (`POST /api/v1/quarantine/entries/{entryId}/release`); other states and stale versions keep their conflicts below. Nothing is written. A `202` is only the stored response of a release made before step 5.3, replayed under its Idempotency-Key.

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
| Release of a quarantined or held message (step 5.3 Q30)     | `409 quarantine_workflow_required` (`entries`, `route`)    |

`409` bodies add `currentState` and `currentVersion`: read them, decide, and retry with the new `expectedVersion`.

**Idempotency-Key** (required on both operations): 1–128 characters of `[A-Za-z0-9._:-]`, case-sensitive, scoped to the organization. The first `2xx` response is stored for 24 hours in the same writer transaction as the change and its audit row. Repeating the request with the same key (same body, path, operation and caller) returns the stored status and body with the header `Idempotency-Replayed: true` and changes nothing; concurrent repeats are serialized (one applies, the others replay). Errors (`4xx`) are never stored: fix the request and retry with the same key. After 24 hours the key may be reused for a new request on another message; on the same message the earlier transition still holds the key, and the request is `422`.

```bash
curl -X POST "$API/api/v1/messages/$MESSAGE_ID/rescan" -H "X-API-Key: $KEY" \
  -H "Idempotency-Key: rescan-$MESSAGE_ID-1" -H 'Content-Type: application/json' \
  -d '{"expectedVersion":5,"reason":"verdicts are stale, rescan before release"}'
# → 202 {"messageId":"…","state":"scanning","version":6,"lifecycleRound":1,"rescanEventId":"…","note":"…"}
```

### Security scan results (`messages` tag, steps 4.1, 4.2, 4.3, 4.4, 4.5 and 4.6)

The scan rounds of a message of the caller's organization ([ADR-0026](../architecture/adr/0026-security-scan-pipeline.md), design [09-rspamd.md](../plan/steps/09-rspamd.md) S16; per-attachment results [10-attachment-scanning.md](../plan/steps/10-attachment-scanning.md) A16, [ADR-0028](../architecture/adr/0028-attachment-scanning-engine.md); per-URL results [11-url-protection.md](../plan/steps/11-url-protection.md) U16, [ADR-0029](../architecture/adr/0029-url-security-engine.md)), from the read replica. A round is one lifecycle round (`0` = the initial scan, each rescan adds one); another organization's message is `404 message_not_found`, and every query (rounds, engine rows, per-attachment rows, attachment metadata, sandbox submissions, URL rows, rewrites, dynamic inspections, click events) filters by the caller's organization.

| Method | Path                          | Access            | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| ------ | ----------------------------- | ----------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| GET    | `/messages/{messageId}/scans` | `message:read`, K | `?limit (1–20, default 10)&cursor` → `{ messageId, data: [{ round, scanKind, status, verdict, reasonCodes, requiredEngines, startedAt, completedAt, deadlineAt, auth: { spf, spfDomain, dkim, dkimSignatures, dmarc, dmarcPolicy, dmarcDomain, arc } \| null, engines: [{ engine, final, engineVersion, outcome, score, requiredScore, action, reasonCodes, symbols: [{ name, score, options }], attempts: [{ attempt, outcome, errorCode, durationMs, at }], durationMs, settingsVersion, completedAt }] }], nextCursor }`, **newest round first** |

**Per-attachment results (step 4.2).** The `attachment` engine entry also carries `attachments: [{ partIndex, filename, declaredContentType, sha256, sizeBytes, detectedType, typeFamily, typeMismatch, verdict (clean \| suspicious \| malicious \| unknown), reasonCodes, clamav: { signature \| null, engineVersion, dbVersion } \| null, yara: { bundleId, matches: [{ rule, severity, scope }] } \| null, archive: { format, supported, entries, depthReached, decompressedBytes, maxRatio, encrypted, findings: [{ path, type, reasonCodes }] } \| null, knownHash: { severity, family: null } \| null, sandbox: { submissionId, status (pending \| submitted \| completed \| failed \| expired \| skipped), skipReason, verdict, reasonCodes, executed, isolation, completedAt } \| null }]` (by part index; empty before the final result and for `skipped`). Rows come from `attachment_scan_results` joined with the part's `email_attachments` row on `(message_id, part_index, received_at)` and its `sandbox_submissions` row. `filename` is the sanitized display name (attacker-controlled text); archive entries are addressed by index path (`"2/0/5"`), never by name; no file content is ever stored or returned. `knownHash.family` is null (results store only the severity of the catalog hit). The content-cache outcome and the per-file duration are never returned (the cache is shared across organizations); the `attachment` engine's `durationMs` is null and its times are whole seconds.

**Per-URL results and the rewrite (step 4.3).** The `url` engine entry also carries `urls: [{ urlSeq, url, host, unicodeHost, registrableDomain, hostKind (domain \| ipv4 \| ipv6), sources ({ text \| html_href \| html_src \| form_action \| meta_refresh \| srcset \| attachment: count }), flags, verdict (clean \| suspicious \| malicious \| unknown), reasonCodes, reputation: [{ provider, kind (url \| domain \| ip), status (listed \| clear \| error), category }], lookalike: [{ rule (L1–L6), targetKind, targetDomain, score }], fetch: { status (completed \| error \| blocked), error, hops, chain: [{ host, status, kind (initial \| http \| meta), blocked }], finalUrl, finalStatus } \| null, landing: { passwordFields, forms, crossOriginFormAction, titleBrandMatches } \| null, dynamic: { status (pending \| completed \| failed \| expired), verdict, reasonCodes, signals } \| null, rewritten, clicks: { total, lastDecision, lastAt } }]` (at most 200, by `urlSeq`; empty before the final result and for `skipped`) and `rewrite: { status (rewritten \| skipped), skipReason (e.g. `no_urls`, `signed_smime`, `dkim_policy`, `too_large`), linksRewritten, partsRewritten, dkimSigned, expiresAt } \| null`. Rows come from `url_scan_results` of the round joined with `message_urls` (the URL in its redirect form: never userinfo; seqs are stable across rounds), the round's `url_dynamic_inspections` row and `url_rewrites` row; `clicks` summarizes `url_click_events` of the message (all rounds: one rewritten link per URL). The redirect chain holds hosts only (no paths or queries). Never returned: anchor text, page content or titles (never stored), the reputation/chain cache outcome and per-URL durations (the caches are shared across organizations, U6); the `url` engine's `durationMs` is null and its times (incl. `clicks.lastAt`, `rewrite.expiresAt`) are whole seconds. Platform threat-feed hits are shown (`provider: local_feed`): they are platform facts, not another tenant's data. `registrableDomain` is null for IP hosts and for a host that is itself a public suffix.

**Explainable BEC verdicts (step 4.4).** Every round carries `scanId` (decimal, the `{scanId}` of the BEC feedback route). The `bec` engine entry (phishing and BEC, design [12-phishing-bec.md](../plan/steps/12-phishing-bec.md) B15, [ADR-0033](../architecture/adr/0033-bec-engine-and-stage-dependencies.md)–[ADR-0035](../architecture/adr/0035-bec-communication-context-privacy.md)) also carries `bec: { rulesVersion, engineVersion, settingsVersion, lexiconVersion, verdict, deterministicVerdict, score, deterministicScore, thresholds: { suspicious, malicious }, inputs: { auth, url, text, history }, rules: [{ id, code, category, severity, weight, suppressed (null \| trust \| feedback), evidence: [{ header?, address?, displayName?, domain?, profile?: { kind, id (public id), match }, lookalike?, auth?, keywords?: { category, language, lexiconIds, spans: [{ source, start, end }] }, urls?, history?: { firstContact, priorMessages (bucket) }, trusted?: { id }, suppression?: { id }, suppressedCodes?, patterns? }] (≤ 5) }] (≤ 32), ai: [{ layer, mode, provider, modelId, modelVersion, promptTemplateVersion, status, labels, confidence, indicators, citedFeatures, spans, effect }], aiShadow: [... without effect], feedback: [{ id, kind, createdAt }] } \| null` (null before the final result and for a failed engine). Span offsets point into the derived text (`bec-text/1`), never text; the stored JSON is validated with the `@email-gateway/security-contracts` view schemas and invalid entries are dropped. Never shown: body or span text, excerpts, the LLM response hash, AI durations, history hashes. The `bec` engine reports no durations and second-granular times (as `attachment` and `url`). `thresholds` come from the engine's final row (`malicious` is null when the engine did not record it). Addresses and display names in evidence are the tenant's own header metadata (already shown by the message metadata routes).

**Masked DLP results (step 4.5).** The `dlp` engine entry (data loss prevention, design [13-dlp.md](../plan/steps/13-dlp.md) D20) carries `dlp: { engineVersion, rulesVersion, settingsVersion, policyVersion, extractorVersion, verdict (clean \| suspicious \| unknown \| skipped), action (allow \| alert \| require_approval \| quarantine \| block), actionSource, coverage, coverageDetail: [{ source, partIndex?, path? (index path, never a name), format, status, reasons, chars, truncated }], aadhaar (enabled \| disabled), categories: [{ category, count, maxSeverity, maxConfidence }], findings: [{ detector, code, category, severity, confidence, count, capped, sources, masked (≤ 3 masked samples), customPatternId?, dictionaryId? }], policy: { winner, matched, exceptionsApplied } (public ids), evidence: { status, expiresAt, purged } }` **only for callers also holding `dlp:read`**; for every other caller (`message:read` alone is held by read-only users, quarantine reviewers, domain admins and platform admins) `dlp` is `null` and the entry shows only the standard fields (outcome, reason codes, versions). Never raw values, context text, offsets, dictionary terms or pattern text; findings whose stored sample looks raw or whose ids are not the organization's are dropped. Like the `attachment`, `url` and `bec` engines, `dlp` reports no durations and second-granular times. Decrypted values only through the audited evidence route (below).

**Sandbox results (step 4.6).** The sandbox is an **asynchronous** engine (design [14-sandbox.md](../plan/steps/14-sandbox.md) X10, X18; [ADR-0040](../architecture/adr/0040-sandbox-engine-dispatch-results-artifacts.md)): its final row may appear after the round completed and **never changes the round's `verdict`**, reason codes or the message lifecycle. Each attachment's `sandbox` object shows its submission's outcome — `status` (`skipped` with `skipReason`: `feature_disabled`, `tenant_disabled`, `type_excluded`, `size_excluded`), `verdict` (`suspicious`, `malicious`, `unknown`, `error`, `timeout`; `clean` only for a complete VM-isolated run, which this release cannot perform), `sandbox.*` `reasonCodes`, `executed`, `isolation` (`none`, `process` = static analyzer child, `container` = the local/CI test runner, **not a VM boundary**, `vm`) and `completedAt` (whole seconds). The `sandbox` engine entry (present once its final row is written) carries `submissions: [{ submissionId, partIndex, sha256, status, skipReason, verdict, reasonCodes, executed, isolation, backend, versions: { controller, backend, analyzer, map }, findings: [{ code, severity, count }], indicators: { dns, httpHosts, tlsSni, ips } (≤ 50 each, host names and canonical IPs only), processes: { count, images (≤ 32 basenames) }, droppedFiles: [{ sha256, sizeBytes, typeHint }], limitsHit, artifacts: [{ seq, kind, contentType, sizeBytes, sha256 (plaintext), expiresAt (rounded down to the day), purged }], completedAt }]` by part index; `symbols` is empty and `durationMs` null. The report comes from the analysis that completed the submission (`sandbox_analyses.report`, read only by the ids of the organization's own submissions and matched by public id) and its `sandbox_artifacts` metadata. **Never returned:** sample or artifact content, file names, paths or URLs, analysis ids, analysis timings, the dispatching organization, or whether an earlier analysis of the same file (possibly another organization's) was reused. There is **no artifact download** in this release. Execution of unknown files is disabled by default and refused in production (see [README](../../README.md#sandbox-step-46)); in the default configuration every analysed submission ends `unknown` with `sandbox.not_executed.backend_disabled`. No new permission: `message:read`.

**Risk scores (step 5.1).** Each round also carries `risk: [...]`, the stored risk scores of the round (design [15-risk-scoring.md](../plan/steps/15-risk-scoring.md) R11, R15; [ADR-0041](../architecture/adr/0041-risk-scoring-model.md), [ADR-0042](../architecture/adr/0042-risk-scoring-placement-and-policy-handoff.md)), revisions ascending (`0` = the round, `1` = with the late sandbox result), `[]` before step 5.1 or while the round runs: `{ revision, status (scored | error), score (0–1000), level (none | low | medium | high | critical), verdict, recommendedAction (deliver | tag | require_approval | quarantine | block), hardBlocks: [{ id, verdict, action }], reasonCodes, contributions: [{ signal, group, weight, codes, applied }], groups, engines, failures, floors, trust, evidence, explanation: { lines, text }, versions: { scorer, signalMap, input, profile: { source, id, versionNo, sha256 } }, inputSha256, createdAt }`. Profile ids are public (`rsk-default/1` or `rsk-default/1+t:<version id>#<n>`); internal ids never appear. Codes and integers only: no addresses, URLs or content. **A recommendation, not a decision**: policy (5.2) decides.

**Policy evaluation (step 5.2).** Each round also carries `policy`: the stored policy evaluation of the round or `null` (not evaluated yet, or a round before step 5.2) (design [16-policy-engine.md](../plan/steps/16-policy-engine.md) P10, P16): `{ status, round, disposition (allow | require_approval | quarantine | reject), finalVerdict, riskScore, decisive: { source (tenant_rule | platform_default | floor), policyPublicId, versionNo, ruleId, reason }, actions: [{ type, params, origin, ruleRefs, applicability }], actionStatuses (enforced | requested | recorded | not_applicable, one per action), delivery, notices, matchedRules, trace, traceTruncated, floor, recommendation, override, clamps, reasonCodes, explanation: { lines, text }, versions: { dsl, evaluator, input, platformDefault, snapshotSha256, generation, tzdata, policies }, inputSha256, lifecycleRound, trigger, direction, finalAction, deliveredObject, evaluatedAt, durationUs, recipientSplit, recipientDecisions }` — step 5.3 adds `recipientSplit` and `recipientDecisions` (`[{ rcptSeq, disposition, source, decisiveRuleRef, reasonCodes }]`, `null` when the round was not evaluated per recipient) and, in `delivery`, the WARN body banner outcome (`bodyBanner`: `applied` or `skipped_*`) and the URL rewrite after the scan (`urlRewrite.policyAttempt`). Ids, codes, enums, integers and hashes only (no addresses, URLs, file names or content; internal ids never appear). Every evaluation of a message (parse-failure evaluations have no scan) is `GET /messages/{messageId}/policy-evaluations`.

**Verdicts** (`verdict`, aggregate of the round, null while running): `clean`, `spam`, `suspicious`, `malicious`, `unknown`, `timeout`, `error`. A failed or timed-out engine never counts as `clean`: the round then ends `scan_failed` (`status: failed` or `timed_out`). Per engine, `final: false` means the engine has no final result yet (attempts are retried); `attempts` lists every attempt with its `errorCode`. `symbols` are the Rspamd symbols with their scores (at most 200) and up to five options of at most 200 characters, which **can contain addresses or URLs of the message**; reason codes follow `<category>.<code>` (e.g. `spam.score`, `auth.dmarc_reject`, `phishing.known_bad_url`).

### Scan settings (`scan-settings` tag, steps 4.1, 4.2, 4.3, 4.4, 4.5 and 4.6)

Per-organization settings of the scan engines (S8, S16; step 4.2 A8; step 4.3 U13) within the platform settings (`SCAN_RSPAMD_*`, `ATTACHMENT_*`, `URL_*`, `BEC_*`). Engines with settings: `rspamd`, `attachment`, `url`, `bec` (step 4.4), `dlp` (step 4.5: `inboundEnabled`, `thresholds.<category>` 0.5–0.95, `disabledDetectors` ⊆ PI1/PI2/BA3/SC1/CF2, `defaultPolicy` alert \| allow, `evidence.{enabled ≤ DLP_EVIDENCE_ENABLED, retentionDays 1..DLP_EVIDENCE_MAX_RETENTION_DAYS}`; the context window and bulk threshold are platform only), `sandbox` (step 4.6, below) (catalog order; each with its own `platform`, `bounds`, `override` and `effective` shape). Users and API keys; the organization is always the caller's scope. Reading needs `policy:read` (every built-in tenant role); changing needs the step 4.1 permission `scan:settings_manage` (`organization_admin`, `security_analyst`; grantable to API keys).

| Method | Path                                        | Access                    | Description                                                                                                                                                                                                   |
| ------ | ------------------------------------------- | ------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| GET    | `/scan-settings`                            | `policy:read`, K          | `{ data: [{ engine, required, tenantMayDisable, platform, bounds, override \| null, effective, overrideApplied, violations, version, updatedAt }], note }` (replica)                                          |
| PUT    | `/scan-settings/{engine}`                   | `scan:settings_manage`, K | `{ expectedVersion (0 = no override yet), settings }` → the engine's view + `note`; replaces the override. Audited as `scan_settings.updated` (`metadata: { engine, fromVersion, toVersion, before, after }`) |
| DELETE | `/scan-settings/{engine}?expectedVersion=n` | `scan:settings_manage`, K | back to the platform settings (the row keeps an empty override and a new version, so versions never repeat). Audited as `scan_settings.reset`; nothing to reset is a no-op                                    |

**Rspamd settings** (`engine = rspamd`, all optional, strict): `spamScore` and `suspiciousScore` (at most two decimals, within `[SCAN_RSPAMD_SCORE_MIN, SCAN_RSPAMD_SCORE_MAX]`, `suspiciousScore < spamScore` after merging; a tenant may loosen or tighten scores), `phishingVerdict` (`suspicious` \| `malicious`), `dmarcRejectVerdict` (`suspicious` \| `malicious`) and `authFailureVerdict` (`reason_only` \| `suspicious`), which may only be **raised** above the platform value. Rspamd is a required engine and cannot be disabled. A stored override that no longer fits (the platform bounds were tightened) is listed with `overrideApplied: false` and its `violations`, and the scan stage ignores it. **Workers apply a change within their settings cache TTL** (`SCAN_SETTINGS_CACHE_TTL_MS`, default 30 s); messages already scanned keep their results.

**Attachment settings** (`engine = attachment`, step 4.2 A8, all optional, strict): `deniedTypes` (file type ids added to the platform deny list `ATTACHMENT_DENIED_TYPES`; a platform entry can never be removed; not `unknown`), `allowedTypes` (allow-list mode, at least one type, never a platform-denied type), `deniedTypeVerdict`, `typeMismatchVerdict`, `encryptedArchiveVerdict` (`suspicious` \| `malicious`, **raise-only**) and `maxAttachmentBytes` (tighten-only, `1 048 576 ≤ x ≤ ATTACHMENT_MAX_BYTES`). Archive depth/entries/sizes/ratio and the inspector's CPU and memory limits are platform-only (`platform` shows them). The attachment engine is required and cannot be disabled.

**URL settings** (`engine = url`, step 4.3 U13, all optional, strict at every level): `allowedDomains` (≤ 500; suppresses lookalike, new-domain, structure and landing rules and excludes the links from rewriting — never a feed or DNSBL malicious finding), `blockedDomains` (≤ 500; → `malicious`, `url.tenant_blocked`), `scanTimeFetch` (`off` \| `shorteners` \| `suspicious` \| `all`, at most the platform's `URL_SCAN_TIME_FETCH`), `lookalike.extraProtectedDomains` (≤ 50), `rewrite.{ enabled (true only when the platform has rewriting on), directions (non-empty subset of inbound, outbound, internal), expiryDays (1–`URL_TOKEN_MAX_EXPIRY_DAYS`), excludedDomains (≤ 200), dkimSignedPolicy (rewrite \| skip), plainText }`, `click.{ suspicious (warn \| block), unknown (allow \| warn \| block), allowContinue }` (`clean` is always allowed, `malicious` always blocked) and `dynamicInspection` (true only when the platform has it on). **Every domain is normalized by `@email-gateway/url-security`** before it is validated and stored: IDNA to ASCII A-labels (`bücher.example` → `xn--bcher-kva.example`), lower case, trailing dots removed; an IP literal, a single label or a public suffix (`co.uk`, `github.io`) is `422` (`code: invalid`, path `<list>.<index>`); a domain both allowed and blocked is `422` (path `blockedDomains`). The rewrite and scan settings apply to messages scanned after the settings cache TTL; the click policy and the lists are read **live** by the click-service (the next click).

**BEC settings** (`engine = bec`, step 4.4 B13, all optional, strict at every level; platform `BEC_*`): `suspiciousScore` (25–60) and `maliciousScore` (60–95) with `suspiciousScore < maliciousScore` after merging; `freemailExtraDomains` (≤ 100, normalized to ASCII by `@email-gateway/url-security`; IP literals, single labels and public suffixes refused with `invalid` at `freemailExtraDomains.<i>`); `history: { enabled (default false: opt-in, ADR-0035), retentionDays (30–BEC_HISTORY_MAX_RETENTION_DAYS) }`; `ai: { localModel, llm (off \| shadow \| active, never above the platform caps BEC_LOCAL_MODEL_MODE / BEC_LLM_MODE; the LLM defaults to off), llmDailyCallLimit (1–BEC_LLM_MAX_CALLS_PER_TENANT_PER_DAY), raiseConfidence (0.6–0.99) }`. The AI malicious band and corroboration confidence are platform only. Rule weights are not tunable (feedback suppressions are the bounded lever). The worker re-validates the row at use and falls back to the platform settings when it no longer fits.

**Sandbox settings** (`engine = sandbox`, step 4.6 X17, all optional, strict; platform `SANDBOX_TENANT_DEFAULT_ENABLED`, `SANDBOX_FILE_TYPES`, `SANDBOX_MAX_SAMPLE_BYTES`, `SANDBOX_BROWSER_ANALYSIS`): `enabled` (submit suspicious/unknown attachments to the sandbox; `true` needs the organization's plan feature `attachment_sandbox`, else `409 feature_not_enabled`; the feature is read on the writer for the caller's organization, and the worker re-checks it at use and skips with `feature_disabled` without it), `fileTypes` (a non-empty subset of the platform list), `maxSampleBytes` (1 … platform maximum) and `browserAnalysis` (`true` only when the platform allows it). The backend, run limits and timeouts are platform-only. The `sandbox` view adds `mode: asynchronous`, `feature: { attachmentSandbox }` and `execution` — what happens to a submitted file in this environment, from the api's `SANDBOX_EXPECTED_BACKEND` (informational): `disabled` (default: nothing is analysed or executed; results are `unknown`), `static_only` (static analysis, nothing executed) or `local_test_runner` (local/CI only: scripts run in a hardened container that is **not a VM boundary**; refused outside `APP_ENV` local/ci). **Execution of unknown files is never available in production in this release.** The sandbox is optional and never required (`required: false`, `tenantMayDisable: true`).

| Case                                                                                       | Response                                                                                                                                                            |
| ------------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Engine not registered                                                                      | `404 scan_engine_not_found`                                                                                                                                         |
| Out of bounds, wrong order, lowered severity, unknown key, URL domain not registrable/host | `422 scan_settings_invalid` with `violations: [{ path, code, message }]` (`code`: `invalid`, `unknown_key`, `out_of_bounds`, `threshold_order`, `severity_lowered`) |
| `expectedVersion` is not the current version                                               | `409 version_conflict` with `currentVersion`                                                                                                                        |
| `sandbox.enabled = true` without the plan feature `attachment_sandbox` (step 4.6)          | `409 feature_not_enabled` with `feature`                                                                                                                            |

```bash
curl -X PUT "$API/api/v1/scan-settings/rspamd" -H "X-API-Key: $KEY" -H 'Content-Type: application/json' \
  -d '{"expectedVersion":0,"settings":{"spamScore":7,"dmarcRejectVerdict":"malicious"}}'
```

### Phishing and BEC tenant data (`bec` tag, step 4.4)

Executive and vendor profiles, trusted senders, analyst feedback with bounded suppressions, the retraining export and the communication-history purge of the caller's organization (design [12-phishing-bec.md](../plan/steps/12-phishing-bec.md) B7, B11, B12, B18). The organization comes from the authenticated scope only; another organization's id is a `404`. Ids are public ids (UUIDv7). Writes run on the writer (120 s transaction budget) with their audit row (before-image on update and delete) in the same transaction; a writer read that returns another row twice is `503 inconsistent_read` (retry). Lists read the replica (newest first, `?limit&cursor`). The engine caches the tenant data for up to `BEC_TENANT_DATA_CACHE_TTL_MS` (30 s): a change applies to messages scanned after that.

| Method | Path                                                | Access                        | Description                                                                                                                                                                                                                                                                                                                                                                                |
| ------ | --------------------------------------------------- | ----------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| GET    | `/bec/executives`, `/bec/executives/{id}`           | `bec:read`, K                 | `?limit&cursor&enabled` → `{ data: [{ id, displayName, normalizedName, aliases, knownAddresses, title, enabled, version, createdByUserId, updatedByUserId, createdAt, updatedAt }], nextCursor }`; `404 bec_executive_not_found`                                                                                                                                                           |
| POST   | `/bec/executives`                                   | `bec:manage`, K               | `{ displayName (2–128), aliases? (≤ 10), knownAddresses? (≤ 20), title?, enabled? }` → `201`; the name is normalized (B5: NFKC, invisible characters removed, case folded, punctuation removed) and unique per organization (`409 executive_exists` with `id`); addresses normalized (IDNA, lower case); ≤ `BEC_MAX_EXECUTIVES` (`409 bec_limit_reached`). Audited `bec_executive.created` |
| PATCH  | `/bec/executives/{id}`                              | `bec:manage`, K               | `{ version, …fields }` → the profile (`version` + 1); `409 version_conflict` with `currentVersion`. Audited `bec_executive.updated` with `before` and `after`                                                                                                                                                                                                                              |
| DELETE | `/bec/executives/{id}`                              | `bec:manage`, K               | `?version` (optional compare-and-set) → `204`. Audited `bec_executive.deleted` with `before`                                                                                                                                                                                                                                                                                               |
| GET    | `/bec/vendors`, `/bec/vendors/{id}`                 | `bec:read`, K                 | as executives: `{ id, name, normalizedName, aliases, domains, knownSenders, paymentChangeSensitive, enabled, version, … }`; `404 bec_vendor_not_found`                                                                                                                                                                                                                                     |
| POST   | `/bec/vendors`                                      | `bec:manage`, K               | `{ name (2–128), domains (1–20), aliases? (≤ 10), knownSenders? (≤ 50), paymentChangeSensitive? (default true), enabled? }`; domains normalized to ASCII registrable domains (public suffixes `400`, free-mail domains `422 vendor_domain_freemail` with `index`); `409 vendor_exists`; ≤ `BEC_MAX_VENDORS`. Audited `bec_vendor.created`                                                  |
| PATCH  | `/bec/vendors/{id}`, DELETE `/bec/vendors/{id}`     | `bec:manage`, K               | as executives (`bec_vendor.updated` / `.deleted`)                                                                                                                                                                                                                                                                                                                                          |
| GET    | `/bec/trusted-senders`                              | `bec:read`, K                 | `?limit&cursor&kind` → `{ data: [{ id, kind (address \| domain), value, reason, expiresAt, expired, version, createdByUserId, createdAt, updatedAt }], nextCursor }`                                                                                                                                                                                                                       |
| POST   | `/bec/trusted-senders`                              | `bec:manage`, K               | `{ kind, value, reason (1–512), expiresAt? (future, ≤ 365 days) }`; an address normalized, a domain must be a registrable domain (subdomains and public suffixes `400`; free-mail `422 trusted_domain_freemail`); unique per (kind, value) (`409 trusted_sender_exists`); ≤ `BEC_MAX_TRUSTED_SENDERS`. Trust applies only when the message authenticates as From (B7). Audited             |
| PATCH  | `/bec/trusted-senders/{id}`                         | `bec:manage`, K               | `{ version, reason?, expiresAt? (null = no expiry) }`; audited `bec_trusted_sender.updated` with `before`/`after`. DELETE `/bec/trusted-senders/{id}?version` → `204`, audited `.deleted`                                                                                                                                                                                                  |
| POST   | `/messages/{messageId}/scans/{scanId}/bec-feedback` | `bec:feedback`, U             | `{ kind (false_positive \| false_negative), reasonCodes? (BEC codes; for a false positive ⊂ the result's codes, else `422 feedback_codes_invalid`), note? (≤ 500, never exported; no message content), suppress? }` → `201 { id, kind, messageId, scanId, reasonCodes, note, createdByUserId, createdAt, suppressions: [...] }`. See below. Audited `bec_feedback.recorded`                |
| GET    | `/bec/feedback`                                     | `bec:read`, K                 | `?limit&cursor&kind&from&to` → `{ data: [{ id, kind, messageId, scanId, reasonCodes, note, createdByUserId, createdAt }], nextCursor }`                                                                                                                                                                                                                                                    |
| GET    | `/bec/feedback/export`                              | `bec:feedback_export`, U, MFA | `?from&to&cursor&limit (≤ 10 000)` → `application/x-ndjson`, oldest first, `X-Next-Cursor` when more remain. 10 per caller per minute. Audited `bec_feedback.exported` (window and count)                                                                                                                                                                                                  |
| GET    | `/bec/suppressions`                                 | `bec:read`, K                 | `?limit&cursor&active` → `{ data: [{ id, reasonCode, senderScope, senderValue, expiresAt, expired, feedbackId, createdByUserId, createdAt }], nextCursor }`                                                                                                                                                                                                                                |
| DELETE | `/bec/suppressions/{id}`                            | `bec:manage`, K               | `204`; `404 bec_suppression_not_found`. Audited `bec_suppression.deleted` with `before`                                                                                                                                                                                                                                                                                                    |
| DELETE | `/bec/history`                                      | `bec:manage`, U, MFA          | Deletes the organization's `bec_contact_history` rows (keyed hashes and counts) in batches of 5 000 → `202 { deleted }`. Audited `bec_history.purged` with the count. Turning `history.enabled` off does not delete rows; this does                                                                                                                                                        |

**Feedback and suppressions (B11).** The message, the round (`scanId`) and its `bec` result must belong to the caller's organization (writer reads; `404 message_not_found`, `scan_not_found`, `bec_result_not_found`). One feedback per scan, user and kind (`409 feedback_exists`). A **false positive** may carry `suppress: { codes, scope (address \| domain), days (1–90) }`: only suppressible codes (`BEC_SUPPRESSIBLE_CODES`: P1, P2, I2, I3, D1, D3, R1, R2, V3, C1, C4, C5, C7, C8, C10, H1, H3, H4, H5 — never authentication, lookalike, Reply-To lookalike, executive or vendor impersonation, payment-change, bank-change, gift-card, payroll, credential, link, engine or AI codes; others are `400`) that the result carries; the sender is the scanned message's From address or its registrable domain (never typed by the caller); a free-mail domain scope is refused. Every refusal is `422 suppression_not_allowed` with `reason` (`not_false_positive`, `code_not_in_result`, `sender_unavailable`, `freemail_domain`). A rule for the same code and sender is renewed (later expiry, new feedback); at most `BEC_SUPPRESSIONS_MAX_PER_TENANT` active rules (`409 bec_limit_reached`). At use the engine caps the suppressed weight per message (`BEC_SUPPRESSION_MAX_WEIGHT`). False negatives are recorded only (they never raise verdicts).

**Retraining export (B11).** One JSON object per line with exactly: `feedbackId, kind, createdAt, rulesVersion, engineVersion, localModel ({ id, version } \| null), llm ({ modelId, promptTemplateVersion } \| null), firedCodes, deterministicScore, score, verdict, deterministicVerdict, features (the AI feature vector stored with the result), aiLabels ([{ layer, mode, label, confidence }])`. Never bodies, excerpts, span text, addresses, display names, domains, notes or message ids.

```bash
curl -X POST "$API/api/v1/bec/executives" -H "X-API-Key: $KEY" -H 'Content-Type: application/json' \
  -d '{"displayName":"Anita Sharma","aliases":["A. Sharma"],"knownAddresses":["anita@acme.example"],"title":"CEO"}'
curl -X POST "$API/api/v1/messages/$MESSAGE/scans/$SCAN/bec-feedback" -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"kind":"false_positive","reasonCodes":["bec.reply_to.freemail"],"suppress":{"codes":["bec.reply_to.freemail"],"scope":"domain","days":30}}'
curl "$API/api/v1/bec/feedback/export?from=2026-11-01T00:00:00Z" -H "Authorization: Bearer $TOKEN" -D - -o feedback.ndjson
```

### Data loss prevention (`dlp` tag, step 4.5)

Policies and rules, exceptions, custom patterns (and the pattern test), keyword dictionaries, the Aadhaar compliance basis, incidents and the audited evidence of the caller's organization (design [13-dlp.md](../plan/steps/13-dlp.md) D8, D9, D11, D12, D14, D16, D17, D21; [ADR-0037](../architecture/adr/0037-dlp-policy-actions-and-lifecycle-binding.md), [ADR-0038](../architecture/adr/0038-dlp-evidence-masking-and-aadhaar-gating.md)). The organization comes from the authenticated scope only; another organization's id is a `404`. Ids are public ids (UUIDv7); `{scanId}` is the decimal round id of `GET /messages/{messageId}/scans`. Writes run on the writer (120 s transaction budget, 10 s to get a connection) **under the organization row lock** (caps, unique names, references and in-use checks are evaluated under it, so concurrent creates never exceed a cap), compare and set `version` (`409 version_conflict` with `currentVersion`) and write their audit row (before-image on update and delete) in the same transaction; a writer read that returns another row twice is `503 inconsistent_read` (retry). Lists and reads come from the read replica (a few seconds behind; the writer above `DATABASE_READ_MAX_LAG_SECONDS`). **The DLP engine caches the organization's policies, rules, exceptions, patterns, dictionaries and compliance setting for up to `DLP_TENANT_DATA_CACHE_TTL_MS` (default 30 s): a change applies to messages scanned after that; finished rounds keep their result.** Permissions: `dlp:read` (organization admin, security analyst, compliance auditor), `dlp:manage` (organization admin, security analyst), `dlp:evidence_read` (organization admin, security analyst, compliance auditor), `dlp:compliance_manage` (organization admin); none of them is held by `read_only_user`, `quarantine_reviewer`, `domain_admin` or `platform_admin` ([rbac.md](../security/rbac.md#data-loss-prevention-step-45)). U = users only, K = users and API keys, MFA = an MFA-authenticated session.

| Method | Path                                                | Access                              | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| ------ | --------------------------------------------------- | ----------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| GET    | `/dlp/policies`, `/dlp/policies/{id}`               | `dlp:read`, K                       | `?limit&cursor&enabled` → `{ data: [{ id, name, description, enabled, mode, priority, directions, ruleCount, version, createdByUserId, updatedByUserId, createdAt, updatedAt }], nextCursor }`; the detail adds `rules` (by priority); `404 dlp_policy_not_found`                                                                                                                                                                                                                                                                                                                                                                    |
| POST   | `/dlp/policies`                                     | `dlp:manage`, K                     | `{ name (1–128), description?, enabled?, mode? (enforce \| monitor), priority? (0–1000, ascending), directions? (default outbound, internal) }` → `201`; unique name (`409 dlp_policy_exists` with `id`); ≤ `DLP_POLICIES_MAX_PER_TENANT` (`409 dlp_limit_reached`). Audited `dlp_policy.created`                                                                                                                                                                                                                                                                                                                                    |
| PATCH  | `/dlp/policies/{id}`                                | `dlp:manage`, K                     | `{ version, …fields }`; narrowing `directions` below a rule's is `400 dlp_directions_invalid`. Audited `dlp_policy.updated` (`before`, `after`)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      |
| DELETE | `/dlp/policies/{id}`                                | `dlp:manage`, K                     | `?version` → `204`; deletes its rules in the same transaction; `409 dlp_policy_in_use` (`references`) while exceptions target the policy or a rule. Audited `dlp_policy.deleted` (`before` with the rules)                                                                                                                                                                                                                                                                                                                                                                                                                           |
| POST   | `/dlp/policies/{id}/rules`                          | `dlp:manage`, K                     | `{ name, enabled?, priority?, conditions, action (allow \| alert \| require_approval \| quarantine \| block) }` → `201`; `conditions` is `dlpRuleConditionsSchema` (strict: `selectors` {detectors, categories, customPatternIds, dictionaryIds, coverageReasons}, `minCount`, `minConfidence`, `minSeverity`, `directions` ⊆ the policy's, `sender`, `recipients` {…, externalOnly}, `attachmentsOnly`) after address/domain normalization; ids must be the organization's (`400 dlp_reference_invalid` with `field`, `index`); unique per policy (`409 dlp_rule_exists`); ≤ `DLP_RULES_MAX_PER_POLICY`. Audited `dlp_rule.created` |
| PATCH  | `/dlp/policies/{id}/rules/{ruleId}`                 | `dlp:manage`, K                     | `{ version, …fields }` (conditions re-validated). Audited `dlp_rule.updated`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| DELETE | `/dlp/policies/{id}/rules/{ruleId}`                 | `dlp:manage`, K                     | `?version` → `204`; `409 dlp_rule_in_use` while exceptions target it. Audited `dlp_rule.deleted`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| GET    | `/dlp/exceptions`                                   | `dlp:read`, K                       | `?limit&cursor&scope&active` → `{ data: [{ id, scope, value, policyId, ruleId, filters, reason, expiresAt, expired, enabled, version, … }], nextCursor }`                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| POST   | `/dlp/exceptions`                                   | `dlp:manage`, K                     | `{ scope (sender_address \| sender_domain \| recipient_address \| recipient_domain), value, policyId? \| ruleId?, filters? { detectors?, categories? }, reason (1–512), expiresAt (required; future, ≤ DLP_EXCEPTION_MAX_DAYS), enabled? }` → `201`; addresses normalized (lower case, IDNA), domains to ASCII (public suffixes and IP literals refused); target ids must be the organization's (`400 dlp_reference_invalid`); unique per (scope, value, target) (`409 dlp_exception_exists`); ≤ `DLP_EXCEPTIONS_MAX_PER_TENANT`. Audited `dlp_exception.created`                                                                    |
| PATCH  | `/dlp/exceptions/{id}`                              | `dlp:manage`, K                     | `{ version, reason?, expiresAt?, enabled?, filters? (null removes) }` (scope, value and target are fixed). Audited `dlp_exception.updated`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| DELETE | `/dlp/exceptions/{id}`                              | `dlp:manage`, K                     | `?version` → `204`. Audited `dlp_exception.deleted`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| GET    | `/dlp/patterns`, `/dlp/patterns/{id}`               | `dlp:read`, K                       | `{ data: [{ id, name, pattern, caseInsensitive, validator, contextKeywords, requireContext, severity, baseConfidence, maskStyle, enabled, version, … }], nextCursor }` (the pattern is tenant configuration)                                                                                                                                                                                                                                                                                                                                                                                                                         |
| POST   | `/dlp/patterns`                                     | `dlp:manage`, K                     | `{ name, pattern, caseInsensitive?, validator? (none \| luhn \| verhoeff \| mod97 \| gstin), contextKeywords? (≤ 20 × 1–64), requireContext?, severity (low–critical), baseConfidence? (0.5–1, default 0.8), maskStyle? (last4 \| full), enabled? }` → `201`; validated by the D9 safety rules (below); unique name (`409 dlp_pattern_exists`); ≤ `DLP_CUSTOM_PATTERNS_MAX_PER_TENANT`. Audited `dlp_pattern.created` (the pattern is in the image)                                                                                                                                                                                  |
| PATCH  | `/dlp/patterns/{id}`                                | `dlp:manage`, K                     | `{ version, …fields }` (re-validated). Audited `dlp_pattern.updated`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 |
| DELETE | `/dlp/patterns/{id}`                                | `dlp:manage`, K                     | `?version` → `204`; `409 dlp_pattern_in_use` (`references`) while a rule selects it. Audited `dlp_pattern.deleted`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| POST   | `/dlp/patterns/test`                                | `dlp:manage`, K, 30/min             | `{ pattern, caseInsensitive?, validator?, contextKeywords?, requireContext?, maskStyle?, sample (≤ 4 096 characters) }` → `200 { valid, code \| null, complexity { repetitionProduct, length }, matches: [{ start, end, masked, validated, contextMatched }] (≤ 50) }`. **Persists nothing; the sample and the pattern are never logged, audited or echoed** (only `dlp_pattern_tests_total{result}`). Use synthetic samples                                                                                                                                                                                                         |
| GET    | `/dlp/dictionaries`, `/dlp/dictionaries/{id}`       | `dlp:read`, K                       | the list shows `termCount` only; the detail adds `terms` (tenant configuration, possibly confidential names: never in the scans read API, logs or audit metadata)                                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| POST   | `/dlp/dictionaries`                                 | `dlp:manage`, K                     | `{ name, category (confidential \| financial \| personal_info \| source_code \| custom), terms (1..DLP_DICTIONARY_MAX_TERMS, each 1–64 characters and 1–8 tokens after normalization, unique after normalization), severity, baseConfidence? (default 0.7), minMatches? (1–100), enabled? }` → `201`; `400 dictionary_terms_count` / `dictionary_term_invalid` (`index`, never the term); ≤ `DLP_DICTIONARIES_MAX_PER_TENANT`. Audited `dlp_dictionary.created` with the term **count**                                                                                                                                              |
| PATCH  | `/dlp/dictionaries/{id}`                            | `dlp:manage`, K                     | `{ version, …fields }` (`terms` replaces the list). Audited `dlp_dictionary.updated` (counts and `termsChanged`)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| DELETE | `/dlp/dictionaries/{id}`                            | `dlp:manage`, K                     | `?version` → `204`; `409 dlp_dictionary_in_use` while a rule selects it. Audited `dlp_dictionary.deleted`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| GET    | `/dlp/compliance`                                   | `dlp:read`, K                       | `{ aadhaar: { enabled, active, basis, reference, attested, recordedByUserId, recordedAt, reviewDueAt }, version (0 = never recorded), updatedAt }`; `active` = the detector runs                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| PUT    | `/dlp/compliance/aadhaar`                           | `dlp:compliance_manage`, U, MFA     | `{ expectedVersion, basis (regulatory_obligation \| uidai_authorised_entity \| data_protection_policy \| other), reference (1–256), attested: true, reviewDueAt (future, ≤ 365 days) }` → the view. Audited `dlp_compliance.aadhaar_enabled` (`before`, `after`)                                                                                                                                                                                                                                                                                                                                                                     |
| DELETE | `/dlp/compliance/aadhaar`                           | `dlp:compliance_manage`, U, MFA     | `?expectedVersion` → the view; disables detection (idempotent). Audited `dlp_compliance.aadhaar_disabled`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| GET    | `/dlp/incidents`                                    | `dlp:read`, K                       | `?limit&cursor&action&direction&from&to` → results whose action is not `allow`, newest first by received time: `{ data: [{ messageId, scanId, lifecycleRound, receivedAt, direction, verdict, action, actionSource, coverage, findingCount, categories, findings: [{ detector, code, category, severity, count, capped, customPatternId?, dictionaryId? }], policy { winner, matched, exceptionsApplied }, detectedAt }], nextCursor }`; no values, masked samples or evidence                                                                                                                                                       |
| GET    | `/messages/{messageId}/scans/{scanId}/dlp-evidence` | `dlp:evidence_read`, U, MFA, 30/min | The decrypted evidence: `{ messageId, scanId, matchCount, expiresAt, evidence: { format: dlp-evidence/1, textDerivationVersion, extractorVersion, aadhaar, matches: [{ detector, code, source, start, end, value, context { before, after } }], dropped } }` with **`Cache-Control: no-store`**; flow below; `404 message_not_found` / `scan_not_found` / `dlp_evidence_not_found`; `410 evidence_purged` / `evidence_expired`; `500 evidence_unreadable`; `503 evidence_unavailable`                                                                                                                                                |
| DELETE | `/messages/{messageId}/scans/{scanId}/dlp-evidence` | `dlp:manage`, MFA                   | Crypto-shreds the round's evidence, then deletes the object → `204` (idempotent). Audited `dlp_evidence.purged`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      |
| DELETE | `/dlp/evidence`                                     | `dlp:manage`, MFA                   | Every evidence of the organization, in batches of 500 → `202 { purged, objectsDeleted, objectsPending }` after completion. Audited `dlp_evidence.purged` (`scope: organization`, the count)                                                                                                                                                                                                                                                                                                                                                                                                                                          |

**Custom pattern safety (D9).** Patterns use RE2 syntax through `re2js` (linear time, no backtracking). Refusals are a `400` whose `code` names the rule, with `repetitionProduct` and `length` (never the pattern): `pattern_syntax` (empty, longer than `DLP_CUSTOM_PATTERN_MAX_LENGTH`, or not RE2), `pattern_unsupported` (backreferences, lookaround, possessive constructs), `pattern_too_complex` (counted repetition above 100 or a nested product above 1 000), `pattern_matches_empty`, `pattern_too_broad` (more than 50 matches on the packaged probe corpus), `pattern_too_slow` (above `DLP_CUSTOM_PATTERN_PROBE_MAX_MS` on it), `pattern_invalid_options` (validator, keywords, `requireContext` without keywords). The test endpoint answers `200 { valid: false, code }` for the same refusals. `pattern_too_slow` is a write-time check of the api only: the email-worker re-validates stored patterns with the deterministic rules (no timing, compiled once per row version), so an accepted pattern does not become invalid because of the worker's load.

**Evidence access (D16).** The only way to see matched values. (1) A writer transaction checks the message, the round and its evidence row in the caller's organization (another organization's ids are `404`), refuses purged (`410 evidence_purged`) and expired (`410 evidence_expired`) evidence and **commits the audit row `dlp_evidence.read` (actor, message, scan, match count; no content) before anything is fetched**; (2) the object is read from the mail bucket only under `org/<org>/dlp-evidence/`, its SHA-256 and size compared with the row, its data key unwrapped with `DLP_EVIDENCE_KEY` (`DLP_EVIDENCE_KEY_PREVIOUS` during a rotation), the payload decrypted with the row-bound AAD and the document validated; any failure afterwards writes `dlp_evidence.read_failed` with a `reason` only (`object_missing`, `object_size`, `integrity`, `decrypt`, `document_invalid`, `storage_error`, …) and answers `500 evidence_unreadable` (or `503 evidence_unavailable` for object-storage errors). Aadhaar numbers, private keys and secrets are masked even inside evidence; card numbers keep first 6 + last 4; card verification codes are never stored. Never cache, log or forward the response. Purging erases the wrapped data key first (crypto-shredding: the object and any old version of it are undecryptable), then deletes the object; scan results keep their masked findings.

**Aadhaar (D17).** Without an active recorded basis (enabled, attested, basis and reference recorded, `reviewDueAt` in the future) the Aadhaar detector (NI2) does not run at all: no counts, no masked values. A rule selecting NI2 or `national_id` is accepted while Aadhaar is disabled but is inert for NI2. The platform records the attestation; whether the basis is lawful is the organization's decision.

```bash
curl -X POST "$API/api/v1/dlp/policies" -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"name":"Card data outbound","directions":["outbound"]}'
curl -X POST "$API/api/v1/dlp/policies/$POLICY/rules" -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"name":"Cards to external","conditions":{"selectors":{"categories":["payment_card"]},"recipients":{"externalOnly":true}},"action":"quarantine"}'
curl -X POST "$API/api/v1/dlp/patterns/test" -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"pattern":"EMP-[0-9]{6}","contextKeywords":["employee"],"sample":"employee EMP-123456"}'
curl "$API/api/v1/messages/$MESSAGE/scans/$SCAN/dlp-evidence" -H "Authorization: Bearer $MFA_TOKEN"
```

### Risk scoring (`risk-scoring` tag, step 5.1)

The organization's risk scoring profile and the dry-run (design [15-risk-scoring.md](../plan/steps/15-risk-scoring.md) R10, R15; runbook [risk-scoring](../runbooks/risk-scoring.md)). **Step 5.1 recommends and does not enforce** (policy 5.2 decides; only the local/CI development pass-through holds on a recommendation), and the defaults are engineering defaults calibrated on synthetic data, **not validated detection accuracy**. The organization comes from the authenticated scope only (another organization's id → `404`); version ids are public ids (UUIDv7); `{scanId}` is the decimal round id of `GET /messages/{messageId}/scans`. A profile change applies to the **next scan round only** (each round snapshots the active version when it opens). Writes run on the writer under the organization row lock and are audited (`risk_profile.*`); reads come from the replica. K = users and API keys.

| Method | Path                                                       | Access                                | Description                                                                                                                                                                                                                                                       |
| ------ | ---------------------------------------------------------- | ------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| GET    | `/risk-scoring/platform-profile`                           | `policy:read`, K                      | The platform default (`RISK_PLATFORM_PROFILE`): effective profile and SHA-256, versions, override bounds, groups, the signal map and the hard-block catalog                                                                                                       |
| GET    | `/risk-scoring/profile`                                    | `policy:read`, K                      | `{ id, profileVersion, platformProfile, active: { source, versionId, versionNo, profileId, sha256, fallback, violations }, effectiveProfile, counts: { drafts, published, limit } }`                                                                              |
| GET    | `/risk-scoring/profile/versions`, `…/versions/{versionId}` | `policy:read`, K                      | `?limit&cursor&status` newest first; the detail adds `overrides` and `resolved` (resolved now against the platform bounds, with violations)                                                                                                                       |
| POST   | `/risk-scoring/profile/versions`                           | `policy:manage`, K                    | `{ overrides?, changeNote?, basedOnVersionId? }` → `201` draft. `400 risk_profile_invalid` (`violations: [{ path, message }]`), `409 risk_profile_limit_reached` (`RISK_PROFILE_MAX_VERSIONS`)                                                                    |
| PUT    | `/risk-scoring/profile/versions/{versionId}`               | `policy:manage`, K                    | `{ overrides, changeNote?, expectedRowVersion }` (drafts only): `409 risk_profile_version_conflict`, `409 risk_profile_version_immutable` for a published version                                                                                                 |
| DELETE | `/risk-scoring/profile/versions/{versionId}`               | `policy:manage`, K                    | `?expectedRowVersion` → `204` (drafts only; `409 risk_profile_version_immutable`)                                                                                                                                                                                 |
| POST   | `/risk-scoring/profile/versions/{versionId}/publish`       | `policy:publish`, K                   | `{ activate (default true), expectedRowVersion }` → `{ version, profile }`; re-validated; the version becomes immutable                                                                                                                                           |
| POST   | `/risk-scoring/profile/versions/{versionId}/activate`      | `policy:publish`, K                   | `{ expectedProfileVersion? }`: make a published version active (rollback); `409 risk_profile_version_not_published`                                                                                                                                               |
| POST   | `/risk-scoring/profile/reset`                              | `policy:publish`, K                   | `{ expectedProfileVersion? }`: back to the platform default                                                                                                                                                                                                       |
| POST   | `/messages/{messageId}/scans/{scanId}/risk/dry-run`        | `policy:manage` and `message:read`, K | `{ profile: 'active' \| 'platform' \| { versionId } \| { overrides }, revision? (0 \| 1) }` → `{ result, stored, reproducible }`; replica; **writes nothing**. `409 scan_round_not_complete` while running or not yet replicated; `409 risk_revision_unavailable` |

### Policies (`policies` tag, step 5.2)

Tenant policies, versions, settings, tests, dry-runs and the execution history (design [16-policy-engine.md](../plan/steps/16-policy-engine.md) P11, P12, P16, P17, P22, P23; DSL reference [policy-dsl.md](../architecture/policy-dsl.md); [ADR-0043](../architecture/adr/0043-policy-dsl-and-deterministic-evaluator.md), [ADR-0045](../architecture/adr/0045-policy-action-semantics.md)). **Step 5.2 enforces** the final disposition (ALLOW delivers, QUARANTINE holds in `quarantined`, REQUIRE_APPROVAL holds in `held_for_review`, REJECT rejects) and the strictness floor; it **requests** ARCHIVE (step 8.1 consumes it), ALERT and sender non-delivery notices (notification-worker); WARN body banners are **recorded** only in 5.2; from step 5.3 (ADR-0049) the policy-engine applies WARN banners and URL_REWRITE to the delivered copy when the message allows it (`skipped_*` recorded otherwise), evaluates per recipient when rules are recipient-scoped (`recipientSplit`), and the quarantine store with release re-validation is the [Quarantine](#quarantine-quarantine-tag-step-53) API. The organization comes from the authenticated scope only (another organization's id → `404`). Writes run on the writer under the organization's `policy_settings` row lock and are audited (`policy.*`); reads come from the replica. A change that affects evaluation (activation, rollback, enable, disable, delete of an active policy, settings) increments the organization's **generation** exactly once and applies to the **next evaluation** only; a change that changes nothing writes nothing. K = users and API keys.

| Method    | Path                                                      | Permission                            | Notes                                                                                                                                                                                                                                                                                                                                                                               |
| --------- | --------------------------------------------------------- | ------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| GET       | `/policies/catalog`                                       | `policy:read`, K                      | DSL/input/evaluator versions, every field (type, scope, operators, identity and AI flags, vocabulary), operators, actions, dispositions, limits with this deployment's bounds, settings defaults, platform default                                                                                                                                                                  |
| GET       | `/policies`                                               | `policy:read`, K                      | `?limit&cursor&status&direction` newest first (archived policies are never listed) → `{ data, nextCursor, generation }`                                                                                                                                                                                                                                                             |
| POST      | `/policies`                                               | `policy:manage`, K                    | `{ name ≤ 128, description?, definition, changeNote? }` → `201 { policy, version }` (policy `draft`, version 1 `draft`). `400 policy_definition_invalid` (`violations: [{ path, code, message }]`), `409 policy_name_taken` (archived names too), `409 policy_limit_reached` (`POLICY_MAX_POLICIES`)                                                                                |
| GET       | `/policies/{policyId}`                                    | `policy:read`, K                      | policy, active version (number, hash, rule count, override flag), newest version number, counts                                                                                                                                                                                                                                                                                     |
| PATCH     | `/policies/{policyId}`                                    | `policy:manage`, K                    | `{ name?, description?, expectedRowVersion }`: `409 policy_conflict` (`currentRowVersion`), `409 policy_name_taken`; no generation change                                                                                                                                                                                                                                           |
| POST      | `/policies/{policyId}/disable`, `…/enable`                | `policy:publish`, K                   | `{ expectedRowVersion? }`; `generation++` when it changes; enable: `409 policy_no_active_version`, `409 policy_rule_limit_reached`                                                                                                                                                                                                                                                  |
| DELETE    | `/policies/{policyId}`                                    | `policy:publish`, K                   | `?expectedRowVersion` → `204`; soft delete (`archived`; versions and name kept); `generation++` if it was active                                                                                                                                                                                                                                                                    |
| GET       | `/policies/{policyId}/versions`, `…/versions/{versionNo}` | `policy:read`, K                      | `?limit&cursor&status` newest first; the detail adds `definition` and `validation` (validated now: violations if the DSL moved)                                                                                                                                                                                                                                                     |
| POST      | `/policies/{policyId}/versions`                           | `policy:manage`, K                    | `{ definition? \| basedOnVersionNo?, changeNote? }` → `201` draft numbered MAX + 1; `409 policy_version_limit_reached` (`POLICY_MAX_VERSIONS_PER_POLICY`)                                                                                                                                                                                                                           |
| PUT       | `/policies/{policyId}/versions/{versionNo}`               | `policy:manage`, K                    | `{ definition, changeNote?, expectedRowVersion }` (drafts only): `409 policy_conflict`, `409 policy_version_immutable`                                                                                                                                                                                                                                                              |
| DELETE    | `/policies/{policyId}/versions/{versionNo}`               | `policy:manage`, K                    | `?expectedRowVersion` → `204` (drafts only)                                                                                                                                                                                                                                                                                                                                         |
| POST      | `/policies/{policyId}/versions/{versionNo}/publish`       | `policy:publish`, K                   | `{ expectedRowVersion, activate (default true) }` → `{ version, policy, generation }`; re-validated (DSL and directory references: `department_unknown`, `user_unknown`), stores hash, references, rule count, override flag; immutable afterwards; activation checks `POLICY_MAX_ACTIVE_RULES` (`409 policy_rule_limit_reached`); publish and activation commit together           |
| POST      | `/policies/{policyId}/versions/{versionNo}/activate`      | `policy:publish`, K                   | `{ expectedRowVersion? }`: rollback / roll forward to a published version (`409 policy_version_not_published`); no-op when already active                                                                                                                                                                                                                                           |
| GET / PUT | `/policy-settings`                                        | `policy:read` / `policy:publish`, K   | P11 settings `{ settings, effective, violations, generation, rowVersion, settingsSha256, … }`; PUT `{ settings, expectedRowVersion }` (0 before the first change): `400 policy_settings_invalid`, `409 policy_conflict`; `generation++`                                                                                                                                             |
| POST      | `/policies/test`                                          | `policy:manage`, K                    | `{ target: 'active' \| 'platform' \| { policyId, versionNo } \| { definition }, facts }` (synthetic facts, P23; `resolveDirectory: true` resolves memberships) → `{ result, recipientSplit, recipientDecisions, lifecycleDisposition, invalidVersions }` (step 5.3 Q4: per-recipient evaluation); **writes nothing**; `400 policy_definition_invalid` / `policy_test_facts_invalid` |
| GET       | `/policies/executions`                                    | `policy:read`, K                      | `?from&to` (required, ≤ `POLICY_HISTORY_MAX_RANGE_DAYS`), `direction`, `disposition`, `source`, `policyId`, `ruleId`, `overrideApplied`, `trigger`, `limit`, `cursor` (by `(receivedAt, id)`) → rows of ids, enums, action statuses, counts and hashes                                                                                                                              |
| POST      | `/messages/{messageId}/scans/{scanId}/policy/dry-run`     | `policy:manage` and `message:read`, K | `{ target }` → `{ result, recipientSplit, recipientDecisions, lifecycleDisposition, invalidVersions, stored, reproducible }` (per-recipient evaluation, step 5.3 Q4); the stored round's rows and directory from the replica; **writes nothing**; `409 scan_round_not_complete`, `409 policy_input_invalid`                                                                         |
| GET       | `/messages/{messageId}/policy-evaluations`                | `message:read`, K                     | every stored evaluation of the message, newest round first                                                                                                                                                                                                                                                                                                                          |

Errors: `503 inconsistent_read` on any write (an echo-checked writer read returned another row twice).

### Departments (`departments` tag, step 5.2)

The tenant directory policies reference (`sender.department`, `recipient.department`; design P5). Membership is live data: a change applies to the next evaluation without a publish (the resolved memberships are part of the hashed evaluation input, so a dry-run then reports `reproducible: false`). Writes are audited (`department.*`, ids only) under the same `policy_settings` lock as activation.

| Method               | Path                                             | Permission                     | Notes                                                                                                                                                                                                                                                                                                    |
| -------------------- | ------------------------------------------------ | ------------------------------ | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| GET / POST           | `/departments`                                   | `user:read` / `user:manage`, K | `{ name ≤ 128, description? }`; `409 department_name_taken`, `409 department_limit_reached` (`DEPARTMENT_MAX_PER_ORG`)                                                                                                                                                                                   |
| GET / PATCH / DELETE | `/departments/{departmentId}`                    | `user:read` / `user:manage`, K | PATCH `{ name?, description?, expectedRowVersion }` (`409 department_conflict`); DELETE (members too) refused while an active version of an active policy references it (`409 department_in_use`, `policies: [{ policyId }]`)                                                                            |
| GET / POST           | `/departments/{departmentId}/members`            | `user:read` / `user:manage`, K | exactly one of `{ address }` (normalized; must be in an active domain of the organization: `400 member_address_not_tenant`) or `{ userId }` (a user of the organization: `400 member_user_not_tenant`); `409 department_member_exists`, `409 department_member_limit_reached` (`DEPARTMENT_MAX_MEMBERS`) |
| DELETE               | `/departments/{departmentId}/members/{memberId}` | `user:manage`, K               | `404 department_member_not_found`                                                                                                                                                                                                                                                                        |

### Quarantine (`quarantine` tag, step 5.3)

Per-recipient quarantine entries, their sanitized preview, the download door, release with re-validation, approvals, end-user self-service, reject, delete, manual quarantine, bulk actions and settings (design [17-quarantine.md](../plan/steps/17-quarantine.md) Q7, Q9–Q18, Q21, Q24, Q26, Q30; [ADR-0046](../architecture/adr/0046-quarantine-store-and-per-recipient-decisions.md)–[ADR-0048](../architecture/adr/0048-quarantine-preview-and-download-controls.md)). Entries are created by the policy-engine (QUARANTINE / REQUIRE_APPROVAL dispositions, one per recipient) and by manual quarantine; releases are queued here and **executed by the policy-engine's release executor**, which re-validates authoritatively (a queued release can still end `approval_required`, `rescan_required`, `refused` or `message_busy`: `GET /quarantine/releases/{releaseId}`). The organization comes from the authenticated scope only: another organization's entry, approval or release is `404`, and on the `/me` routes another address's entry is `404`. Responses carry ids, enums, counts, addresses already stored by earlier steps and (only for `quarantine:preview` holders and on self routes) the sanitized subject: never bodies, attachments or URLs, and never an S3 URL. Every mutation takes an `Idempotency-Key` (except `PUT /settings` and `PUT /me/preferences`, idempotent by `rowVersion` / value, and download grants, which are single-use by design) and runs in one writer transaction (`QUARANTINE_TX_TIMEOUT_MS`, message lock → entry lock → request lock, compare-and-set on `rowVersion`; a twice-inconsistent read is `503 inconsistent_read`). Searches and views read the replica (an entry just created may be missing for the replication lag). U = users only, K = users and API keys, MFA = an MFA-authenticated session.

| Method   | Path                                                       | Permission / guards                                                                      | Notes                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| -------- | ---------------------------------------------------------- | ---------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| GET      | `/quarantine/catalog`                                      | `quarantine:read` or `quarantine:self`, K                                                | enums, error codes with status, platform limits, effective self-service switches, `downloadEnabled`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| GET      | `/quarantine/summary`                                      | `quarantine:read`, K                                                                     | `?from&to` (required, ≤ `QUARANTINE_SEARCH_MAX_RANGE_DAYS`) → `{ counts by state, pendingApprovals }`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| GET      | `/quarantine/entries`                                      | `quarantine:read`, K                                                                     | `?from&to` (required, bounded) `&state&kind&direction&reason&riskLevel\|minRiskLevel&primaryEngine&policyId&ruleId&sender&headerFrom&senderDomain&recipient&hasAttachments&hasHardBlock&messageId&limit&cursor` → `{ items: QuarantineEntrySummary[], nextCursor }` newest `quarantinedAt` first (keyset; the cursor is bound to the filters: `400 quarantine_cursor_invalid`); no free-text or subject search; `Cache-Control: no-store`; audited `quarantine.searched` (filter hash and count only)                                                                                                       |
| POST     | `/quarantine/entries`                                      | `quarantine:manage`, K                                                                   | manual quarantine `{ messageId, rcptSeqs?, reason }` → `201 { messageId, entries, messageTransition: E16 \| E29 }`: pending review entries of a `held_for_review` message become `held` (E16 when none remains); a policy-rejected message (`policy_reject`/`policy_discard`, within `QUARANTINE_MANUAL_FROM_REJECT_MAX_DAYS`, EML present) → E29 and new `manual` entries; `409 quarantine_manual_not_allowed` (`cause`), any other state `409 quarantine_state_conflict`                                                                                                                                  |
| GET      | `/quarantine/entries/{entryId}`                            | `quarantine:read`, K                                                                     | `QuarantineEntryDetail` (explanation, floor reasons, reason codes, releases, `allowedActions` for the caller, `contentAvailable`); `no-store`; writes a `view` action + `quarantine.entry_viewed`                                                                                                                                                                                                                                                                                                                                                                                                           |
| GET      | `/quarantine/entries/{entryId}/history`                    | `quarantine:read`, K                                                                     | `{ actions: [{ action, actor, result, reason, at }], releases }` (operator reasons; system actions without)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 |
| GET      | `/quarantine/entries/{entryId}/preview`                    | `quarantine:preview`, K, `QUARANTINE_PREVIEW_RATE_PER_MINUTE`                            | sanitized JSON text (`preview/1`: headers, body text from the decoded part read with a bounded Range GET, defanged non-clickable links, attachments with verdicts and `downloadable`, DLP masking counts); `no-store`; audit `quarantine.previewed` committed before reading; `410 quarantine_content_purged`                                                                                                                                                                                                                                                                                               |
| POST     | `/quarantine/entries/{entryId}/download-grants`            | `quarantine:download`, U, MFA, `QUARANTINE_DOWNLOAD_GRANTS_PER_HOUR`                     | `{ object: eml \| attachment, partIndex?, password, totpCode? }` → `201 { token, expiresAt, filename, sizeBytes, sha256 }`; `403 quarantine_download_disabled` (tenant `download.enabled` off, the default), `401 quarantine_reauth_failed` (counts toward the login lockout), `409 quarantine_download_blocked` (`reason`: hard block, malware/phishing verdict, attachment not clean, malicious URL)                                                                                                                                                                                                      |
| GET      | `/quarantine/downloads/{token}`                            | `quarantine:download`, U, rate                                                           | the bytes once, by the granted user (`404 quarantine_download_token_invalid`, `410 quarantine_download_token_used`), gating re-run, headers `Content-Type: application/octet-stream`, `Content-Disposition: attachment; filename="<name>.eml.bin\|.bin"`, `X-Content-Type-Options: nosniff`, `Cache-Control: no-store`, `Content-Security-Policy: sandbox; default-src 'none'`                                                                                                                                                                                                                              |
| POST     | `/quarantine/entries/{entryId}/release`                    | `quarantine:release`, K                                                                  | `{ reason, expectedRowVersion? }` (entry `held`) → `202 { outcome: queued, releaseId }` or `202 { outcome: approval_requested, approvalRequestId, approvalReasons }`; `409 quarantine_rescan_required` (`staleness`: rescan with `POST /messages/{messageId}/rescan`), `409 quarantine_hard_block_release_disabled`; refusals audited `quarantine.release_refused`                                                                                                                                                                                                                                          |
| POST     | `/quarantine/entries/{entryId}/request-release`            | `quarantine:request_release`, K                                                          | `{ reason }` → `202 approval_requested` (`release_request`, approvers notified)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| POST     | `/quarantine/entries/{entryId}/reject`                     | `quarantine:reject`, K                                                                   | `{ reason, notifySender?, expectedRowVersion? }` → `{ entryId, state: rejected, rowVersion, messageTransition: E17 \| E18 \| null, purge }`; sender notice only for outbound/internal entries                                                                                                                                                                                                                                                                                                                                                                                                               |
| POST     | `/quarantine/entries/{entryId}/delete`                     | `quarantine:delete`, K                                                                   | `{ reason, expectedRowVersion? }` → `{ …, state: deleted, purge: pending \| retained }`; `409 quarantine_legal_hold` (`legalHoldId`), `409 quarantine_retention_active` (`retainUntil`); refusals audited `quarantine.delete_refused`                                                                                                                                                                                                                                                                                                                                                                       |
| GET      | `/quarantine/releases/{releaseId}`                         | `quarantine:read`, K                                                                     | `QuarantineReleaseView` + `entryIds` (`pending` until the executor ran)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| GET      | `/quarantine/approvals`, `/quarantine/approvals/{id}`      | `quarantine:read`, K                                                                     | `?status&kind&from&to&limit&cursor` newest first → `{ items: QuarantineApprovalView[], nextCursor }`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        |
| POST     | `/quarantine/approvals/{id}/approve`, `…/deny`             | `quarantine:approve`, U, MFA                                                             | `{ reason }`; never the requester, never the entry's recipient (user or verified address) (`403 quarantine_approval_forbidden`, `reason`); `409 quarantine_approval_not_pending`; approve → `202 { status: approved, entryState: releasing, releaseId }`; deny of a `policy_review` rejects the entry (E17/E18 rule), other kinds return it to `held`                                                                                                                                                                                                                                                       |
| POST     | `/quarantine/approvals/{id}/cancel`                        | requester (`quarantine:release`, `:request_release`, `:self`) or `quarantine:approve`, K | `{ reason }` → entry `held`; a `policy_review` cannot be cancelled (`409`)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| POST     | `/quarantine/bulk`                                         | the action's permission (approve/deny: U + MFA), `QUARANTINE_BULK_REQUESTS_PER_MINUTE`   | `{ action: release \| reject \| delete \| approve \| deny, ids, reason, notifySender? }`; `400 quarantine_bulk_limit` (`cause`, `maxItems`), `429 quarantine_bulk_rate_limited` (`Retry-After`; `QUARANTINE_BULK_MAX_ITEMS_PER_MINUTE` items per organization and minute); `200 { action, results: [{ id, status: queued \| approval_requested \| done \| refused \| not_found \| skipped, code?, releaseId?, approvalRequestId? }], counts }`, each item through the single-item operation in its own transaction until `QUARANTINE_BULK_DEADLINE_MS`; the whole response stored under the Idempotency-Key |
| GET, PUT | `/quarantine/settings`                                     | `quarantine:read` / `settings:manage`, K                                                 | `{ effective, raw, invalidStored, bounds, rowVersion }`; PUT `{ settings, expectedRowVersion }` (0 creates): `400 quarantine_settings_invalid` (`violations: [{ path, code, message }]`), `409 quarantine_settings_conflict`; audited `quarantine.settings_updated` (changed paths)                                                                                                                                                                                                                                                                                                                         |
| GET      | `/quarantine/me/entries`, `/quarantine/me/entries/{id}`    | `quarantine:self`, U                                                                     | the caller's own address only (verified email), search subset `?from&to&state&reason&limit&cursor`; empty when `endUser.enabled` is off                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| GET      | `/quarantine/me/entries/{id}/preview`                      | `quarantine:self`, U, rate                                                               | when `endUser.preview` and the entry has no hard block and is not malware/phishing (`403 quarantine_preview_not_allowed`)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| POST     | `/quarantine/me/entries/{id}/release`, `…/request-release` | `quarantine:self`, U                                                                     | self-release within `endUser.selfRelease`, `selfReleaseReasons`, `selfReleaseMaxLevel`, no approval reason, fresh verdicts (`403 quarantine_self_release_not_allowed`, `cause`); request when `endUser.requestRelease`                                                                                                                                                                                                                                                                                                                                                                                      |
| GET, PUT | `/quarantine/me/preferences`                               | `quarantine:self`, U                                                                     | `{ digestOptOut }`; opting out needs `digest.allowOptOut`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |

**Audit actions** (`audit_logs.action`, ids/enums/counts/hashes only; the operator's reason is in `quarantine_actions.reason`, shown by `…/history`): `quarantine.searched`, `.entry_viewed`, `.previewed`, `.preview_failed`, `.download_granted`, `.downloaded`, `.download_refused`, `.release_requested`, `.release_refused`, `.self_released`, `.rejected`, `.deleted`, `.delete_refused`, `.manual_quarantined`, `.approval_requested`, `.approval_approved`, `.approval_denied`, `.approval_cancelled`, `.bulk`, `.settings_updated`, `.preferences_updated`.

**Error codes** (`GET /quarantine/catalog` lists them with their status): `quarantine_entry_not_found` 404, `quarantine_approval_not_found` 404, `quarantine_release_not_found` 404, `quarantine_state_conflict` 409, `quarantine_version_conflict` 409, `quarantine_message_busy` 409, `quarantine_rescan_required` 409, `quarantine_approval_not_pending` 409, `quarantine_approval_forbidden` 403, `quarantine_self_release_not_allowed` 403, `quarantine_preview_not_allowed` 403, `quarantine_preview_unavailable` 409, `quarantine_content_purged` 410, `quarantine_legal_hold` 409, `quarantine_retention_active` 409, `quarantine_download_disabled` 403, `quarantine_download_blocked` 409, `quarantine_reauth_failed` 401, `quarantine_download_token_invalid` 404, `quarantine_download_token_used` 410, `quarantine_bulk_limit` 400, `quarantine_bulk_rate_limited` 429, `quarantine_cursor_invalid` 400, `quarantine_search_range_invalid` 400, `quarantine_settings_invalid` 400, `quarantine_settings_conflict` 409, `quarantine_hard_block_release_disabled` 409, `quarantine_manual_not_allowed` 409, `inconsistent_read` 503.

```bash
# Search held phishing entries of the last week, then release one (Idempotency-Key required).
curl "$API/api/v1/quarantine/entries?from=2026-11-05T00:00:00Z&to=2026-11-12T00:00:00Z&state=held&reason=phishing" \
  -H "Authorization: Bearer $TOKEN"
curl -X POST "$API/api/v1/quarantine/entries/$ENTRY_ID/release" -H "Authorization: Bearer $TOKEN" \
  -H "Idempotency-Key: release-$ENTRY_ID-1" -H 'Content-Type: application/json' \
  -d '{"reason":"false positive confirmed by the security team"}'
# → 202 {"outcome":"approval_requested","entryId":"…","state":"pending_approval",
#        "approvalRequestId":"…","approvalReasons":["hard_block"],"rowVersion":2}
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

### Platform threat indicators (`platform` tag, step 4.3)

The platform-wide catalog of malicious URLs, domains and IP addresses (platform rows of `threat_indicators`, `organization_id` NULL; design [11-url-protection.md](../plan/steps/11-url-protection.md) U6, U16). The URL engine's `local_feed` provider and the click-service consult it on **every scan and every click, never cached**, so a change applies to the next scan and the next click of every organization: `high`/`critical` → `malicious` (`url.feed_malicious`, rule M1, never overridden by a tenant allow list), `low`/`medium` → `suspicious` (`url.feed_suspicious`). A `domain` indicator matches the host and every subdomain down to the registrable domain; a `url` indicator matches the URL's identity form exactly; an `ip` indicator a literal IP host (and literal IP hops of a redirect chain). Permission **`platform:threat_intel_manage`** (the step 4.2 permission, role `platform_admin`; no new permission), user sessions with MFA, never API keys or override tokens; 60 calls per caller per minute; writes on the writer with their audit row in the same transaction.

| Method | Path                                       | Access                                 | Description                                                                                                                                                                                                                                                                                                                                                                                 |
| ------ | ------------------------------------------ | -------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| GET    | `/platform/threat-indicators`              | `platform:threat_intel_manage`, U, MFA | `?limit&cursor&type (url \| domain \| ip)&source (analyst \| feed:<name>)&value` (normalized like a new indicator; requires `type`) → `{ data: [{ id, type, value, valueSha256, severity, category, source, reason, expiresAt, addedByUserId, firstSeenAt, lastSeenAt, createdAt, updatedAt }], nextCursor }`, newest first (replica)                                                       |
| POST   | `/platform/threat-indicators`              | `platform:threat_intel_manage`, U, MFA | `{ type (url \| domain \| ip), value, severity (low \| medium \| high \| critical), category (phishing \| malware \| spam \| scam \| c2 \| other), reason (1–512), expiresAt? (future) }` → `201` the indicator (`source: analyst`, the caller as `addedByUserId`, confidence 100, first/last seen now); `409 indicator_exists` with the existing `id`. Audited as `threat_indicator.added` |
| DELETE | `/platform/threat-indicators/{id}?reason=` | `platform:threat_intel_manage`, U, MFA | `204`; `404 threat_indicator_not_found` (also for a tenant-scoped or non-URL row). Hard delete; audited as `threat_indicator.removed` with `metadata: { reason, before }`                                                                                                                                                                                                                   |

**Normalization** (`@email-gateway/url-security` `normalizeIndicator`; the response shows the stored `value`, `valueSha256` is its SHA-256): `url` → the identity form (WHATWG parse, lower-case scheme and host, IDN as A-labels, default port removed, dot segments resolved, **no userinfo, no fragment**; http(s) only; longer than 2 048 characters after normalization is refused); `domain` → lower-case ASCII host (A-labels, trailing dots removed), at least two labels, **never a public suffix** (`co.uk`, `github.io`) and never an IP literal; `ip` → canonical text (dotted IPv4, RFC 5952 IPv6). A value that does not normalize is `400` (`value: …`). Values are never logged (hash prefix only).

```bash
curl -X POST "$API/api/v1/platform/threat-indicators" -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"type":"domain","value":"Login.Evil-Example.test","severity":"high","category":"phishing","reason":"campaign 2026-11"}'
# → 201 {"id":"41","type":"domain","value":"login.evil-example.test","valueSha256":"…","source":"analyst",…}
```

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

**What a replay does.** One replay runs at a time platform-wide (Redis lock `dlq:replay:lock`, 5 minutes; otherwise `409 replay_in_progress`). The api fetches dead letters one by one with manual acks and **holds** them until `limit` matched, the queue is empty or `DEAD_LETTER_REPLAY_SCAN_MAX` (default 10 000) were scanned. A message matches when its source queue (`x-eg-source-queue`, or the broker's `x-first-death-queue` for a delivery-limit dead letter) equals `sourceQueue` and every given filter matches (`eventType`; `organizationId`; `failureReason` = `x-eg-failure-reason` or the broker reason such as `delivery_limit`). Each match is decoded against the event registry (schema version, payload schema, tenant agreement of header, routing key and envelope) and passes the content guard; an invalid one stays in the queue (`skipped.invalid`). A valid one is republished **unchanged** (same body, `messageId` = `eventId`, `correlationId`, type, timestamp, appId) to `retry.<sourceQueue>.org.<id>.<eventType>` on the source queue's home exchange with fresh headers (the base headers, `x-eg-attempt: 0`, `x-eg-transient-retries: 0`, `x-eg-replay-id`, `x-eg-replay-count` + 1, `x-eg-replayed-at`; no failure or `x-death` headers), and the dead letter is acked **only after the broker confirmed the copy**. Everything not replayed is returned to the queue at the end (also on a dry run and on errors). `sourceQueue` must be a work queue (`email.received`, `email.delivery.pending`, since step 4.1 `scan.spam`, since step 4.2 `scan.attachment`, since step 4.3 `scan.url`, `scan.url.inspect`, `scan.url.results`); a dormant, delay or dead-letter queue is `400` with `sourceQueue: source_queue_not_replayable`. An unknown `organizationId` is `404`.

**Safety.** A replayed event keeps its `eventId`: a consumer that already processed it records a ledger duplicate (`processOnce`), so replaying twice is harmless. A crash between the confirm and the ack leaves a copy in both queues, which is again a duplicate. Replay is cross-tenant by nature; the organization filter narrows it.

**Audit.** Every replay writes one `audit_logs` row (`action: platform.dead_letters_replayed`, `resource_type: queue`, `resource_id: <sourceQueue>`, the platform user as actor) with `metadata: { replayId, dryRun, filters, scanned, matched, replayed, skipped, reason, outcome, eventIds (≤ 100) }`, also when nothing matched. When the broker fails half-way the row says `outcome: partial` and the request answers `503 dead_letter_replay_unavailable`; what was replayed before stays replayed, the rest is back in the queue.

### Messages (`messages` tag, step 6.1)

The message metadata of your organization, from the read replica (a few seconds behind the writer). Subjects, addresses and filenames are attacker-controlled text returned as JSON strings; bodies, attachment content and the S3 object keys are never returned (content is reachable only through the step 5.3 quarantine preview and download grants). Every list follows the [list contract](#pagination-and-lists) with signed v1 cursors.

| Method | Path                               | Permission        | Notes                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| ------ | ---------------------------------- | ----------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| GET    | `/messages`                        | `message:read`, K | `from`/`to` (default the last 24 h, at most `API_MESSAGES_MAX_RANGE_DAYS`, 31), `sort=-receivedAt` (default) or `receivedAt`; filters `direction`, `status`, `verdict`, `action` (comma lists, ≤ 5), `domainId`, `sender` (exact envelope sender), `headerFrom`, `recipient`, `internetMessageId` (exact), `riskScore` / `riskScore.gte\|lte\|gt\|lt` (0–1000), `hasAttachments`. Item: id, `receivedAt`, direction, status, subject, senders, counts, size, final verdict/action, risk score, domain id |
| GET    | `/messages/{messageId}`            | `message:read`, K | The list fields plus `internetMessageId`, `lifecycleRound`, `version` (the token of rescan/release), `statusReason`, `clientIp`, `clientHelo`, `mtaQueueId`. `404 message_not_found`. Not audited (metadata behind `message:read`)                                                                                                                                                                                                                                                                       |
| GET    | `/messages/{messageId}/recipients` | `message:read`, K | RCPT order (`rcptSeq`): address, status, final action, direction, matched user, latest delivery `{ status, finalSmtpCode, deliveredAt }` or null                                                                                                                                                                                                                                                                                                                                                         |

How the list is read: no filter besides the range and sort → the `(organization_id, received_at, id)` index; exactly one `verdict` → `(organization_id, final_verdict, received_at, id)`; only `recipient` → the recipient index; any other filter or combination is scan-bounded (at most `API_LIST_SCAN_BUDGET_ROWS` index entries per request, short pages possible). A search with `sender`, `headerFrom`, `recipient` or `internetMessageId` is audited (`message.searched`, first page only, values as SHA-256).

```bash
# Phishing messages of the last 7 days, newest first; then the next page with the same filters.
curl -s "$API/api/v1/messages?verdict=phishing&from=2026-11-05T00:00:00Z&to=2026-11-12T00:00:00Z&limit=50" \
  -H "Authorization: Bearer $TOKEN"
# → {"data":[{"id":"0192…","receivedAt":"2026-11-11T09:14:03.120Z","direction":"inbound",…}],"nextCursor":"eyJ2Ijox….Qm9…"}
curl -s "$API/api/v1/messages?verdict=phishing&from=2026-11-05T00:00:00Z&to=2026-11-12T00:00:00Z&limit=50&cursor=$NEXT" \
  -H "Authorization: Bearer $TOKEN"
```

### Attachments and URLs (`attachments`, `url-protection` tags, step 6.1)

| Method | Path                                | Permission        | Notes                                                                                                                                                                                                                                                                                                                                                                                           |
| ------ | ----------------------------------- | ----------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| GET    | `/messages/{messageId}/attachments` | `message:read`, K | Part order (`partIndex`): sanitized filename, declared/detected type, size, SHA-256, disposition, depth and the latest round's result as in `GET …/scans` (verdict, reason codes, ClamAV signature, YARA rules, archive inspection, known-hash hit). Never content, original filenames or archive entry names; no download                                                                      |
| GET    | `/attachments?sha256=`              | `message:read`, K | Required 64-hex `sha256`, range (default 24 h, ≤ 31 days); every attachment of your organization with that hash: message id, `receivedAt`, part index, filename, size, detected type, verdict. Read in index order (`(organization_id, sha256, received_at, id)`), so a page costs about `limit` rows however common the hash; no short pages. Class `expensive`; audited `attachment.searched` |
| GET    | `/messages/{messageId}/urls`        | `message:read`, K | URL order (`urlSeq`): normalized URL fields of the tenant URL view (never cache outcomes), the latest verdict and reason codes, rewrite status of the latest round, click counts by decision                                                                                                                                                                                                    |
| GET    | `/url-protection/clicks`            | `message:read`, K | Time-of-click events (`(clickedAt, id)` keyset; range default 24 h, ≤ 31 days); filters `decision`, `verdict` (comma lists), `messageId` (one of your messages, else `404 message_not_found`); item: click id, time, decision, verdict, reason codes, message id, URL sequence, host, registrable domain, client network. Never token material                                                  |

```bash
curl -s "$API/api/v1/attachments?sha256=$(sha256sum invoice.pdf | cut -d' ' -f1)&from=2026-11-01T00:00:00Z" \
  -H "X-API-Key: $API_KEY"
```

### Recipient suppressions (`recipients` tag, step 6.1)

The addresses outbound mail of your organization is not delivered to (`delivery_suppressions`, enforced by the smtp-adapter since step 2.2: hard bounces, complaints, and manual or unsubscribe entries created here).

| Method | Path                                       | Permission                       | Notes                                                                                                                                                                                                                                                                                                                     |
| ------ | ------------------------------------------ | -------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| GET    | `/recipients/suppressions`                 | `delivery:read`, K               | Newest first (`id`); filters `address` (exact, the unique key), `reason`, `active` (scan-bounded)                                                                                                                                                                                                                         |
| GET    | `/recipients/suppressions/{suppressionId}` | `delivery:read`, K               | Decimal id; `404 suppression_not_found` (also right after a create, until the replica has it)                                                                                                                                                                                                                             |
| POST   | `/recipients/suppressions`                 | `delivery:suppression_manage`, K | **Idempotency-Key required** (transactional), class `sensitive`. `{ address, reason?: manual \| unsubscribe, expiresAt? (≤ 3650 days) }` → `201`. `409 suppression_exists` (with `id`), `409 suppression_limit_reached` (`RECIPIENT_SUPPRESSIONS_MAX_MANUAL`). Audit `recipient_suppression.created` (address as SHA-256) |
| DELETE | `/recipients/suppressions/{suppressionId}` | `delivery:suppression_manage`, K | **Idempotency-Key required**, `sensitive`. Removes any entry, including bounces and complaints (unsuppress) → `204`; a replay answers `204` again. Audit `recipient_suppression.deleted` with the former reason and source                                                                                                |

```bash
curl -s -X POST "$API/api/v1/recipients/suppressions" -H "Authorization: Bearer $TOKEN" \
  -H "Idempotency-Key: suppress-2026-11-12-0001" -H 'Content-Type: application/json' \
  -d '{"address":"former.customer@example.org","reason":"unsubscribe"}'
# → 201 {"id":"4711","address":"former.customer@example.org","reason":"unsubscribe","source":"api","active":true,…}
```

### Audit logs (`audit`, `platform` tags, step 6.1)

| Method | Path                   | Permission                                   | Notes                                                                                                                                                                                                                                                                                                                                                                                                                                                      |
| ------ | ---------------------- | -------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| GET    | `/audit/logs`          | `audit:read`, K                              | Your organization's `audit_logs` (mutations, audited reads, override requests into it). Range default 7 days, at most `API_AUDIT_MAX_RANGE_DAYS` (90); `sort=-createdAt\|createdAt`; filters `action` or `actionPrefix` (`[a-z_]+.`), `resourceType`, `resourceId`, `actorType`, `actorId` (scan-bounded; exact and case-sensitive: `resourceId=0192ABC…` does not match the stored lower-case id). Each search's first page is audited (`audit.searched`) |
| GET    | `/platform/audit/logs` | `platform:operations` + `audit:read`, U, MFA | Platform organization users only (API keys, override sessions and customer users are refused). Exactly one target: `organizationId` (`404 organization_not_found` when unknown) or `scope=platform` (rows without an organization). Audited `platform.audit_searched` in the searched trail                                                                                                                                                                |

Items: `id`, `createdAt`, `actor { type, id }`, `action`, `resourceType`, `resourceId`, `correlationId`, `sourceIp`, `metadata` (already scrubbed of credential-like keys when written).

```bash
curl -s "$API/api/v1/audit/logs?actionPrefix=quarantine.&from=2026-11-01T00:00:00Z" -H "Authorization: Bearer $TOKEN"
```

### Reports (`reports` tag, step 6.1)

Computed on the read replica from recorded rows (no estimates, no rollup tables) over a bounded UTC window aligned to bucket boundaries; every bucket is listed (empty ones with zeros); cached per organization and normalized query for `REPORTS_CACHE_TTL_SECONDS` (`generatedAt` shows when). Class `expensive`. A query stopped by `REPORTS_QUERY_TIMEOUT_MS` (`MAX_EXECUTION_TIME`) is `503 report_timeout`: narrow the range.

| Method | Path                   | Permission       | Notes                                                                                                                                                                                                           |
| ------ | ---------------------- | ---------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| GET    | `/reports/traffic`     | `report:read`, K | `granularity=hour` (≤ 7 days, default the last 24 h) or `day` (≤ `REPORTS_MAX_RANGE_DAYS`, default 7 days), `direction?`; buckets `{ start, total, inbound, outbound, internal, verdicts: {…, none} }` + totals |
| GET    | `/reports/threats`     | `report:read`, K | Messages by final verdict and final action, the verdict × action matrix `outcomes` (step 7.1), quarantine entries by reason and primary engine (default 7 days, aligned to whole hours)                         |
| GET    | `/reports/url-clicks`  | `report:read`, K | Clicks per bucket by decision (`allowed`, `warned`, `blocked`, `continued`, `expired`, `not_found`); window rules of the traffic report                                                                         |
| GET    | `/reports/delivery`    | `report:read`, K | Step 7.1. Deliveries by bucket and status, `successRate`, delivery latency histogram; window rules of the traffic report                                                                                        |
| GET    | `/reports/processing`  | `report:read`, K | Step 7.1. Initial scan rounds by bucket and status, time to verdict (histogram, mean, p50/p95 upper bounds); window rules of the traffic report                                                                 |
| GET    | `/reports/top-domains` | `report:read`, K | Step 7.1. Inbound messages with a threat verdict per tenant domain, `limit` 1–25 (default 10); default 7 days, aligned to whole hours                                                                           |

```bash
curl -s "$API/api/v1/reports/traffic?granularity=day&from=2026-11-01T00:00:00Z&to=2026-11-12T00:00:00Z" -H "X-API-Key: $API_KEY"
# → {"from":"2026-11-01T00:00:00.000Z","to":"2026-11-12T00:00:00.000Z","granularity":"day","buckets":[…],"totals":{…},"generatedAt":"…"}
```

**Threats `outcomes` (step 7.1).** `GET /reports/threats` also returns `outcomes: [{ verdict, action, count }]`: the messages of the window by final verdict × final action (`none` = not decided yet), non-zero pairs only, ordered by `count` descending, then `verdict` and `action` alphabetically. The pairs add up to `messages.verdicts` and `messages.actions`. Example: spam blocked = Σ `count` where `verdict ∈ {spam, bulk}` and `action ∈ {quarantine, discard, reject}`.

```json
"outcomes": [
  { "verdict": "clean", "action": "deliver", "count": 1180 },
  { "verdict": "spam", "action": "quarantine", "count": 25 },
  { "verdict": "none", "action": "none", "count": 4 }
]
```

**Delivery report (step 7.1).** One row per recipient delivery chain (`email_deliveries`) of the messages **received** in the window, bucketed by the message's receipt. `statuses` lists `pending, in_progress, queued, deferred, delivered, bounced, expired, failed, suppressed, unknown`. `successRate = delivered ÷ (delivered + bounced + failed + expired)`, rounded to 4 decimals, `null` when none of those final states occurred (in-flight, deferred and suppressed deliveries do not count either way). `latency` covers `delivered` deliveries with a delivery time: `delivered_at − received_at`.

```bash
curl -s "$API/api/v1/reports/delivery?granularity=day&from=2026-11-10T00:00:00Z&to=2026-11-12T00:00:00Z" -H "X-API-Key: $API_KEY"
# → {"granularity":"day","buckets":[{"start":"2026-11-10T00:00:00.000Z","total":1040,"statuses":{…,"delivered":1000,"bounced":12,…},"successRate":0.9843},…],
#    "totals":{"total":1560,"statuses":{…},"successRate":0.9862},
#    "latency":{"delivered":1500,"averageMs":4210,"p50UpperBoundMs":1000,"p95UpperBoundMs":30000,"histogram":[{"leMs":1000,"count":900},…,{"leMs":null,"count":0}]},…}
```

**Processing report (step 7.1).** The initial scan round (`email_scans.scan_kind = 'initial'`; rescans and release re-validations are not counted) of every message received in the window, by bucket and status (`pending, running, completed, failed, timed_out`). The time to verdict is receipt (`email_scans.received_at`) to the round's completion (`completed_at`), completed rounds only; each bucket carries its `averageMs` and `p95UpperBoundMs`, the totals add `p50UpperBoundMs` and the histogram. `definition` repeats this in the response.

```bash
curl -s "$API/api/v1/reports/processing?granularity=hour" -H "X-API-Key: $API_KEY"
# → {"granularity":"hour","buckets":[{"start":"…","rounds":120,"statuses":{…,"completed":117,…},"averageMs":1830,"p95UpperBoundMs":5000},…],
#    "totals":{"rounds":200,…,"p50UpperBoundMs":1000,"p95UpperBoundMs":5000,"histogram":[{"leMs":250,"count":20},…]},"definition":"…"}
```

**Latency histograms.** The bounds are fixed (milliseconds): processing `250, 500, 1000, 2000, 5000, 10000, 30000, 60000, 120000, 300000, 900000`; delivery `1000, 5000, 10000, 30000, 60000, 300000, 900000, 3600000, 14400000, 86400000`. `histogram` lists the samples per bucket (not cumulative): `leMs` is the inclusive upper bound, the last entry `leMs: null` counts the samples above the last bound. MySQL has no percentile function, so `p50UpperBoundMs` / `p95UpperBoundMs` are **histogram upper bounds**: the smallest bound that 50 % / 95 % of the samples do not exceed ("p95 ≤ 5 s"), exact for the histogram, never an estimate; `null` without samples or when the percentile lies above the last bound ("> 15 min"). `averageMs` is the mean, rounded to whole milliseconds (a negative clock skew counts as 0).

**Top attacked domains (step 7.1).** Inbound messages (`direction = inbound`) of the window per domain of the organization, with the threat verdicts `spam, phishing, malware, bec, suspicious` (`threatVerdicts`). Only domains with at least one threat are listed, ordered by `threats` and `inbound` (descending), then `name`; at most `limit`. Each entry carries the public `domainId`, `name`, `status` and `deleted` (a domain deleted after its mail arrived is still listed, with `deleted: true`). Messages without a tenant domain are counted in `unattributed`. A message that references a domain outside the organization is never shown: the report answers `503 inconsistent_read`.

```bash
curl -s "$API/api/v1/reports/top-domains?limit=5" -H "X-API-Key: $API_KEY"
# → {"threatVerdicts":["spam","phishing","malware","bec","suspicious"],
#    "domains":[{"domainId":"0193…","name":"alpha.example.test","status":"active","deleted":false,"inbound":812,"threats":37,
#                "verdicts":{"spam":30,"phishing":3,"malware":1,"bec":0,"suspicious":3}}],
#    "unattributed":{"inbound":4,"threats":1},…}
```

### Usage and billing (`usage`, `billing` tags, step 6.1)

| Method | Path                    | Permission             | Notes                                                                                                                                                                                                                                                                                         |
| ------ | ----------------------- | ---------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| GET    | `/usage`                | `organization:read`, K | Exactly `GET /organizations/{id}/usage` for the caller's organization (the key's, the user's, or the override target): users, domains, messages by direction, active quarantine entries, API keys, sessions, limits and their use. Default 30 days, ≤ 31 days                                 |
| GET    | `/billing/plan`         | `billing:read`, K      | `{ plan: { code, name, description }, limits: [{ key, value, source: plan \| override }], features: [{ key, enabled, source }], pricing: null, note }`. No prices, invoices or payments exist                                                                                                 |
| GET    | `/billing/usage?month=` | `billing:read`, K      | `month=YYYY-MM` (default the current UTC month, counted up to now): messages by direction, current users, domains, active API keys, limits. Future months or months older than the message retention (6 months + the current one) → `400 usage_period_unavailable`. Cached; class `expensive` |

### Threat-intelligence lookup (`threat-intelligence` tag, step 6.1)

| Method | Path                          | Permission             | Notes                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| ------ | ----------------------------- | ---------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| GET    | `/threat-intelligence/lookup` | `threat_intel:read`, K | `type=sha256\|url\|domain\|ip`, `value`. Normalized exactly as the engines do; matched by `value_sha256` against the platform indicators the URL engine and click-service use (`org_scope = 0`, not expired; a domain also matches its parent domains down to the registrable domain) and, for `sha256`, the known-threat hash catalogue. `{ type, valueSha256, known, matches: [{ source, severity, category, firstSeenAt, lastSeenAt, expiresAt }] }`; never analyst reasons or user ids. Class `expensive`; audited `threat_intel.looked_up` (the value as SHA-256) |

```bash
curl -s "$API/api/v1/threat-intelligence/lookup?type=domain&value=login.evil-example.test" -H "X-API-Key: $API_KEY"
# → {"type":"domain","valueSha256":"…","known":true,"matches":[{"source":"platform_indicator","severity":"high","category":"phishing",…}]}
```

Tenant-managed indicators are not offered: no engine reads tenant-owned `threat_indicators` rows, so managing them would change nothing (step 6.1 §1.2). Your own allow-lists are BEC trusted senders, DLP exceptions and policy conditions.

### Webhooks (`webhooks` tag, step 6.2)

Signed HTTP callbacks for mail, threat, quarantine and domain events of your organization. Design: [docs/plan/steps/19-webhooks-notifications.md](../plan/steps/19-webhooks-notifications.md); decisions: [ADR-0054](../architecture/adr/0054-webhook-event-model.md) (event model), [ADR-0055](../architecture/adr/0055-webhook-signing-and-delivery.md) (signing and delivery), [ADR-0057](../architecture/adr/0057-idempotent-secret-bearing-routes-redacted-replay.md) (redacted replay of the secret routes). Reads need `webhook:read`, every change `webhook:manage`; API keys may hold both. Creating, re-activating, testing and replaying need the plan feature `webhooks` (`403 webhooks_not_enabled`; on in the standard, enterprise and dedicated plans, off in trial). Another organization's webhook, delivery or replay id answers `404` like a missing one.

| Method | Path                                                   | Permission          | Notes                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| ------ | ------------------------------------------------------ | ------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| GET    | `/webhooks`                                            | `webhook:read`, K   | Newest first, v1 cursor; `status` (≤ 4; default every status except `deleted`)                                                                                                                                                                                                                                                                                                                                                                                                   |
| POST   | `/webhooks`                                            | `webhook:manage`, K | **Idempotency-Key required** (redacted replay), class `sensitive`. `{ name, description?, url, eventTypes (1–10), filters?, status?: active \| paused, maxConcurrency? (1–32) }` → `201` with the webhook and `secret` (shown once). `409 webhook_limit_reached` (WEBHOOK_MAX_SUBSCRIPTIONS_PER_ORG, default 10 live webhooks), `422 webhook_url_not_allowed` (`reason`), `422 webhook_filter_invalid` (`path`). Audit `webhook.created`                                         |
| GET    | `/webhooks/event-types`                                | `webhook:read`, K   | The catalogue: type, version, description, severity rule, applicable filters, example envelope                                                                                                                                                                                                                                                                                                                                                                                   |
| GET    | `/webhooks/{webhookId}`                                | `webhook:read`, K   | `404 webhook_not_found`. Deleted webhooks are shown with `status: deleted`                                                                                                                                                                                                                                                                                                                                                                                                       |
| PATCH  | `/webhooks/{webhookId}`                                | `webhook:manage`, K | Any of `name`, `description`, `url`, `eventTypes`, `filters`, `status` (`active`, `paused`, `disabled`), `maxConcurrency`, with `expectedRowVersion` (`409 webhook_version_conflict` with `currentRowVersion`). `paused` parks the pending deliveries (`nextAttemptAt: null`, still `pending`); `active` makes them due now; `disabled` cancels them. Audit `webhook.updated` (changed paths; `urlHost` and `urlSha256` for a new URL; `parkedDeliveries` / `resumedDeliveries`) |
| DELETE | `/webhooks/{webhookId}`                                | `webhook:manage`, K | **Idempotency-Key required**, `sensitive`. Soft delete; pending deliveries are cancelled in the same transaction → `204` (a replay answers `204` again; a new key is `404`). Audit `webhook.deleted`                                                                                                                                                                                                                                                                             |
| POST   | `/webhooks/{webhookId}/rotate-secret`                  | `webhook:manage`, K | **Idempotency-Key required** (redacted replay), `sensitive`. `{ overlapHours? (0–168, default 24) }` → `200 { id, secret, secretVersion, secretRotatedAt, previousSecretExpiresAt }`. Audit `webhook.secret_rotated` (version and overlap only)                                                                                                                                                                                                                                  |
| POST   | `/webhooks/{webhookId}/test`                           | `webhook:manage`, K | A `webhook.ping` event and a `trigger: test` delivery → `202 { deliveryId, eventId }`. Webhook must be `active` (`409 webhook_not_active`). RL: WEBHOOK_TEST_REQUESTS_PER_MINUTE (6) per webhook. Audit `webhook.test_requested`                                                                                                                                                                                                                                                 |
| GET    | `/webhooks/{webhookId}/deliveries`                     | `webhook:read`, K   | History newest event first, v1 cursor; required range on the event time `from`/`to` (default the last 24 h, at most WEBHOOK_HISTORY_MAX_RANGE_DAYS = 31); filters `status` (≤ 5), `eventType` (≤ 10), `trigger` (`event`, `replay`, `test`); scan-bounded when filtered. Kept 2 months                                                                                                                                                                                           |
| GET    | `/webhooks/{webhookId}/deliveries/{deliveryId}`        | `webhook:read`, K   | The delivery with every attempt (outcome, HTTP status, latency, sanitized response snippet ≤ 512 characters, Retry-After, error code, signature count) and the stored envelope (`null` after retention). `404 webhook_delivery_not_found`                                                                                                                                                                                                                                        |
| POST   | `/webhooks/{webhookId}/deliveries/{deliveryId}/replay` | `webhook:manage`, K | **Idempotency-Key required**, `sensitive`. A new delivery of the same stored event → `202 { deliveryId }`. `409 webhook_not_active`, `409 webhook_replay_limit` (WEBHOOK_REPLAY_MAX_PER_DELIVERY = 10 per event), `410 webhook_event_expired`. Audit `webhook.delivery_replayed`                                                                                                                                                                                                 |
| POST   | `/webhooks/{webhookId}/replays`                        | `webhook:manage`, K | **Idempotency-Key required**, `sensitive`. `{ from, to (≤ 72 h, within retention), statuses? (default failed, dead; ⊆ succeeded, failed, dead, cancelled), eventTypes? }` → `202 { replayId, status: queued }`. One queued or running replay per webhook (`409 webhook_replay_in_progress` with `replayId`). RL: WEBHOOK_REPLAY_REQUESTS_PER_HOUR (10) per organization. Audit `webhook.replay_requested`                                                                        |
| GET    | `/webhooks/{webhookId}/replays/{replayId}`             | `webhook:read`, K   | `{ id, status, from, to, statuses, eventTypes, matchedCount, createdCount, truncated, errorCode, createdAt, startedAt, completedAt }`. `404 webhook_replay_not_found`                                                                                                                                                                                                                                                                                                            |

**Webhook representation:** `{ id, name, description, url, eventTypes, filters, status, disabledReason, disabledAt, maxConcurrency, secretVersion, secretRotatedAt, previousSecretExpiresAt, consecutiveFailures, failingSince, lastSuccessAt, lastFailureAt, createdBy: { type: "user", id } | null, createdAt, updatedAt, rowVersion }`. The secret and its ciphertext are never returned again. The `url` is shown to `webhook:read` holders (it may carry a receiver token): `webhook:read` is therefore not part of the read-only role.

**Event types and filters.** A webhook lists 1–10 types of the catalogue below (no wildcard; `webhook.ping` is sent only by the test route). Optional `filters` (strict; every field optional): `directions` (1–3 of `inbound`, `outbound`, `internal`), `domainIds` (1–20 of **your** domain ids; another organization's or an unknown id is `422 webhook_filter_invalid`), `minSeverity` (`info` < `low` < `medium` < `high`), `verdicts` (1–7 scan verdicts). An event is delivered when its type is listed **and** every present filter matches the attribute the event carries (domain events carry no direction or verdict and pass those filters; a message of no tenant domain never matches `domainIds`). Only events that occur after the webhook was created, while it is `active`, are delivered: there is no back-fill. Changes reach the delivery worker within its cache TTL (5 s by default).

**Endpoint URL rules** (checked at create and update, `422 webhook_url_not_allowed` with `reason`):

- absolute `https` URL of at most 2048 characters, without userinfo (`user:pass@`), fragment (`#…`), whitespace or control characters (`reason: format`, or `scheme` for another scheme; plain `http` only where the TEST-ONLY `WEBHOOK_ALLOW_HTTP` is set, which the configuration refuses outside local/CI);
- a port of `WEBHOOK_ALLOWED_PORTS` (default 443; `reason: port`);
- a host that is not `localhost`, a single label or a `.local`/`.internal`/`.localdomain`/`home.arpa` name (`name`), not the click-service host, the portal host or the host the API request reached (`deny_list`), and, for an IP literal, not a loopback, private, link-local, CGNAT, multicast, documentation, metadata (169.254.169.254, fd00:ec2::254), ULA, IPv4-mapped or other reserved address (the reason names the class).

DNS is **not** resolved at registration (it can change). The delivery worker resolves the host at every attempt and refuses the attempt when **any** answer is a non-public address (DNS rebinding), dials the checked address itself, re-checks the connected address and never follows redirects. A refused attempt fails with `lastError: blocked:<reason>` and is not retried.

**Secrets, shown once, and the redacted replay (ADR-0057).** Create and rotate return the signing secret (`whsec_` followed by 43 base64url characters; 256 bits) in that response only. It is stored encrypted (AES-256-GCM, bound to your organization, the webhook and the secret version) with a key only the api (encrypt) and the delivery worker (decrypt) hold; it is never logged, audited or stored in an idempotency record. Both routes require an `Idempotency-Key`: the stored response is the same body with `secret: null`, so repeating the request with the same key (within 24 h) returns `Idempotency-Replayed: true` and `secret: null` and creates or rotates nothing. **If you lost the original response, rotate the secret with a new key.**

**Rotation overlap.** `rotate-secret` makes a new secret current (`secretVersion + 1`); the retiring secret keeps signing until `previousSecretExpiresAt` (`overlapHours`, default 24, 0 = none). During the overlap every request carries two `v1=` signatures (the new secret first), so a receiver can deploy the new secret at its own pace. Rotating again during an overlap retires the then-current secret (only one previous secret exists).

**The delivery contract.** The worker sends `POST <url>` with the stored envelope as body (UTF-8 JSON, at most 16 KiB, byte-identical on every attempt and replay) and exactly these headers:

| Header                | Value                                                                                                                         |
| --------------------- | ----------------------------------------------------------------------------------------------------------------------------- |
| `Content-Type`        | `application/json`                                                                                                            |
| `User-Agent`          | `EmailGateway-Webhooks/1`                                                                                                     |
| `EG-Signature`        | `t=<unix seconds>,v1=<hex HMAC-SHA256(secret, "<t>.<raw body>")>`; a second `,v1=…` during a rotation overlap (current first) |
| `EG-Event-Id`         | the envelope `id` (deterministic: the same event always has the same id)                                                      |
| `EG-Event-Type`       | the envelope `type`                                                                                                           |
| `EG-Delivery-Id`      | the delivery id (new for each replay)                                                                                         |
| `EG-Delivery-Attempt` | attempt number, 1-based                                                                                                       |
| `EG-Subscription-Id`  | the webhook id                                                                                                                |
| `Idempotency-Key`     | the envelope `id`                                                                                                             |

The HMAC key is the UTF-8 bytes of the **whole** secret string (including `whsec_`). Receivers must: **verify before parsing** (over the raw body bytes), reject a timestamp more than **300 s** away from their clock, compare signatures in **constant time** and accept the request when **any** `v1` matches any of their current secrets; answer `2xx` within 10 s (process asynchronously); **deduplicate by `EG-Event-Id`** (delivery is at least once, and replays re-send the same event).

**Retries, Retry-After, dead letters, auto-disable.** `2xx` is delivered. Every other status, redirects (`3xx` is never followed), timeouts (3 s connect, 10 s total), DNS, connection and TLS errors and oversized responses are retried with exponential backoff and jitter (about 0 s, 30 s, 1.5 min, 3.5 min, 7.5 min, 15.5 min, 31.5 min, 63.5 min: 8 attempts by default). A `Retry-After` on any non-`2xx` answer (seconds or HTTP date) is honoured up to 1 h (a larger value is clamped). After the last attempt, or 24 h after the first, the delivery becomes `dead`: dead deliveries are the webhook dead-letter store (list them with `status=dead`, replay them). A webhook whose deliveries fail continuously (by default 50 consecutive failures over at least 24 h) is disabled by the system (`disabledReason: sustained_failure`, audited `webhook.auto_disabled`, a security alert to `webhook:manage` holders); re-enable it with `PATCH { status: "active" }` and replay what you missed. While a webhook is `paused` no new deliveries are created and pending ones wait; `disabled` and deleted webhooks have their pending deliveries cancelled.

**Replay semantics.** A replay (single or range) re-sends the **stored** envelope: same `EG-Event-Id` and bytes, a new `EG-Delivery-Id`, timestamp and signature. Events that occurred while a webhook was paused or disabled were never recorded for it and cannot be replayed. A range replay skips events that already have `WEBHOOK_REPLAY_MAX_PER_DELIVERY` (default 10) replays, so `createdCount` can be lower than `matchedCount`; it ends `failed` (`errorCode`) when the webhook is no longer active (`webhook_not_active`), the organization is suspended or being deleted (`organization_inactive`) or the `webhooks` feature was revoked (`webhooks_not_enabled`). While an organization is not active or lacks the feature, nothing is delivered: its due deliveries become `cancelled` (`lastError` `organization_inactive` / `webhooks_not_enabled`) and can be replayed afterwards. Stored events and the delivery history are kept 2 months (`410 webhook_event_expired` afterwards).

**What payloads never contain.** No message body, subject, attachment content or file name, address local part (domains only), raw header other than `internetMessageId`, URL found in mail, S3 key, secret or token. A payload guard refuses to build an envelope that would violate this. Response snippets shown in the history are untrusted text (secrets and tokens redacted): never render them as HTML.

#### Verifying a delivery (Node.js, `node:crypto` only)

<!-- webhook-verify-snippet:start -->

```js
import { createHmac, timingSafeEqual } from 'node:crypto';

/**
 * Verifies an EmailGateway webhook request. `rawBody` is the exact request body (a Buffer, read
 * BEFORE any JSON parsing); `header` is the EG-Signature header; `secrets` are your current
 * secrets (two during a rotation). Returns true when the timestamp is within the tolerance and
 * any v1 signature matches any secret.
 */
export function verifyEmailGatewayWebhook(
  rawBody,
  header,
  secrets,
  toleranceSeconds = 300,
  nowMs = Date.now(),
) {
  if (typeof header !== 'string' || header.length > 1024) return false;
  let timestamp = null;
  const signatures = [];
  for (const part of header.split(',')) {
    const eq = part.indexOf('=');
    if (eq < 1) return false;
    const key = part.slice(0, eq).trim();
    const value = part.slice(eq + 1).trim();
    if (key === 't') timestamp = value;
    else if (key === 'v1' && /^[0-9a-f]{64}$/.test(value))
      signatures.push(Buffer.from(value, 'hex'));
  }
  if (timestamp === null || !/^\d{1,12}$/.test(timestamp) || signatures.length === 0) return false;
  if (Math.abs(Math.floor(nowMs / 1000) - Number(timestamp)) > toleranceSeconds) return false;
  let valid = false;
  for (const secret of secrets) {
    const expected = createHmac('sha256', Buffer.from(secret, 'utf8'))
      .update(`${timestamp}.`)
      .update(rawBody)
      .digest();
    // No early exit: every comparison runs in constant time.
    for (const signature of signatures) {
      if (timingSafeEqual(expected, signature)) valid = true;
    }
  }
  return valid;
}
```

<!-- webhook-verify-snippet:end -->

With Express, read the raw body (`express.raw({ type: 'application/json', limit: '64kb' })`), call `verifyEmailGatewayWebhook(req.body, req.get('EG-Signature'), [process.env.EG_WEBHOOK_SECRET])` and answer `401` when it returns false; only then `JSON.parse(req.body)`, skip events whose `EG-Event-Id` you already processed, and answer `204`. `apps/api/src/modules/webhooks/verify-snippet.test.ts` runs this exact snippet against the platform's signer (valid, tampered body, wrong secret, stale and future timestamps, rotation with two `v1`).

#### Verifying or producing a signature with openssl and curl

```bash
SECRET='whsec_…'                                  # your webhook secret
BODY_FILE=delivery.json                           # the raw body exactly as received
T=1763025243                                      # the t= value of EG-Signature
# The expected v1 value: compare it with the header's v1 (any of them).
printf '%s.' "$T" | cat - "$BODY_FILE" | openssl dgst -sha256 -hmac "$SECRET" -hex | sed 's/^.*= //'

# Exercise your receiver with a correctly signed request (current time):
T=$(date +%s); SIG=$(printf '%s.' "$T" | cat - "$BODY_FILE" | openssl dgst -sha256 -hmac "$SECRET" -hex | sed 's/^.*= //')
curl -sS -X POST "https://hooks.example.com/email-gateway" -H 'Content-Type: application/json' \
  -H "EG-Signature: t=$T,v1=$SIG" -H "EG-Event-Id: $(jq -r .id "$BODY_FILE")" --data-binary @"$BODY_FILE"
```

```bash
# Register a webhook (the secret is in this response only), then send it a test event.
curl -s -X POST "$API/api/v1/webhooks" -H "X-API-Key: $API_KEY" -H "Idempotency-Key: hook-siem-0001" \
  -H 'Content-Type: application/json' \
  -d '{"name":"SIEM","url":"https://hooks.example.com/email-gateway","eventTypes":["email.threat.detected","email.quarantined"],"filters":{"minSeverity":"medium"}}'
# → 201 {"id":"0193…","status":"active","secretVersion":1,…,"secret":"whsec_…"}
curl -s -X POST "$API/api/v1/webhooks/0193…/test" -H "X-API-Key: $API_KEY"
# → 202 {"deliveryId":"0193…","eventId":"…"}
```

#### Event catalogue (payload version 1)

Every envelope is `{ id, type, version, occurredAt, organizationId, data }`: `id` is deterministic (the same event redelivered or replayed keeps it), `occurredAt` is when the fact happened, `organizationId` is your organization's public id. A breaking change of a type's `data` would ship as `version: 2` without changing version 1 (not built in 6.2). Shared objects: `message` = `{ id, receivedAt, direction, domainId | null, internetMessageId | null, senderDomain | null, headerFromDomain | null, recipientCount, recipientDomains (≤ 20), sizeBytes, attachmentCount }` (domains only, never local parts or a subject); `domain` = `{ id, name, status }` (your own domain). Severities: `info` < `low` < `medium` < `high`.

**`email.received`** — A message was accepted and stored by the gateway. Severity: info. Filters: `directions`, `domainIds`, `minSeverity`.

```json
{
  "id": "89ce8a67-39df-8ab9-a503-4ae5c0b19b77",
  "type": "email.received",
  "version": 1,
  "occurredAt": "2026-11-13T09:14:03.120Z",
  "organizationId": "0192f0c4-7d1e-7b6a-9c55-6f3e2a1d4b10",
  "data": {
    "message": {
      "id": "0192f0c4-8a11-7c2e-9d3f-1a2b3c4d5e6f",
      "receivedAt": "2026-11-13T09:14:02.481Z",
      "direction": "inbound",
      "domainId": "0192f0c4-7d1e-7b6a-9c55-6f3e2a1d4b11",
      "internetMessageId": "<CAF1x2y3z@mail.partner.example>",
      "senderDomain": "partner.example",
      "headerFromDomain": "partner.example",
      "recipientCount": 2,
      "recipientDomains": ["acme.example"],
      "sizeBytes": 48213,
      "attachmentCount": 1
    }
  }
}
```

**`email.scanned`** — A scan round of a message completed (initial scan or rescan). Severity: clean/unknown/timeout/error → info, spam → low, suspicious → medium, malicious → high. Filters: `directions`, `domainIds`, `minSeverity`, `verdicts`.

```json
{
  "id": "9e83e129-eb3d-8e4c-8cc1-55b055ed602d",
  "type": "email.scanned",
  "version": 1,
  "occurredAt": "2026-11-13T09:14:03.120Z",
  "organizationId": "0192f0c4-7d1e-7b6a-9c55-6f3e2a1d4b10",
  "data": {
    "message": "<the message object, as in email.received>",
    "scan": {
      "lifecycleRound": 0,
      "kind": "initial",
      "outcome": "scanned",
      "verdict": "malicious",
      "engines": [
        {
          "engine": "rspamd",
          "outcome": "suspicious"
        },
        {
          "engine": "attachment",
          "outcome": "malicious"
        },
        {
          "engine": "url",
          "outcome": "clean"
        }
      ],
      "reasonCodes": ["attachment.clamav_match", "spam.score"],
      "completedAt": "2026-11-13T09:14:03.010Z"
    }
  }
}
```

**`email.threat.detected`** — The final verdict of a message is spam, suspicious or malicious, or the sandbox found a malicious attachment after delivery. Severity: spam → low, suspicious → medium, malicious → high. Filters: `directions`, `domainIds`, `minSeverity`, `verdicts`.

```json
{
  "id": "8754c726-2d7b-80f4-a78d-9cfb9653d672",
  "type": "email.threat.detected",
  "version": 1,
  "occurredAt": "2026-11-13T09:14:03.120Z",
  "organizationId": "0192f0c4-7d1e-7b6a-9c55-6f3e2a1d4b10",
  "data": {
    "message": "<the message object, as in email.received>",
    "detection": {
      "stage": "scan",
      "verdict": "malicious",
      "riskScore": 940,
      "reasonCodes": ["attachment.clamav_match"],
      "lifecycleRound": 0,
      "finalAction": "quarantine",
      "attachment": null
    }
  }
}
```

**`email.policy.triggered`** — At least one tenant policy rule matched a message. Severity: reject/quarantine/require_approval dispositions → medium, otherwise low. Filters: `directions`, `domainIds`, `minSeverity`.

```json
{
  "id": "ac346d1b-045e-8624-bc51-dd103bd44770",
  "type": "email.policy.triggered",
  "version": 1,
  "occurredAt": "2026-11-13T09:14:03.120Z",
  "organizationId": "0192f0c4-7d1e-7b6a-9c55-6f3e2a1d4b10",
  "data": {
    "message": "<the message object, as in email.received>",
    "policy": {
      "disposition": "quarantine",
      "finalAction": "quarantine",
      "decisionSource": "tenant_rule",
      "decisive": {
        "policyId": "0192f0c4-9b22-7d3f-8e40-2b3c4d5e6f70",
        "versionNo": 3,
        "ruleId": "block-macros"
      },
      "matchedRules": [
        {
          "policyId": "0192f0c4-9b22-7d3f-8e40-2b3c4d5e6f70",
          "versionNo": 3,
          "ruleId": "block-macros"
        }
      ],
      "actions": ["ALERT", "TAG"],
      "overrideApplied": false,
      "lifecycleRound": 0,
      "evaluatedAt": "2026-11-13T09:14:03.120Z"
    }
  }
}
```

**`email.quarantined`** — A message was quarantined (by policy or manually) for one or more recipients. Severity: medium. Filters: `directions`, `domainIds`, `minSeverity`.

```json
{
  "id": "d920d55c-adb1-879a-a804-bd261487a9bc",
  "type": "email.quarantined",
  "version": 1,
  "occurredAt": "2026-11-13T09:14:03.120Z",
  "organizationId": "0192f0c4-7d1e-7b6a-9c55-6f3e2a1d4b10",
  "data": {
    "message": "<the message object, as in email.received>",
    "quarantine": {
      "origin": "policy",
      "lifecycleRound": 0,
      "entryCount": 2,
      "kinds": {
        "quarantine": 2,
        "review": 0
      },
      "reasons": ["malware"],
      "entryIds": ["0192f0c4-a133-7e40-9f51-3c4d5e6f7081", "0192f0c4-a133-7e40-9f51-3c4d5e6f7082"],
      "earliestExpiresAt": "2026-12-13T09:14:03.120Z"
    }
  }
}
```

**`email.released`** — Quarantined recipients of a message were released for delivery. Severity: info. Filters: `directions`, `domainIds`, `minSeverity`.

```json
{
  "id": "77ed1c49-9250-8cbf-8c1d-18871fd483a3",
  "type": "email.released",
  "version": 1,
  "occurredAt": "2026-11-13T09:14:03.120Z",
  "organizationId": "0192f0c4-7d1e-7b6a-9c55-6f3e2a1d4b10",
  "data": {
    "message": "<the message object, as in email.received>",
    "release": {
      "releaseId": "0192f0c4-b244-7f51-8a62-4d5e6f708192",
      "mode": "operator",
      "entryIds": ["0192f0c4-a133-7e40-9f51-3c4d5e6f7081"],
      "recipientCount": 1,
      "deliverySeq": 1,
      "approvedAt": "2026-11-13T10:02:11.000Z"
    }
  }
}
```

**`email.delivered`** — Delivery of a message completed (all or some recipients delivered). Severity: info. Filters: `directions`, `domainIds`, `minSeverity`.

```json
{
  "id": "f5ceaea5-8aa8-860f-9419-cc09d9e58af2",
  "type": "email.delivered",
  "version": 1,
  "occurredAt": "2026-11-13T09:14:03.120Z",
  "organizationId": "0192f0c4-7d1e-7b6a-9c55-6f3e2a1d4b10",
  "data": {
    "message": "<the message object, as in email.received>",
    "delivery": {
      "outcome": "complete",
      "lifecycleRound": 0,
      "recipients": {
        "delivered": 2,
        "failed": 0,
        "bounced": 0,
        "expired": 0,
        "suppressed": 0,
        "quarantined": 0,
        "discarded": 0,
        "other": 0
      },
      "completedAt": "2026-11-13T09:14:05.900Z"
    }
  }
}
```

**`email.rejected`** — A stored message was rejected by policy, quarantine or delivery. Severity: low. Filters: `directions`, `domainIds`, `minSeverity`.

```json
{
  "id": "a1810c49-cd34-8343-999f-a58078dd4842",
  "type": "email.rejected",
  "version": 1,
  "occurredAt": "2026-11-13T09:14:03.120Z",
  "organizationId": "0192f0c4-7d1e-7b6a-9c55-6f3e2a1d4b10",
  "data": {
    "message": "<the message object, as in email.received>",
    "rejection": {
      "reason": "policy_reject",
      "stage": "policy",
      "lifecycleRound": 0,
      "rejectedAt": "2026-11-13T09:14:03.120Z"
    }
  }
}
```

**`domain.verified`** — Ownership of a tenant domain was verified. Severity: info. Filters: `domainIds`, `minSeverity`.

```json
{
  "id": "eb32f691-c117-821c-a76c-3ad4b457676a",
  "type": "domain.verified",
  "version": 1,
  "occurredAt": "2026-11-13T09:14:03.120Z",
  "organizationId": "0192f0c4-7d1e-7b6a-9c55-6f3e2a1d4b10",
  "data": {
    "domain": {
      "id": "0192f0c4-7d1e-7b6a-9c55-6f3e2a1d4b11",
      "name": "acme.example",
      "status": "verified"
    },
    "previousStatus": "pending_verification",
    "verifiedAt": "2026-11-13T08:00:00.000Z"
  }
}
```

**`domain.dns.failed`** — Domain verification failed, or a DNS record of a verified domain stopped validating. Severity: verification → medium, mx/spf/dkim/dmarc records → high, other records → medium. Filters: `domainIds`, `minSeverity`.

```json
{
  "id": "b6ac9409-25c8-8130-80cc-e6bdd0a20dc4",
  "type": "domain.dns.failed",
  "version": 1,
  "occurredAt": "2026-11-13T09:14:03.120Z",
  "organizationId": "0192f0c4-7d1e-7b6a-9c55-6f3e2a1d4b10",
  "data": {
    "domain": "<the domain object, as in domain.verified>",
    "failure": {
      "kind": "records_failed",
      "reason": null,
      "records": [
        {
          "purpose": "spf",
          "recordKey": "spf",
          "previousStatus": "valid",
          "status": "invalid"
        }
      ],
      "checkedAt": "2026-11-13T09:00:00.000Z"
    }
  }
}
```

**`webhook.ping`** — Test event sent by POST /webhooks/{id}/test; not subscribable. Severity: info. Filters: none (not subscribable).

```json
{
  "id": "e68adad7-c6c5-87f0-b0f3-62c2d01dd259",
  "type": "webhook.ping",
  "version": 1,
  "occurredAt": "2026-11-13T09:14:03.120Z",
  "organizationId": "0192f0c4-7d1e-7b6a-9c55-6f3e2a1d4b10",
  "data": {
    "subscriptionId": "0192f0c4-c355-7062-9b73-5e6f708192a3",
    "requestedAt": "2026-11-13T09:20:00.000Z"
  }
}
```

Not events (by design, step 6.2 §11): SMTP-time refusals (no message is stored), per-recipient delivery outcomes (`email.delivered` carries counts; per-recipient detail is `GET /messages/{id}/recipients`), URL clicks, DLP incidents, archive and connector events (8.1, 8.2), quarantine adoption of pre-5.3 messages.

### Notifications (`notifications` tag, step 6.2)

Security alerts by e-mail ([ADR-0056](../architecture/adr/0056-security-alert-notifications.md)): **threat detected** (a threat at or above the configured severity), **DNS record failures** (a verified domain's verification, MX, SPF, DKIM or DMARC record stops validating) and **webhook disabled** (sustained delivery failure). They go to the active, verified users of your organization holding the kind's permission (`quarantine:approve`, `domain:manage`, `webhook:manage`) who did not opt out, plus `organization_settings.notification_email` when `includeOrganizationContact` is on; at most one alert per organization, kind, scope (the domain, the webhook) and throttle window, the next one saying how many events it summarizes. Alerts carry ids, counts, the verdict and links into the portal: never a subject, address, URL from mail, file name, endpoint URL or secret. The existing policy alerts (5.2) and quarantine admin alerts, approval requests and digests (5.3) are unchanged and honour the same preference center.

| Method | Path                         | Permission             | Notes                                                                                                                                                                                                                                                                                                                                                                                    |
| ------ | ---------------------------- | ---------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| GET    | `/notifications/settings`    | `organization:read`, K | `{ settings (effective), stored (or null), invalidStored, rowVersion (0 = nothing stored), updatedAt, defaults, bounds }`                                                                                                                                                                                                                                                                |
| PUT    | `/notifications/settings`    | `settings:manage`, K   | `{ settings, expectedRowVersion }` replaces the whole document (`{}` = defaults). `400 notification_settings_invalid` with `violations` (path, rule), `409 notification_settings_conflict` with `currentRowVersion`. Audit `notification.settings_updated` (changed paths only)                                                                                                          |
| GET    | `/notifications/preferences` | authenticated, **U**   | Your own: `{ optOut, quarantineDigestOptOut, quarantineDigestOptOutAllowed, kinds, invalidStored }`. API keys and platform overrides get `403`                                                                                                                                                                                                                                           |
| PUT    | `/notifications/preferences` | authenticated, **U**   | `{ optOut: kinds (unique), quarantineDigestOptOut }`. Kinds: `threat_detected`, `domain_dns_failed`, `webhook_disabled`, `policy_alert`, `quarantine_admin_alert`, `quarantine_approval_requested`. The digest opt-out is the same setting as `/quarantine/me/preferences` and needs the organization's `digest.allowOptOut` (`400` otherwise). Audit `notification.preferences_updated` |

Settings document (strict, every key optional; defaults in brackets): `{ alerts: { threatDetected: { enabled [true], minSeverity: medium | high [high], throttleMinutes: 15–1440 [60] }, domainDnsFailed: { enabled [true], throttleMinutes: 60–10080 [360] }, webhookDisabled: { enabled [true], throttleMinutes: 60–10080 [1440] }, includeOrganizationContact [true] } }`. Decisions on your own release requests and sender notices are not optional. SMS, chat and push channels are not offered.

```bash
curl -s -X PUT "$API/api/v1/notifications/settings" -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"settings":{"alerts":{"threatDetected":{"minSeverity":"medium","throttleMinutes":30}}},"expectedRowVersion":0}'
# → 200 {"settings":{"alerts":{"threatDetected":{"enabled":true,"minSeverity":"medium","throttleMinutes":30},…}},"rowVersion":1,…}
```

## Conventions (step 6.1)

Binding decisions: [ADR-0050](../architecture/adr/0050-api-conventions.md) (resources, status codes, envelope, errors, Request-Id, strict validation, deprecation, OpenAPI), [ADR-0051](../architecture/adr/0051-pagination-cursor-filtering-sorting.md) (pagination, filters, sorting, scan budget), [ADR-0052](../architecture/adr/0052-rate-limiting-and-idempotency.md) (rate limits, idempotency), [ADR-0053](../architecture/adr/0053-public-internal-api-boundary.md) (public/internal boundary); design [docs/plan/steps/18-rest-api.md](../plan/steps/18-rest-api.md). `apps/api/test/route-inventory.e2e.test.ts` enforces them for every route.

- **Resources:** plural kebab-case nouns, at most two levels of nesting; commands are `POST /…/{id}/<verb>`.
- **Status codes:** `GET` 200; `POST` create 201 with the resource; synchronous command 200, asynchronous command 202; `PUT`/`PATCH` 200; `DELETE` 204 (a few older `DELETE`s answer 200).
- **Success bodies:** a single resource is returned bare; a collection is `{ "data": [...], "nextCursor": string | null }` (the three quarantine lists of step 5.3 keep `{ "items": [...], "nextCursor" }`).
- **Representation:** ids are strings (public UUIDv7 or decimal strings), timestamps ISO 8601 UTC with milliseconds, enums lower-snake; never message content, secrets or S3 keys.
- **OpenAPI extensions** for the portal: `x-eg-permissions`, `x-eg-rate-class`, `x-eg-idempotency`, `x-eg-cursor`, `x-eg-returns-secret`.

### Headers

| Header                                                          | Direction | Rule                                                                                               |
| --------------------------------------------------------------- | --------- | -------------------------------------------------------------------------------------------------- |
| `X-Request-Id`                                                  | response  | Every response (success, error, unknown route, probes): a server-minted UUID, never taken from you |
| `x-correlation-id`                                              | both      | Yours if well formed (8–128 chars of `[A-Za-z0-9._:-]`), otherwise a new one; echoed and audited   |
| `RateLimit-Limit`, `RateLimit-Remaining`, `RateLimit-Reset`     | response  | Every authenticated response: the most restrictive counter applied to the request                  |
| `Retry-After`                                                   | response  | `429`, `409 idempotency_request_in_progress`                                                       |
| `Idempotency-Key`                                               | request   | Required on the [sensitive mutations](#idempotency)                                                |
| `Idempotency-Replayed: true`                                    | response  | A stored response returned again                                                                   |
| `Deprecation: true`, `Link: <…#idempotency>; rel="deprecation"` | response  | A legacy sensitive route called without a key while `API_IDEMPOTENCY_LEGACY_MODE=warn`             |
| `Cache-Control: no-store`                                       | response  | Every `/api/v1` response unless the route sets its own                                             |

Quote `X-Request-Id` (or the body's `requestId`) when reporting a problem: it finds the request's log lines and its `audit_logs.metadata.requestId`.

## Errors

Every error of the api has one shape, rendered by the global `ApiExceptionFilter`:

```json
{
  "statusCode": 429,
  "error": "TOO_MANY_REQUESTS",
  "code": "rate_limited",
  "message": "Too many requests",
  "scope": "tenant",
  "correlationId": "…",
  "requestId": "0b9c6a2e-…"
}
```

`code` is a stable snake_case machine code (branch on it, not on `message`); `message` is a string, or a list of `"<path>: <issue>"` strings for validation errors (input values are never echoed); coded errors may add detail fields (ids, states, versions, limits; never content). Default codes:

| Status | Default `code`           | Specific codes and notes                                                                                                                                                          |
| ------ | ------------------------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `400`  | `validation_failed`      | `cursor_invalid`, `idempotency_key_required`, `idempotency_key_invalid`, `usage_period_unavailable`; malformed ids, unknown fields, invalid or used tokens                        |
| `401`  | `unauthorized`           | Missing, invalid, expired or revoked credentials (`Invalid credentials` on login); user or organization no longer active; override ended                                          |
| `403`  | `forbidden`              | `mfa_required`, `mfa_enrollment_required`, `user_required` (API key on a user-only route); module codes such as `quarantine_approval_forbidden`                                   |
| `404`  | `not_found`              | `route_not_found` (unknown path); module codes (`message_not_found`, `suppression_not_found`, …). **Resources of another tenant answer exactly like missing ones**                |
| `409`  | `conflict`               | `idempotency_request_in_progress` (+ `Retry-After`), `suppression_exists`, `suppression_limit_reached`, duplicates, limits, state conflicts, version conflicts (`currentVersion`) |
| `413`  | `payload_too_large`      |                                                                                                                                                                                   |
| `415`  | `unsupported_media_type` |                                                                                                                                                                                   |
| `422`  | `unprocessable`          | `idempotency_key_reused`; a refused destination server (`reason`, `field`); `Not implemented` recipient validation modes                                                          |
| `429`  | `rate_limited`           | `scope`: `principal`, `tenant`, `sensitive`, `expensive` or `route` (and module codes such as `quarantine_bulk_rate_limited`); `Retry-After` in seconds                           |
| `500`  | `internal_error`         | Generic message only; details in the logs under `requestId` / `correlationId`                                                                                                     |
| `503`  | `service_unavailable`    | A dependency failed closed (rate-limit store, authentication store, domain-verification backend); `inconsistent_read`, `report_timeout`                                           |

**Coded errors (step 3.3, 4.1, 4.2, 4.4, 4.5).** The message lifecycle routes, the step 4.1 scan routes (`scan_engine_not_found`, `scan_settings_invalid` with `violations`, `version_conflict` with `currentVersion`, `organization_not_found`, `content_unavailable`, `scan_training_not_applicable`, `rspamd_unavailable`) and the step 4.2 platform routes (`hash_exists`, `threat_hash_not_found`, `rescan_job_not_found`, `rescan_job_not_cancellable` with `status`) and the step 4.4 BEC routes (`bec_executive_not_found`, `bec_vendor_not_found`, `bec_trusted_sender_not_found`, `bec_suppression_not_found`, `scan_not_found`, `bec_result_not_found`, `executive_exists` / `vendor_exists` / `trusted_sender_exists` with `id`, `version_conflict` with `currentVersion`, `bec_limit_reached` with `resource` and `limit`, `feedback_exists`, `vendor_domain_freemail` with `index`, `trusted_domain_freemail`, `feedback_codes_invalid` with `reasonCode`, `suppression_not_allowed` with `reason`, `inconsistent_read` (503)) and the step 4.5 DLP routes (`dlp_policy_not_found`, `dlp_rule_not_found`, `dlp_exception_not_found`, `dlp_pattern_not_found`, `dlp_dictionary_not_found`, `scan_not_found`, `dlp_evidence_not_found`, `dlp_policy_exists` / `dlp_rule_exists` / `dlp_exception_exists` / `dlp_pattern_exists` / `dlp_dictionary_exists` with `id`, `dlp_policy_in_use` / `dlp_rule_in_use` / `dlp_pattern_in_use` / `dlp_dictionary_in_use` with `references`, `version_conflict`, `dlp_limit_reached` with `resource` and `limit`, `dlp_reference_invalid` (400, `field`, `index`), `dlp_directions_invalid` (400), the D9 pattern codes `pattern_syntax` … `pattern_invalid_options` (400, `repetitionProduct`, `length`), `dictionary_terms_count` / `dictionary_term_invalid` (400, `index`), `evidence_purged` / `evidence_expired` (410), `evidence_unreadable` (500), `evidence_unavailable` and `inconsistent_read` (503); never a pattern, sample, term, address or value) carry their own stable `code` (since step 6.1 every other error carries a default one) (and, for `409`, the message's `currentState` and `currentVersion`); `message` stays human-readable:

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

### Validation errors

Request bodies, queries and path parameters are validated with zod schemas (the same schemas generate the OpenAPI shapes) before any database access. Since step 6.1 **every** body and query schema is strict at every object node: an unknown field is rejected (it used to be silently dropped on many routes; see the [changelog](#changelog)):

```json
{
  "statusCode": 400,
  "error": "BAD_REQUEST",
  "code": "validation_failed",
  "message": ["slug: is reserved", "colour: Unrecognized key"],
  "correlationId": "…",
  "requestId": "…"
}
```

## Pagination and lists

- `?limit=` 1–100 (default 25; quarantine search keeps its configured cap) and `?cursor=` (the opaque `nextCursor` of the previous page). Keyset order, newest first by default. The response is `{ "data": [...], "nextCursor": "…" | null }`; `null` means the last page.
- **No totals and no offsets** (counting is unbounded at a million messages a day; use the reports for aggregates).
- **Short pages.** Lists that filter on a non-indexed column examine at most `API_LIST_SCAN_BUDGET_ROWS` (5 000) index entries per request: a page may hold fewer rows than `limit`, even none, while `nextCursor` is non-null. **Follow `nextCursor` until it is `null`**; do not stop at an empty page.
- **Cursor v1** (`x-eg-cursor: v1`, every list added in 6.1): signed (HMAC) and bound to your organization, the resource, the filters, the sort and the first page's resolved time window, and valid for `API_CURSOR_TTL_SECONDS` (24 h). Repeat the same filters with it (you may omit `from`/`to`); anything else, a tampered or expired cursor or another tenant's cursor is `400 cursor_invalid` (restart the list without a cursor).
- **Cursor v0** (`x-eg-cursor: v0`, the lists of steps 1.2–5.3): unsigned, unchanged; an invalid one is a `400` (the quarantine search: `quarantine_cursor_invalid`). They never widen access: the tenant scope is always re-applied.
- Lists, details, usage and reports read the replica (ADR-0014): a row created a moment ago can appear after a short delay. Every create returns the created resource from the writer.

### Filtering and sorting

Each list documents its own allow-list of filters; anything else is `400 validation_failed`.

| Syntax                                                  | Meaning                                                                                             |
| ------------------------------------------------------- | --------------------------------------------------------------------------------------------------- |
| `field=value`                                           | equals                                                                                              |
| `field=a,b,c`                                           | one of (at most 10 values unless the list says fewer)                                               |
| `field.gte=` / `field.lte=` / `field.gt=` / `field.lt=` | typed range (numbers, timestamps)                                                                   |
| `field=true\|false`                                     | booleans                                                                                            |
| `from=` / `to=`                                         | ISO 8601 window `[from, to)`; required bounds on partitioned tables (defaults and maximum per list) |
| `sort=-receivedAt` / `sort=receivedAt`                  | descending (default) or ascending on the list's leading keyset key                                  |

Ids in filters (`domainId`, `messageId`) are resolved inside your organization: another tenant's id answers like a missing one (`404`).

**Which lists use this vocabulary.** Only the 9 lists added in step 6.1 (`x-eg-cursor: v1`: `/messages`, `/messages/{id}/recipients`, `/messages/{id}/attachments`, `/attachments`, `/messages/{id}/urls`, `/url-protection/clicks`, `/recipients/suppressions`, `/audit/logs`, `/platform/audit/logs`) take `sort` and the operators above. The 33 lists of steps 1.2–5.3 (`x-eg-cursor: v0`, e.g. `/users`, `/domains`, `/deliveries`, `/policies`, `/dlp/incidents`, `/quarantine/entries`, `/organizations`, `/api-keys`) take **no `sort` parameter** (a fixed keyset order, documented per operation) and keep their own module-specific filters as documented in their OpenAPI operations; unknown parameters are still `400 validation_failed`. Converging them is a follow-up (see below).

## Rate limits

Every authenticated request counts against fixed 60-second windows in Redis ([ADR-0052](../architecture/adr/0052-rate-limiting-and-idempotency.md)):

| Counter     | Applies to                                                                                        | Limit                                                                                                                                                                                                                                       |
| ----------- | ------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `principal` | each user or API key (override sessions count as the user)                                        | `API_RATE_PRINCIPAL_PER_MINUTE` (600)                                                                                                                                                                                                       |
| `tenant`    | each organization (under an override: the target)                                                 | the organization's `api_requests_per_minute` (plan: 60 / 300 / 1 200 / 3 000; platform overrides possible), clamped to `[API_RATE_TENANT_MIN_PER_MINUTE, …_MAX_…]` (10, 10 000); `API_RATE_TENANT_DEFAULT_PER_MINUTE` (300) without a value |
| `sensitive` | per principal, the [sensitive mutations](#idempotency) and secret-bearing routes                  | `API_RATE_SENSITIVE_PER_MINUTE` (30)                                                                                                                                                                                                        |
| `expensive` | per principal: reports, `/billing/usage`, threat lookup, `/attachments`, policy test and dry-runs | `API_RATE_EXPENSIVE_PER_MINUTE` (60)                                                                                                                                                                                                        |
| `route`     | route-specific limits (authentication, BEC feedback, DLP tests, domain checks, quarantine, …)     | per route, unchanged; since step 6.2 also `POST /webhooks/{id}/test` per webhook (`WEBHOOK_TEST_REQUESTS_PER_MINUTE`, 6) and `POST /webhooks/{id}/replays` per organization (`WEBHOOK_REPLAY_REQUESTS_PER_HOUR`, 10 per hour)               |

Every authenticated response carries `RateLimit-Limit`, `RateLimit-Remaining` and `RateLimit-Reset` of the most restrictive counter. Over a limit: `429 rate_limited` with `scope` and `Retry-After`; wait that long. Public routes (login and the other **P** routes, `GET /meta`) keep their per-IP limits. When the rate-limit store is unreachable the api answers `503 service_unavailable` (fail closed). Operations: [runbook](../runbooks/api-rate-limits-and-reports.md).

## Idempotency

Send `Idempotency-Key: <1–128 chars of [A-Za-z0-9._:-]>` (unique per organization) on the sensitive mutations below. The first successful (2xx) response is stored for 24 hours; repeating the same request with the same key returns it again with `Idempotency-Replayed: true` and changes nothing. The same key with a different request (body, path, operation or caller) is `422 idempotency_key_reused`; while the first request is still running, `409 idempotency_request_in_progress` with `Retry-After`. Errors are not stored: fix the request and retry with the same key. Without the header: `400 idempotency_key_required`.

| Mechanism (`x-eg-idempotency`)                                                                                       | Routes                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| -------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `required` — exactly once (effect, audit row and stored response in one transaction)                                 | `POST /messages/{id}/rescan`, `POST /messages/{id}/release`; quarantine `POST /quarantine/bulk`, `POST /quarantine/entries`, `POST /quarantine/entries/{id}/release`, `…/request-release`, `…/reject`, `…/delete`, `POST /quarantine/approvals/{id}/approve`, `…/deny`, `…/cancel`, `POST /quarantine/me/entries/{id}/release`, `…/request-release`; `POST /recipients/suppressions`, `DELETE /recipients/suppressions/{id}`; (step 6.2) `POST /webhooks`, `DELETE /webhooks/{id}`, `POST /webhooks/{id}/rotate-secret`, `POST /webhooks/{id}/deliveries/{deliveryId}/replay`, `POST /webhooks/{id}/replays`                                                                                                                                                                      |
| `legacy` — at most once per key (a reservation row before the handler, the response stored after it; since step 6.1) | `POST /domains/{id}/dkim/rotate`; `PATCH /organizations/{id}/status`, `POST /organizations/{id}/deletion`, `POST /organizations/{id}/deletion/confirm`; `POST /users/invitations`, `POST /users/{id}/invitation`, `POST /users/{id}/mfa/reset`; `POST /policies/{id}/versions/{n}/publish`, `…/activate`; `POST /risk-scoring/profile/versions/{id}/publish`, `…/activate`, `POST /risk-scoring/profile/reset`; `DELETE /bec/history`; `DELETE /dlp/evidence`, `DELETE /messages/{id}/scans/{scanId}/dlp-evidence`, `PUT` and `DELETE /dlp/compliance/aadhaar`; `POST /platform/dead-letters/replay`, `POST /platform/attachment-rescans`, `POST /platform/organizations/{orgId}/messages/{id}/scan-training`, `POST /platform/threat-hashes`, `POST /platform/threat-indicators` |

- The `legacy` routes accepted no key before step 6.1. While the deprecation switch `API_IDEMPOTENCY_LEGACY_MODE=warn` is set (default `enforce`), a keyless call is processed as before and answered with `Deprecation: true` and `Link: <…/docs/api/README.md#idempotency>; rel="deprecation"`. A `legacy` request whose process crashed between the effect and the stored response blocks the key for `API_IDEMPOTENCY_PENDING_TTL_SECONDS` (300 s); a retry after that may repeat the effect.
- **Secret-bearing responses are never stored**, so these routes take no key: `POST /api-keys`, `POST /smtp-connectors`, `POST /smtp-connectors/{id}/rotate-secret`, `POST /platform/overrides`, `POST /auth/mfa/totp/setup`, `POST /auth/mfa/recovery-codes` (`x-eg-returns-secret: true`, class `sensitive`) and the public authentication routes (single-use tokens, uniqueness and their rate limits protect them).
- **Exception (step 6.2, [ADR-0057](../architecture/adr/0057-idempotent-secret-bearing-routes-redacted-replay.md)):** `POST /webhooks` and `POST /webhooks/{id}/rotate-secret` return a signing secret **and** require an `Idempotency-Key` (`x-eg-secret-replay: redacted`). The stored response is the redacted representation (`secret: null`); a replay returns it with `Idempotency-Replayed: true` and never generates, re-encrypts or reveals a secret. A client that lost the original response rotates the secret with a new key.
- `POST /quarantine/entries/{id}/download-grants` (a single-use grant) and `PUT /quarantine/settings` (a replace with `expectedRowVersion`) take no key.

## Audit of sensitive reads

Every mutation writes an `audit_logs` row in its transaction. Since step 6.1 these **searches** are audited too, one row per search on its first page (without `cursor`): `message.searched` (when `sender`, `headerFrom`, `recipient` or `internetMessageId` is used), `attachment.searched`, `audit.searched`, `platform.audit_searched` (with the target) and `threat_intel.looked_up`. The rows hold the filter names, the filter hash, SHA-256 hashes of identifying values and the result count; never addresses, subjects, hashes in the clear or content. Earlier audited reads are unchanged (quarantine search/preview/download, DLP evidence, BEC export). Detail reads (`GET /messages/{id}`, recipients, attachments, URLs) are not audited: they are metadata behind `message:read`. Every audit row carries `metadata.requestId`.

## Not offered, and deferred

| Area                                                                                                                                                                             | Status                                                                                                                                                          |
| -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Archive, journal search, retention policies, legal holds, export                                                                                                                 | Step 8.1 (the `archive:*` permissions and tables exist; no route)                                                                                               |
| Microsoft 365 / Google Workspace connectors                                                                                                                                      | Step 8.2. **Integration surfaces today:** organization API keys (`/api-keys`), SMTP connectors (`/smtp-connectors`) and signed webhooks (`/webhooks`, step 6.2) |
| Admin-portal screens for webhooks, delivery history and preferences                                                                                                              | Steps 7.x (the API is ready)                                                                                                                                    |
| Webhook events for SMTP-time refusals, per-recipient deliveries, URL clicks, DLP incidents; payload version 2; custom headers or mTLS; an egress proxy; SMS, chat or push alerts | Not offered in 6.2 ([Webhooks](#webhooks-webhooks-tag-step-62)); archive events 8.1, connector events 8.2                                                       |
| Deployment manager                                                                                                                                                               | Step 8.3                                                                                                                                                        |
| `delivery_routes` management                                                                                                                                                     | Not offered: no service reads the table (inbound destinations are `/domains/{id}/destinations`, outbound relay is SMTP connectors)                              |
| Tenant threat indicators, IP/domain/URL reputation, brand lists                                                                                                                  | Not offered: no engine reads tenant rows; brand lists are code constants. Use the lookup, BEC trusted senders, DLP exceptions and policy conditions             |
| Prices, invoices, payments, subscriptions                                                                                                                                        | Not offered: no such data exists (`pricing: null`)                                                                                                              |
| Total counts, offsets, field selection, ETags, bulk message export                                                                                                               | Not offered (unbounded at scale; field selection and ETags may come with the portal, 7.x)                                                                       |
| Signing the v0 cursors                                                                                                                                                           | Follow-up (14.1 or a 7.x need)                                                                                                                                  |
| `sort` and the shared filter operators on the 33 v0 lists                                                                                                                        | Not offered in 6.1: fixed order and module-specific filters ([Filtering and sorting](#filtering-and-sorting)); follow-up with the portal (7.x)                  |

## Changelog

### Step 7.1 (2026-11-13)

Additive only: 3 new operations (269 in total) under the `reports` tag — `GET /reports/delivery`, `GET /reports/processing` and `GET /reports/top-domains` (`report:read`, API keys accepted, class `expensive`, cached, `503 report_timeout`) — and the new field `outcomes` (verdict × action matrix) on `GET /reports/threats`. No existing field or operation changed. Internal only: the trusted client-IP forwarder headers of the admin portal ([Clients behind the admin portal](#clients-behind-the-admin-portal-internal)).

### Step 6.2 (2026-11-13)

Additive only: 17 new operations (266 in total) under the `webhooks` and `notifications` tags — webhook subscriptions with signed deliveries (`EG-Signature`, secret shown once, rotation with overlap), the event catalogue, the delivery history with attempts, single and range replays, test pings, security-alert settings and the personal preference center. New permission `webhook:read` (organization administrators, security analysts, compliance auditors); `webhook:manage` now gates the webhook mutations. `POST /webhooks` and `POST /webhooks/{id}/rotate-secret` are the two secret-bearing routes that take an `Idempotency-Key`, with a redacted replay (ADR-0057). No existing operation changed (the snapshot test compares every operationId).

### Step 6.1 (2026-11-12)

Two contract changes for existing clients (pre-GA; no `/api/v2`):

1. **Unknown request fields are rejected.** Every body and query schema is strict: a field the documented schema does not define is `400 validation_failed` (`"<path>: Unrecognized key"`) instead of being silently dropped. Nothing that was accepted changes meaning.
2. **`Idempotency-Key` is required** on the 22 `legacy` sensitive mutations listed under [Idempotency](#idempotency) (`400 idempotency_key_required` without it). `API_IDEMPOTENCY_LEGACY_MODE=warn` keeps the old keyless behaviour with `Deprecation` headers during the transition.

Additive: every error carries `code` and `requestId`; every response carries `X-Request-Id`, authenticated responses `RateLimit-*`; per-principal, per-tenant and class rate limits (`429 rate_limited` with `scope`); 20 new operations (messages, recipients, attachments, URLs and clicks, suppressions, audit logs, reports, usage, billing, threat lookup); the probes left the public OpenAPI document (they keep working); `/api/metrics`, `/api/health/*`, `/api/docs` are `404`.

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
