# Authentication, sessions and the platform override

This document describes how the control-plane API (`apps/api`) authenticates users and API keys, how sessions live and die, and how platform operators reach customer data. Decisions: [ADR-0016](../architecture/adr/0016-authentication-sessions-rbac.md) and the step design [docs/plan/steps/02-tenants-auth-rbac.md](../plan/steps/02-tenants-auth-rbac.md) (D4–D10, D13, D14). Code: `apps/api/src/modules/auth/`.

All paths below are under `/api/v1`.

## Credentials at a glance

| Credential        | Format                               | Stored as                                                 | Lifetime                                                              |
| ----------------- | ------------------------------------ | --------------------------------------------------------- | --------------------------------------------------------------------- |
| Password          | 12–128 characters, NFKC-normalized   | Argon2id (`m=19456,t=2,p=1` or higher), rehashed on login | until changed or reset                                                |
| Access token      | JWT, HS256, `kid: current`           | not stored                                                | `AUTH_ACCESS_TOKEN_TTL_SECONDS` (default 600, at most 900)            |
| Refresh token     | `egr_` + 32 random bytes (base64url) | SHA-256 in `user_sessions.refresh_token_hash`             | single use; the session idles out after 7 days and ends after 30 days |
| Single-use tokens | `egt_` + 32 random bytes             | SHA-256 in `user_tokens.token_hash`                       | reset 30 min, email verification 24 h, invitation 7 days              |
| MFA challenge     | `egt_…` (`mfaToken`)                 | SHA-256 as the Redis key `auth:mfa:<hash>`                | 300 s, at most 5 attempts                                             |
| TOTP secret       | 160-bit, base32                      | AES-256-GCM (`DATA_ENCRYPTION_KEY`, AAD `mfa:user:<id>`)  | until MFA is disabled or reset                                        |
| Recovery codes    | 10 × `xxxxx-xxxxx` (base32)          | HMAC-SHA256 with `AUTH_TOKEN_PEPPER`                      | single use; regenerating replaces all                                 |
| API key           | `egk_<12 base62>_<32 random bytes>`  | prefix + HMAC-SHA256 with `AUTH_TOKEN_PEPPER`             | `expires_at` (WP4), revocable                                         |

Tokens and passwords never appear in URLs (except the `#token=` fragment of emailed links, which browsers do not send to servers), in logs, or in `audit_logs` / `login_audit_logs`.

## Login

`POST /auth/login { email, password, organization? }`. An email is unique per organization only, so `organization` (a slug) selects the account when the same email exists in several organizations. Without it, the login works only when exactly one non-deleted account in a non-deleted organization has that email; otherwise it fails exactly like a wrong password. The slug only selects the account: the tenant of every later request comes from the authenticated principal, never from the client.

Checks, in order (each path writes exactly one `login_audit_logs` row; `failure_reason` in brackets):

1. Rate limit: 20 requests per minute per client IP → `429` with `Retry-After` (no row: the request never reaches the handler).
2. IP failure block: `AUTH_LOGIN_MAX_IP_FAILURES` (50) failures within `AUTH_LOGIN_FAILURE_WINDOW_SECONDS` (900 s) → `429` [`rate_limited`, `ip_blocked`].
3. Unknown account → a dummy Argon2 verification (same timing), `401` [`unknown_account`].
4. Locked account (`users.locked_until` in the future) → dummy verification, `401` [`locked`, `account_locked`].
5. Invited account without a password → dummy verification, `401` [`not_activated`]. Wrong password → account and IP counters, `401` [`invalid_password`, or `locked`/`lockout_started` when this failure starts a lockout].
6. User not active or deleted, organization not active → `401` [`user_disabled` / `org_inactive`].
7. Hash upgraded if the Argon2 parameters were raised. MFA enabled → `200 { mfaRequired: true, mfaToken, expiresIn }` [`mfa_required`].
8. Success → counters reset, `last_login_at`, a new session, `200` with the token response [`success`].

Every `401` has the body message `Invalid credentials`. The response never says whether the account exists, is locked, or is disabled.

**Token response:** `{ accessToken, tokenType: "Bearer", expiresIn, refreshToken, refreshTokenExpiresAt, sessionId, mfaEnrollmentRequired, user: { id, email, displayName }, organization: { id, slug, name, kind } }`. Refresh tokens travel in JSON bodies only. The admin portal keeps them server-side in its BFF (sealed httpOnly session cookie, a single browser-side refresh coordinator, CSRF): [step 7.1 design P2–P6](../plan/steps/20-admin-portal.md#p2-browser-session-sealed-httponly-cookie-tokens-never-reach-javascript) and [ADR-0058](../architecture/adr/0058-admin-portal-architecture.md).

### Brute-force protection and lockout

| Parameter                           | Default | Meaning                                                              |
| ----------------------------------- | ------- | -------------------------------------------------------------------- |
| `AUTH_LOGIN_MAX_ACCOUNT_FAILURES`   | 5       | wrong passwords or MFA codes within the window that lock the account |
| `AUTH_LOGIN_MAX_IP_FAILURES`        | 50      | failures from one IP within the window that block the IP (`429`)     |
| `AUTH_LOGIN_FAILURE_WINDOW_SECONDS` | 900     | counter window                                                       |
| `AUTH_LOCKOUT_BASE_SECONDS`         | 900     | first lockout                                                        |
| `AUTH_LOCKOUT_MAX_SECONDS`          | 86400   | cap                                                                  |

The _n_-th lockout within 24 hours lasts `min(base × 2^(n−1), max)`: 15 min, 30 min, 1 h, … The counters live in Redis (`auth:fail:acct:<userId>`, `auth:fail:ip:<ip>`, `auth:lockouts:<userId>`); the lock itself is mirrored to `users.locked_until` and `users.failed_login_count`, so the database stays the source of truth. A lockout expires on its own; an administrator unlocks earlier with `PATCH /users/{id}/status { status: "active" }` (identity administration), which calls `LoginThrottleService.clearForUser` to clear both Redis counters and the database columns. A successful password reset also clears the lock.

Other rate limits (per client IP unless noted): MFA verify 20/min; refresh 60/min; password forgot 5 per 15 min **and** 3 per hour per email; password reset, email verify, invitation inspect and accept 20 per 15 min each; email verification resend 10 per hour per IP **and** 3 per hour per user; password change, MFA enable, MFA disable and recovery-code regeneration 10 per 15 min.

### Client IP

The client IP (per-IP limits above, the IP failure block, `login_audit_logs.ip_address`, `audit_logs.source_ip`, session IPs) is Express's `req.ip` with `trust proxy` = `HTTP_TRUST_PROXY` hops (`0` locally, `1` behind the ALB/ingress). `X-Forwarded-For` is never read directly.

**Requests through the admin portal** ([ADR-0060](../architecture/adr/0060-portal-ingress-and-trusted-client-ip-forwarding.md), step 7.1 P5). The portal's BFF calls the api from its own address, which would make every portal user share one per-IP budget (one attacker could block every login) and record the portal in the audit rows. The BFF therefore sends the browser's address in `X-EG-Client-IP` together with `X-EG-Forwarder-Token` = `API_TRUSTED_FORWARDER_TOKEN` (32–256 characters, `_FILE` accepted; a Secret mounted only in the api and the portal). The api's first middleware compares SHA-256 digests of the token in constant time; on a match and a valid IPv4/IPv6 literal (IPv4-mapped IPv6 normalized) that address becomes the request's `req.ip`, so everything above uses the browser's address. A missing or wrong token or an invalid address is ignored (the `trust proxy` address stays), counted in `api_trusted_forwarder_total{outcome}` and logged without values; both headers are always removed before anything else reads the request. An empty token turns the forwarder off (startup warning in production). `X-Forwarded-For` hop counting cannot replace this: the api is reached through its own ingress (one hop) and directly by the portal (zero hops) at the same time. A leaked token affects per-IP limits and IP attribution only; per-principal and per-tenant limits never use the IP. Rotation: [runbook](../runbooks/api-rate-limits-and-reports.md#trusted-client-ip-forwarder-admin-portal).

## Access tokens

HS256 JWTs signed with `AUTH_JWT_SECRET` (≥ 64 characters). Claims: `iss` (`AUTH_JWT_ISSUER`), `aud` (`AUTH_JWT_AUDIENCE`), `sub` (user public id), `org` (home organization public id), `sid` (session id), `typ: "access"`, `amr` (`["pwd"]` or `["pwd","otp"]`), `jti`, `iat`, `exp`, optional `mfa_enroll: true`, optional `ovr` (override id). Verification pins the algorithm, issuer and audience and allows 30 s of clock skew; `alg: none` and other algorithms are refused.

**Key rotation:** set the new secret as `AUTH_JWT_SECRET` and the old one as `AUTH_JWT_PREVIOUS_SECRET`; tokens signed with either verify. Remove the previous secret after one access-token lifetime (plus the longest override, at most 240 min).

For every request, `AuthGuard` verifies the token, rejects a deny-listed `sid`, and loads the principal snapshot (user status, organization status and kind, MFA state, permission keys). The snapshot is cached in Redis for 60 s (`auth:principal:<userPublicId>`) and is only valid while its organization version matches `auth:orgver:<orgId>` and its user version matches `auth:userver:<userPublicId>`. Status, role, MFA and organization changes invalidate it immediately (`PrincipalCacheService`): an organization change INCRs the organization version; a user change writes a fresh random nonce as the user version (kept for an hour, longer than any cache entry) and deletes the entry. On a cache miss both versions are read **before** the database, so a request that read the database just before a change commits writes an entry carrying the old version, which is never served. API-key records follow the same scheme (`auth:apikeyver:<prefix>`).

## Sessions, rotation and reuse detection

A session is a refresh-token family (`user_sessions.family_id`, exposed as `sessionId`). Each issued refresh token is one row; exactly one row of a live family is unrevoked.

- **Refresh** (`POST /auth/refresh { refreshToken }`) runs in one writer transaction: the presented row is marked `rotated` with a conditional update and a new row is inserted in the same family (idle expiry `now + AUTH_REFRESH_TOKEN_TTL_SECONDS`, never past the family's `absolute_expires_at`). The new access token re-evaluates `mfa_enroll`.
- **Reuse detection:** presenting a token that was already rotated means it was copied. The whole family is revoked (`reuse_detected`), its `sid` deny-listed and `audit_logs` gets `auth.refresh_token_reused`; the caller gets `401`, and so does the legitimate holder at their next refresh.
- **Clients must serialize refreshes.** Two concurrent refreshes with the same token look exactly like reuse (the loser of the conditional update triggers it) and end the session. Queue refreshes in the client; refresh shortly before `expiresIn` runs out, not on every `401`.
- Expired, otherwise revoked, or unknown tokens, inactive users and inactive organizations get `401` without revoking anything.

### Revocation

Logout (current session), logout-all, revoking one own session (`DELETE /auth/sessions/{id}`), password change (other sessions), password reset (all), MFA enrollment (other sessions), and the administrative paths (user disable/delete, MFA reset, organization suspension/deletion; identity administration and organizations modules) set `revoked_at`/`revoked_reason` and write `auth:revoked:<sid>` to Redis with a TTL of the access-token lifetime + 60 s. The guard rejects deny-listed sessions, so revocation takes effect on the next request, not when the access token expires.

`GET /auth/sessions` lists the caller's live sessions (`id`, `current`, `authenticatedAt`, `lastUsedAt`, `expiresAt`, `ipAddress`, `userAgent`, `mfaAuthenticated`). It reads the replica, so a session created a moment ago can appear after a short delay.

### Purge

`SessionPurgeService` runs hourly (an `unref()`ed timer, one instance at a time via the Redis lock `jobs:auth-purge`, 55 min) and deletes in batches of 1,000: sessions whose idle expiry passed more than a day ago, single-use tokens expired more than 7 days ago, and `login_audit_logs` rows older than `AUTH_LOGIN_AUDIT_RETENTION_DAYS` (365). `AUTH_BACKGROUND_JOBS_ENABLED=false` disables it (tests, the bootstrap CLI).

## MFA (TOTP)

RFC 6238: SHA-1, 6 digits, 30 s steps, ±1 step accepted. **Replay protection:** the accepted step is stored in `users.mfa_last_used_step` with a conditional update; a code is accepted only for a later step, so each code works once.

- **Enrollment:** `POST /auth/mfa/totp/setup` stores a new encrypted pending secret and returns `{ secret, otpauthUri }` (`409` when MFA is already on). `POST /auth/mfa/totp/enable { code }` verifies it, enables MFA, returns 10 recovery codes once, marks the current session `mfa_authenticated` and revokes every other session (`auth.mfa_enabled`). The access token in hand keeps `amr = ["pwd"]` (claims are fixed at issue); the client refreshes once to get an `amr = ["pwd","otp"]` token, which step-up routes require.
- **Login:** a user with MFA gets an `mfaToken` instead of tokens. `POST /auth/mfa/verify { mfaToken, code }` or `{ mfaToken, recoveryCode }` (exactly one). Each challenge allows 5 attempts and is deleted on success; failures count toward the account lockout. Success creates a session with `mfa_authenticated = true` and `amr = ["pwd","otp"]`.
- **Recovery codes:** single use, case and separator insensitive (`ABCDE FGHIJ` = `abcde-fghij`). `POST /auth/mfa/recovery-codes { code }` replaces all of them (`auth.recovery_codes_regenerated`).
- **Disable:** `POST /auth/mfa/totp/disable { password, code }`; `409` while the organization requires MFA (`auth.mfa_disabled`).
- **Organization policy:** when `organization_settings.mfa_required` is true (always for the platform organization) and the user has not enrolled, login succeeds with `mfaEnrollmentRequired: true` and the principal may only call `GET /auth/me`, `GET /auth/sessions`, the MFA setup/enable endpoints, logout and logout-all; everything else is `403 MFA enrollment required`. The restriction is computed from the current state on every request, so turning the policy on restricts existing tokens immediately and enrolling lifts it immediately.
- **Step-up:** the platform override, organization deletion and the admin MFA reset require an MFA-authenticated session (`403 MFA required`).
- **Key rotation:** set `DATA_ENCRYPTION_KEY_PREVIOUS` to the old key; secrets that only the old key opens are re-encrypted with the new key on their next successful use.

## Password reset, change and email verification

- `POST /auth/password/forgot { email, organization? }` always answers `202`. The lookup and sending happen after the response, so neither the answer nor its timing reveals whether an account matched. Every active account with that **verified** email (in the given organization, if any) receives its own link; issuing a link retires earlier unused reset links of that account. An address set by an administrator (`PATCH /users/{id}`) is unverified until its owner confirms it with the verification link, so a reset link never reaches an address the account owner has not proven.
- `POST /auth/password/reset { token, newPassword }` → `204`; signs the user out everywhere, clears a lockout (`auth.password_reset`). An unknown, used or expired token is `400 Invalid or expired token`.
- `POST /auth/password/change { currentPassword, newPassword }` → `204`; revokes all other sessions (`auth.password_changed`). A wrong current password is `403`.
- Password policy (NIST SP 800-63B): 12–128 characters after NFKC normalization; not the email address or containing its local part; not in the bundled common-password list; not one repeated character. No composition rules.
- `POST /auth/email/verification` sends a verification link for the caller's own unverified address; `POST /auth/email/verify { token }` marks it verified (`auth.email_verified`).

## Invitations

Identity administration creates invited users and calls `InvitationService.createToken(tx, …)` inside its transaction and `sendInvitation(…)` after commit. `POST /auth/invitations/inspect { token }` shows `{ email, organizationName, expiresAt }` without consuming the token; `POST /auth/invitations/accept { token, password, displayName? }` requires the user to still be invited and the organization to be active, sets the password, activates the user and marks the email verified (`user.invitation_accepted`).

## API keys

`X-API-Key: egk_…` authenticates an organization-scoped automation principal (keys are created by identity administration). The guard looks the key up by its 16-character prefix (Redis cache 60 s, writer on a miss, invalidated on revocation and organization changes), compares the HMAC in constant time, and rejects revoked or expired keys, keys of inactive organizations, and organizations without the `api_access` feature. Effective permissions are the key's scopes ∩ tenant permissions, never `apikey:manage`, `role:manage` or `session:manage`. `last_used_at` is updated at most once per minute per key. A request carrying both `Authorization` and `X-API-Key` is `401`. Routes marked user-only (all `/auth/*` self-service routes, the override) answer `403` to API keys.

## Browser sessions in the admin portal (step 7.1)

The admin portal never exposes api tokens to browser JavaScript ([ADR-0058](../architecture/adr/0058-admin-portal-architecture.md), [design P2–P6](../plan/steps/20-admin-portal.md#p2-browser-session-sealed-httponly-cookie-tokens-never-reach-javascript), [runbook](../runbooks/admin-portal.md)):

- **Cookies.** `__Host-eg_session` (`eg_session` on an `http://` origin, allowed only for `APP_ENV=local|ci`): AES-256-GCM sealed JSON with the access and refresh tokens, session id, CSRF token and an active override (`HttpOnly; Secure; SameSite=Strict; Path=/`, ≤ 3,800 bytes), key `PORTAL_SESSION_KEY` (+ unseal-only `PORTAL_SESSION_KEY_PREVIOUS`). `__Host-eg_mfa`: the sealed MFA challenge (≤ 300 s). `__Host-eg_csrf`: the readable double-submit token, rotated with every token pair. Nothing is stored in `localStorage`/`sessionStorage`/IndexedDB.
- **CSRF.** Every non-GET `/bff/*` request must carry the portal's `Origin` (or `Sec-Fetch-Site: same-origin`) and, for session-bearing routes, `X-CSRF-Token` equal to the sealed token; `SameSite=Strict` is the third line.
- **Refresh coordinator.** The BFF proxy never refreshes on its own (it answers `401 access_token_expired`); one coordinator per browser (in-memory single flight + `navigator.locks`) calls `POST /bff/session/refresh`, so the single-use refresh token is never sent twice (reuse detection above would revoke the session). It refreshes proactively before expiry (60 s before for the default 600 s token, at half the remaining lifetime for shorter tokens) and retries a failed request once. Sign-out, sign-out-everywhere and starting or ending a tenant override take the same lock, so a refresh in flight cannot re-create the cookie after a logout (step 7.1 WP6 fix) and these routes may refresh server-side. After an api `401 unauthorized` (a token the BFF still considers fresh) the coordinator forces the refresh past the BFF's "fresh enough" short-circuit, so a revoked session (sign-out everywhere elsewhere, a disabled user) ends at the next request instead of when the access token expires.
- **Session mutations refresh server-side first.** `POST /bff/session/logout`, `/logout-all` and `POST`/`DELETE /bff/session/override` refresh an access token that expired (or expires within 5 s) with the sealed refresh token before calling the api, and set the rotated cookies on every later response. So sign-out really ends the api session and an active override even after a tab slept past the access-token TTL. Logout clears the cookies in every case; when the api session could not be ended it answers `502 logout_incomplete` and the UI says the server session may still be active (a refused refresh token counts as ended). Ending an override treats only `404` as already ended; any other api error (including `401`) keeps the override in the session and is passed through (step 7.1 closing fix).
- **Client IP.** Requests carry the browser's address through the trusted forwarder above (ADR-0060).
- Verified end to end by `tests/portal-e2e` (`auth.spec.ts`): password, TOTP and recovery-code logins, forced enrollment, silent refresh after the 60 s access token of the e2e api expired, parallel requests and two tabs at expiry, sign-out everywhere from a second browser.

## Authorization guards

`AuthGuard` then `PermissionsGuard` run on every route (global `APP_GUARD`s). `@Public()` routes skip both. Every other route must declare `@RequirePermissions(...)`, `@RequireAnyPermission(...)` or `@AuthenticatedOnly()`; a route without a requirement is denied with `403` and an error log (fail closed), and `apps/api/test/route-security.e2e.test.ts` enumerates every route of the running app so such a route cannot ship. Further markers: `@UserOnly()` (API keys get `403`), `@RequireMfa()`, `@AllowDuringMfaEnrollment()`. Guards check permission keys, never role names. The guard also sets `req.tenantScope` (the home organization, the API key's organization, or the override target) and the `tenantId` of the request's log context.

## Platform override (procedure)

Platform operators belong to the platform organization and reach customer data only through an explicit, audited override.

1. Log in with password and TOTP (the platform organization requires MFA).
2. `POST /platform/overrides { organizationId, reason, durationMinutes }` — `organizationId` is the customer organization's public id, `reason` 10–500 characters (a ticket reference), `durationMinutes` 5 to `PLATFORM_OVERRIDE_MAX_MINUTES` (default 30). Requires `platform:tenant_override` and an MFA session; not possible under another override; the target must be a non-deleted customer organization. Audited as `platform.override_started`.
3. Use the returned `accessToken`. Its scope is the target organization, its permissions are the operator's permissions ∩ tenant permissions (all `platform:*` permissions are stripped), it expires with the override and it cannot be refreshed. Every request made with it, including rejected ones, writes `platform.override_request` with the override id, reason, method, route template and status code; mutations carry `metadata.override` in their own audit rows.
4. End it with `DELETE /platform/overrides/{overrideId}` (`platform.override_ended`). Logging out (or any revocation of the operator's session) ends it too, as does removing the operator's override permission.

Managing the organization catalog (`/organizations` with `platform:organizations`) is a platform function, not an override.

## Initial access: the bootstrap CLI

The first platform administrator is created from the command line on a host that can reach the database (the platform organization must exist: `pnpm db:seed`, or `--catalog-only --allow-production` in production):

```bash
pnpm --filter @email-gateway/api build
pnpm --filter @email-gateway/api auth:bootstrap -- --email ops@example.com [--display-name "Ops"] [--additional]
```

It creates (or re-invites) an invited platform user with the `super_admin` role, issues an invitation token and prints the acceptance link **to stdout only** (never to a log). It refuses when an active super admin already exists unless `--additional` is given, and refuses for an existing active or disabled user with that email. It is audited as `user.bootstrap_invited` with actor `system`. The invitee opens the link, sets a password, logs in and must enroll in MFA before anything else. Treat the link like a password: deliver it over a secure channel; it is single use and expires after `AUTH_INVITATION_TTL_SECONDS` (7 days).

## Email delivery and its limitations

Invitation, password-reset and verification emails go through the `EmailSender` port after the database transaction commits. A delivery failure is logged (without the token) and nothing is rolled back; the user can request another email.

- **Relay configured** (`NOTIFY_SMTP_HOST` set): `SmtpEmailSender` submits to the authenticated relay (`NOTIFY_SMTP_PORT`, `NOTIFY_SMTP_SECURE` = `tls` / `starttls` / `none` (local and CI only), `NOTIFY_SMTP_USER` / `NOTIFY_SMTP_PASSWORD`, `NOTIFY_SMTP_FROM`). Certificate verification is always on.
- **Local stack:** the api submits to the internal smarthost `postfix-notify` (`NOTIFY_SMTP_HOST=postfix-notify`, port 25, `NOTIFY_SMTP_SECURE=none` on the private network), which relays to the upstream submission relay (`NOTIFY_RELAY_*`). The smarthost holds the relay credentials (SASL), requires TLS 1.2+ and pins the upstream certificate by its SHA-256 fingerprint (`NOTIFY_RELAY_TLS_FINGERPRINT`), which works with a self-signed relay certificate without disabling verification. It does not pipeline (`smtp_discard_ehlo_keywords = pipelining`), because the current upstream advertises PIPELINING but answers `RCPT TO` before processing `MAIL FROM` (`503 5.5.1`), which breaks nodemailer. Without `NOTIFY_RELAY_HOST` (CI, fresh checkouts) the smarthost accepts and **discards** mail, and logs that it does. A direct relay remains supported through `NOTIFY_SMTP_USER` / `NOTIFY_SMTP_PASSWORD` and `NOTIFY_SMTP_CA_PATH` (extra trusted certificate) for relays that handle pipelining correctly.
- **No relay:** `LogEmailSender` logs the kind, a masked recipient and the subject. Only when `NODE_ENV` is not `production` and `APP_ENV` is `local` or `ci` does it also log `devLink` (the link with the token) so developers can follow it. In production without a relay **emails are not delivered** (a startup warning says so); configure the relay.
- Links are `${PORTAL_PUBLIC_URL}/auth/<accept-invitation|reset-password|verify-email>#token=<token>`. The token is in the URL fragment, which browsers never send to servers or in `Referer`. The admin portal serves these three pages (step 7.1): they read the token from the fragment, remove it from the address bar and call the public operations through the BFF proxy; the token can still be posted to the API directly.
- Tests never send real email: the integration harness replaces the sender with a recording double.

## Redis is fail-closed

Authentication depends on Redis (rate limits, failure counters, MFA challenges, the session deny-list, the principal cache, overrides). When Redis is unavailable, authentication answers `503` instead of skipping a check: nobody can log in or call authenticated routes until it is back. Redis is part of the API readiness probe. Redis is never the source of truth for anything durable: sessions, locks and tokens live in MySQL.

## Audit and logging

- `login_audit_logs`: one row per login or MFA-verification attempt (email attempted, lower-cased; outcome; failure reason; IP; user agent). Never passwords, tokens or codes. Queryable through `GET /audit/login-events` (identity administration).
- `audit_logs` actions written here: `auth.password_changed`, `auth.password_reset`, `auth.email_verified`, `auth.mfa_enabled`, `auth.mfa_disabled`, `auth.recovery_codes_regenerated`, `auth.refresh_token_reused`, `session.revoked`, `session.revoked_all`, `user.invitation_accepted`, `user.bootstrap_invited`, `platform.override_started`, `platform.override_ended`, `platform.override_request`.
- Request bodies are never logged. The logger censors `password`, `secret`, `token`, `authorization`, `cookie`, `accessToken`, `refreshToken`, `mfaToken`, `recoveryCode(s)`, `code`, `newPassword`, `currentPassword`, `key`, `apiKey`, `otpauthUri` and the `X-API-Key` header (top level and one level down). The integration tests capture the app's logs and assert that passwords, tokens, TOTP secrets and recovery codes never appear.

## Implementation notes (deviations from the step design)

These refine the design without weakening it; each is covered by tests.

- The principal cache key is `auth:principal:<userPublicId>` rather than the numeric user id, because access tokens carry the public id. `PrincipalCacheService.invalidateUser(userId)` resolves the public id first.
- An override token additionally requires that its session is still live in MySQL (override tokens can outlive the deny-list TTL) and that the operator still holds `platform:tenant_override`.
- The locked-account path runs a dummy Argon2 verification (the real hash is not checked), so a lock is not revealed by timing. Failed logins of invited users (no password) count toward the IP counter only.
- The per-IP failure block (`429`) carries no `Retry-After` header; the decorator rate limits do.
- Wrong re-authentication input on self-service routes (current password, TOTP code at enable/disable/regeneration) is `403`, not `401`, so clients do not mistake it for an expired session. Invalid single-use tokens are `400 Invalid or expired token`.
- `LoginThrottleService.clearForUser` also clears `locked_until` and `failed_login_count`, not only the Redis counters.
- Additional rate limits beyond D6 on password change, MFA enable/disable and recovery-code regeneration (10 per 15 min per IP) and on verification resend (10 per hour per IP, besides 3 per hour per user).
