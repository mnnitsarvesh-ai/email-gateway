# Runbook: admin portal

Operating `apps/admin-portal` (step 7.1): a Next.js 15 application whose same-origin BFF (`/bff/*`) holds the api tokens in a sealed httpOnly cookie and forwards to the api over the internal network ([ADR-0058](../architecture/adr/0058-admin-portal-architecture.md), [ADR-0060](../architecture/adr/0060-portal-ingress-and-trusted-client-ip-forwarding.md), [design note](../plan/steps/20-admin-portal.md)). Local commands: [running and testing](../frontend/running-and-testing.md). Pages: [page inventory](../frontend/page-inventory.md).

Contents: [deploy](#deploy) · [configuration and secrets](#configuration-and-secrets) · [session key rotation](#session-key-rotation) · [forwarder token rotation](#forwarder-token-rotation) · [health checks](#health-checks) · [logs](#logs) · [CSP problems](#csp-problems) · [login problems](#login-problems) · [refresh and session expiry](#refresh-and-session-expiry) · [rollback](#rollback)

## Deploy

- **Image:** `infrastructure/docker/admin-portal.Dockerfile` (build alone: `docker compose --profile apps build admin-portal`). The build runs the OpenAPI drift check (a changed `docs/api/openapi.json` fails the build until `pnpm --filter @email-gateway/admin-portal api:generate` and a portal that compiles against it), `next build`, and `assert-no-mock-layer` (fails when dev fixture code reached `.next`). Runtime: `node:22-bookworm-slim`, `tini`, user `node` (uid 1000), port 3001, `HEALTHCHECK` on `/api/health`, standalone output (`node apps/admin-portal/server.js`).
- **Compose:** service `admin-portal` (profile `apps`), `127.0.0.1:${ADMIN_PORTAL_HOST_PORT:-3001}:3001`, `API_INTERNAL_URL=http://api:3000`, depends on a healthy api; requires `PORTAL_SESSION_KEY` and `API_TRUSTED_FORWARDER_TOKEN` (`:?`).
- **Kubernetes:** `infrastructure/kubernetes/base/admin-portal.yaml`: Deployment (non-root 1000, read-only root filesystem, `/tmp` and `.next/cache` emptyDirs, probes on `/api/health`), Service :80, HPA, PDB and the Ingress `admin-portal` (`Prefix /` on the portal host, distinct from the api host; ADR-0060). Secrets `email-gateway-admin-portal-session` (`key`, optional `previous-key`; portal only, `PORTAL_SESSION_KEY_FILE`) and `email-gateway-api-trusted-forwarder` (`token`; api and portal, `API_TRUSTED_FORWARDER_TOKEN_FILE`); `PORTAL_TRUST_PROXY_HOPS: '1'`, `PORTAL_API_TIMEOUT_MS: '15000'`, `PORTAL_PUBLIC_URL` from the ConfigMap. Rendered with `kubectl kustomize` (saas and dedicated, 123 documents each); **not applied to a cluster** in step 7.1.
- **Order:** api first (the portal's generated client must match the api's OpenAPI document), then the portal. The portal holds no data-store credential and needs no migration.

## Configuration and secrets

| Key                                     | Rule                                                                                                                                                      |
| --------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `API_INTERNAL_URL`                      | Internal api origin. Never the public api host (the BFF must reach the api without the api Ingress)                                                       |
| `PORTAL_PUBLIC_URL`                     | The exact browser origin (scheme, host, port): the CSRF `Origin` check and the cookie names depend on it. `https` required in production                  |
| `PORTAL_SESSION_KEY` (`_FILE`)          | 64 hex. Seals the session, MFA-challenge and override cookies (AES-256-GCM)                                                                               |
| `PORTAL_SESSION_KEY_PREVIOUS` (`_FILE`) | Unseal-only key during a rotation                                                                                                                         |
| `API_TRUSTED_FORWARDER_TOKEN` (`_FILE`) | 32–256 characters, same value as the api's; the portal refuses to start without it when `NODE_ENV=production`                                             |
| `PORTAL_TRUST_PROXY_HOPS`               | Proxies in front of the portal that append to `X-Forwarded-For` (Ingress: 1). `0` is refused outside `APP_ENV=local\|ci` (the client could choose its IP) |
| `PORTAL_API_TIMEOUT_MS`                 | Upstream timeout (≥ `REPORTS_QUERY_TIMEOUT_MS` + margin)                                                                                                  |
| `PORTAL_DEV_MOCKS`                      | Must be `disabled` (the config and `next.config.ts` refuse `enabled` outside `NODE_ENV=development`)                                                      |

No `NEXT_PUBLIC_*` variable exists; no key reaches the browser.

## Session key rotation

The session cookie is sealed with `PORTAL_SESSION_KEY`; `PORTAL_SESSION_KEY_PREVIOUS` is accepted for unsealing only.

1. Generate a key: `node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"`.
2. Kubernetes: set Secret `email-gateway-admin-portal-session` to `key=<new>`, `previous-key=<old>`; `kubectl rollout restart deployment/admin-portal -n email-gateway`. Locally: `PORTAL_SESSION_KEY_PREVIOUS=<old>`, `PORTAL_SESSION_KEY=<new>` in `.env`, restart the portal.
3. Existing sessions keep working; each refresh (at the latest after `AUTH_ACCESS_TOKEN_TTL_SECONDS`) reseals with the new key. After the refresh-token lifetime (`AUTH_REFRESH_TOKEN_TTL_SECONDS`, 7 days by default) remove `previous-key` and restart again.
4. **Suspected key leak:** rotate **without** keeping the previous key. Every portal user is signed out (cookies no longer unseal; the BFF treats them as absent). Revoke api sessions as needed (users: Settings → Security → sign out everywhere; administrators: Users → sessions).

## Forwarder token rotation

`API_TRUSTED_FORWARDER_TOKEN` is shared by the api and the portal; the procedure, the alert `ApiTrustedForwarderRejected` and the metric `api_trusted_forwarder_total{outcome}` are in [api rate limits and reports → trusted forwarder](api-rate-limits-and-reports.md#trusted-client-ip-forwarder-admin-portal). Summary: update Secret `email-gateway-api-trusted-forwarder`, restart **api and admin-portal**; during the rollout some requests are `rejected` and use the portal's address (shared per-IP limits for a minute), nothing fails.

## Health checks

| Check                                         | Meaning                                                                                                                                                      |
| --------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `GET /api/health` → `{ service, status: ok }` | Portal process alive (liveness and readiness; no api call, so an api outage does not restart portal pods)                                                    |
| `GET /bff/session` (no cookie)                | `{ authenticated: false, … }`: the BFF and its config load                                                                                                   |
| Dashboard platform card                       | For `platform:operations` holders: the api's `/health/ready` checks through `GET /bff/platform/health`                                                       |
| `curl -sI https://<portal>/login`             | `Content-Security-Policy` with a nonce, `X-Frame-Options: DENY`, `X-Content-Type-Options`, `Referrer-Policy`, `Permissions-Policy`, COOP/CORP, HSTS on https |

## Logs

The BFF writes JSON lines (pino-compatible fields, `service: "admin-portal"`, `src/server/log.ts`) for: upstream failures (`upstream call failed`, `kind` `timeout`/`unavailable`, method, correlation id), unexpected token or override responses from the api, an over-budget session cookie, an override that does not fit (ended), logout/override-end failures (cookies cleared anyway) and unhandled route errors. Field names that look like secrets (`token`, `cookie`, `password`, `secret`, `authorization`, `code`, `key`) are redacted by the logger; tokens, cookies, bodies and recovery codes are never passed to it. Correlate a user-reported `requestId` (shown in every error state with a copy button) with the api logs. Next.js server errors appear on stdout of the portal container; a dev-fixture warning appears only in development.

## CSP problems

The policy is set per request by `src/middleware.ts`: `script-src 'self' 'nonce-…' 'strict-dynamic'` (no `'unsafe-eval'` outside development), `style-src 'self' 'unsafe-inline'`, `connect-src 'self'`, `frame-ancestors 'none'`, `form-action 'self'`, `base-uri 'none'`, `object-src 'none'`.

- **Symptom:** a blank page or a broken widget, and a `Refused to …` message in the browser console. The e2e suite fails on any `securitypolicyviolation`.
- `script-src eval`: a library probed `new Function` (zod 4 does unless configured): zod runs `jitless` through `src/instrumentation-client.ts`, which must stay first. Never add `'unsafe-eval'` to production.
- `connect-src`: the browser tried to reach another origin (the api host directly, a CDN, a font host). Every call must go to `/bff/*`; fonts are self-hosted.
- Missing nonce on an inline script: a page was statically rendered or cached by a proxy. Console routes are `force-dynamic`; make sure no CDN caches HTML (`Cache-Control: private, no-store`).

## Login problems

| Symptom                                                         | Cause and fix                                                                                                                                                                                                                                                                 |
| --------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `403 csrf_failed` on sign-in                                    | The browser origin differs from `PORTAL_PUBLIC_URL` (e.g. `127.0.0.1` vs `localhost`, a different port or host). Fix the URL or the setting                                                                                                                                   |
| Many users get `429` on login at the same time                  | The forwarder is broken and every user shares the portal's per-IP budget (login 20/min, failure block after 50 in 15 min): check `api_trusted_forwarder_total{outcome}` (`rejected` = token mismatch, `invalid_ip` = wrong `PORTAL_TRUST_PROXY_HOPS`) and rotate/fix as above |
| One user gets `429` / "Try again in N s"                        | Their own IP or account is throttled (authentication.md lockout rules); the form shows the `Retry-After` countdown                                                                                                                                                            |
| Login works, then every page sends the user back to `/login`    | Cookies are not stored: `Secure` cookies on plain http other than `localhost`, a proxy stripping `Set-Cookie`, or `__Host-` cookies with a `Domain` attribute added by a proxy                                                                                                |
| A platform user lands on `/mfa/enroll` every time               | The platform organization requires MFA and the user has not enrolled; enrolling refreshes the session (`force`) and clears the requirement                                                                                                                                    |
| "Starting an override needs an MFA session"                     | The operator's session is not MFA-authenticated (e.g. it started before MFA was enabled): sign out and sign in with the authenticator code                                                                                                                                    |
| `502 upstream_unavailable` / `504 upstream_timeout` on any call | The portal cannot reach `API_INTERNAL_URL` or the api is slower than `PORTAL_API_TIMEOUT_MS`                                                                                                                                                                                  |
| `502 session_cookie_too_large`                                  | The api returned tokens larger than the 3,800-byte budget (unusually long issuer/audience or claims); shorten them                                                                                                                                                            |

## Refresh and session expiry

- The browser refreshes once for all tabs (in-memory single flight plus Web Locks): proactively before expiry while visible (60 s before for the default 600 s token, at half the remaining lifetime for shorter ones), and reactively when the BFF answers `401 access_token_expired` (or, forced past the BFF's "fresh enough" short-circuit, after an api `401 unauthorized`, so a revoked session ends at the next request); the failed request is retried once. Sign-out, sign-out-everywhere and override start/end take the same lock and refresh an expired access token server-side before calling the api, so a refresh never re-creates a session after a logout and a sign-out after a long-hidden tab still ends the api session.
- **"The server session could not be ended" after sign-out** (`502 logout_incomplete`, BFF log `api logout failed` / `api logout unreachable` / `api logout: refresh failed`): the cookies were cleared but the api did not confirm the logout (api down or erroring). The api session ends at its refresh-token expiry; the user can sign in and use "Sign out everywhere", or an administrator can revoke the sessions.
- **Unexpected logouts with "Your session expired":** the refresh was refused (`401` from `/auth/refresh`): the refresh token expired (`AUTH_REFRESH_TOKEN_TTL_SECONDS` idle / `AUTH_SESSION_MAX_AGE_SECONDS` absolute), the user or an administrator signed out everywhere, the account was disabled, or **refresh-token reuse** was detected (two refreshes of one token, e.g. a browser that does not support Web Locks with many tabs, or a proxy that replays requests). Reuse revokes the whole session family; the api logs and audits it.
- **Many refreshes per minute in the api log:** more than about two per tab per minute means the proactive timer misbehaves (it is bounded to ≥ 5 s and to half the token lifetime); the api's refresh limit is 60/min per IP.
- **Override ended unexpectedly:** override tokens are never refreshed; at `expiresAt` the BFF drops the override and the user continues as the operator.

## Rollback

The portal is stateless: roll back the Deployment (`kubectl rollout undo deployment/admin-portal -n email-gateway`) or redeploy the previous image tag. Sessions survive when the session key is unchanged. A portal built against a newer OpenAPI document than the running api can call operations the api does not have (`404`); roll the portal back together with the api, or forward the api first.
