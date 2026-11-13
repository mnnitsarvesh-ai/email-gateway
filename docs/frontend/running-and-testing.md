# Running and testing the admin portal

How to run `apps/admin-portal` locally (development, fixture mode, production build), its configuration, and its three test layers: unit/component tests (Vitest), the end-to-end suite against the real stack (`tests/portal-e2e`, Playwright) and the image checks. Architecture: [ADR-0058](../architecture/adr/0058-admin-portal-architecture.md); design system: [design-system.md](design-system.md); pages: [page-inventory.md](page-inventory.md); operations: [runbook](../runbooks/admin-portal.md).

## Ports on this machine

| Process       | Port        | Notes                                                                                                                 |
| ------------- | ----------- | --------------------------------------------------------------------------------------------------------------------- |
| admin portal  | 3001        | `next dev` or `next start` on the host, or the Compose `admin-portal` service (`127.0.0.1:${ADMIN_PORTAL_HOST_PORT}`) |
| api           | 3200        | Host process with `HTTP_PORT=3200`, or the Compose `api` service (`127.0.0.1:${API_HOST_PORT}:3000`); 3000 is taken   |
| MySQL / Redis | 3307 / 6390 | Writer; replica on 3308 (`.env` overrides)                                                                            |

Only one process can hold 3001 and 3200: stop the Compose `api`/`admin-portal` containers (`docker compose stop api admin-portal`) before running them on the host. Use `http://localhost:3001`, not `127.0.0.1`: the BFF compares the `Origin` with `PORTAL_PUBLIC_URL`.

## Configuration

The portal reads the repository `.env` (`--env-file-if-exists=../../.env`); keys and bounds are in `apps/admin-portal/src/server/config.ts` and §3.5 of the [design note](../plan/steps/20-admin-portal.md), section "Admin portal (step 7.1)" of `.env.example`:

| Key                           | Local value             | Meaning                                                                                                    |
| ----------------------------- | ----------------------- | ---------------------------------------------------------------------------------------------------------- |
| `API_INTERNAL_URL`            | `http://localhost:3200` | Upstream api origin (Compose: `http://api:3000`)                                                           |
| `PORTAL_PUBLIC_URL`           | `http://localhost:3001` | Origin check and cookie names (`eg_session` on http in `APP_ENV=local\|ci`, `__Host-eg_session` on https)  |
| `PORTAL_SESSION_KEY`          | generated (64 hex)      | AES-256-GCM key sealing the session cookie (`_FILE` accepted)                                              |
| `PORTAL_SESSION_KEY_PREVIOUS` | empty                   | Unseal-only key during a rotation                                                                          |
| `API_TRUSTED_FORWARDER_TOKEN` | generated               | Shared with the api: the BFF forwards the browser's IP (ADR-0060); required when `NODE_ENV=production`     |
| `PORTAL_TRUST_PROXY_HOPS`     | `0`                     | Hops in `X-Forwarded-For` before the portal (1 behind the Ingress; 0 allowed only for `APP_ENV=local\|ci`) |
| `PORTAL_API_TIMEOUT_MS`       | `15000`                 | Upstream timeout                                                                                           |
| `PORTAL_DEV_MOCKS`            | `disabled`              | `enabled` only with `NODE_ENV=development` (fixture mode)                                                  |

The portal defines no `NEXT_PUBLIC_*` variable; no secret reaches the browser (a build-output test greps `.next/static`).

## Development

```bash
pnpm --filter @email-gateway/api build                       # once, or after api changes
(cd apps/api && HTTP_PORT=3200 node --env-file=../../.env dist/main.js)
pnpm --filter @email-gateway/admin-portal dev                 # http://localhost:3001
```

The first platform administrator is created from the command line (README "First login (local)"); platform users must enroll in MFA at their first login (`/mfa/enroll`).

**Fixture mode** (no api needed): `PORTAL_DEV_MOCKS=enabled pnpm --filter @email-gateway/admin-portal dev`; sign in as `<role key>@example.com` with any password (details in [design-system.md](design-system.md#dev-fixtures)). The top bar shows **DEV FIXTURES**. Production builds refuse the mode and contain no fixture code.

Never run `next build` while a `next dev` of the same tree is running: both write `apps/admin-portal/.next` and the dev server then fails with missing chunks (observed by WP4/WP5). Stop the dev server first, or build a copy.

## Production build on the host

```bash
pnpm --filter @email-gateway/admin-portal build   # api:check (drift) → next build → assert-no-mock-layer
cd apps/admin-portal && NODE_ENV=production node --env-file=../../.env node_modules/next/dist/bin/next start --port 3001
```

`next start` prints a warning because the build uses `output: 'standalone'`; it serves the same build. The image runs `node apps/admin-portal/server.js` from the standalone output instead.

## Unit and component tests

```bash
pnpm --filter @email-gateway/admin-portal test        # Vitest, jsdom, Testing Library, MSW, axe-core
pnpm --filter @email-gateway/admin-portal typecheck   # includes the OpenAPI drift check
pnpm --filter @email-gateway/admin-portal lint
```

56 test files / 601 tests at the end of step 7.1. Every page is tested for loading, empty, error, success, URL filters, hidden actions, contract-valid form bodies and axe; the kit is described in [design-system.md](design-system.md#testing-pages). After an OpenAPI snapshot change run `pnpm --filter @email-gateway/admin-portal api:generate`.

## End-to-end suite (`tests/portal-e2e`)

Playwright 1.64.1 (pinned exactly, the version of `playwright-core` in `apps/url-browser-worker`) with `@axe-core/playwright` 4.14.0, Chromium only, against the real api, MySQL writer and replica, Redis and MinIO, and the portal production build. It is **not** part of `pnpm test` or `pnpm test:e2e`; run it with `pnpm test:portal`.

### One-time browser install

```bash
pnpm --filter @email-gateway/portal-e2e browsers:install   # playwright install chromium (pinned revision 1248)
```

This is the **only** step that downloads a browser (into the default cache, `~/Library/Caches/ms-playwright` on macOS, `~/.cache/ms-playwright` on Linux). The test script sets `PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD=1` and the global setup fails with this instruction when the pinned Chromium is missing; a test run never downloads anything.

### Running

1. Infrastructure up (MySQL writer + replica, Redis, MinIO, RabbitMQ; the policy-engine container if you want the release execution asserted).
2. The api on the host, with 60-second access tokens (the session-expiry tests idle past the expiry), DNS only through the local `dns-sink` (domain verification lookups of the reserved `.test` names stay on the machine) and the **shipped** `expensive` budget (`API_RATE_EXPENSIVE_PER_MINUTE` 60; the dashboard makes five report calls per load, so the default allows 12 loads a minute). Do not raise it for the suite: the dashboard must work at the shipped default (step 7.1 closing round). The rate limits themselves are tested by the api suites:
   ```bash
   (cd apps/api && HTTP_PORT=3200 AUTH_ACCESS_TOKEN_TTL_SECONDS=60 DNS_SERVERS=127.0.0.1:1053 \
     node --env-file=../../.env dist/main.js)
   ```
   Alternatively, run the suite against the Compose `api` and `admin-portal` containers (the images under test). Recreate `api` for the run with a Compose override file that sets the same two variables, using `DNS_SERVERS: "172.31.250.53"` (dns-sink on `mailtest`) and adding `mailtest` to the api's networks. Afterwards, recreate `api` without the override.
3. The portal production build on 3001 (above), or the Compose `admin-portal` container.
4. `pnpm test:portal` (builds `@email-gateway/database`, typechecks the package and runs `PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD=1 playwright test`).

The global setup asserts the pinned browser, probes `GET /health/ready` (api) and `GET /api/health` (portal), then seeds. Useful variants:

```bash
pnpm --filter @email-gateway/portal-e2e test -- --project=desktop specs/dashboard.spec.ts
pnpm --filter @email-gateway/portal-e2e test -- --headed --retries=0 -g "platform override"
pnpm --filter @email-gateway/portal-e2e seed         # seed only (prints counts, never credentials)
pnpm --filter @email-gateway/portal-e2e seed:clean   # remove the run's data
```

### Seeding

`tests/portal-e2e/seed` (idempotent; the previous run is removed first): organizations `e2e-portal-alpha` and `e2e-portal-beta` (standard plan, limits, features, deployment, `mfa_required` false); domains `alpha.e2e-portal.test` (+ a deleted `old.alpha.e2e-portal.test`) and `beta.e2e-portal.test`; users of every role in alpha (`organization_admin`, `security_analyst`, `read_only_user`, `quarantine_reviewer`, `domain_admin`, `mailbox_user` with the mailbox address, `mfa-admin` without MFA, an MFA `approver`), 32 more alpha users for pagination, a beta administrator and a `platform_admin` of the platform organization (MFA required: enrolled through the UI by the first spec that signs in); 382 alpha and 24 beta messages over the last six days with directions, verdicts, actions, domain ids, risk scores, recipients, deliveries in several statuses, initial scan rounds and URL clicks; quarantine entries in several states (one whose release needs an approver, one with a sanitized HTML part and an EML in MinIO), pending approval requests, audit rows, and one webhook per tenant created through the api. It waits until the replica has the rows. Passwords are generated per run and kept in memory and in `tests/portal-e2e/.auth/state.json` (git-ignored, mode 0600, excluded from the Docker build context); the dashboard spec compares the widgets with figures computed from the seed plan (`seed/plan.ts`), not from the api.

The global teardown removes the run's data again (both organizations, the e2e platform user, the MinIO objects and the state file) so the shared database looks as before the run (other suites count platform users); `E2E_KEEP_DATA=1` keeps it for debugging. Cleanup follows the api integration helpers' order (quarantine purge order, message graph, `Fixtures.cleanup`); partitioned tables are deleted with a predicate on their partition column; MinIO objects under `org/<organizationId>/`. `audit_logs` rows stay (append-only by policy).

### What the specs cover

| Spec                 | Covers                                                                                                                                                                                                                                                                                                            |
| -------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `auth.spec.ts`       | Password login, logout, login redirect, wrong password; MFA enabled in Settings → Security from the displayed key (RFC 6238 helper), TOTP login, recovery code; forced platform enrollment; silent refresh after > 60 s idle; parallel requests and two tabs at expiry; sign out everywhere from a second browser |
| `navigation.spec.ts` | Five roles: visible navigation = gates evaluated from `x-eg-permissions` of the snapshot and `GET /auth/me`; `/` lands on the first entry; hidden pages show the 403 page; hidden actions                                                                                                                         |
| `isolation.spec.ts`  | Beta ids (domain, message, webhook, entry, approval) look exactly like missing ids for an alpha admin; no beta data in alpha lists; platform override with reason, banner, target data, end, audit row                                                                                                            |
| `pages.spec.ts`      | Every page, tab and emailed route renders seeded data with no error state and passes axe (serious/critical); unavailable states of 7.2, 7.3, 8.1, 8.2, 8.3 and the "Not offered" states                                                                                                                           |
| `pagination.spec.ts` | Users (25), messages (50), audit logs (25): Next/Previous, no repeated rows, Previous restores page 1                                                                                                                                                                                                             |
| `filters.spec.ts`    | Domains (q, status), quarantine (state, reason, cursor reset), audit (exact action, prefix), explorer (direction, verdict)                                                                                                                                                                                        |
| `crud.spec.ts`       | Users invite → roles → disable → delete; domain onboarding to DNS, verify pending, delete; webhook create (secret once) → edit → test delivery recorded → delete                                                                                                                                                  |
| `quarantine.spec.ts` | Reviewer requests the release, a second (MFA) admin approves, states, release status (executor), audit rows; sanitized preview; download grant → `message-<entryId>.eml.bin`, single use (`410`)                                                                                                                  |
| `responsive.spec.ts` | Desktop 1440×900, tablet 834×1112, mobile 390×844: sidebar / rail / drawer (focus trap, focus return), no horizontal page overflow on any top-level page, tables as cards on mobile                                                                                                                               |
| `dashboard.spec.ts`  | The 12 widgets equal the figures computed from the seed for the last 7 days                                                                                                                                                                                                                                       |

Every test runs under one fixture (`support/fixtures.ts`): each request whose origin is not `http://localhost:3001` is aborted and fails the test (the browser never reaches the api, a CDN or the internet); `securitypolicyviolation` events and uncaught page errors fail the test. Each test sends its own `X-Forwarded-For` from the documentation ranges; with `PORTAL_TRUST_PROXY_HOPS=0` (local/ci only) the BFF forwards it through the trusted forwarder, so tests get separate per-IP login budgets at the api, as separate browsers would.

### Debugging

- `pnpm --filter @email-gateway/portal-e2e test -- --debug -g "<title>"` (inspector) or `--headed`.
- Failures keep a trace and a screenshot in `tests/portal-e2e/test-results/` and an HTML report in `playwright-report/` (both git-ignored): `pnpm --filter @email-gateway/portal-e2e exec playwright show-trace <trace.zip>`. **Traces and `error-context.md` page snapshots contain the run's generated test passwords** (typed into the login form); they are synthetic, replaced at the next seed, and must not be shared outside the machine.
- Session problems: `GET http://localhost:3001/bff/session` shows the session state (no tokens); the api log shows `/auth/refresh` calls.
- A spec that fails only in the full run usually depends on the first page of a list that the run itself grows (audit rows): filter by action.

### CI: pinned container instead of the browser cache

In CI run the suite inside the Playwright image of the same version, pinned by digest, so no browser is downloaded at run time:

```
mcr.microsoft.com/playwright:v1.64.1-noble@sha256:<digest>
```

The digest has **not been verified** in step 7.1 (the image was not pulled on this machine); resolve it once with `docker buildx imagetools inspect mcr.microsoft.com/playwright:v1.64.1-noble` and record it here and in the CI workflow. The job needs the stack services (MySQL writer + replica, Redis, MinIO), the api and the portal as above.

## Image

```bash
docker compose --profile apps build admin-portal   # alone; never in parallel with other images
```

The image build runs the package `build` script: the OpenAPI drift check (`api:check: generated client matches docs/api/openapi.json`), `next build` and `assert-no-mock-layer` (`no dev fixture code in .next`). Checks done in step 7.1: the marker `eg-dev-mock-layer-7f3a9c` is absent from the whole image filesystem; the container runs as `node` (uid 1000) with a read-only root filesystem (`/tmp` and `.next/cache` writable), the `HEALTHCHECK` reports healthy, and `/login` carries the CSP and security headers.
