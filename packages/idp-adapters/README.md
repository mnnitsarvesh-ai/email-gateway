# @email-gateway/idp-adapters

Account-takeover (ATO) identity-provider adapters of step 8.5
([design note](../../docs/plan/steps/26-ato-provider-adapters.md), ADR-0082 to ADR-0086). This is a
pure library: plain HTTPS clients (no vendor SDK), mappers to normalized provider events,
per-stream cursors, mailbox-state snapshots, provider-confirmed response actions, read-only
capability probes, the permission catalogue and local provider simulators. Runtime dependencies:
`zod`, the built 8.4 port (`@email-gateway/ato-detection`), step 8.2's library
(`@email-gateway/provider-integrations`, used only by `src/bindings/*` and `src/kinds.ts`) and
`@email-gateway/database` (types of the bindings). The simulators import only `node:*`.

**Status (WP1 + WP2 + WP3, 2026-11-20):** the core, the simulator framework, the **Microsoft Entra
ID / Microsoft 365 adapter** (`msgraph-ato/1`), the **Google Workspace adapter** (`gws-ato/1`), the
factory `createIdpAdapter`, the port re-exported from the built 8.4 package (merge note M1; the 8.4
contract kit `describeProviderAdapterContract` passes for both adapters on the simulators) and the
8.2 bindings (`ProviderConnectionBinding` for the ato-worker, `ConnectionDirectory` for the api) are
built and tested. The ato-worker runner, api routes and portal pages that use them are WP4–WP6.
**No real Microsoft or Google endpoint has been called**: live verification needs the product
owner's test tenants and is pending.

## Layout

| Path                          | Content                                                                                                                                                                                                        |
| ----------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `src/port/ato-port.ts`        | Re-exports of the built 8.4 port (types, `providerEventSchema`, `ProviderAdapterError`; PX1 `deviceLabel` added to 8.4) and 8.5's stricter `looksSecretShaped`                                                 |
| `src/port/connection-port.ts` | `ProviderConnectionAccess` (8.2 connections, grants, tokens; §0.3)                                                                                                                                             |
| `src/port/state-ports.ts`     | `RateBudget`, `MailboxStateStore`, `ActionStateStore` (WP4 implements them over Redis and MySQL)                                                                                                               |
| `src/kinds.ts`                | `microsoft_365 → microsoft_entra`, `google_workspace → google_workspace` (compile-time check against 8.2's `IntegrationProvider`)                                                                              |
| `src/bindings/*`              | 8.2 bindings (§0.4): `ProviderConnectionBinding` / `createProviderConnectionBinding` (worker; reader, grant store, token service with R1 options) and `ConnectionDirectory` / `eligibilityOf` (api, read-only) |
| `src/requirements.ts`         | `PERMISSION_REQUIREMENTS` (profiles, permissions per stream and action, licences, notes), `STREAM_ROLES`, `PROVIDER_RETENTION_DAYS`                                                                            |
| `src/config.ts`               | `idpAdapterConfigSchema` / `loadIdpAdapterConfig` over the `ATO_IDP_*` keys                                                                                                                                    |
| `src/core/*`                  | HTTP client (`http`, `errors`), cursor codec, polling windows, hashes, rule traits, snapshot diff, probes and capabilities, binding settings, rate budgets, action helpers                                     |
| `src/microsoft/*`             | Microsoft adapter: Graph and Office 365 Management clients, schemas, mappers, mailbox stream, actions, probe                                                                                                   |
| `src/google/*`                | Google adapter: Reports, Directory and Gmail settings clients, schemas, mappers (`login`, `token`, settings), settings sweep, actions, probe                                                                   |
| `src/factory.ts`              | `createIdpAdapter(kind, deps)`, `createProviderHttpClient(config, options)`, `IDP_ADAPTER_VERSIONS`                                                                                                            |
| `src/testing/*`               | Test-only subpath `@email-gateway/idp-adapters/testing`: simulators, synthetic datasets, in-memory ports, wired Microsoft and Google testbeds                                                                  |

## Using an adapter

```ts
import {
  createIdpAdapter,
  createProviderHttpClient,
  loadIdpAdapterConfig,
} from '@email-gateway/idp-adapters';

const config = loadIdpAdapterConfig({ env: process.env, appEnv: 'production' });
const http = createProviderHttpClient(config, { provider: integration.provider, logger, metrics });
// integration.provider is 'microsoft_entra' or 'google_workspace' and must equal the kind.
const adapter = createIdpAdapter(integration.provider, {
  integration,
  connections,
  http,
  budget,
  mailboxState,
  actionState,
  clock,
  config,
});
const page = await adapter.ingest('sign_ins', cursor, signal); // { events, cursor, hasMore, retryAfterMs? }
const report = await adapter.probe(signal); // IdpAdapterExtras
```

Adapters are created **per integration** (an 8.4 `ato_provider_integrations` row bound to one 8.2
connection). They never store a credential or a token: tokens come from `ProviderConnectionAccess`
and live only inside a request.

### Streams (Microsoft)

| Stream                                     | Role                          | Source                                                                                                                             |
| ------------------------------------------ | ----------------------------- | ---------------------------------------------------------------------------------------------------------------------------------- |
| `sign_ins`                                 | primary                       | Graph `auditLogs/signIns` (Entra ID P1/P2)                                                                                         |
| `risk_events`                              | primary                       | Graph `identityProtection/riskDetections` (full detail with P2)                                                                    |
| `session_events`                           | companion of `risk_events`    | token risk detection types                                                                                                         |
| `oauth_consents`                           | primary                       | Graph `auditLogs/directoryAudits` consent activities; publisher verification cached 24 h                                           |
| `mailbox_audit`                            | primary                       | Office 365 Management `Audit.Exchange` (allow-listed operations), Graph inbox rules (priority refresh, audit-driven, weekly sweep) |
| `forwarding_changes`, `delegation_changes` | companions of `mailbox_audit` | produced by the mailbox stream                                                                                                     |

A companion's `ingest` returns `{ events: [], cursor: 'companion:v1:<primary>', hasMore: false }`;
the runner never polls it. Events of a stream disabled in the binding settings are dropped before
they leave a page. Throttling (`429`, rate budget) ends a page early with `retryAfterMs` and a
cursor that resumes exactly there; other errors throw a classified `ProviderCallError`.

Behaviour worth knowing:

- The first `mailbox_audit` poll after binding runs the inbox-rule sweep, so rules that already
  exist are reported once as `inbox_rule_added` (state, not "who changed it").
- The first audit window starts the `Audit.Exchange` subscription once if the provider answers
  `AF20022`; this is the only write outside response actions. Probes never start it.
- Cursor-confirmed snapshots: mailbox items written by a page that the runner did not commit are
  re-emitted with the same event id on the next poll from the previous cursor.

### Actions (Microsoft, Graph v1.0)

`revoke_sessions`, `require_password_reset` (cloud-only users), `suspend_account`, `require_mfa`
(tenant-designated group), `remove_forwarding_rule` (inbox rules; mailbox-level forwarding is
`unsupported` with result code `requires_exchange_admin`), `revoke_oauth_grant`. Every action
checks the linked-domain guard, captures pre-state once, is idempotent per action public id,
confirms by read-back where the state is readable (`pending` with 10 s → 5 min polling
otherwise) and rolls back only what the gateway changed. The provider reference is
`msgraph:<action>:<actionPublicId>`; result codes (`already_in_state`,
`restored_previous_state_noop`, `partial`, …) are kept in the action's `provider_state`.

### Streams (Google Workspace)

| Stream                                | Role                               | Source                                                                                                                   |
| ------------------------------------- | ---------------------------------- | ------------------------------------------------------------------------------------------------------------------------ |
| `sign_ins`                            | primary                            | Admin SDK Reports `activities.list` application `login` (window `[watermark − 60 min, now − 5 min]`, `pageToken` paging) |
| `risk_events`                         | companion of `sign_ins`            | `suspicious_login*`, `gov_attack_warning`, `account_disabled_*` events of the same feed                                  |
| `session_events`                      | unsupported                        | not offered by Google (`ingest` answers `unsupported:v1:session_events`, never throws)                                   |
| `oauth_consents`                      | primary                            | Reports application `token`, `eventName=authorize` (client id hashed, never emitted)                                     |
| `forwarding_changes`                  | primary                            | Gmail settings snapshot sweep: Directory `users.list` (active users), per user auto-forwarding, filters, delegates       |
| `mailbox_audit`, `delegation_changes` | companions of `forwarding_changes` | filters without forwarding, accepted delegates                                                                           |

- Admin SDK calls (Reports, Directory) impersonate the grant's delegated administrator
  (`subjectEmail`); Gmail settings calls impersonate **each mailbox owner** (token `subject` =
  the user, R1) and address the mailbox by its primary address.
- The telemetry adapter only reads Gmail settings (`gmail.settings.basic` would allow filter
  writes; PQ14). The sweep runs every `snapshot.sweepIntervalHours` (Google default 24 h), at most
  `ATO_IDP_SNAPSHOT_MAX_USERS_PER_POLL` users and `ATO_IDP_PAGE_MAX_EVENTS` events per page, with
  the position (users page token, offset) in the cursor; priority refreshes (api route) run first.
  Users whose Gmail is not enabled are skipped. The first sweep reports existing state as added.
- Throttling (`429`, `403 rateLimitExceeded`/`userRateLimitExceeded`) and quota
  (`403 dailyLimitExceeded`/`quotaExceeded`, `retryAfterMs` 1 h) end a page early; a throttled
  sweep page returns the events of the users already processed and resumes after them.

### Actions (Google Workspace)

| Action                   | Provider write                                                                       | Confirmation      | Rollback                           |
| ------------------------ | ------------------------------------------------------------------------------------ | ----------------- | ---------------------------------- |
| `revoke_sessions`        | Directory `users.signOut`, then `tokens.delete` of every OAuth token of the user     | re-list, no token | –                                  |
| `require_password_reset` | `users.update` `changePasswordAtNextLogin = true`                                    | read-back         | –                                  |
| `suspend_account`        | `users.update` `suspended = true`                                                    | read-back         | only if the user was not suspended |
| `require_mfa`            | `users.update` `orgUnitPath = settings.mfaEnforcement.orgUnitPath` (2SV-enforced OU) | read-back         | restores the previous OU           |
| `remove_forwarding_rule` | Gmail auto-forwarding `enabled = false` or filter `DELETE` (as the mailbox owner)    | read-back         | – (not reversible)                 |
| `revoke_oauth_grant`     | `tokens.delete` of the tokens whose client id hashes to `appIdHash`                  | re-list, absent   | –                                  |

The provider reference is `gws:<action>:<actionPublicId>`. A `403` on a write whose scope the
grant holds (for example a delegated administrator acting on a super administrator) fails
`missing_privileged_role`. `require_mfa` without a configured OU is `unsupported`
(`not_configured`); a rollback over a later administrator move of the user fails `conflict`.

## Configuration

Read through `loadIdpAdapterConfig({ env, appEnv, allowHttpEndpoints })` (design note §4.2). The
`ATO_IDP_*_BASE_URL` keys default to the production origins and are **refused at start** when they
differ from them outside `APP_ENV ∈ {local, ci}`; `http:` is allowed only with
`allowHttpEndpoints` (8.2's `PROVIDER_ALLOW_HTTP_ENDPOINTS`) in those environments. Errors name
keys, never values. The keys are in `.env.example` (block "ATO identity-provider adapters (step 8.5)").

## Simulators

- **In-process** (`startSimulators({ dataset })`): Graph (`/graph`), Office 365 Management
  (`/o365`), Google Admin SDK Reports and Directory (`/google-admin`) and Gmail settings
  (`/gmail`) on `127.0.0.1:0`, tokens minted by `InMemoryConnectionAccess`
  (`EXAMPLE-sim-token-<n>`) with the grant's permissions or scopes, so missing permissions
  produce real `403`s. Script API on `SimScript`: `inject` (Google errors take a `reason`, e.g.
  `rateLimitExceeded`, `userRateLimitExceeded`, `dailyLimitExceeded`, `quotaExceeded`),
  `delayReadBack`, `revokePermission`, `setLicense` (Microsoft), `calls`/`writes` (with the token
  subject, so impersonation is assertable).
- **Testbeds:** `createMicrosoftTestbed()` and `createGoogleTestbed()` wire an adapter (through
  `createIdpAdapter`), the simulators, the in-memory connection port and stores, a capturing
  logger and a settable clock:

  ```ts
  import { createGoogleTestbed } from '@email-gateway/idp-adapters/testing';

  const tb = await createGoogleTestbed();
  await tb.adapter.probe(signal);
  tb.sims.script.inject({ simulator: 'gmail', path: /settings/, status: 429, retryAfter: '5' });
  const page = await tb.adapter.ingest('forwarding_changes', null, signal);
  await tb.stop();
  ```

- **Google simulator rules:** Admin SDK tokens must impersonate an administrator of the customer;
  writes on a super administrator need a super-administrator subject; a Gmail token may read only
  its own mailbox (`users/me` or the owner's address); `users.list` supports
  `customer=my_customer`, `maxResults` ≤ 500, `pageToken` and `query=isSuspended=false`; Reports
  supports `startTime`, `endTime` (RFC 3339, ≤ 180 days back), `maxResults` ≤ 1000, `pageToken`
  and `eventName`, newest activity first.
- **Standalone** (`node dist/testing/simulators/main.js`; Compose service `idp-simulator`, profile
  `smtp-test`, mounts the compiled folder read-only: build the package first): every registered simulator on `IDP_SIM_PORT` (8080) under `/graph`, `/o365`, …, `/health`,
  and an admin API on `IDP_SIM_ADMIN_PORT` (8081): `POST /admin/dataset`, `/admin/reset`,
  `/admin/inject`, `/admin/delay-read-back`, `/admin/permissions`, `/admin/revoke-permission`,
  `/admin/license`, `GET /admin/calls`. Any non-empty bearer token is accepted; permissions are
  set per directory. The sources import only `node:*` and each other (unit-tested), so the
  compiled folder runs without `node_modules`.
- Synthetic data only: Entra directory `11111111-2222-4333-8444-555555555555` (domain
  `contoso-it.example`), Google customer `Cexample01` (domain `fabrikam-it.example`, delegated
  administrator `ato-admin@fabrikam-it.example`, 2SV OU `/Security/2SV-Enforced`), documentation
  IP ranges (RFC 5737, RFC 3849). In standalone mode (stack tokens carry no subject) Gmail must be
  addressed by the owner's address, which the adapter always does.

## Tests

`pnpm --filter @email-gateway/idp-adapters test` runs everything (no infrastructure): core units,
mappers, the Microsoft and Google adapters end to end on the simulators (streams, paging, overlap,
late events, throttling and quota, permissions and licences, blob slicing, subscription start,
settings sweep pagination and priority refresh, crash recovery, every action, rollback, probes,
identity resolution), the factory, the **8.4 contract kit** (`src/testing/contract.test.ts`) and a
local conformance suite for both adapters, the 8.2 bindings against 8.2's `FakeProviderServer`,
`StaticGrantSource` and token service (`src/bindings/bindings.test.ts`), the Prisma enums against
the library lists, capturing-logger redaction tests and the standalone simulator entry. Under
Vitest `@email-gateway/ato-detection` resolves to its TypeScript sources (`vitest.config.ts`): its
test kit imports Vitest, which the compiled CommonJS cannot require.
`test:integration` has nothing to run (pure library).
