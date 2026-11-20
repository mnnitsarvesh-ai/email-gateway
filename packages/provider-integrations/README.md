# @email-gateway/provider-integrations

The provider-integration framework of step 8.2 ([design note](../../docs/plan/steps/25-m365-google-connectors.md)
D1–D6, §4.3; [ADR-0076](../../docs/architecture/adr/0076-provider-integration-framework.md),
[ADR-0077](../../docs/architecture/adr/0077-provider-credential-custody-and-encryption.md)):
Microsoft 365 (Exchange Online) and Google Workspace connections, read-only permission profiles,
encrypted credentials, OAuth2 client credentials (Microsoft admin consent) and service-account JWT
bearer with domain-wide delegation (Google), provider API clients, health checks, validation,
customer-specific setup guides, impact tokens and egress range imports.

Who uses what:

| Consumer              | Uses                                                                                                                                                                                           | Never                            |
| --------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------- |
| api                   | profiles, `ProviderCredentialCipher.encryptCredential` (encrypt only), credential parsers and fingerprints, consent URL and state, impact tokens, setup guides, attestations, validation types | decrypts, calls a provider       |
| integration-worker    | everything: grant store with the decrypting cipher, token service, directories, health and validation, egress imports, re-encryption                                                           | –                                |
| step 8.5 (ato-worker) | the **stable reuse surface** below                                                                                                                                                             | mail-flow logic (guides, wizard) |

Tests use the in-process provider fake only; no real Microsoft or Google endpoint is ever
contacted.

## Stable reuse surface (D6, for step 8.5)

Everything below is exported from the package root and is a stable contract
(`PROVIDER_INTEGRATIONS_CONTRACT_VERSION = 1`).

### Permission profiles (`src/profiles/`)

- `PermissionProfile` (`key`, `version`, `provider`, `purpose` `mail_flow | ato_telemetry | ato_response`, `readOnly`, `permissions`, `authMethods`, `platformApp` **key names**, `title`, `description`).
- `PERMISSION_PROFILES` (live registry array), `profileByKey`, `requireProfile`, `profilesFor(provider, purpose?)`, `mailFlowProfileFor(provider)`, `comparePermissions(profile, observed)` → `{ missing, excess }`.
- `registerPermissionProfiles(profiles)` validates and appends. 8.5 adds `src/profiles/ato.ts` and **one line** in `src/profiles/index.ts`: `import './ato';` (that file calls `registerPermissionProfiles`). Rules: dotted lower-case keys ≤ 48 characters, unique; auth methods valid for the provider; `platformApp` values are UPPER_SNAKE configuration key names; a `readOnly: true` profile may not declare a write permission; `mail_flow` profiles must be read-only and pass the D1 deny list (`mailFlowDenyReason`). Write-capable ATO profiles declare `readOnly: false`.
- Import profiles through the package root (or `src/profiles/index.ts`), never `profiles/registry` directly, so the registrations run.
- 8.2 profiles: `m365.mail_flow` (`Organization.Read.All`, `Domain.Read.All`), `google.mail_flow` (`admin.directory.customer.readonly`, `admin.directory.domain.readonly`).

### Credential custody (`src/crypto/credential-cipher.ts`, ADR-0077)

- `ProviderCredentialCipher` (`fromConfig({ PROVIDER_CREDENTIAL_ENCRYPTION_KEY, PROVIDER_CREDENTIAL_ENCRYPTION_KEY_PREVIOUS })`): AES-256-GCM, `v1.<kid>.<iv>.<tag>.<ct>`, AAD `provider-credential:v1:<organizationId>:<connectionPublicId>:<grantPublicId>:<credentialVersion>` (`credentialAad`). `kid` = `k` + 7 hex of SHA-256(key) (`credentialKeyId`), stored in `credential_key_id`; `encrypt`/`decrypt` (raw) and `encryptCredential`/`decryptCredential` (strict documents).
- Documents: `{ method: 'customer_app_secret', clientSecret }`, `{ method: 'customer_service_account', key: ServiceAccountKey }`. `parseServiceAccountKey(json, { tokenUrl })` keeps only `type`, `client_email`, `private_key`, `private_key_id`, `token_uri`, `client_id`, requires `token_uri` = `PROVIDER_GOOGLE_TOKEN_URL` and an RSA key ≥ 2048 bits; `parseClientSecret`. Errors (`ProviderCredentialInvalidError.field`) name the field, never the value.
- `credentialFingerprint({ clientId, privateKeyId?, credentialVersion })` (64 hex), `shortFingerprint` (12 hex).

### Request primitive and errors (`src/http/`, `src/errors.ts`)

- `providerRequest({ origin, method, path, query?, headers?, body?, maxResponseBytes?, timeoutMs?, retryAfterCapMs?, acceptStatuses?, signal, api?, allowHttp?, fetch?, logger?, observe? })` → `{ status, headers, json }`. Rules: URL = configured origin + base path + relative `path` (`''` = the origin itself); nothing may leave the origin or base path (`buildProviderUrl`, `isUnderOrigin`); `redirect: 'error'`; byte cap (default 1 MiB); JSON only; timeout (default 10 s); `Retry-After` on 429/503 capped (default 60 s). `observe` receives `{ api, method, status, result, durationMs }` for metrics. Usable with `POST`/`PATCH`/`DELETE` by 8.5's own clients (the deny list applies to profiles, not to the primitive).
- `ProviderRequestError { code, retryable, retryAfterMs?, status? }`; codes `invalid_client`, `consent_missing`, `unauthorized_client`, `tenant_not_found`, `forbidden`, `throttled`, `unavailable`, `timeout`, `bad_response`, `credential_unavailable`. Messages contain only the code. `withProviderRetry(op, signal, policy)` retries `throttled`/`unavailable`.

Classification (`classifyProviderFailure`):

| Response                                                                                        | Code                  |
| ----------------------------------------------------------------------------------------------- | --------------------- |
| 429                                                                                             | `throttled`           |
| 408, 504, client timeout                                                                        | `timeout`             |
| other 5xx, network error                                                                        | `unavailable`         |
| AADSTS 90002 / 900023 / 90072 / 90023                                                           | `tenant_not_found`    |
| AADSTS 65001 / 700016 / 7000112 / 500011, `consent_required`, `access_denied`                   | `consent_missing`     |
| AADSTS 7000215 / 7000222 / 700027 / 700024 / 50012 / 7000218, `invalid_client`, `invalid_grant` | `invalid_client`      |
| Microsoft `unauthorized_client` (other codes)                                                   | `unauthorized_client` |
| Google token `unauthorized_client` / `invalid_scope` (delegation missing)                       | `consent_missing`     |
| API 401 / 403                                                                                   | `forbidden`           |
| redirect, oversize, non-JSON, schema mismatch, other 4xx                                        | `bad_response`        |

### Tokens (`src/tokens/`, D2, R1)

- `ProviderTokenService({ grants: GrantTokenSource, endpoints, platform?, http?, cacheMax? (2 000), refreshMarginMs? (5 min), now?, logger?, onTokenRequest? })`.
- `getAccessToken(grant: GrantRef, signal, options?: { resource?: 'graph' | 'o365_management' | 'google'; subject?: string })` → `{ token, expiresAt, observedPermissions }`. Microsoft: client secret or certificate assertion (`x5t`), scope `https://graph.microsoft.com/.default` or, for `o365_management` (**only profiles whose purpose starts with `ato_`**), `<PROVIDER_M365_MANAGEMENT_URL origin>/.default`; observed permissions from the token's `roles` claim (reporting only). Google: JWT bearer RS256 (`iss` SA e-mail, `sub` = `subject` or the grant's delegated admin, `scope` = profile scopes, `aud` = token URL, 1 h). Cache: in-memory LRU keyed `(grantPublicId, credentialVersion, resource, subject)`; concurrent callers share one request; `invalidate(grantPublicId)`. Grants must be `verifying`, `active` or `error`.
- `GrantTokenSource.loadForToken(ref)` → `GrantTokenRecord` — implemented by `ProviderGrantStore`, or `testing.StaticGrantSource` in tests.
- `platformCredentialsFromEnv(env, profiles, { readFile, googleTokenUrl, allowPlatformSecret })` builds the platform apps/service accounts from each profile's `platformApp` key names (8.5's ATO keys work the same way); refuses a platform client secret unless `PROVIDER_M365_ALLOW_PLATFORM_SECRET=true`.
- `resolveProviderEndpoints({ m365LoginUrl, m365GraphUrl, m365ManagementUrl?, googleTokenUrl, googleAdminUrl, allowHttp? })`.

### Provider clients (`src/microsoft/`, `src/google/`)

- `MicrosoftGraphClient({ graphUrl, tokens, http?, retry?, version? })`: `get(grant, path, signal, { select?, query?, nullOn? })`, `list(...)` following `@odata.nextLink` only on the configured Graph origin and base path.
- `GoogleAdminClient({ adminUrl, tokens, http?, retry? })`: `get`, `list(grant, path, signal, { itemsField, query?, nullOn? })` with `pageToken`.
- `MicrosoftDirectory`, `GoogleDirectory` implement `ProviderDirectory`: `tenant()` → `{ tenantId, displayName, verifiedDomains }`, `domain(name)` → `{ status: verified | unverified | absent | alias, mxHost }`.
- Lower level: `requestMicrosoftToken`, `microsoftClientAssertion`, `requestGoogleToken`, `googleJwtAssertion`.

### Grants and connections (`src/grants/`, D6)

- `ProviderGrantStore(prismaWriter, cipher | null)`: `findGrant(ref)` (no credential), `loadGrant(ref)` (decrypted credential; needs the cipher), `loadForToken(ref)`, `updateGrantStatus(grantId, expectedRowVersion, patch)` and `updateConnectionStatus(connectionId, expectedRowVersion, patch)` (CAS on `row_version`; `null` = lost), `reencryptBatch({ limit, fromKeyId? })` (key rotation). Every read is scoped by `organizationId`.
- `ProviderConnectionReader(prisma)`: `get(organizationId, connectionPublicId)`, `listForOrganization(organizationId)` → `{ publicId, organizationId (decimal string), provider, displayName, status, externalTenantId (the BOUND tenant only: null while the tenant is a claim not yet proven by a linked domain, or after the binding was released), linkedDomains: { name, providerVerified }[], grants: { publicId, profile, status, observedPermissions, subjectEmail }[], updatedAt }`, never ciphertext. This is the single 8.2 surface 8.5's binding file reads.

### Health (`src/health/`, D10, D11, R2)

- `HealthCheckDefinition { code, provider, severityOnFail, periodic, title, remediation, appliesToGrant? }`, `HEALTH_CHECKS`, `registerHealthChecks` (8.5 adds `src/health/ato.ts` + `import './ato';` in `src/health/index.ts`), `healthCheckByCode`, `periodicHealthChecks(provider)`, `grantsForCheck(check, grants)`.
- **R2:** the generic per-grant checks `credentials.token` and `permissions.granted` iterate only over grants whose profile purpose is `mail_flow` (`isMailFlowGrant`).
- `evaluateHealth(results, now, graceMinutes, previous?)` (pure: worst failing severity; `error` counts only after the grace period; nothing evaluable → `previous ?? 'unknown'`), `failingCheckCodes`, `evaluateCredentialExpiry`.

### Testing (`testing` namespace)

- `testing.FakeProviderServer({ adminToken?, graphPageSize?, googlePageSize?, tokenLifetimeSeconds? })`: in-process HTTP fake at `/m365/login`, `/m365/graph`, `/google/token`, `/google/admin` (`endpoints()` gives the configuration). Verifies client secrets, certificate assertions (`x5t`, audience, lifetime) and Google JWT bearer assertions (signature, `kid`, audience, ≤ 1 h, delegated scopes, subject in a customer domain). Issues client-credentials tokens for **any** `<resource>/.default` consented per resource (incl. `https://manage.office.com`, 8.5 R4) and Google tokens for **any user** of a customer domain (admins for the directory). Admin-consent redirect simulation (`setConsentTenant`). Scripted failures (`failNext({ endpoint, status, body, headers, times, delayMs, redirectTo, bodyBytes })`), paging (`setPaging`), request log without secrets, captured assertion claims. Audiences and paging links follow the request's `Host`, so the class also runs behind a Compose service name. With `adminToken`, the same state is configurable over HTTP (`/_fake/*`; `testing.FakeProviderAdminClient`), so WP4's Compose `provider-fake` can run this class.
- `testing.describeProviderClientContract({ describe, it, beforeAll, afterAll, beforeEach }, name, connect)`: the reusable contract suite (assertions via `node:assert`; no test-runner dependency in the library). `connect()` returns `{ baseUrl, adminToken, close? }`.
- Helpers: `generateTestRsaKey()` (runtime keys only; never commit a key), `testServiceAccountKey`, `testClientSecret`, `testGuid`, `StaticGrantSource`.

## 8.2-only modules (not part of the reuse surface)

- `generateSetupGuide(input)` (`setup-guide/1`), `renderSetupGuideMarkdown`, `setupGuideFileName`, `exampleSetupGuideInput(provider)` (the docs templates' placeholder input: `example.com`, `gateway.example.net`, `11111111-2222-3333-4444-555555555555`), `maskRouteToken`; attestation codes (`ATTESTATIONS`, `inboundRequiredAttestations`, `lockdownAttestations`, `internalRoutingAttestation`).
- Step 8.6 (journal intake, [design note](../../docs/plan/steps/27-journal-intake-and-archive-split.md) D10): `generateJournalIntakeGuide(input)` (`journal-intake-guide/1`) for the kinds `JOURNAL_INTAKE_KINDS` (`microsoft_365_journal`: Purview journal rule, undeliverable-reports mailbox, `New-JournalRule` / `Set-TransportConfig`; `google_workspace_copy`: routing "Also deliver to", `X-Gm-Original-To`, custom header `X-EG-Journal-Token`; `exchange_onprem_journal`: journal recipient, journal rule or database journaling, TLS Send connector; `smtp_bcc`: Postfix `always_bcc` / `sender_bcc_maps` / `recipient_bcc_maps` with a TLS policy). The address and header token are masked (`journal-••••<last 4>@…`, `••••<last 4>`) everywhere, commands included, unless `input.reveal` is true. `renderJournalIntakeGuideMarkdown`, `journalIntakeGuideFileName`, `exampleJournalIntakeGuideInput(kind)`, `maskJournalIntakeAddress`, `maskJournalIntakeToken`; attestation codes `INTAKE_ATTESTATIONS` (`journal.m365.rule_created`, `journal.m365.ndr_mailbox_set`, `journal.google.route_created`, `journal.google.headers_added`, `journal.onprem.journal_recipient_created`, `journal.onprem.send_connector_tls`, `journal.smtp.bcc_configured`), `intakeAttestationsFor(kind)`, `intakeAttestationByCode`, `intakeConfigureAttestations(kind)`. Both guide families render through the shared `renderGuideMarkdown(head, sections)` (8.2 output unchanged, snapshots identical).
- Validation results `provider-validation/1` (`VALIDATION_CHECKS`, `checksForRun`, `validationOutcome`, `validationResultSchema`, `boundEvidence`, `summarizeResults`).
- `buildAdminConsentUrl`, `createConsentState`, `hashConsentState`, `sanitizeProviderErrorDescription`.
- `signImpactToken` / `verifyImpactToken` / `canonicalJson` / `impactTokenKey` (D13).
- `parseEgressImport(json)` for `{ "schema"?: "provider-egress-import/1", "provider", "cidrs" }` (canonical CIDRs, public ranges only — no overlap with special-purpose blocks, IPv4 ≥ /8, IPv6 ≥ /16, 1–5 000 entries; hashes like the seed via `@email-gateway/database`), `diffEgressSets` (> 50 % removed requires `--force`).

## Checks

```sh
pnpm --filter @email-gateway/provider-integrations build
pnpm --filter @email-gateway/provider-integrations lint
pnpm --filter @email-gateway/provider-integrations typecheck
pnpm --filter @email-gateway/provider-integrations test              # unit + in-process contract
pnpm --filter @email-gateway/provider-integrations test:integration  # grant store on the MySQL writer
```

The integration suite creates synthetic `it-prov-*` organizations and deletes them afterwards;
in the parallel build it refuses to run against the main schema `email_gateway`.
