# @email-gateway/integration-worker

Microsoft 365 and Google Workspace connectors: grant verification, connector validation, health monitoring and maintenance (step 8.2, [design](../../docs/plan/steps/25-m365-google-connectors.md) D2–D5, D10–D12, D15, D18; [ADR-0079](../../docs/architecture/adr/0079-connector-validation-probes-and-health.md)). MySQL writer (claims, updates, audit, outbox) and reader (delivery statistics only, writer fallback); **no RabbitMQ** (events leave through `message_outbox` and the event-relay), **no Redis**, no S3. HTTP port `INTEGRATION_WORKER_HTTP_PORT` (3086) serves `/health/live`, `/health/ready` (mysql) and `/metrics` only. Deployment: [docs/deployment/provider-integrations.md](../../docs/deployment/provider-integrations.md); operations: [docs/runbooks/provider-integrations.md](../../docs/runbooks/provider-integrations.md). Provider clients, token service, cipher, health registry and guides come from [`@email-gateway/provider-integrations`](../../packages/provider-integrations/README.md).

The mail path never waits for this worker (I1): a provider outage, a revoked consent or this worker being down degrades health and wizard steps only.

## Roles (`INTEGRATION_WORKER_ROLES`, default `tasks,health,maintenance`)

| Role          | Loop (module)                                                                                  | Concurrency                                                                       | State                                                                                                          |
| ------------- | ---------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------- |
| `tasks`       | grant verification (`tasks/grant-verifier.ts`, tenant binding `tasks/binding.ts`)              | every replica, `FOR UPDATE SKIP LOCKED` + lease, `INTEGRATION_TASK_CONCURRENCY`   | `provider_connection_grants` (`verifying` → `active`/`error`), `provider_connections` (binding, I10)           |
|               | provider domain checks (`tasks/domain-checks.ts`)                                              | same                                                                              | `provider_connection_domains` (`provider_verification`, `provider_mx_host`)                                    |
|               | validation runs and probe completion (`tasks/validation-runner.ts`, checks in `checks/`)       | same; one claimed run per slot, lease 120 s                                       | `provider_validation_runs` (`queued` → `running` → `awaiting_probe` → `passed`/`warning`/`failed`/`expired`)   |
| `health`      | periodic health (`health/health-runner.ts`)                                                    | every replica, claims connections due (`next_health_check_at ≤ now`) with a lease | `provider_health_checks`, `provider_health_events`, connection health columns, audit, outbox                   |
| `maintenance` | retention, consent/probe expiry, re-encryption, platform gauges (`maintenance/maintenance.ts`) | leader `eg:integration:maintenance` (`GET_LOCK`), every 5 minutes                 | §3.3 retention; credentials under the previous key; `provider_connections`, egress-age and shared-range gauges |

Polling: tasks every `INTEGRATION_TASK_POLL_MS` (an immediate next pass while work remains), health every `INTEGRATION_HEALTH_TICK_SECONDS`. A failing pass is logged (class name and code only) and retried with back-off. Leader-written gauges are 0 on the other replicas (aggregate them with `max()`).

## Grant verification and tenant binding (D3, D4, I10)

1. Token for the grant (client credentials for the claimed Microsoft tenant, secret or certificate assertion; JWT bearer with the delegated admin for Google), through the platform app/service account (`platform_*`, worker-held, ADR-0077) or the customer credential (decrypted with `PROVIDER_CREDENTIAL_ENCRYPTION_KEY`, AAD bound to organization, connection, grant and credential version).
2. Tenant identity (`GET /organization` / Admin SDK customer); it must equal the claim and, after the first binding, the bound tenant (`tenant_mismatch`).
3. Permissions: missing permissions fail the grant (`permissions_missing`), excess permissions are recorded and reported by `permissions.granted` (over-privileged). The grant becomes `active`; the tenant is still only a **claim** (the Microsoft admin-consent redirect is not signed, and the shared platform app or service account gets a token for every tenant that ever consented or delegated to it), so nothing about it is stored on the connection yet and every linked domain is re-checked.
4. Binding on proof of control (`tasks/tenant-binding.ts`, `TenantBinder`, run after every provider domain check by the verifier, the domain-check task and the health role): the tenant is bound (`external_tenant_id`, `external_tenant_name`, `tenant_verified_at`, audit `integration.tenant_bound`) only when at least one linked domain that is TXT-verified at the gateway (which only this organization can have) is verified **in the claimed tenant** by a provider check made after the grant's current verification. The tenant identity is read again right before binding. `active_tenant_key` is unique platform-wide, so one provider tenant binds to at most one non-disabled connection (`tenant_bound_elsewhere`; the grant errs).
5. I10: the connection becomes `active` only when the grant is active, the tenant bound **and** ≥ 1 linked domain is verified in that tenant, otherwise it stays `configuring`.

Grants of other purposes (8.5 `ato_*`, step API-1 `mailbox_remediation`: `m365.mailbox_remediation` with Graph `Mail.ReadWrite` + `User.Read.All`, `google.mailbox_remediation` with `gmail.modify` + `admin.directory.user.readonly` for the grant's delegated admin) go through `verifyAuxiliary`: the connection must already be bound (`tenant_not_bound` otherwise), only the token's permissions are compared, nothing is bound or changed on the connection. The mailbox-access platform app / service account are read from `PROVIDER_M365_MAILBOX_APP_CLIENT_ID`, `_CLIENT_SECRET` (only with `PROVIDER_M365_ALLOW_PLATFORM_SECRET=true`), `_CERT_PATH`, `_CERT_THUMBPRINT` and `PROVIDER_GOOGLE_MAILBOX_SA_CLIENT_ID`, `PROVIDER_GOOGLE_MAILBOX_SA_KEY_PATH` (`platformCredentialsFromEnv` over `PERMISSION_PROFILES`; empty = customer-owned grants only). The periodic 8.2 checks (`credentials.token`, `permissions.granted`) cover `mail_flow` grants only.

Provider `throttled`/`unavailable`/`timeout` keep the grant `verifying` with back-off; every outcome writes an audit row (`integration.grant_verified` / `integration.grant_verification_failed` / `integration.tenant_bound`, actor `system`; ids and codes only).

## Validation runs (D10)

Every check of D10 (`credentials.token`, `permissions.granted`, `tenant.identity`, `domains.gateway_verified`, `domains.provider_verified`, `dns.mx_gateway`, `inbound.destination`, `inbound.destination_matches_provider`, `inbound.smtp`, `inbound.recent_deliveries`, `dns.spf_gateway`, `dns.dkim_provider`, `outbound.probe`, `routing.no_loops`, `lockdown.attested`) selected by the run's kind (`checksForRun`); results are the bounded `provider-validation/1` list (≤ 64 entries, evidence ≤ 2 KiB, never a secret).

- **SMTP probe** (`checks/smtp-probe.ts`, a minimal SMTP client over `node:net`/`node:tls` with no code path that writes `DATA`; it connects to the already validated address and verifies the certificate chain plus the preset's `tls_verify_names`, see the design note §13 D-WP4-1): resolve the destination host (`INTEGRATION_PROBE_DNS_SERVERS`), re-validate it with `validateDestinationHost` (`@email-gateway/mail-routing`), connect to port 25 within `INTEGRATION_SMTP_PROBE_TIMEOUT_MS`, EHLO `INTEGRATION_PROBE_HELO` (default `POSTFIX_OUTBOUND_MYHOSTNAME`), STARTTLS required, TLS ≥ 1.2, certificate verified against the preset's names (Postfix `match=` semantics), `MAIL FROM:<>`, `RCPT TO:<postmaster@domain>`, `RSET`, `QUIT`. **DATA is never sent** (the unit and integration servers assert it). `5xx` at RCPT = `warn`; connection or TLS failure = `fail`.
- **Outbound probe:** a run of kind `outbound`/`full` with outbound mode not `off` gets a single-use address `eg-probe-<26 base32>@PROVIDER_PROBE_DOMAIN` (only its SHA-256 is stored, expiry `PROVIDER_PROBE_TTL_SECONDS`) and waits in `awaiting_probe`; the smtp-adapter records the observation when the probe arrives on the provider relay; the tasks role completes the run from it (idempotently), the maintenance role ends it `expired` after the TTL.

## Health (D11, D15)

Periodic checks: `credentials.token`, `permissions.granted`, `tenant.identity`, `domains.provider_verified`, `dns.mx_gateway`, `inbound.recent_deliveries`, `outbound.relay_activity`, `routing.loops`, `credential.expiry`, `egress.ranges_fresh`. `evaluateHealth` = worst failing severity; provider-API `error`s count only after `INTEGRATION_HEALTH_ERROR_GRACE_MINUTES`; a provider failure backs off that connection's provider checks (×2 up to 3600 s) without delaying the mail-flow checks. A **transition** writes, in **one transaction**, the `provider_health_events` row, the connection's health columns (never `row_version`, which binds impact tokens), the audit row `integration.health_changed` and the outbox event `integration.connection.health_changed.v1` (public webhook `integration.health_changed`, alert `integration_unhealthy` via the webhook-worker). No transition is written for an equal status.

## Maintenance (§3.3)

Consent states 24 h after expiry; validation runs after 180 days and beyond the newest 50 per connection; probe observations 30 days; health events 365 days; relay counters 35 days; superseded egress sets beyond the newest 5 per provider. Expired probe runs end `expired`. After a key rotation (`PROVIDER_CREDENTIAL_ENCRYPTION_KEY_PREVIOUS` set) grants still under the previous key id are re-encrypted in batches of 100 (counts audited, idempotent). Gauges: `provider_connections{provider,status,health}`, `provider_connections_outbound_active`, `provider_egress_set_age_seconds`, `smtp_connector_shared_provider_networks`.

## Egress range import (CLI, D11)

```bash
node dist/cli/egress-import.js --provider microsoft_365 --file ranges.json \
  --source "https://learn.microsoft.com/…" --published-at 2026-11-01 --operator ops.oncall [--force] [--dry-run]
```

`ranges.json` = `{ "schema": "provider-egress-import/1", "provider": "microsoft_365", "cidrs": ["…"] }`. Validated (canonical CIDRs, public ranges only, ≤ 5 000 entries, IPv4 ≥ /8, IPv6 ≥ /16), refused when it removes more than 50 % of the active ranges unless `--force`; one writer transaction creates the next version, supersedes the active one and audits `integration.egress_ranges_imported`. An identical set is a no-op. Needs only `DATABASE_URL`. Exit codes: 0 ok, 1 refused/invalid, 2 failure. No automatic Internet fetch (§15 Q8).

## Configuration (`src/config.ts`, §4.4)

`baseConfigSchema` + `httpConfigSchema(3086)` + writer + reader and every worker key of §4.4 with its bounds. Endpoints must be `https:` unless `PROVIDER_ALLOW_HTTP_ENDPOINTS=true`, which is refused outside `APP_ENV` local/ci (as is `INTEGRATION_PROBE_CA_PATH`); with `NODE_ENV=production` and no `APP_ENV` the worker assumes `production`. A platform client secret is refused unless `PROVIDER_M365_ALLOW_PLATFORM_SECRET=true` (production: certificate). Errors name keys, never values.

## Metrics (D18)

`provider_token_requests_total{provider,method,result}`, `provider_api_requests_total{provider,api,result}`, `provider_api_duration_seconds{provider,api}`, `provider_validation_runs_total{kind,result}`, `provider_connections{provider,status,health}`, `provider_connections_outbound_active{provider}`, `provider_health_transitions_total{provider,to}`, `provider_egress_set_age_seconds{provider}`, `smtp_connector_shared_provider_networks`, `integration_worker_task_lag_seconds`, plus `provider_grant_verifications_total`, `provider_smtp_probes_total`, `integration_maintenance_deleted_total`, `provider_credentials_reencrypted_total`, `integration_worker_leader{job}`. Labels are bounded enums only. Alerts: `infrastructure/monitoring/rules/integrations.rules.yml`.

## Tests

- `pnpm --filter @email-gateway/integration-worker test` — config, check helpers, CLI arguments, SMTP probe against an in-process SMTP server (test-PKI-style certificates generated at runtime; the server fails the test on DATA).
- `pnpm --filter @email-gateway/integration-worker test:integration` — real MySQL writer/reader (the 8.2 worktree refuses the main schema until the merge), the in-process `FakeProviderServer`, an injected clock and synthetic `it-prov-*` organizations (cleaned up): grant verification per auth method, validation runs and claims, health transitions (rollback test), maintenance, egress import, and the provider-client contract suite against `infrastructure/provider-fake` (in-process, or the Compose service with `PROVIDER_FAKE_URL=http://127.0.0.1:${PROVIDER_FAKE_HOST_PORT}`, `PROVIDER_FAKE_DNS=127.0.0.1:${DNS_SINK_HOST_PORT}`).

No test contacts a real Microsoft or Google endpoint; RSA keys are generated at runtime.
