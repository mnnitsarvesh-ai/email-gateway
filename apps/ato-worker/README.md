# @email-gateway/ato-worker

The account takeover (ATO) worker of step 8.4 ([design](../../docs/plan/steps/24-account-takeover-core.md) D3–D16, D19, D22; ADR-0070..0075). It turns authentication telemetry, account changes and outbound mail into explainable risk signals, account scores, `account_takeover` security incidents and safeguarded responses, using the shared libraries `@email-gateway/ato-detection` (rules, scoring, baselines, windows, the transactional `AtoStore`, GeoIP, the provider port) and `@email-gateway/security-incidents`. HTTP port **3085** serves probes (`/health/live`, `/health/ready`) and `/metrics` only.

Deployment: [docs/deployment/account-takeover.md](../../docs/deployment/account-takeover.md). Operations: [docs/runbooks/account-takeover.md](../../docs/runbooks/account-takeover.md). Performance: [docs/performance/ato.md](../../docs/performance/ato.md).

## Roles (`ATO_WORKER_ROLES`)

| Role          | What it does                                                                                                                                                                                                                                                                                              |
| ------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `detect`      | Consumes `ato.events` (ledger `ato-worker.events`) and the lossy `ato.mail` (ledger `ato-worker.mail`, key `atoMailKey(messageId, scanId)`) as `eg-ato`                                                                                                                                                   |
| `respond`     | Consumes `ato.responses` (ledger `ato-worker.respond`): provider actions through the `ProviderRegistry` with `idempotencyKey = action public id`; `confirmed` → `succeeded`, `pending` → `executing`, retryable failures retried by the queue, no adapter/integration/identity/capability → `unsupported` |
| `maintenance` | Leader-elected jobs (`GET_LOCK('eg:ato:<job>')`): `mail-catchup`, `decay`, `baselines`, `expiry`, `confirm`, `digests`, `retention`, `retirement`, `status` (gauges, resolutions, the `system_settings 'ato.worker.capabilities'` row every 5 minutes)                                                    |
| `provider`    | The provider ingestion runner (`FOR UPDATE SKIP LOCKED` claims of `ato_provider_integrations`, one ledgered transaction per page, backoff, `error` after repeated failures); idle until step 8.5 registers adapters                                                                                       |

Every replica also reloads changed GeoIP files (`ATO_GEOIP_RELOAD_SECONDS`) and refreshes the breach-indicator capability every 5 minutes.

## Sources (detect role)

| Event                         | Handler                            | Account                                                  | Notes                                                                                                                                                                                                                                                                                      |
| ----------------------------- | ---------------------------------- | -------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `auth.login.recorded.v1`      | `detect/login.handler.ts`          | `gateway_user`                                           | Reads `login_audit_logs` back (echo-checked). Every failure counts in the platform IP windows (also unknown accounts and organizations without ATO; the attempted e-mail only as an HMAC). Unknown accounts: an account-less row of the platform organization only when it has ATO enabled |
| `auth.account.changed.v1`     | `detect/account-change.handler.ts` | `gateway_user` (actor; `user.mfa_reset`: target)         | Reads `audit_logs` back by `(id, created_at)`; API-key and system actors are `unattributed` (API keys are not accounts in 8.4)                                                                                                                                                             |
| `smtp.auth.recorded.v1`       | `detect/smtp.handler.ts`           | `smtp_connector`                                         | Per entry (ledger key `eventId`/`seq`); failures feed the platform IP windows; successes aggregated per connector, IP and hour in `ato_auth_events`; unknown usernames: account-less platform rows                                                                                         |
| `smtp.submission.recorded.v1` | `detect/smtp.handler.ts`           | `smtp_connector`                                         | Connector attribution of the queue id (Redis `ato:sub:{org}:{queueId}`, 2 h) and the submission rules (O7, O8)                                                                                                                                                                             |
| `mail.message.scanned.v1`     | `detect/mail.handler.ts`           | `mailbox` (envelope sender) and the attributed connector | Outbound/internal only; reads the message, recipients (domains only), attachments, `In-Reply-To`, the round's risk, DLP and BEC observation rows on the writer (echo-checked); inbound, feature-off and inactive organizations are no-op acks without a ledger row                         |

**Two-phase detection** (`detect/pipeline.ts`): `prepare` runs without a transaction (settings, the account — created on first sight, `last_seen_at` refreshed at most once a minute —, the baseline view, today's seen sets, the idempotent Redis windows keyed by the observation and their snapshot, the last success, trusted contexts and the pure `evaluateRules`); `commit` runs in the short ledger transaction (`ATO_TX_TIMEOUT_MS`): the auth event row, the day row and, only when rules fired, signals deduplicated under the account lock, correlation over the account's and its linked accounts' recent signals, rescoring, the incident policy and automation. Same-day novelty marks and the last-success location are written after the commit. Enrichment (GeoIP, `AtoReputation`, the campaign flag, tenant networks) runs before the transaction: no network call ever runs inside one.

**Reputation contract (D7).** `src/enrichment/reputation.ts` is the only file that calls url-security's `ReputationService` (`AtoReputation.lookupIps(organizationId, ips, signal)`; a boundary test enforces it). Providers: the platform feed (`threat_indicators` of type `ip`, never cached) and, with `ATO_DNSBL_IP_ZONES`, a DNSBL provider; DNSBL answers are cached under `eg:ato:rep:v1:…` sealed with `ATO_HMAC_KEY`. Rules consume `AtoIpReputation` (`confidence` is `null` today) and the separate DNSBL flag (T2).

## Breach importer

```sh
pnpm --filter @email-gateway/ato-worker build
pnpm --filter @email-gateway/ato-worker breach:import -- --source <name> --file <path> [--severity medium] [--expires-days 365]
```

Keeps only addresses of active tenant domains, upserts platform `email` indicators (`feed:<name>`), prints counts only and writes one `threat_intel.breach_imported` audit row (D7).

## Run locally

```sh
pnpm --filter @email-gateway/ato-worker dev        # reads ../../.env (synthetic GeoIP, documentation ranges)
docker compose --profile apps up -d ato-worker      # build it alone: docker compose build ato-worker
```

ATO stays off until a platform operator enables `ato_detection` for an organization. The local `.env` gains the ATO keys of `.env.example` (generate `ATO_HMAC_KEY`); an existing `RECONCILE_QUEUES` needs `,ato.responses` added by hand.

## Tests

- Unit (`pnpm --filter @email-gateway/ato-worker test`): configuration bounds and test-seam refusals, the reputation adapter mapping (feed vs DNSBL, errors never clear), outbound finding classification, digest time zones, the breach importer's parsing, and boundaries (only `reputation.ts` calls `ReputationService`; no IP indicator reads; no S3, no replica, no test kit at runtime).
- Integration (`pnpm --filter @email-gateway/ato-worker test:integration`; real MySQL writer, Redis and RabbitMQ, the synthetic GeoIP databases, the dns-sink DNSBL zone `rbl.scan.test`, the fake identity provider, an injected clock; `it-ato-*` organizations only, removed afterwards; a live ato-worker is paused meanwhile; requires `pnpm --filter @email-gateway/ato-worker build` for the process-kill test):
  - `auth.test.ts`: brute force (portal, SMTP), spraying/stuffing across organizations (campaign flag, T5, T3 → incident), impossible travel with new country/prefix/ASN, new device, anonymizer downgrade, the accuracy guard, no GeoIP, platform-feed and DNSBL reputation, K1 and X2, tenant isolation, duplicates, unknown accounts, feature off.
  - `outbound.test.ts`: O1 immature and mature, O2–O5, P1 with X1 and the linked incident, P2, P4/P5 from BEC observations, O9, connector attribution, fast paths, live + catch-up exactly once.
  - `responses.test.ts`: automatic and approved SMTP restrictions, rollback, expiry, approval expiry; provider actions through the fake adapter (confirmed, pending → confirmed, retryable and final failures, unsupported); the runner (M1, Q1, X5) and provider failures (throttling, auth errors, backoff, `error`).
  - `lifecycle.test.ts`: escalation and decay, false positives and overrides, learning, the platform organization guard, baseline rebuild, digests, retention and resolutions, retirement, capabilities, the breach importer and T4.
  - `broker.test.ts`: redelivery, the respond queue, `ato.mail` overflow without dead letters plus catch-up, SIGKILL of a worker process mid-batch.
  - `volume.test.ts`: ≥ 50 000 scanned events and ≥ 20 000 telemetry entries across 20 organizations (scale with `IT_ATO_VOLUME_ORGS`, `IT_ATO_VOLUME_MESSAGES_PER_ORG`); prints `ATO-PERF {…}`.
