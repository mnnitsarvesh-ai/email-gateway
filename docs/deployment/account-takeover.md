# Deployment: account takeover (ATO) detection (step 8.4)

Design: [docs/plan/steps/24-account-takeover-core.md](../plan/steps/24-account-takeover-core.md) (D3, D7, D13–D16, D19, D21, D22, §4.2), ADR-0070..0075. Operations: [runbooks/account-takeover.md](../runbooks/account-takeover.md). Worker internals: [apps/ato-worker/README.md](../../apps/ato-worker/README.md). SMTP enforcement: [runbooks/smtp-ato-enforcement.md](../runbooks/smtp-ato-enforcement.md).

## What is deployed

| Workload      | Image                      | Roles (`ATO_WORKER_ROLES`)     | Replicas         | Talks to                                                           |
| ------------- | -------------------------- | ------------------------------ | ---------------- | ------------------------------------------------------------------ |
| `ato-detect`  | `email-gateway/ato-worker` | `detect`                       | 2–8 (HPA on CPU) | MySQL writer, Redis, RabbitMQ (`eg-ato`: `ato.events`, `ato.mail`) |
| `ato-respond` | `email-gateway/ato-worker` | `respond,maintenance,provider` | 1                | MySQL writer, Redis, RabbitMQ (`eg-ato`: `ato.responses`)          |

Manifests: `infrastructure/kubernetes/base/ato-detect.yaml`, `ato-respond.yaml` (both in `kustomization.yaml`); the optional GeoIP component `infrastructure/kubernetes/components/ato-geoip`. Locally one Compose service `ato-worker` (profile `apps`, host port `${ATO_WORKER_HOST_PORT:-3085}`) runs every role.

- **detect** consumes `ato.events` (logins, account changes, SMTP AUTH and submission telemetry; ledger `ato-worker.events`) and the **lossy** `ato.mail` (`mail.message.scanned.v1`, drop-head at 500 000 without dead-lettering; ledger `ato-worker.mail` keyed by `atoMailKey`).
- **respond** consumes `ato.responses` (provider actions through the provider registry; ledger `ato-worker.respond`). In 8.4 no identity-provider adapter is registered, so every provider action ends `unsupported` (never executed, never claimed).
- **maintenance** runs leader-elected jobs (`GET_LOCK('eg:ato:<job>')`): `mail-catchup`, `decay`, `baselines`, `expiry` (approvals, restrictions), `confirm` (provider confirmations), `digests`, `retention`, `retirement`, `status` (gauges, resolutions, the capabilities row `system_settings 'ato.worker.capabilities'` every 5 minutes).
- **provider** runs the ingestion runner (idle until step 8.5 binds adapters to 8.2's connectors).

Readiness: mysql, redis and (detect, respond) rabbitmq with the role's queues verified passively. The worker has no object-storage access and no Internet egress: its NetworkPolicies allow MySQL, Redis, RabbitMQ, cluster DNS (which also answers the optional DNSBL zones) and OTLP only. Probes and `/metrics` are on port 3085.

Nothing on the mail path depends on the ato-worker (§2.0 invariants 1 and 2): `ato.mail` is lossy (a stopped worker never makes the relay nack a mail event), SMTP restrictions are read by the smtp-adapter from its own cache, and the policy-engine reads ATO facts from MySQL rows. A stopped worker means stale scores, never delayed mail.

## Rollout order

1. Migrations `security_incidents` and `account_takeover` (the migration Job, as every release) and the seed (four `ato:*` permissions, feature `ato_detection` **false** in every plan).
2. Topology v13 and the role user `eg-ato` (`infrastructure/rabbitmq/init.mjs` / the broker definitions of the environment); Secret key `rabbitmq-ato-url` in `email-gateway-secrets`.
3. The Secret `email-gateway-ato-key` (key `hmac-key`, ≥ 32 random characters, e.g. 48 hex), mounted by the two ATO Deployments only. The smtp-adapter's own Secret `email-gateway-smtp-ato-key` (key `username-hash-key`, step 8.4 WP3) is separate.
4. smtp-adapter, policy-engine, email-worker, api, notification-worker and webhook-worker of this release (producers, enforcement, policy facts, routes and channels).
5. `event-relay` with `RECONCILE_QUEUES` including `ato.responses` (below).
6. `ato-detect`, then `ato-respond`.
7. Optional: the GeoIP component once the operator has a MaxMind account (below).
8. Enable ATO **per organization** (below). Nothing happens for any organization before this step.

## Enabling ATO for an organization (PO1, D21)

ATO is **off for every plan and organization**. A platform operator enables it per organization with the existing feature override route (`OrganizationConfigurationController_overrideFeature_v1`, platform permission, audited; `{id}` is the organization's public id):

```http
PUT /api/v1/organizations/{id}/features/ato_detection
Content-Type: application/json

{ "enabled": true }
```

The row becomes `organization_features (ato_detection, enabled = true, source = override)`.

On the organization's first ATO event the worker creates its settings with the defaults: `mode: monitor` (signals, scores, incidents, notifications and recommendations; no automatic medium/high-impact response), a 14-day learning period (baseline-relative rules are recorded as informational), automation off or `recommend` for every medium/high-impact action. The tenant tunes everything under **Account security → Settings** (`PUT /api/v1/ato/settings`). The ato.mail catch-up of a newly enabled organization starts at the enablement time (at most `ATO_MAIL_CATCHUP_MAX_AGE_HOURS` back), so recent outbound mail is analysed without a backfill of old history.

Disabling the feature (`"enabled": false`) stops detection and policy facts at once (the worker's per-organization cache expires within `ATO_SETTINGS_CACHE_SECONDS`); active SMTP restrictions stay until they expire or are lifted (they are tenant-visible rows); the tenant's `mode: off` is the tenant's own pause. Never enable `ato_detection` for an organization without its administrator's agreement; the platform organization's own accounts are never acted on automatically.

## Configuration

Worker keys (all in `.env.example`, section "Account takeover"; Kubernetes values in the two manifests): roles, prefetches, `ATO_TX_TIMEOUT_MS` (≥ 120 000), `ATO_SETTINGS_CACHE_SECONDS`, `ATO_HMAC_KEY` (secret), the GeoIP paths and reload/age, `ATO_DNSBL_IP_ZONES`, `ATO_DNS_SERVERS`, `ATO_REPUTATION_TIMEOUT_MS`, the IP campaign window, `ATO_AUTOMATED_RESPONSES_ENABLED`, `ATO_MAX_AUTOMATED_RESPONSES_PER_ORG_PER_HOUR`, `ATO_MAX_ACTIVE_RESTRICTIONS_PER_ORG`, `ATO_APPROVAL_TTL_HOURS`, the maintenance intervals, retention, the catch-up knobs, the provider runner and `ATO_DIGEST_ENABLED`. The api reads `API_ATO_OVERVIEW_CACHE_SECONDS` and `API_ATO_REPORT_MAX_ITEMS` (and the automation/approval keys it shares with the worker). The notification-worker reads `NOTIFY_ATO_PLATFORM_SOC_EMAIL`: the platform SOC mailbox that receives the critical account takeover incident alerts of every organization (audience `platform_soc`: organization slug, incident public id, severity and portal link only). Empty (the default in `.env.example`, Compose and the Kubernetes manifest `notification-worker.yaml`) = off: platform SOC notifications are dropped by the worker and never sent; set the address per environment (Compose: `.env`; Kubernetes: the overlay). Test seams are refused unless `APP_ENV` is `local` or `ci`: `ATO_GEOIP_ALLOW_DOCUMENTATION_RANGES` (the synthetic databases) and `ATO_PROVIDER_FAKE_ENABLED` (the fake identity provider). Never set them in a cluster.

**Platform automation switches.** `ATO_AUTOMATED_RESPONSES_ENABLED=false` holds every automatic medium/high-impact response for approval on the whole platform (low-impact alerts still run); `ATO_MAX_AUTOMATED_RESPONSES_PER_ORG_PER_HOUR` caps automatic actions per organization below the tenant's own cap. The SMTP enforcement kill switch is the smtp-adapter's `SMTP_ATO_ENFORCEMENT_ENABLED` ([smtp-ato-enforcement.md](../runbooks/smtp-ato-enforcement.md)).

### Writer pool and transient database errors (step AI-4 D14)

**Cause it fixes.** Before step AI-4 the worker's single writer client used Prisma's default pool (`2 × CPUs + 1`, 17 on an 8-CPU host; in Kubernetes the node's CPU count) and the default `pool_timeout` of 10 s, while up to 68 queue handlers (prefetch 32 + 32 + 4, each an interactive transaction), 4 parallel IdP stream polls, the probe loop and about ten maintenance jobs share it. Measured: an interactive transaction does **not** wait its `maxWait` (30 s) for a pool connection; it fails with `P2024` after `pool_timeout` like a plain query. Under load (for example the full portal Playwright run) the IdP loops then turned a transient `P2024` / `P1001` into long stalls: the probe loop leases an integration for `ATO_IDP_HEALTH_INTERVAL_SECONDS` (900 s) before probing, and a probe that threw kept that lease (a new integration stays "not probed", nothing is ingested); the stream runner counted the error as a provider failure (`consecutive_failures + 1`, back-off `poll interval × 2^n` up to 1 h, the integration's failure aggregate, a forced probe after three).

**Transient-error behaviour.** Database outages are not provider failures. A pool timeout, an unreachable or lost server, an expired interactive transaction or a lock conflict (`isTransientInfrastructureError` of `@email-gateway/common`, the classifier of the queue consumers, plus MySQL 1205/1213) is retried (a page transaction ≤ 5 attempts, a claim / success / failure / re-schedule write ≤ 3 attempts; jittered back-off `200 ms × 2^(n−1)` ≤ 5 s) and then **deferred**: the stream's `next_poll_at`, or the integration's `next_health_at`, moves to now + 5–60 s (growing with consecutive deferrals, reset on success), and `consecutive_failures`, `last_error_code`, `health_status`, the integration aggregate and the probe trigger are not touched. Any other unexpected probe exception re-schedules the probe after min(health interval, 300 s) instead of keeping the 15-minute lease. Provider errors (throttling, HTTP failures, provider timeouts) keep the ADR-0083 back-off unchanged. Provider actions (`ato.responses`, the confirmation job) rethrow a database error raised during the action so the queue redelivers it as transient (no attempt counted) or the job's back-off retries it; the action is never marked failed for it. Series: `ato_idp_transient_db_errors_total{loop="stream"|"probe", outcome="retried"|"deferred"}`; warn logs `ato idp stream poll deferred after a transient database error` / `ato idp probe deferred after a transient database error` carry the error class and code only.

**Keys** (not secrets; `.env.example` "Account takeover" section, Compose `ato-worker` environment, Kubernetes `ato-detect.yaml` and `ato-respond.yaml`):

| Key                                 | Default | Bounds | Meaning                                                                                                                                            |
| ----------------------------------- | ------- | ------ | -------------------------------------------------------------------------------------------------------------------------------------------------- |
| `ATO_DATABASE_CONNECTION_LIMIT`     | 32      | 4–200  | `connection_limit` of the writer client of one worker process (the advisory-lock connection is separate, `connection_limit=1`)                     |
| `ATO_DATABASE_POOL_TIMEOUT_SECONDS` | 30      | 5–300  | `pool_timeout`: how long a query waits for a pool connection; must be ≥ 30 (the writer transaction `maxWait`), a smaller value is refused at start |

**Budget rule (per MySQL writer):** the writer budget is 80 % of `max_connections`, and the ATO workers at their HPA maximum take at most 60 % of it: `Σ maxReplicas × (ATO_DATABASE_CONNECTION_LIMIT + 1 lock connection) ≤ 0.6 × 0.8 × max_connections` (144 of 300); the other services keep the rest. Compose runs one ato-worker container with the default 32 (33 connections); the local MySQL has `max_connections` 300 and measured `Max_used_connections` 93 before the change. Kubernetes: `ato-detect` (2 replicas, HPA up to 8) sets `ATO_DATABASE_CONNECTION_LIMIT=12`, because its detection handlers hold short writer transactions and wait for a connection up to the 30 s pool timeout; `ato-respond` (1 replica: the leader-elected jobs, IdP polls and probes) keeps 32. At full scale that is 8 × 13 + 1 × 33 = 137 connections (a pool of 32 on `ato-detect` would have been 297, nearly all of `max_connections`). The unit test `apps/ato-worker/src/deployment/connection-budget.test.ts` recomputes this from the base manifests and `infrastructure/mysql/conf.d/gateway.cnf`, and fails when an overlay or component sets the pool size or raises an HPA maximum. If you raise `max_connections` for a larger installation, raise the pools or replica maxima in the base manifests and the test together. Check `SHOW GLOBAL STATUS LIKE 'Max_used_connections'` after a load test.

### RECONCILE_QUEUES

The event-relay reconciles `ato.responses` (provider action requests are ledgered; a lost one is re-driven). The `.env.example` default and the Compose default of `RECONCILE_QUEUES` include `ato.responses` since step 8.4. An existing `.env` keeps its own value: add `,ato.responses` to `RECONCILE_QUEUES` by hand (the repository never rewrites an existing key). `ato.events` and `ato.mail` are not reconciled (no-op events are acked without a ledger row; `ato.mail` is lossy and completed by the catch-up). Kubernetes: the event-relay manifest's `RECONCILE_QUEUES` value must include `ato.responses` as well.

## GeoIP (operator data, ADR-0074)

Geographic rules (new country G1, impossible travel G2, inconsistent sessions G3), ASN novelty (C2) and anonymizer flags (G4) need MaxMind databases provided by the **operator**. The gateway never ships, bundles or downloads a database on its own; without them the rules are honestly `unavailable` (the portal and `GET /ato/rules` say so) and no location is ever guessed.

| Database                       | Key                           | Licence                                              | Used by          |
| ------------------------------ | ----------------------------- | ---------------------------------------------------- | ---------------- |
| GeoLite2-City (or GeoIP2-City) | `ATO_GEOIP_CITY_DB_PATH`      | GeoLite2 EULA (free, account required) or commercial | G1, G2, G3       |
| GeoLite2-ASN (or GeoIP2-ISP)   | `ATO_GEOIP_ASN_DB_PATH`       | GeoLite2 EULA or commercial                          | C2               |
| GeoIP2-Anonymous-IP (optional) | `ATO_GEOIP_ANONYMOUS_DB_PATH` | commercial only                                      | G4 (always weak) |

1. Create a MaxMind account, accept the **GeoLite2 End User License Agreement** and generate a licence key. The EULA requires attribution — keep this sentence in the product documentation and the portal's About information: _"This product includes GeoLite2 data created by MaxMind, available from https://www.maxmind.com"_ — and requires outdated copies to be replaced (the refresh below; `AtoGeoIpDatabaseStale` fires after `ATO_GEOIP_MAX_AGE_DAYS`, default 35).
2. Create the Secret `email-gateway-geoip` with the keys `account-id` and `license-key` (External Secrets, as every Secret).
3. Enable the Kustomize component in the overlay: `components: [../../components/ato-geoip]`. It adds MaxMind's `geoipupdate` (`ghcr.io/maxmind/geoipupdate`, pinned) as a native sidecar of both ATO Deployments, downloads `GeoLite2-City` and `GeoLite2-ASN` into a shared `emptyDir` at `/var/lib/geoip` every 72 hours, sets the worker's database paths and checks the files for changes every 5 minutes (`ATO_GEOIP_RELOAD_SECONDS`). The worker swaps a reloaded database atomically; a broken download keeps the previous reader. The sidecar alone gets HTTPS egress (to `updates.maxmind.com`); the credentials are mounted into the sidecar only.
4. With a commercial licence, add `GeoIP2-Anonymous-IP` to `GEOIPUPDATE_EDITION_IDS` and set `ATO_GEOIP_ANONYMOUS_DB_PATH=/var/lib/geoip/GeoIP2-Anonymous-IP.mmdb`. Anonymizer flags are always a weak signal and a reason to downgrade travel evidence, never proof.

Check: `system_settings 'ato.worker.capabilities'` (and the api's capability view) shows `geoipCity.loaded: true` with a recent `buildEpoch`; `ato_geoip_database_loaded{database="city"} == 1`.

Local and CI use the **synthetic** databases in `packages/ato-detection/test-fixtures/geoip/` (documentation ranges only, regenerated byte-identically with `pnpm --filter @email-gateway/ato-detection geoip:synthetic`). Compose mounts them read-only at `/opt/ato/geoip` and enables the documentation ranges; they contain no real data and must never be used in a cluster.

## IP reputation and DNSBL zones

Every ATO IP lookup goes through url-security's `ReputationService` from one adapter (`apps/ato-worker/src/enrichment/reputation.ts`, the Reputation contract of D7): the platform threat feed (`threat_indicators` of type `ip`, platform scope, never cached) always, and a DNSBL provider over `ATO_DNSBL_IP_ZONES` when set. DNSBL answers are cached in Redis under `eg:ato:rep:v1:…`, sealed with `ATO_HMAC_KEY` (a separate namespace from the URL engine's `eg:url:rep:v1:…`).

**Zone guidance.** List only zones of **exploited or compromised hosts** (botnet, proxy and exploit lists such as an XBL- or CSS-style zone of your DNSBL provider). Never list policy zones such as PBL that enumerate residential or dynamic ranges: users legitimately sign in from those networks, and listing them would raise strong-looking signals on ordinary logins. Syntax: `zone=code:category[,code:category]`, zones separated by `;` (e.g. `xbl.example-dnsbl.test=127.0.0.4:other`); commercial zones that embed a key in the name are configured the same way (the value is a secret then: provide it from a Secret). Errors and timeouts are `error`, never `clear`. Without zones rule T2 is unavailable. Tenants add their own trusted and blocked networks in their settings.

## Breach intelligence importer (T4)

Rule T4 (weak) checks whether an account address is a platform `email` indicator. Operators load lists they are entitled to use with the importer; no third-party breach API is ever called (it would send tenant addresses out) and passwords are never involved:

```sh
pnpm --filter @email-gateway/ato-worker build
pnpm --filter @email-gateway/ato-worker breach:import -- --source <name> --file <path> [--severity medium] [--expires-days 365]
# In a cluster: kubectl exec deploy/ato-respond -- node dist/cli/breach-import.js --source <name> --file <path>
```

The file holds one address per line (`#` comments allowed). The importer keeps **only addresses whose domain is an active tenant domain**, upserts platform indicators (`source = 'feed:<name>'`, category `other`, the given severity and expiry), prints counts only (`read`, `invalid`, `outsideTenantDomains`, `duplicatesInFile`, `imported`, `updated`) and writes one `audit_logs` row `threat_intel.breach_imported` with the counts. Re-importing the same source refreshes expiry and severity. To withdraw a list, delete its indicators by source (an operator SQL change, audited by the change process). The worker's capability flag `breach_intel` follows the number of unexpired indicators (refreshed every 5 minutes).

## Monitoring

Prometheus job `ato-worker` (port 3085 of the Compose service; Kubernetes scrapes the `ato-detect` and `ato-respond` Services under the same job name). Alert rules: `infrastructure/monitoring/rules/ato.rules.yml` (tested by `infrastructure/monitoring/tests/ato.rules.test.yml`): `AtoWorkerDown`, `AtoEventsBacklog`, `AtoMailQueueNearBound`, `AtoDetectionLagHigh`, `AtoDeadLetters`, `AtoSmtpTelemetryDropped`, `AtoRestrictionLookupErrors` (critical: submissions tempfail), `AtoPolicyFactsErrors`, `AtoGeoIpDatabaseStale`, `AtoResponseFailures`, `AtoProviderFailures` (inactive until 8.5), `AtoFalsePositiveRateHigh`, `AtoCredentialAttackCampaign`, `AtoAutomationGuardTripped`, `AtoMailCatchupBehind`. Grafana dashboards are step 10.3.

## Data, retention and deletion

ATO stores IP addresses, coarse locations, ASNs, device family labels, rule evidence (allow-listed keys), addresses of the tenant's own mailboxes and users, analyst notes and the policy facts of outbound evaluations; never passwords, SASL secrets, tokens, attempted e-mails of unknown accounts (Redis HMACs only), subjects, bodies, attachments or recipient addresses (registrable domains and counts only). Retention (D22): auth events 3 months, daily activity 6 months, signals and scores 13 months (partition maintenance, `pnpm db:partitions apply`); closed `account_takeover` incidents with their events, links, details and actions, action logs and cleared overrides 730 days (`ATO_RETENTION_INCIDENT_DAYS`, the maintenance role); lifted/expired restrictions 400 days; expired trusted contexts 30 days after expiry; settings versions 730 days except the current one; accounts of deleted users or connectors, or without events for 13 months, are retired and deleted when no incident or response references them. Organization deletion: [runbooks/account-takeover.md](../runbooks/account-takeover.md#organization-deletion).

## Limits (stated plainly)

- Identity-provider adapters (Microsoft Entra ID / Microsoft 365, Google Workspace) are step 8.5; their views say so.
- Geography needs the operator's MaxMind data; anonymizer detection needs a commercial database.
- Throughput is measured on a laptop only ([docs/performance/ato.md](../performance/ato.md)); the 1M messages/day estimate of D22 is not verified locally.
- Defaults are engineering defaults without an accuracy claim; calibrate with the false-positive metric before enabling automation.
