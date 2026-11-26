# AI assistant deployment (api-assistant)

Step AI-6 D10 ([design](../plan/steps/34-ai-chat-hardening-operations.md), [ADR-0091](../architecture/adr/0091-assistant-architecture-loopback-tools.md), [ADR-0092](../architecture/adr/0092-llm-provider-abstraction-and-data-handling.md), [ADR-0096](../architecture/adr/0096-assistant-async-report-jobs-session-job-token.md), [ADR-0097](../architecture/adr/0097-assistant-provider-routing-tenant-keys-pseudonymization.md)). Manifests: [`infrastructure/kubernetes/base/api-assistant.yaml`](../../infrastructure/kubernetes/base/api-assistant.yaml), the portal split in [`admin-portal.yaml`](../../infrastructure/kubernetes/base/admin-portal.yaml) and the component [`components/assistant-llm-egress`](../../infrastructure/kubernetes/components/assistant-llm-egress/kustomization.yaml). Runbook: [assistant](../runbooks/assistant.md). Alerts: [`assistant.rules.yml`](../../infrastructure/monitoring/rules/assistant.rules.yml).

> **Status.** The manifests were rendered with `kubectl kustomize` (base, `overlays/saas`, `overlays/dedicated`) and have **not been applied** to a cluster. The egress ranges in the component are placeholders (`192.0.2.0/24`); a real environment must set its own (see [Egress](#egress)).

## Topology

```
browser ──► ingress-nginx ──► admin-portal (BFF) ─┬─ /api/v1/assistant/* ──► api-assistant Service ──► api-assistant pods
                                                    └─ everything else ─────► api Service
API client ─► ingress-nginx ── /api/v1/assistant/* (Ingress api-assistant, SSE settings) ──► api-assistant pods
                           └── /api/v1/*           (Ingress api) ─────────────────────────► api pods

api-assistant pod ── model calls (HTTPS, component egress) ──► LLM provider(s)
                  ── tool calls (loopback, ASSISTANT_LOOPBACK_URL) ──► api Service ──► api pods ──► MySQL, OpenSearch, ...
                  ── report jobs: RabbitMQ assistant.reports (eg-assistant) ──► loopback GETs with a job token ──► api pods
                  ── report objects (HTTPS) ──► S3 mail bucket, org/<id>/assistant/report/*
```

| Deployment      | Image                            | Role                                                                                                                                                                                                                                                                                                                                                         | Holds                                                                                                                                           |
| --------------- | -------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ----------------------------------------------------------------------------------------------------------------------------------------------- |
| `api`           | `email-gateway/api`              | Every `/api/v1` route except the assistant's. Serves the assistant's **loopback tool calls** and the **report-job reads** as ordinary authenticated requests (guards, RBAC, tenant scope, rate limits, HPA). `ASSISTANT_ENABLED` unset (assistant off), `ASSISTANT_BACKGROUND_JOBS_ENABLED=false`.                                                           | The api secrets; **no** LLM key, **no** tenant-key encryption key                                                                               |
| `api-assistant` | `email-gateway/api` (same image) | `/api/v1/assistant/*`: turns over SSE, conversations, confirmations, reports, settings and tenant keys, admin usage/feedback, conversation audit view, search. Model calls with provider routing and fallback, pseudonymization, the `assistant.reports` consumer, the assistant's background jobs (retention purge, stale-turn sweeper, report-job expiry). | The api secrets (same boot config, design risk R11) **plus** `email-gateway-assistant-llm` and `email-gateway-assistant-tenant-key` (only here) |

Why the same image: only the api may depend on `@email-gateway/assistant`, and the assistant's routes use the api's guards and services. Why tool calls go to the api Service instead of the pod itself: the LLM-holding pods then need no route to OpenSearch, DNS resolvers, SMTP relays or provider endpoints, and tool load lands where the api's HPA scales (design §5).

`api-assistant` still mounts every api secret, because the api's config schema needs them to boot. Its NetworkPolicy keeps what it can reach small; a boot profile that loads only the assistant module is a follow-up (risk R11).

## Secrets

| Secret                               | Keys                                                                                                                    | Read as                                                                                               | Mounted in                              |
| ------------------------------------ | ----------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------- | --------------------------------------- |
| `email-gateway-assistant-llm`        | `anthropic-api-key` (required for `ASSISTANT_PROVIDER=anthropic`), `openai-api-key` (optional: OpenAI primary/fallback) | `ASSISTANT_ANTHROPIC_API_KEY_FILE`, `ASSISTANT_OPENAI_API_KEY` (env from `secretKeyRef`, optional)    | `api-assistant` only                    |
| `email-gateway-assistant-tenant-key` | `key` (64 hex, AES-256-GCM, required even while tenant keys are off), `previous-key` (optional, rotation)               | `ASSISTANT_TENANT_KEY_ENCRYPTION_KEY_FILE`, `ASSISTANT_TENANT_KEY_ENCRYPTION_KEY_PREVIOUS` (optional) | `api-assistant` only                    |
| `email-gateway-secrets` (existing)   | new key `rabbitmq-assistant-url`: `amqps://eg-assistant:<password>@<broker>/email-gateway`                              | `RABBITMQ_ASSISTANT_URL_FILE`                                                                         | bundle mounted in api and api-assistant |
| every api Secret (existing)          | unchanged                                                                                                               | as in `api.yaml`                                                                                      | api and api-assistant                   |

- Azure OpenAI: set `ASSISTANT_AZURE_OPENAI_ENDPOINT`, `_DEPLOYMENT`, `_API_VERSION` in an overlay patch and add the key to `email-gateway-assistant-llm` with an extra env entry; Azure is not offered for tenant keys (A6-7).
- Generate the tenant-key encryption key with `openssl rand -hex 32` (64 hex). It never leaves `api-assistant`; rotation: [runbook](../runbooks/assistant.md#tenant-key-encryption-key-rotation).
- Tenant-supplied provider keys stay off (`ASSISTANT_TENANT_KEYS_ENABLED=false`) until the platform operator enables them in an overlay; the encryption key must exist anyway, because the Secret is mounted as a file.

## Configuration

`api-assistant.yaml` sets, in addition to the api's env: `ASSISTANT_ENABLED=true`, `ASSISTANT_PROVIDER=anthropic`, `ASSISTANT_MODEL=claude-opus-5-5`, `ASSISTANT_EFFORT=low`, `ASSISTANT_FALLBACK_PROVIDER=none`, the timeouts (`ASSISTANT_TIMEOUT_MS` 30 000, `ASSISTANT_TURN_DEADLINE_MS` 90 000, `ASSISTANT_TOOL_TIMEOUT_MS` 15 000), `ASSISTANT_MAX_CONCURRENT_TURNS` 20, `ASSISTANT_TURNS_PER_USER_PER_MINUTE` 6, the tenant/platform token budgets, the breaker (5 failures, 60 s), `ASSISTANT_LOOPBACK_URL=http://api.email-gateway.svc.cluster.local`, `ASSISTANT_BACKGROUND_JOBS_ENABLED=true`, the report jobs (`ASSISTANT_REPORT_JOBS_ENABLED=true`, `ASSISTANT_REPORT_SYNC_MAX_HOURS` 168, `ASSISTANT_REPORT_JOB_TTL_SECONDS` 1 800, `ASSISTANT_REPORT_JOBS_CONSUMER=true`, `ASSISTANT_REPORT_JOB_CONCURRENCY` 2), `ASSISTANT_TENANT_KEYS_ENABLED=false`, the pseudonym cap and search bounds. Both api Deployments read `ARCHIVE_EXPORT_TTL_HOURS` from the shared ConfigMap key (`configMapKeyRef`), so the export card always states the archive-jobs value (D13).

To enable the secondary provider (D6, ADR-0097) an overlay sets `ASSISTANT_FALLBACK_PROVIDER` and `ASSISTANT_FALLBACK_MODEL`, adds the provider's key and adds its ranges to the egress component. The fake provider is refused with `NODE_ENV=production`.

The portal gets `API_ASSISTANT_INTERNAL_URL=http://api-assistant.email-gateway.svc.cluster.local` (empty = `API_INTERNAL_URL`): its BFF sends proxied paths under `/api/v1/assistant/` there, everything else to `API_INTERNAL_URL`. Same-origin checks, CSRF, the trusted client-IP forwarder and streaming are unchanged.

## Ingress and SSE

Turns stream `assistant-stream/1` over server-sent events for up to `ASSISTANT_TURN_DEADLINE_MS` (≤ 300 s). Two extra Ingress objects carry them, each with `proxy-buffering: "off"`, `proxy-request-buffering: "off"`, `proxy-http-version: "1.1"`, `proxy-read-timeout`/`proxy-send-timeout` `330` and **no configuration snippets**:

| Ingress                  | Host        | Path (Prefix)            | Backend                 |
| ------------------------ | ----------- | ------------------------ | ----------------------- |
| `api-assistant`          | api host    | `/api/v1/assistant/`     | `api-assistant` Service |
| `admin-portal-assistant` | portal host | `/bff/api/v1/assistant/` | `admin-portal` Service  |

ingress-nginx merges Ingress objects of the same host and the longer prefix wins, so `/api/v1/` (Ingress `api`) and `/` (Ingress `admin-portal`) keep everything else with their shorter timeouts. Browser chat traffic never uses the `api-assistant` Ingress: the browser talks to the portal, and the portal's BFF reaches `api-assistant` in-cluster (the split above). The api-host Ingress serves API clients that call the assistant routes directly.

## Egress

The `api-assistant` NetworkPolicy allows ingress on port 3000 from the ingress controller, the admin portal and Prometheus, and egress to the MySQL writer and reader (3306), Redis (6379), RabbitMQ (5671/5672), cluster DNS, the OTel collector (4318) and the **api pods on 3000** (the api Service's target port; policies match after Service translation). HTTPS (443) is **not** in the base: the component `components/assistant-llm-egress` adds one rule with `ipBlock`s for the LLM endpoints and the S3 endpoint only. Both overlays include it.

The component's values are `192.0.2.0/24` (RFC 5737, never routed), so a fresh environment **fails closed**: model calls fail with `connection` errors and readiness fails on S3. Per environment, patch the rule with:

- **LLM providers**: the provider's published API address ranges (for Anthropic, the published IP addresses of the API; for OpenAI and Azure OpenAI, their published ranges, or for Azure a private endpoint inside the VPC). Use only the providers actually configured as primary, fallback or tenant-key providers. Never use a one-off DNS lookup: the addresses rotate.
- **S3**: the S3 ranges of `S3_REGION` from AWS `ip-ranges.json` (service `S3`), or the ranges of the VPC gateway endpoint's prefix list.
- **FQDN alternative**: with a DNS-aware CNI policy (Cilium `CiliumNetworkPolicy` `toFQDNs`, Calico domain-based policies) or an HTTPS egress proxy, drop the component and allow 443 to `api.anthropic.com` (and the other configured hosts) and the regional S3 endpoint by name, as for the BEC engine ([bec-detection.md](bec-detection.md)).

Re-check the published ranges on a schedule; a provider adding addresses shows up as `assistant_llm_requests_total{outcome="connection"}` and the alert [AssistantProviderErrorRatioHigh](../runbooks/assistant.md#assistantprovidererrorratiohigh).

## RabbitMQ

Topology v16 ([messaging-topology.md](../architecture/messaging-topology.md)) adds the queue `assistant.reports` (role `work`, bound to `assistant.report.generate_requested.v1` on `email.policy` plus its retry binding; hold retry, 5 attempts, 10–60 s, 30 min retry age) and the role user **`eg-assistant`**: configure `^$`, read `^assistant\.reports$`, write `^email\.(policy|events)$` with topic grants `email.policy` `^retry\.assistant\.reports\.` and `email.events` `^dead-letter\.assistant\.reports(\.|$)`. The `eg-ops` user's retry grant gains `assistant\.reports` (dead-letter replay). Provision with `infrastructure/rabbitmq/init.mjs` (the same as every topology change), then store `rabbitmq-assistant-url` in `email-gateway-secrets`. The producer is the api-assistant turn (outbox row `assistant.report.generate_requested.v1`, published by the event-relay); the consumer is `ReportJobConsumer` in api-assistant (prefetch `ASSISTANT_REPORT_JOB_CONCURRENCY`, ledger `api-assistant.reports`).

## S3 permissions

Report objects live in the mail bucket (`S3_BUCKET_MAIL`) under `org/<organizationId>/assistant/report/<yyyy>/<mm>/<dd>/<reportId>.html` (AI-R, ADR-0095). The `api-assistant` ServiceAccount's IRSA role needs:

| Action                                     | Resource                                                                 | Why                                                           |
| ------------------------------------------ | ------------------------------------------------------------------------ | ------------------------------------------------------------- |
| `s3:PutObject`, `s3:GetObject`             | `arn:aws:s3:::<mail-bucket>/org/*/assistant/report/*`                    | store a generated report, serve `GET /assistant/reports/{id}` |
| `s3:DeleteObjectVersion`                   | `arn:aws:s3:::<mail-bucket>/org/*/assistant/report/*`                    | content purge and the pending sweep delete every version      |
| `s3:ListBucketVersions`                    | `arn:aws:s3:::<mail-bucket>` with `s3:prefix` `org/*/assistant/report/*` | find the versions to delete                                   |
| `s3:ListBucket` (HeadBucket for readiness) | `arn:aws:s3:::<mail-bucket>`                                             | readiness probe of the S3 indicator                           |

The api's role keeps its existing permissions (organization deletion purges every object under `org/<id>/`). KMS: the bucket's key policy must allow the role `kms:GenerateDataKey`/`kms:Decrypt` when SSE-KMS is used.

## Scaling

- HPA 2–6 on CPU 60 %. Turns mostly wait on the model, so CPU under-reports load: watch `assistant_active_turns` per pod against `ASSISTANT_MAX_CONCURRENT_TURNS` (20; `503 assistant_busy` beyond). With a Prometheus adapter, add it as a Pods metric (target about 60 % of the limit). The dedicated overlay lowers every HPA to 1–4.
- PDB `minAvailable: 1`; `terminationGracePeriodSeconds: 330` (turn deadline plus headroom: on SIGTERM the pod stops accepting turns and running SSE turns finish).
- Every tool call of a turn is an api request: size the `api` HPA for the extra loopback traffic (one request per tool call, at most `ASSISTANT_MAX_TOOL_CALLS_PER_TURN` = 12 per turn). The per-tenant API rate class counts these calls.
- A laptop measurement of the limits (fake provider, not a capacity figure): [assistant-load.md](../performance/assistant-load.md).

## Rollout order

1. Migration `ai_assistant_hardening` (migration 42) with the migration Job.
2. Topology v16 (`init.mjs`: queue, bindings, `eg-assistant`, `eg-ops` grant); store `rabbitmq-assistant-url`.
3. Secrets `email-gateway-assistant-llm` and `email-gateway-assistant-tenant-key`; IRSA role of `api-assistant`; the egress ranges in the environment's overlay.
4. event-relay (it must know `assistant.report.generate_requested.v1`, otherwise the rows become poison), then the `api` Deployment (assistant off, background jobs off, `ARCHIVE_EXPORT_TTL_HOURS`).
5. `api-assistant` (Deployment, Service, Ingress, HPA, PDB, NetworkPolicy); check readiness, `/metrics` and one turn by a platform operator.
6. `admin-portal` with `API_ASSISTANT_INTERNAL_URL` and the `admin-portal-assistant` Ingress.
7. Alerts (`assistant.rules.yml`) and the runbook links in Alertmanager.

Rolling back: remove `API_ASSISTANT_INTERNAL_URL` (the BFF falls back to the api, which answers `503 assistant_disabled`), delete the two assistant Ingress objects and scale `api-assistant` to 0. Queued report jobs expire after `ASSISTANT_REPORT_JOB_TTL_SECONDS`.

## Local stack

Compose runs one api container with the assistant settings of `.env` and `ASSISTANT_REPORT_JOBS_CONSUMER=false`; the host-run api (`pnpm --filter @email-gateway/api dev`) consumes report jobs (local `.env`: `true`). There is no route split locally.
