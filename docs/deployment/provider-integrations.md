# Deployment: Microsoft 365 and Google Workspace connectors (step 8.2)

Design: [docs/plan/steps/25-m365-google-connectors.md](../plan/steps/25-m365-google-connectors.md) (D2–D5, D10, D11, D15, D18, §3.3, §4.4), ADR-0076..0081. Operations: [runbooks/provider-integrations.md](../runbooks/provider-integrations.md). Worker internals: [apps/integration-worker/README.md](../../apps/integration-worker/README.md). Customer-facing setup guides are generated per connection by the api (`GET /provider-connections/{id}/setup-guide`); this page is the **operator** side.

What the gateway may do in a customer tenant: **read** the tenant id and name and the verification state and MX target of the customer's domains. Nothing else, ever (I3): no mail, no users, no configuration changes. Every permission below is read-only and the profile registry refuses a mail-flow profile with a write permission.

## What is deployed

| Workload             | Image                              | Replicas  | Talks to                                                                                                                                                          |
| -------------------- | ---------------------------------- | --------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `integration-worker` | `email-gateway/integration-worker` | 2 (PDB 1) | MySQL writer + reader, HTTPS to the Microsoft identity platform, Microsoft Graph, Google OAuth and Admin SDK, SMTP port 25 to customer destination hosts (probes) |
| `api`                | `email-gateway/api`                | as before | MySQL; encrypts customer credentials, builds consent URLs and guides; never calls a provider                                                                      |
| `smtp-adapter`       | `email-gateway/smtp-adapter`       | as before | provider relay acceptance and proof (DNS for DKIM keys), probe interception                                                                                       |
| `delivery-worker`    | `email-gateway/delivery-worker`    | as before | adds `X-EG-Route-Token` for Microsoft 365 internal routing                                                                                                        |

Manifest: `infrastructure/kubernetes/base/integration-worker.yaml` (Deployment, ServiceAccount without cloud permissions, Service for metrics, PDB, NetworkPolicy; listed in `kustomization.yaml`). Every replica runs the three roles (`INTEGRATION_WORKER_ROLES=tasks,health,maintenance`): verifications, validation runs and health checks are claimed with `FOR UPDATE SKIP LOCKED` and leases; maintenance is leader-elected (`GET_LOCK('eg:integration:maintenance')`). Readiness = MySQL only: provider endpoints are deliberately not readiness dependencies (an outage degrades connection health, not the worker). Locally (Compose `apps` profile) one container runs all three roles on host port `INTEGRATION_WORKER_HOST_PORT` (3086).

NetworkPolicy egress: MySQL (3306), cluster DNS, OTLP, and TCP 443 + 25 to **public** addresses only. The worker re-validates every destination host with `validateDestinationHost` before an SMTP probe and never sends DATA. The probes originate from the cluster's NAT egress, not from the gateway's MTAs: a destination that refuses `RCPT` from unknown addresses yields a `warn`, not a failure.

## Rollout order

1. Migration `provider_integrations` (the migration Job, as every release); the seed adds the two permissions and the egress snapshot (below).
2. Topology v14 (one binding of `integration.connection.health_changed.v1` to `email.webhooks`).
3. The Secrets below, the ConfigMap values (set per overlay), the probe domain's DNS.
4. `api`, `smtp-adapter`, `delivery-worker`, `webhook-worker` (new keys only; behaviour unchanged until a connection exists). `api.yaml` mounts `PROVIDER_CREDENTIAL_ENCRYPTION_KEY_FILE` (+ the optional `_PREVIOUS`), `PROVIDER_IMPACT_TOKEN_KEY_FILE` and `PROVIDER_ROUTE_TOKEN_KEY_FILE` from their Secrets (the api's configuration requires all three); `delivery-worker.yaml` mounts `PROVIDER_ROUTE_TOKEN_KEY_FILE` (optional in its configuration; without it Microsoft 365 internal deliveries are retried, never sent without the token). Create the three Secrets before rolling out the api.
5. `integration-worker`.
6. **Import current egress ranges** for both providers (below) before any organization activates outbound relay.

Nothing on the mail path depends on the integration-worker (I1); starting it late only delays verifications and health.

## Configuration

Shared keys (ConfigMap `email-gateway-config`, read by the api, the smtp-adapter and the worker): `PROVIDER_M365_LOGIN_URL`, `PROVIDER_M365_GRAPH_URL`, `PROVIDER_GOOGLE_TOKEN_URL`, `PROVIDER_GOOGLE_ADMIN_URL` (the public endpoints; `https:` only), `PROVIDER_ALLOW_HTTP_ENDPOINTS=false`, `PROVIDER_M365_MAILFLOW_APP_CLIENT_ID`, `PROVIDER_GOOGLE_MAILFLOW_SA_CLIENT_ID`, `PROVIDER_CONSENT_REDIRECT_URL`, the consent/impact TTLs, `PROVIDER_MAX_CONNECTIONS_PER_ORG` (10), `PROVIDER_MAX_DOMAINS_PER_CONNECTION` (500), `PROVIDER_PROBE_DOMAIN`, `PROVIDER_PROBE_TTL_SECONDS`, `PROVIDER_EGRESS_MAX_AGE_DAYS` (45), `GATEWAY_EGRESS_NETWORKS`, `GATEWAY_RELAY_HOSTS`, `GATEWAY_RELAY_TLS_NAME` (the values the customer guides print), `INTEGRATION_ALERT_THROTTLE_MINUTES`. Worker tunables are in the manifest with their §4.4 defaults (`INTEGRATION_HEALTH_INTERVAL_SECONDS` 900, `INTEGRATION_SMTP_PROBE_TIMEOUT_MS` 15 000, …). Values marked `replace-per-environment` must be set in the overlay.

Never set in a cluster (refused outside `APP_ENV` local/ci): `PROVIDER_ALLOW_HTTP_ENDPOINTS=true`, `INTEGRATION_PROBE_CA_PATH`, `PROVIDER_EGRESS_EXTRA_RANGES`.

## Secrets and key custody (ADR-0077)

| Secret (External Secrets)                 | Item                                                 | Read as                                             | Mounted in                                                |
| ----------------------------------------- | ---------------------------------------------------- | --------------------------------------------------- | --------------------------------------------------------- |
| `email-gateway-secrets`                   | `database-url`, `database-read-url`                  | `DATABASE_URL_FILE`, `DATABASE_READ_URL_FILE`       | `integration-worker` (only these two items are projected) |
| `email-gateway-provider-credential-key`   | `key` (64 hex, `openssl rand -hex 32`)               | `PROVIDER_CREDENTIAL_ENCRYPTION_KEY_FILE`           | `integration-worker` (decrypt) and `api` (encrypt only)   |
| `email-gateway-provider-credential-key`   | `previous-key` (optional, during a rotation)         | `PROVIDER_CREDENTIAL_ENCRYPTION_KEY_PREVIOUS`       | same                                                      |
| `email-gateway-provider-platform`         | `m365-mailflow-cert.pem` (certificate + private key) | `PROVIDER_M365_MAILFLOW_APP_CERT_PATH` (plain path) | `integration-worker` only                                 |
| `email-gateway-provider-platform`         | `m365-mailflow-cert-thumbprint` (40 hex, SHA-1)      | `PROVIDER_M365_MAILFLOW_APP_CERT_THUMBPRINT`        | `integration-worker` only                                 |
| `email-gateway-provider-platform`         | `google-mailflow-sa-key.json`                        | `PROVIDER_GOOGLE_MAILFLOW_SA_KEY_PATH` (plain path) | `integration-worker` only                                 |
| `email-gateway-provider-impact-token-key` | `key` (64 hex)                                       | `PROVIDER_IMPACT_TOKEN_KEY_FILE`                    | `api` only                                                |
| `email-gateway-provider-route-token-key`  | `key` (64 hex)                                       | `PROVIDER_ROUTE_TOKEN_KEY_FILE`                     | `api` and `delivery-worker` (identical value)             |

- The api **encrypts** customer credentials and never decrypts; the integration-worker **decrypts**; no other workload holds the key. The platform certificate and service-account key are held **only** by the integration-worker (the api holds only the client ids, to build consent URLs and guides).
- Ciphertexts are bound (AAD) to organization, connection, grant and credential version; a copied ciphertext does not decrypt elsewhere.
- Secrets are never logged, audited, put on the outbox or in Redis; the api shows only fingerprints and expiry dates. Access tokens live only in the worker's process memory.
- `PROVIDER_M365_MAILFLOW_APP_CLIENT_SECRET` (a client secret instead of the certificate) is refused unless `PROVIDER_M365_ALLOW_PLATFORM_SECRET=true`; keep it `false` in production.
- A deployment that does not offer one of the platform methods removes that method's env entries with an overlay patch (unset client id or path = method unavailable; customer-owned methods remain). A set path whose file is missing stops the worker at start.
- Key rotation: [runbook](../runbooks/provider-integrations.md#credential-key-rotation).

## Registering the platform Microsoft app (profile `m365.mail_flow`)

One multi-tenant Microsoft Entra app per permission profile; 8.2 has one profile. Register it in the **operator's** tenant:

1. Entra admin center → **App registrations → New registration**: name e.g. "Email security gateway — mail flow (read-only)", **Accounts in any organizational directory (multitenant)**, redirect URI platform **Web** = `PROVIDER_CONSENT_REDIRECT_URL` (`https://<portal>/integrations/providers/consent-callback`).
2. **API permissions**: remove the default delegated `User.Read`. Add **Microsoft Graph → Application permissions** `Organization.Read.All` and `Domain.Read.All` — **exactly these two**, nothing else (no delegated permissions, no Exchange permissions). `permissions.granted` reports excess permissions in every customer tenant as over-privileged.
3. **Certificates & secrets → Certificates → Upload certificate**: the public certificate of a key pair the operator generates, e.g. `openssl req -x509 -newkey rsa:3072 -sha256 -days 365 -nodes -subj "/CN=email-gateway-mailflow" -keyout key.pem -out cert.pem`, then `cat cert.pem key.pem` into the Secret item `m365-mailflow-cert.pem` and the SHA-1 thumbprint (`openssl x509 -in cert.pem -noout -fingerprint -sha1 | tr -d ':' | cut -d= -f2`) into `m365-mailflow-cert-thumbprint`. Do not create a client secret for production.
4. **Overview → Application (client) ID** → `PROVIDER_M365_MAILFLOW_APP_CLIENT_ID` (ConfigMap). Publisher verification is recommended: customers see a verified publisher on the consent screen.
5. Customers consent through the wizard (admin consent URL built by the api); the worker then requests a client-credentials token for the consenting tenant and verifies it.

Certificate rotation: upload the new certificate to the app (both are valid), switch the Secret items (worker restart), remove the old certificate from the app.

## Registering the platform Google service account (profile `google.mail_flow`)

1. In an operator Google Cloud project: **enable the Admin SDK API**; **IAM → Service accounts → Create** (no project roles: it needs none).
2. **Keys → Add key → JSON**: store the file as the Secret item `google-mailflow-sa-key.json` (only `client_email`, `private_key`, `private_key_id` and `token_uri` are used; `token_uri` must equal `PROVIDER_GOOGLE_TOKEN_URL`). Never commit or mail it.
3. The service account's **OAuth 2 client ID** (numeric "Unique ID") → `PROVIDER_GOOGLE_MAILFLOW_SA_CLIENT_ID` (ConfigMap). The guide shows it to customers.
4. Customers authorize that client id in **Admin console → Security → Access and data control → API controls → Domain-wide delegation** with **exactly** `https://www.googleapis.com/auth/admin.directory.customer.readonly` and `https://www.googleapis.com/auth/admin.directory.domain.readonly`, and name a delegated administrator (ideally a dedicated admin with a custom read-only role) in the wizard.

Key rotation: add a new key, switch the Secret item (worker restart), delete the old key in the console.

## Egress ranges

The provider relay accepts Microsoft 365 / Google Workspace mail only from the active `provider_egress_range_sets` of each provider (ADR-0078). The seed creates **version 1** of each from a snapshot in `packages/database/src/seed/provider-egress.ts` (Microsoft: Exchange Online outbound ranges; Google: the `_netblocks` SPF ranges; `published_at` 2026-06-01). The snapshot is **not authoritative** and already older than `PROVIDER_EGRESS_MAX_AGE_DAYS`: `ProviderEgressRangesStale` fires until current data is imported.

Verify the seeded snapshot (writer):

```sql
SELECT provider, version, status, range_count, sha256, published_at, imported_by
FROM provider_egress_range_sets ORDER BY provider, version;
-- Microsoft 365 v1: 8 ranges; Google Workspace v1: 27 ranges (both status 'active').
SELECT s.provider, COUNT(*) FROM provider_egress_ranges r
JOIN provider_egress_range_sets s ON s.id = r.set_id AND s.status = 'active' GROUP BY s.provider;
```

Import current data (no automatic Internet fetch, §15 Q8): convert the provider's published list into `{ "schema": "provider-egress-import/1", "provider": "microsoft_365" | "google_workspace", "cidrs": [ … ] }` (Microsoft: the Exchange Online ranges of the Microsoft 365 IP address and URL web service; Google: the ranges of the `_netblocks*.google.com` TXT records), then:

```bash
# Kubernetes: the root filesystem is read-only; /tmp is writable.
kubectl -n email-gateway cp ranges-m365.json deploy/integration-worker:/tmp/ranges-m365.json
kubectl -n email-gateway exec deploy/integration-worker -- node dist/cli/egress-import.js \
  --provider microsoft_365 --file /tmp/ranges-m365.json \
  --source "https://learn.microsoft.com/microsoft-365/enterprise/urls-and-ip-address-ranges" \
  --published-at 2026-11-01 --operator <your-name> --dry-run   # then without --dry-run
```

The CLI validates (canonical CIDRs, public ranges only, ≤ 5 000 entries, IPv4 ≥ /8, IPv6 ≥ /16), refuses a set that removes more than 50 % of the active ranges unless `--force`, and in one transaction creates the next version, supersedes the previous one and audits `integration.egress_ranges_imported`. The smtp-adapter loads the new set within `PROVIDER_EGRESS_CACHE_SECONDS` (60). Check `smtp_provider_egress_ranges{provider}` afterwards. Repeat at least every 45 days (the stale alert).

## Probe domain

`PROVIDER_PROBE_DOMAIN` is an operator-owned subdomain that no tenant uses (§15 Q9), e.g. `probe.<gateway domain>`; the same value on the api, the smtp-adapter and the worker (ConfigMap). The api refuses to verify a tenant domain equal to or under it. Probe addresses are single-use (`eg-probe-<token>@<probe domain>`, only the token's SHA-256 is stored, expiry `PROVIDER_PROBE_TTL_SECONDS`). The smtp-adapter accepts them **only** on provider-relay sessions and stores nothing (no S3 object, no message row). Publish a **null MX** (`MX 0 .`, RFC 7505) for the probe domain: a probe that a misconfigured tenant sends directly instead of through the gateway then bounces at the provider instead of being retried, and the validation shows the probe missing.

## Monitoring

Prometheus job `integration-worker` (port 3086, `/metrics`; locally `infrastructure/monitoring/prometheus.yml`, in-cluster the NetworkPolicy admits Prometheus from the `observability` namespace). Rules: `infrastructure/monitoring/rules/integrations.rules.yml` (`IntegrationWorkerDown`, `ProviderEgressRangesStale`, `ProviderEgressRangesEmpty`, `ProviderRelayProofFailuresHigh`, `ProviderConnectionsCritical`, `ProviderTokenFailures`, `SmtpConnectorOnSharedProviderRange`, `IntegrationTaskBacklog`) with promtool tests in `infrastructure/monitoring/tests/integrations.rules.test.yml`. Tenant-facing: the webhook `integration.health_changed` and the alert `integration_unhealthy` (organization administrators), produced from the worker's outbox event.

## Local stack (Compose)

```bash
docker compose --profile smtp-test --profile apps up -d --wait   # build images one at a time first
```

- `integration-worker` (apps profile) uses container values: every provider endpoint is `http://provider-fake:8480/…` (`PROVIDER_ALLOW_HTTP_ENDPOINTS=true`, local only), probes resolve through dns-sink (`172.31.250.53`) and trust the test CA (`/pki/ca/ca.pem` of the `test-pki` volume, created by the smtp-test profile).
- `provider-fake` (smtp-test profile, TEST-ONLY): `infrastructure/provider-fake` = the library's `FakeProviderServer` behind a small front server: Microsoft token, Graph `organization`/`domains`, the admin-consent redirect (`/m365/login/organizations/v2.0/adminconsent`), Google token and Admin SDK customer/domains; the admin API `/_fake/*` (Bearer `PROVIDER_FAKE_ADMIN_TOKEN`) registers tenants, domains, apps, consents, customers, service-account **public** keys, delegations, scripted failures and DNS TXT records at runtime; host `127.0.0.1:${PROVIDER_FAKE_HOST_PORT}` (18093). It registers the local platform Microsoft app (`PROVIDER_M365_MAILFLOW_APP_CLIENT_ID` / `_CLIENT_SECRET` of `.env`) at start. Its DNS responder (5300) serves `relay-proof.test`, which dns-sink forwards without cache.
- The api builds consent URLs with `http://127.0.0.1:${PROVIDER_FAKE_HOST_PORT}/m365/login` (the URL a browser on the host follows).
- `provider-sender-m365` (172.31.250.70) and `provider-sender-google` (172.31.250.71): smtp-tools clients whose addresses are the `PROVIDER_EGRESS_EXTRA_RANGES` of the local `.env`; `docker compose exec provider-sender-m365 swaks --server postfix-outbound --port 25 …` is provider-relay traffic.
- The smtp-adapter joins `mailtest` to resolve DKIM keys through dns-sink.
- Contract suite against the Compose fake: `PROVIDER_FAKE_URL=http://127.0.0.1:18093 PROVIDER_FAKE_DNS=127.0.0.1:1053 pnpm --filter @email-gateway/integration-worker test:integration -- provider-fake-contract`.

Build the images one at a time (8 GB Docker VM): `docker compose build provider-fake`, then `docker compose build integration-worker`.
