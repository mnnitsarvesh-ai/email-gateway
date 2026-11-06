# URL protection deployment (step 4.3)

Design: [11-url-protection.md](../plan/steps/11-url-protection.md) (U6, U8, U12, U14, U15, U19), ADRs [0029](../architecture/adr/0029-url-security-engine.md)–[0032](../architecture/adr/0032-url-browser-isolation.md). Runbooks: [url-scanning](../runbooks/url-scanning.md), [click-service](../runbooks/click-service.md), [url-browser-worker](../runbooks/url-browser-worker.md). Manifests: `infrastructure/kubernetes/base/{email-worker-url,click-service,url-egress-proxy,url-browser-worker}.yaml`, shared keys in `config.yaml`.

## Topology

| Workload             | Role                                                                                          | Talks to                                                                 |
| -------------------- | --------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------ |
| `email-worker-url`   | URL engine (`scan.url`), results consumer (`scan.url.results`), pending-inspection sweeper    | MySQL writer, S3, Redis, RabbitMQ (`eg-scanner`), resolver, egress proxy |
| `click-service`      | `https://protect.<domain>/c/<token>`: verify, recheck, redirect / warn / block, log the click | MySQL writer (`gateway_click`), Redis, resolver, egress proxy            |
| `url-egress-proxy`   | Authenticated forward proxy with the SSRF guard (every fetcher in mode 2, the browser always) | Internet (80/443) only, resolver                                         |
| `url-browser-worker` | Headless Chromium inspections (`scan.url.inspect` → `inspection_completed.v1`)                | RabbitMQ (`eg-url-browser`), egress proxy                                |

## Egress modes (U8)

Every outbound HTTP(S) request of URL protection — scan-time fetches, click-time rechecks, RDAP, browser traffic — is validated by the same `SsrfGuard` (scheme, port, blocked names, every non-globally-reachable IANA range incl. mapped/NAT64/6to4 forms, deny lists) and resolved by the `RestrictedResolver` (explicit DNS servers, never `getaddrinfo`/`/etc/hosts`, any blocked answer blocks the host); the socket dials the validated IP literal and re-checks `remoteAddress`.

1. **Direct** (`URL_FETCH_EGRESS_PROXY_URL` empty): the fetching pod resolves and dials itself. Add a NetworkPolicy on the fetching pods that allows egress `0.0.0.0/0` on 80/443 **except** RFC 1918, CGNAT `100.64.0.0/10`, link-local `169.254.0.0/16` (metadata), loopback and the platform's own ranges — the guard plus the network layer. Simpler, but the fetching pods (which hold MySQL/S3/token secrets) then have an Internet route.
2. **Egress proxy** (recommended for production; the base `config.yaml` sets `URL_FETCH_EGRESS_PROXY_URL=http://url-egress-proxy:3128`): clients still check scheme/name/port, then send `CONNECT host:port` (https) or an absolute-form `GET` (http) with `Proxy-Authorization: Basic eg:<URL_EGRESS_PROXY_TOKEN>`; the client never resolves the target. The proxy resolves, guards and dials (no TLS termination), caps connections (`URL_EGRESS_MAX_CONNECTIONS`), bytes per connection, idle time and duration, and answers refusals with `403` + `x-egress-blocked-reason`. Its NetworkPolicy admits only pods labelled `email-gateway.io/egress-client=true` and allows egress to the Internet only (private, CGNAT, link-local, metadata and loopback excluded). In this mode the fetching pods need **no** Internet route: give them egress only to the proxy (and their data stores), ideally run the proxy on an egress-only node group/subnet with its own NAT gateway (static egress IPs make provider allow-listing possible).

Set `URL_FETCH_DENY_CIDRS` / `URL_FETCH_DENY_HOSTS` to the platform's own public ranges and names (load balancers, the API, the portal) so a URL can never make the gateway call itself; the click host (`URL_CLICK_BASE_URL`) is refused automatically. The TEST-ONLY seams `URL_FETCH_TEST_ALLOW_CIDRS` / `URL_FETCH_TEST_DIAL_MAP` / `URL_FETCH_CA_FILE` are never set outside local/CI (the services refuse the first two unless `APP_ENV` is `local`/`ci`; with `NODE_ENV=production` and no `APP_ENV` they assume production).

### Egress policy of `email-worker-url` (mode 2)

`email-worker-url.yaml` ships without a NetworkPolicy because its targets depend on the environment's addressing. With the egress proxy, give the pods no Internet route; for example (CIDRs are the managed services' subnets; S3 through a VPC gateway endpoint uses the S3 prefix list, which a NetworkPolicy cannot name: allow 443 to the endpoint's ranges or use a CNI that supports FQDN policies):

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata: { name: email-worker-url }
spec:
  podSelector: { matchLabels: { app.kubernetes.io/name: email-worker-url } }
  policyTypes: [Egress]
  egress:
    - to: [{ podSelector: { matchLabels: { app.kubernetes.io/name: url-egress-proxy } } }]
      ports: [{ protocol: TCP, port: 3128 }]
    - to: [{ ipBlock: { cidr: 10.0.32.0/20 } }] # MySQL writer
      ports: [{ protocol: TCP, port: 3306 }]
    - to: [{ ipBlock: { cidr: 10.0.48.0/20 } }] # Redis
      ports: [{ protocol: TCP, port: 6379 }]
    - to: [{ ipBlock: { cidr: 10.0.64.0/20 } }] # RabbitMQ
      ports: [{ protocol: TCP, port: 5671 }]
    - to: [{ ipBlock: { cidr: 10.0.0.0/16 } }] # S3 interface endpoint / OTel collector
      ports: [{ protocol: TCP, port: 443 }, { protocol: TCP, port: 4318 }]
    - to:
        - namespaceSelector: { matchLabels: { kubernetes.io/metadata.name: kube-system } }
          podSelector: { matchLabels: { k8s-app: kube-dns } }
      ports: [{ protocol: UDP, port: 53 }, { protocol: TCP, port: 53 }]
```

The DNSBL queries of the URL engine and the click-service go to `URL_DNS_SERVERS` (port 53), not through the proxy: allow that resolver too when it is not cluster DNS.

## Resolver requirement

`URL_DNS_SERVERS` must point at a **recursive resolver that does not serve internal zones** (no split-horizon answers for the VPC, the cluster or corporate names) and answers public names only, e.g. a dedicated Unbound/CoreDNS forwarder to public resolvers, or the VPC resolver only if no private hosted zones are associated with the VPC. Empty uses the pod's `resolv.conf` (cluster DNS): acceptable only when cluster DNS forwards non-cluster names to such a resolver; the guard still blocks private and loopback answers (any-blocked rule), but internal names would leak existence through timing. DNSBL providers need a resolver that is **not** a large public one (Spamhaus refuses queries from public resolvers: answer `127.255.255.254`, mapped to `error`, never `clear`). DNS timeouts: `URL_DNS_TIMEOUT_MS` × `URL_DNS_TRIES` per query. The same resolver answers the A/AAAA lookups of every URL and chain host for IP reputation (also in egress-proxy mode; only public answers are sent to the IP blocklists), so it must allow those queries from `email-worker-url` and the click-service.

## Tracing

With `OTEL_EXPORTER_OTLP_ENDPOINT` set (ConfigMap `config.yaml`), the email-worker and the click-service export spans. The guarded fetcher runs every request with tracing suppressed: no `traceparent`/`tracestate`/`baggage` header ever reaches a scanned site and no span carries its path or query. The click-service does not trace incoming `/c/` requests (`untracedIncomingPaths`), so click tokens and continue nonces never reach the collector; its admin port (health, metrics) is traced as usual.

## Reputation providers (U6)

`URL_REPUTATION_PROVIDERS` (comma list). Implemented:

| Provider     | Configuration                                                                                              | Notes                                                                                                                                         |
| ------------ | ---------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------- |
| `local_feed` | none (MySQL `threat_indicators`, platform rows; analyst API `/api/v1/platform/threat-indicators`)          | Never cached: an analyst's block applies to the next scan and the next click.                                                                 |
| `dnsbl`      | `URL_DNSBL_DOMAIN_ZONES`, `URL_DNSBL_IP_ZONES` (`zone=code:category[,…];zone2=…`), `URL_DNSBL_ERROR_CODES` | Spamhaus DBL/ZEN via DQS (the key is part of the zone name: treat the zone string as a secret in the overlay), SURBL, URIBL by configuration. |
| `rdap`       | `URL_RDAP_BASE_URL` (an RDAP bootstrap/aggregator base, e.g. `https://rdap.org`), `URL_NEW_DOMAIN_DAYS`    | Through the guarded fetcher (and the proxy in mode 2); registration date → `url.new_domain`.                                                  |

Never enable `dnsbl` with placeholder zones: a non-existent zone answers NXDOMAIN, which reads as `clear`. The base `config.yaml` enables `local_feed` only; overlays add `dnsbl` and `rdap` with real zones.

**Documented, not implemented** (§10; the provider interface `ReputationProvider` in `@email-gateway/url-security` is the integration point; `createReputationProviders` refuses these names today). Configuration shape when they are added, and data-handling notes:

- **Google Safe Browsing** — `URL_GSB_API_KEY` (secret), `URL_GSB_MODE=update|lookup`, `URL_GSB_CLIENT_ID`. The v4 **Lookup** API (and v5 `hashes:search` with full hashes) sends full URLs (or URL hashes plus prefixes) to Google per lookup: a data transfer of message content to a third party (DPA required; tenants must be told). Prefer the v4 **Update** API / v5 local hash-prefix lists: only 4-byte hash prefixes of candidate URLs leave the platform, and only on a local prefix match. Non-commercial terms apply to the free tier.
- **PhishTank** — `URL_PHISHTANK_APP_KEY` (secret), `URL_PHISHTANK_FEED_URL` (hourly `online-valid.json` download). Use the feed download, not per-URL `checkurl` calls (which send each URL); import into `threat_indicators` (`source = feed:phishtank`, out of scope for 4.3) so lookups stay local. Respect the attribution and rate rules.
- **URLhaus (abuse.ch)** — `URL_URLHAUS_AUTH_KEY` (secret), `URL_URLHAUS_FEED_URL` (CSV/JSON "online" dumps every 5 minutes) or the `/v1/url/` lookup endpoint. Prefer the dumps (local lookups); the lookup API sends each URL. Data is CC0.
- **OpenPhish / commercial URL classification** — feed URL + licence key; same rule: download and match locally whenever the licence allows; per-URL APIs only with a DPA and a tenant notice.

Answers of cacheable providers are cached in the shared Redis under `eg:url:rep:v1:…`, authenticated with HMAC-SHA256 (`URL_CACHE_HMAC_KEY`); entries hold no tenant data and their hit/miss is never shown to tenants.

## Click host: DNS, TLS, CDN, HA (U14)

- **Name:** one host per deployment, `protect.<platform domain>` (`URL_CLICK_BASE_URL=https://protect.<domain>`, https required outside local/CI). It appears in every rewritten link: choose it once; changing it later leaves old links pointing at the old host (keep the old name serving until `URL_TOKEN_MAX_EXPIRY_DAYS` after the change).
- **DNS:** `A`/`AAAA` (or `ALIAS`) to the ingress load balancer; low TTL (60–300 s) for failover. Dedicated customers may use their own name (overlay sets the Ingress host, the TLS secret and `URL_CLICK_BASE_URL`).
- **TLS:** the Ingress terminates TLS (`click-service-tls`, e.g. cert-manager with ACME); TLS 1.2+, HSTS is sent by the service in production. Never put the click host on a shared certificate with customer names.
- **CDN/WAF (optional, not in 4.3):** allowed in front if it does not cache (`Cache-Control: no-store` is sent on every response), does not rewrite query strings or paths, and forwards the client address (`X-Forwarded-For`): then set `CLICK_TRUST_PROXY` to the number of proxy hops (ingress = 1, +1 per CDN layer). A WAF rate rule per client is a useful second layer to `CLICK_RATE_LIMIT_*`.
- **HA:** ≥ 3 replicas across zones, PDB `minAvailable: 2`, HPA on CPU and request rate (prometheus-adapter rule for `click_requests_per_second`), critical alert `ClickServiceDown`. The service is stateless; its decision dependency is MySQL (writer reads through the `gateway_click` account) — a database outage answers 503, never a blind redirect. Redis is optional for correctness (rate limits fail open, cache bypassed). The admin port (3081) is never in the Ingress.

## Secrets

| Secret (Kubernetes)                  | Keys                                                 | Mounted by                                                                    | Notes                                                                                                       |
| ------------------------------------ | ---------------------------------------------------- | ----------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------- |
| `email-gateway-url-token-keys`       | `current`, `current-id`, `previous`?, `previous-id`? | `email-worker-url`, `click-service`                                           | 64 hex characters (32 bytes) each; rotation with two slots and the 90-day rule (click-service runbook).     |
| `email-gateway-url-cache-key`        | `hmac-key`                                           | `email-worker-url`, `click-service`                                           | ≥ 32 characters; rotating it invalidates the cache (entries are `rejected` and refilled).                   |
| `email-gateway-click-db`             | `database-url`                                       | `click-service`                                                               | `mysql://gateway_click:…@<writer>/<db>`; table grants only (`01-users.sh`; Terraform/DBA in production).    |
| `email-gateway-url-egress-token`     | `token`                                              | `url-egress-proxy`, `url-browser-worker`, `click-service`, `email-worker-url` | Shared proxy password; rotate by updating the Secret and restarting the proxy and its clients together.     |
| `email-gateway-rabbitmq-url-browser` | `url`                                                | `url-browser-worker`                                                          | `amqps://eg-url-browser:…@<broker>/<vhost>`; the user may read `scan.url.inspect` and publish results only. |

The Compose equivalents are `.env` keys (`URL_TOKEN_KEY_CURRENT`, `URL_CACHE_HMAC_KEY`, `MYSQL_CLICK_PASSWORD`, `URL_EGRESS_PROXY_TOKEN`, `RABBITMQ_URL_BROWSER_PASSWORD`), each passed only to the containers that need it. The browser worker refuses to start with any database, S3, Redis or token/cache key.

## Rewritten copies in S3

The URL engine stores rewritten EMLs under `org/<org>/rewrite/…` with the object tag `eg-object=rewrite`, set in the creating request (`x-amz-tagging` of PutObject / CreateMultipartUpload; the IAM policy of `email-worker-url` therefore needs `s3:PutObjectTagging` on that prefix, which S3 requires for tagging on create). Production S3 needs the same lifecycle rule as local MinIO (`infrastructure/minio/init-buckets.sh`, rule `eg-rewrite-expiry`): expire objects tagged `eg-object=rewrite` after `URL_REWRITE_OBJECT_RETENTION_DAYS` (30) and their noncurrent versions after 1 day (Terraform `aws_s3_bucket_lifecycle_configuration` with a tag filter). The original EML is never modified.

## Tenants' mailbox platforms: DKIM and gateway trust

Rewriting changes the message body, so an existing DKIM signature of the sender no longer verifies downstream (`url_rewrites.dkim_signed = 1` records it; `rewrite.dkimSignedPolicy=skip` leaves DKIM-signed mail unrewritten). The gateway authenticated the original message (Rspamd, step 4.1) before rewriting; the tenant's mailbox platform must trust the gateway instead of re-evaluating DKIM/DMARC on the modified copy:

- **Microsoft 365:** inbound connector from the gateway's egress IPs, with **Enhanced Filtering for Connectors** (skip listing) enabled, so Exchange Online evaluates the original sending IP and the gateway's authentication results rather than failing DMARC on the rewritten body.
- **Google Workspace:** configure the gateway as an **inbound gateway** (Gmail → Spam, phishing and malware → Inbound gateway) with its IPs, "Automatically detect external IP" on, and "Reject all mail not from gateway IPs" when MX points at the gateway.
- **Other platforms:** an equivalent trusted relay / ARC-sealer allow-list for the gateway. ARC sealing of rewritten mail is not done in 4.3 (§10).

Tenant-facing details: [domain onboarding](../domains/onboarding.md). Outbound rewriting (opt-in direction) happens before the outbound DKIM signer, so the gateway's own signature covers the rewritten body.

## Local (Compose)

- `click-service` (profile `apps`): `127.0.0.1:${CLICK_SERVICE_HOST_PORT:-3080}` public, `${CLICK_SERVICE_ADMIN_HOST_PORT:-3081}` admin; needs `mysql-grants` (creates `gateway_click`).
- `url-egress-proxy` and `url-browser-worker` (profile `url-browser` only; never with analytics/observability on the 8 GB VM; build the image alone): see the [url-browser-worker runbook](../runbooks/url-browser-worker.md#profile-usage-on-the-8-gb-vm).
- `url-test` and `dns-sink` (profile `smtp-test`, TEST-ONLY): the URL corpus in TEST-NET-3 (`203.0.113.10`) and its DNS names.
