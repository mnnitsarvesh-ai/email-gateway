# @email-gateway/url-security

URL protection primitives of step 4.3 ([design](../../docs/plan/steps/11-url-protection.md),
ADR-0029 … ADR-0032). Pure TypeScript, no Nest, no Prisma: database access is injected
(`FeedQuery`), Redis is an ioredis-like client (`RedisLike`). Used by the email-worker url engine,
the click-service, the url-browser-worker / egress proxy and the api (indicator normalization).

| Module        | Design | Main exports                                                                                                                                                                                                                                                                                                                               |
| ------------- | ------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `extract/`    | U4     | `extractFromHtml`, `extractFromText`, `extractMessageUrls`, `rewritableOccurrences`, `decodeText`, `EXTRACTOR_VERSION` (`url-extract/1`), `URL_SOURCES`                                                                                                                                                                                    |
| `normalize/`  | U5     | `normalizeUrl` (identity / redirect form, A-label + Unicode host, registrable domain, SHA-256), `normalizeDomainInput`, `normalizeIndicator`, `canonicalIp`, `hostMatchesDomain`                                                                                                                                                           |
| `lookalike/`  | U7     | `loadBrands` (`data/brands.json`), `ProtectedSet`, `detectLookalikes` (L1–L6), `skeleton` (UTS #39, `data/confusables.json`), `isHighlyRestrictive`, `lookalikeVersion`                                                                                                                                                                    |
| `net/`        | U8/U15 | `SsrfGuard`, `RestrictedResolver`, `GuardedFetcher` (`FETCHER_VERSION` `url-fetch/1`, direct and proxy client mode; every request under `untraced()`: OpenTelemetry tracing suppressed, so no propagation header reaches an untrusted site and no span records its path), `createEgressProxy`, `parseDialMap`, `ConcurrencyLimiter`        |
| `reputation/` | U6     | `ReputationProvider`, `LocalFeedProvider`, `DnsblProvider`, `RdapProvider`, `ReputationService` (breaker + timeout + cache), `UrlCache` (`eg:url:{rep,chain,dyn}:v1:…`, HMAC-SHA256), `HostAddressResolver` (public A/AAAA answers of domain hosts for IP reputation), `reputationItemsFor` / `chainHosts` / `chainItems` / `addressItems` |
| `landing/`    | U9     | `extractLandingFeatures` (counts, booleans, hosts and brand ids only)                                                                                                                                                                                                                                                                      |
| `verdict/`    | U10    | `mapUrlVerdict` (`url-map/1`), `URL_MAPPER_CODES`, `aggregateUrlEngine`, `decideClick`, `selectScanTimeFetch`, `loadShorteners` (`data/shorteners.txt`)                                                                                                                                                                                    |
| `token/`      | U12    | `signToken` / `verifyToken` (46 bytes, 62 base64url characters), `parseTokenKey`, `continueNonce` / `verifyContinueNonce`                                                                                                                                                                                                                  |
| `rewrite/`    | U11    | `rewriteEml` (streaming, untouched nodes byte-identical), `checkRewriteEligibility`, `REWRITE_SKIP_REASONS`                                                                                                                                                                                                                                |

## Invariants this package enforces

- Nothing resolves a URL target with `dns.lookup`/getaddrinfo: the `RestrictedResolver` uses
  `dns.promises.Resolver` with explicit servers, and the connector dials the validated IP literal
  (its `lookup` accepts IP literals only) and re-checks `remoteAddress`.
- Every hop (redirects, meta refresh, RDAP redirects, proxy requests) is validated before it is
  requested; mixed DNS answers are blocked (any-blocked rule).
- A provider error, an open breaker, a timeout or an incomplete fetch is never `clean`
  (`mapUrlVerdict` reaches `clean` only by C1).
- TEST-ONLY seams (`URL_FETCH_TEST_ALLOW_CIDRS`: documentation ranges only; `URL_FETCH_TEST_DIAL_MAP`)
  are refused unless `testSeamsAllowed` (APP_ENV `local`/`ci`, or NODE_ENV not `production`).

## Data files

- `data/brands.json` — protected brands (`{ id, label, officialDomains }`; official domains must be
  registrable domains, validated on load). Replace with `URL_PROTECTED_BRANDS_FILE`.
- `data/confusables.json` — generated by `pnpm --filter @email-gateway/url-security
confusables:generate` from `https://www.unicode.org/Public/security/16.0.0/confusables.txt`
  (SHA-256 pinned in the script; `--check` verifies; `--source <file>` uses a local copy). Unicode
  License v3: `data/LICENSE-UNICODE.txt`.
- `data/shorteners.txt` — shortener hosts. Replace with `URL_SHORTENER_HOSTS_FILE`.

## Tests

```sh
pnpm --filter @email-gateway/url-security test              # unit: in-process HTTP/HTTPS/proxy servers, no infrastructure
docker compose --profile smtp-test up -d test-pki dns-sink url-test
pnpm --filter @email-gateway/url-security test:integration  # dns-sink + url-test via the dial map (.env)
```

The unit suite generates its TLS certificates at run time with the `openssl` CLI.
