import {
  ConcurrencyLimiter,
  createReputationProviders,
  DEFAULT_LOOKALIKE_PARAMS,
  extractLandingFeatures,
  GuardedFetcher,
  HostAddressResolver,
  loadBrands,
  loadShorteners,
  parseDialMap,
  ProtectedSet,
  readCaFile,
  ReputationService,
  RestrictedResolver,
  SsrfGuard,
  UrlCache,
  type Brand,
  type FeedQuery,
  type LookalikeParams,
  type RedisLike,
} from '@email-gateway/url-security';
import type { ClickConfig } from '../config';
import type { ClickMetrics } from './click-metrics';

/**
 * The URL machinery of the click-time recheck (U14 step 4), built once per process from the
 * validated configuration: the shared SSRF guard + restricted resolver (also resolving host
 * addresses for IP reputation) + guarded fetcher of
 * `@email-gateway/url-security` (U8; the click host itself is refused: loop prevention), the
 * authenticated Redis cache (U6) and the reputation service (local feed uncached through the
 * injected query; dnsbl/rdap through the cache).
 */
export interface UrlRuntime {
  guard: SsrfGuard;
  resolver: RestrictedResolver;
  fetcher: GuardedFetcher;
  /** Public addresses of domain hosts for IP reputation (brief item 4, U3 step 5). */
  addresses: Pick<HostAddressResolver, 'resolve'>;
  cache: UrlCache;
  reputation: ReputationService;
  brands: readonly Brand[];
  shorteners: readonly string[];
  lookalikeParams: LookalikeParams;
  /** Platform protected set (brands + URL_PROTECTED_EXTRA_DOMAINS) for landing title matches. */
  platformProtected: ProtectedSet;
}

export function buildUrlRuntime(
  config: Readonly<ClickConfig>,
  deps: { redis: RedisLike; feedQuery: FeedQuery; metrics: ClickMetrics },
): UrlRuntime {
  const env = { nodeEnv: config.NODE_ENV, appEnv: config.APP_ENV };
  const guard = new SsrfGuard({
    allowedPorts: config.URL_FETCH_ALLOWED_PORTS.map(Number),
    denyCidrs: config.URL_FETCH_DENY_CIDRS,
    denyHosts: config.URL_FETCH_DENY_HOSTS,
    testAllowCidrs: config.URL_FETCH_TEST_ALLOW_CIDRS,
    clickHost: config.clickHost,
    nodeEnv: config.NODE_ENV,
    appEnv: config.APP_ENV,
  });
  const resolver = new RestrictedResolver({
    servers: config.URL_DNS_SERVERS,
    timeoutMs: config.URL_DNS_TIMEOUT_MS,
    tries: config.URL_DNS_TRIES,
  });
  const brands = loadBrands(config.URL_PROTECTED_BRANDS_FILE ?? null);
  const platformProtected = new ProtectedSet({
    brands,
    extraDomains: config.URL_PROTECTED_EXTRA_DOMAINS,
  });
  const titleBrands = platformProtected.titleEntries();
  const fetcher = new GuardedFetcher({
    guard,
    resolver,
    userAgent: config.URL_FETCH_USER_AGENT,
    connectTimeoutMs: config.URL_FETCH_CONNECT_TIMEOUT_MS,
    headerTimeoutMs: config.URL_FETCH_HEADER_TIMEOUT_MS,
    totalTimeoutMs: config.URL_FETCH_TOTAL_TIMEOUT_MS,
    maxHeaderBytes: config.URL_FETCH_MAX_HEADER_BYTES,
    maxBodyBytes: config.URL_FETCH_MAX_BODY_BYTES,
    maxHops: config.URL_FETCH_MAX_HOPS,
    ca: readCaFile(config.URL_FETCH_CA_FILE ?? null),
    dialMap: parseDialMap(config.URL_FETCH_TEST_DIAL_MAP, env),
    proxy: config.URL_FETCH_EGRESS_PROXY_URL
      ? { url: config.URL_FETCH_EGRESS_PROXY_URL, token: config.URL_EGRESS_PROXY_TOKEN ?? '' }
      : null,
    limiter: new ConcurrencyLimiter(config.URL_FETCH_CONCURRENCY),
    landing: (html, pageUrl) => extractLandingFeatures(html, pageUrl, titleBrands),
    hooks: {
      onResult: (result) => deps.metrics.fetch(result.status, result.durationMs / 1000),
      onBlocked: (reason) => deps.metrics.fetchBlockedReason(reason),
    },
  });
  const cache = new UrlCache({
    client: deps.redis,
    hmacKey: config.URL_CACHE_HMAC_KEY,
    enabled: config.URL_CACHE_ENABLED,
    ttls: {
      cleanSeconds: config.URL_CACHE_CLEAN_TTL_SECONDS,
      maliciousSeconds: config.URL_CACHE_MALICIOUS_TTL_SECONDS,
      otherSeconds: config.URL_CACHE_OTHER_TTL_SECONDS,
      errorSeconds: config.URL_CACHE_ERROR_TTL_SECONDS,
    },
    timeoutMs: config.URL_CACHE_TIMEOUT_MS,
    onResult: (name, result) => deps.metrics.cacheResult(name, result),
  });
  const providers = createReputationProviders(
    {
      providers: config.URL_REPUTATION_PROVIDERS,
      dnsblDomainZones: config.URL_DNSBL_DOMAIN_ZONES ?? null,
      dnsblIpZones: config.URL_DNSBL_IP_ZONES ?? null,
      dnsblErrorCodes: config.URL_DNSBL_ERROR_CODES ?? null,
      rdapBaseUrl: config.URL_RDAP_BASE_URL ?? null,
      newDomainDays: config.URL_NEW_DOMAIN_DAYS,
      concurrency: config.URL_PROVIDER_CONCURRENCY,
    },
    { resolver, fetcher, feedQuery: deps.feedQuery },
  );
  const reputation = new ReputationService(providers, {
    timeoutMs: config.URL_PROVIDER_TIMEOUT_MS,
    breakerThreshold: config.URL_PROVIDER_BREAKER_THRESHOLD,
    breakerResetMs: config.URL_PROVIDER_BREAKER_RESET_MS,
    cache,
    hooks: {
      onLookup: (provider, status, seconds) =>
        deps.metrics.reputationLookup(provider, status, seconds),
      onBreakerState: (provider, state) => deps.metrics.breakerState(provider, state),
    },
  });
  for (const provider of providers) deps.metrics.breakerState(provider.id, 'closed');
  return {
    guard,
    resolver,
    fetcher,
    addresses: new HostAddressResolver(resolver, guard, {
      concurrency: config.URL_PROVIDER_CONCURRENCY,
    }),
    cache,
    reputation,
    brands,
    shorteners: loadShorteners(
      config.URL_SHORTENER_HOSTS_FILE ?? null,
      config.URL_SHORTENER_EXTRA_HOSTS,
    ),
    lookalikeParams: {
      ...DEFAULT_LOOKALIKE_PARAMS,
      minLabel: config.URL_LOOKALIKE_MIN_LABEL,
      longLabel: config.URL_LOOKALIKE_LONG_LABEL,
      maxDistanceShort: config.URL_LOOKALIKE_MAX_DISTANCE_SHORT,
      maxDistanceLong: config.URL_LOOKALIKE_MAX_DISTANCE_LONG,
      highScore: config.URL_LOOKALIKE_HIGH_SCORE,
    },
    platformProtected,
  };
}
