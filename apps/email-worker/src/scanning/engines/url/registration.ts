import { createHash } from 'node:crypto';
import {
  engineCatalogEntry,
  type EngineCatalogEntry,
  resolveUrlSettings,
  settingsVersion,
  URL_MAPPING_VERSION,
} from '@email-gateway/security-contracts';
import {
  ConcurrencyLimiter,
  createReputationProviders,
  extractLandingFeatures,
  FETCHER_VERSION,
  GuardedFetcher,
  HostAddressResolver,
  loadBrands,
  loadShorteners,
  lookalikeVersion,
  parseDialMap,
  parseTokenKey,
  ProtectedSet,
  readCaFile,
  ReputationService,
  RestrictedResolver,
  SsrfGuard,
  UrlCache,
} from '@email-gateway/url-security';
import type { WorkerConfig } from '../../../config';
import { S3PartReader } from '../../parts/part-reader';
import type { EngineDeps, EngineSettingsResolution, ScanEngineRegistration } from '../../registry';
import { urlPlatformFromConfig } from '../../url-config';
import { type RewriteStore, S3RewriteStore } from './rewrite-store';
import { type FetchComponent, UrlMetrics } from './url-metrics';
import { FeedErrorScope, UrlEngine, type UrlEngineLimits } from './url.engine';
import { PrismaUrlStore, type UrlStore } from './url-store';

/** Ledger consumer of `scan.url` (topology v5 `ledgerName`). */
export const URL_CONSUMER = 'email-worker.scan.url';

const catalog = engineCatalogEntry('url') as EngineCatalogEntry;

/** U13 / S8: tenant row → effective settings (an invalid row falls back to the platform). */
export function urlSettingsFor(
  config: Readonly<WorkerConfig>,
  row: { settings: unknown; version: number } | null,
): EngineSettingsResolution {
  const platform = urlPlatformFromConfig(config);
  const resolved = resolveUrlSettings(platform, row?.settings ?? null);
  if (resolved.ok) {
    return {
      settings: resolved.settings,
      settingsVersion: settingsVersion(URL_MAPPING_VERSION, platform, row ? row.version : null),
      invalidRow: false,
      violations: [],
    };
  }
  const fallback = resolveUrlSettings(platform, null);
  if (!fallback.ok) throw new Error('the platform URL settings are invalid');
  return {
    settings: fallback.settings,
    settingsVersion: settingsVersion(URL_MAPPING_VERSION, platform, null),
    invalidRow: true,
    violations: [...new Set(resolved.violations.map((v) => v.code))],
  };
}

/** The bounds of one engine call from the configuration (U4, U9, U11, U15). */
export function urlLimitsFromConfig(config: Readonly<WorkerConfig>): UrlEngineLimits {
  return {
    maxUrls: config.URL_MAX_PER_MESSAGE,
    maxOccurrences: config.URL_MAX_OCCURRENCES,
    maxLength: config.URL_MAX_LENGTH,
    maxPartBytes: config.URL_MAX_PART_BYTES,
    maxExtraParts: config.URL_MAX_EXTRA_PARTS,
    extraPartMaxBytes: config.URL_EXTRA_PART_MAX_BYTES,
    extractTimeoutMs: config.URL_EXTRACT_TIMEOUT_MS,
    fetchMaxPerMessage: config.URL_FETCH_MAX_PER_MESSAGE,
    suspiciousHops: config.URL_FETCH_SUSPICIOUS_HOPS,
    dynamicMaxPerMessage: config.URL_DYNAMIC_MAX_PER_MESSAGE,
    dynamicPendingTtlSeconds: config.URL_DYNAMIC_PENDING_TTL_SECONDS,
    rewriteMaxMessageBytes: config.URL_REWRITE_MAX_MESSAGE_BYTES,
    rewriteMaxPartBytes: config.URL_REWRITE_MAX_PART_BYTES,
    maxHeadSize: config.MIME_MAX_HEADER_BLOCK_BYTES,
    maxExpiryDays: config.URL_TOKEN_MAX_EXPIRY_DAYS,
  };
}

/** The SSRF guard of every fetcher of this worker (U8). */
export function createGuard(config: Readonly<WorkerConfig>): SsrfGuard {
  return new SsrfGuard({
    allowedPorts: config.URL_FETCH_ALLOWED_PORTS.map(Number),
    denyCidrs: config.URL_FETCH_DENY_CIDRS,
    denyHosts: config.URL_FETCH_DENY_HOSTS,
    testAllowCidrs: config.URL_FETCH_TEST_ALLOW_CIDRS,
    clickHost: new URL(config.URL_CLICK_BASE_URL).hostname,
    nodeEnv: config.NODE_ENV,
    appEnv: config.APP_ENV,
  });
}

export function createResolver(config: Readonly<WorkerConfig>): RestrictedResolver {
  return new RestrictedResolver({
    servers: config.URL_DNS_SERVERS,
    timeoutMs: config.URL_DNS_TIMEOUT_MS,
    tries: config.URL_DNS_TRIES,
  });
}

/** The authenticated URL cache (U6), or null when disabled or without Redis. */
export function createUrlCache(
  config: Readonly<WorkerConfig>,
  redis: EngineDeps['redis'],
  metrics: UrlMetrics,
): UrlCache | null {
  if (!config.URL_CACHE_ENABLED) return null;
  if (!redis) throw new Error('REDIS_URL is required when URL_CACHE_ENABLED is true');
  if (!config.URL_CACHE_HMAC_KEY) {
    throw new Error('URL_CACHE_HMAC_KEY is required when URL_CACHE_ENABLED is true');
  }
  return new UrlCache({
    client: redis.client,
    hmacKey: config.URL_CACHE_HMAC_KEY,
    ttls: {
      cleanSeconds: config.URL_CACHE_CLEAN_TTL_SECONDS,
      maliciousSeconds: config.URL_CACHE_MALICIOUS_TTL_SECONDS,
      otherSeconds: config.URL_CACHE_OTHER_TTL_SECONDS,
      errorSeconds: config.URL_CACHE_ERROR_TTL_SECONDS,
    },
    timeoutMs: config.URL_CACHE_TIMEOUT_MS,
    onResult: (cache, result) => metrics.cacheResult(cache, result),
  });
}

/** Test seams and replacements of the URL engine's dependencies (integration tests). */
export interface UrlEngineOverrides {
  store?: UrlStore;
  rewriteStore?: RewriteStore;
  resolver?: RestrictedResolver;
  now?: () => Date;
}

/** Everything the url engine is built from (also used by the integration tests). */
export function createUrlEngine(deps: EngineDeps, overrides: UrlEngineOverrides = {}): UrlEngine {
  const { config, logger } = deps;
  const metrics = UrlMetrics.for(deps.registry);
  const nowMs = overrides.now ? () => overrides.now!().getTime() : Date.now;
  const brands = loadBrands(config.URL_PROTECTED_BRANDS_FILE ?? null);
  const shorteners = loadShorteners(
    config.URL_SHORTENER_HOSTS_FILE ?? null,
    config.URL_SHORTENER_EXTRA_HOSTS,
  );
  // Landing title matches use the platform entries only (brands + URL_PROTECTED_EXTRA_DOMAINS):
  // chain results are cached across tenants, so they must not depend on a tenant (U6).
  const titleBrands = new ProtectedSet({
    brands,
    extraDomains: config.URL_PROTECTED_EXTRA_DOMAINS,
  }).titleEntries();
  const guard = createGuard(config);
  const resolver = overrides.resolver ?? createResolver(config);
  const dialMap = parseDialMap(config.URL_FETCH_TEST_DIAL_MAP, {
    nodeEnv: config.NODE_ENV,
    appEnv: config.APP_ENV,
  });
  const limiter = new ConcurrencyLimiter(config.URL_FETCH_CONCURRENCY);
  const ca = readCaFile(config.URL_FETCH_CA_FILE ?? null);
  const proxy =
    config.URL_FETCH_EGRESS_PROXY_URL && config.URL_EGRESS_PROXY_TOKEN
      ? { url: config.URL_FETCH_EGRESS_PROXY_URL, token: config.URL_EGRESS_PROXY_TOKEN }
      : null;
  const fetcherFor = (component: FetchComponent): GuardedFetcher =>
    new GuardedFetcher({
      guard,
      resolver,
      userAgent: config.URL_FETCH_USER_AGENT,
      connectTimeoutMs: config.URL_FETCH_CONNECT_TIMEOUT_MS,
      headerTimeoutMs: config.URL_FETCH_HEADER_TIMEOUT_MS,
      totalTimeoutMs: config.URL_FETCH_TOTAL_TIMEOUT_MS,
      maxHeaderBytes: config.URL_FETCH_MAX_HEADER_BYTES,
      maxBodyBytes: config.URL_FETCH_MAX_BODY_BYTES,
      maxHops: config.URL_FETCH_MAX_HOPS,
      ca,
      dialMap,
      proxy,
      limiter,
      landing: (html, pageUrl) =>
        extractLandingFeatures(html, pageUrl, titleBrands, config.URL_FETCH_MAX_BODY_BYTES),
      hooks: {
        onResult: (result) => metrics.fetch(component, result.status, result.durationMs / 1000),
        onBlocked: (reason) => metrics.blocked(component, reason),
      },
    });
  const store = overrides.store ?? new PrismaUrlStore(deps.prisma);
  const feedErrors = new FeedErrorScope();
  const providers = createReputationProviders(
    {
      providers: config.URL_REPUTATION_PROVIDERS,
      dnsblDomainZones: config.URL_DNSBL_DOMAIN_ZONES,
      dnsblIpZones: config.URL_DNSBL_IP_ZONES,
      dnsblErrorCodes: config.URL_DNSBL_ERROR_CODES,
      rdapBaseUrl: config.URL_RDAP_BASE_URL ?? null,
      newDomainDays: config.URL_NEW_DOMAIN_DAYS,
      concurrency: config.URL_PROVIDER_CONCURRENCY,
    },
    {
      resolver,
      fetcher: fetcherFor('rdap'),
      // MySQL failures of the feed are internal (U3): recorded for the engine call, rethrown.
      feedQuery: feedErrors.wrap(store.feedQuery),
      now: nowMs,
    },
  );
  for (const provider of providers) metrics.provider(provider.id);
  const cache = createUrlCache(config, deps.redis, metrics);
  const reputation = new ReputationService(providers, {
    timeoutMs: config.URL_PROVIDER_TIMEOUT_MS,
    breakerThreshold: config.URL_PROVIDER_BREAKER_THRESHOLD,
    breakerResetMs: config.URL_PROVIDER_BREAKER_RESET_MS,
    cache,
    now: nowMs,
    hooks: {
      onLookup: (provider, status, seconds) => metrics.lookup(provider, status, seconds),
      onBreakerState: (provider, state) => {
        metrics.breaker(provider, state);
        const log = { provider, state };
        if (state === 'open') logger.warn(log, 'url reputation provider circuit opened');
        else logger.info(log, 'url reputation provider circuit changed state');
      },
    },
  });
  const lookalikeHash = createHash('sha256')
    .update(lookalikeVersion(brands))
    .update('\n')
    .update([...config.URL_PROTECTED_EXTRA_DOMAINS].sort().join(','))
    .digest('hex')
    .slice(0, 8);
  const engineVersion =
    `url/2;${FETCHER_VERSION};${lookalikeHash};${reputation.versionsHash}`.slice(0, 64);
  const tokenKey =
    config.URL_REWRITE_ENABLED && config.URL_TOKEN_KEY_CURRENT
      ? parseTokenKey(config.URL_TOKEN_KEY_CURRENT, config.URL_TOKEN_KEY_CURRENT_ID)
      : null;
  if (config.URL_REWRITE_ENABLED && !tokenKey) {
    throw new Error('URL_TOKEN_KEY_CURRENT is required when URL_REWRITE_ENABLED is true');
  }
  const redis = deps.redis;
  return new UrlEngine({
    store,
    parts: new S3PartReader(deps.s3.client, deps.s3.mailBucket, config.SCAN_S3_TIMEOUT_MS),
    reputation,
    fetcher: fetcherFor('engine'),
    // IP reputation of resolved addresses (U3 step 5): public answers of the restricted resolver.
    addresses: new HostAddressResolver(resolver, guard, {
      concurrency: config.URL_PROVIDER_CONCURRENCY,
    }),
    cache,
    rewriteStore:
      overrides.rewriteStore ??
      new S3RewriteStore(deps.s3.client, deps.s3.mailBucket, {
        partSizeBytes: config.MIME_S3_PART_SIZE_BYTES,
        queueSize: config.MIME_S3_QUEUE_SIZE,
      }),
    feedErrors,
    brands,
    extraDomains: config.URL_PROTECTED_EXTRA_DOMAINS,
    shorteners,
    lookalike: {
      minLabel: config.URL_LOOKALIKE_MIN_LABEL,
      longLabel: config.URL_LOOKALIKE_LONG_LABEL,
      maxDistanceShort: config.URL_LOOKALIKE_MAX_DISTANCE_SHORT,
      maxDistanceLong: config.URL_LOOKALIKE_MAX_DISTANCE_LONG,
      highScore: config.URL_LOOKALIKE_HIGH_SCORE,
    },
    limits: urlLimitsFromConfig(config),
    tokenKey,
    clickBaseUrl: config.URL_CLICK_BASE_URL,
    engineVersion,
    probes: {
      redis:
        cache && redis
          ? async () => {
              const reply = await Promise.race([
                redis.client.ping(),
                new Promise<never>((_, reject) =>
                  setTimeout(() => reject(new Error('redis ping timeout')), 2_000).unref(),
                ),
              ]);
              if (reply !== 'PONG') throw new Error('unexpected PING reply');
            }
          : null,
      dns: () => dnsProbe(resolver),
      mode: proxy ? 'proxy' : 'direct',
    },
    metrics,
    logger,
    ...(overrides.now ? { now: overrides.now } : {}),
  });
}

/**
 * Resolver reachability for readiness (non-fatal detail): any DNS answer, including NXDOMAIN,
 * REFUSED or SERVFAIL, means the server answered; a timeout or socket error means unreachable.
 */
export async function dnsProbe(resolver: RestrictedResolver): Promise<'ok' | 'unreachable'> {
  try {
    await resolver.resolve4Raw('eg-readiness-probe.invalid', AbortSignal.timeout(2_000));
    return 'ok';
  } catch (error) {
    const { kind, code } = error as { kind?: unknown; code?: unknown };
    if (code === 'ECONNREFUSED') return 'unreachable';
    return kind === 'refused' || kind === 'servfail' ? 'ok' : 'unreachable';
  }
}

export const urlRegistration: ScanEngineRegistration = {
  catalog,
  consumerName: URL_CONSUMER,
  budget: (config) => ({
    concurrency: config.SCAN_URL_CONCURRENCY,
    timeoutMs: config.SCAN_URL_TIMEOUT_MS,
    maxAttempts: config.SCAN_URL_MAX_ATTEMPTS,
  }),
  create: (deps) => createUrlEngine(deps),
  settingsFor: urlSettingsFor,
};
