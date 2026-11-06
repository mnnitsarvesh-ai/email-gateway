import { MetricsService } from '@email-gateway/common';
import { createLogger, type Logger } from '@email-gateway/logger';
import {
  sha256Hex,
  signToken,
  type FeedRow,
  type FetchResult,
  type ReputationKind,
} from '@email-gateway/url-security';
import { loadClickConfig, type ClickConfig } from '../config';
import {
  ClickRepository,
  InconsistentReadError,
  type ClickEventRecord,
  type DynamicRow,
  type OutboxRecord,
  type ScanResultRow,
  type UrlKey,
  type UrlRow,
} from './click-repository';
import { ClickEventWriter } from './event-writer';
import { ClickMetrics } from './click-metrics';
import { ClickService } from './click.service';
import { INCR_SCRIPT, PEEK_SCRIPT, RateLimiter } from './rate-limiter';
import { Rechecker } from './recheck';
import { buildUrlRuntime, type UrlRuntime } from './url-runtime';

/** Test fixtures of the click-service (unit and e2e suites); never part of the build. */

export const TEST_KEY_HEX = 'a'.repeat(64);
export const TEST_PREVIOUS_KEY_HEX = 'b'.repeat(64);
export const TEST_CACHE_KEY = 'c'.repeat(48);

export function testEnv(overrides: Record<string, string | undefined> = {}): NodeJS.ProcessEnv {
  return {
    NODE_ENV: 'test',
    APP_ENV: 'ci',
    LOG_LEVEL: 'fatal',
    CLICK_DATABASE_URL: 'mysql://click:pw@127.0.0.1:1/none',
    REDIS_URL: 'redis://127.0.0.1:1/0',
    URL_CACHE_HMAC_KEY: TEST_CACHE_KEY,
    URL_CLICK_BASE_URL: 'http://localhost:3080',
    URL_TOKEN_KEY_CURRENT: TEST_KEY_HEX,
    URL_TOKEN_KEY_CURRENT_ID: '2',
    URL_TOKEN_KEY_PREVIOUS: TEST_PREVIOUS_KEY_HEX,
    URL_TOKEN_KEY_PREVIOUS_ID: '1',
    URL_REPUTATION_PROVIDERS: 'local_feed',
    URL_DNS_SERVERS: '127.0.0.1:9',
    URL_DNS_TIMEOUT_MS: '200',
    URL_DNS_TRIES: '1',
    CLICK_RECHECK_BUDGET_MS: '1000',
    CLICK_EVENT_WRITE_WAIT_MS: '300',
    URL_SHORTENER_EXTRA_HOSTS: 'short-link.test',
    URL_PROTECTED_EXTRA_DOMAINS: 'examplebank.test',
    ...overrides,
  };
}

export const testConfig = (overrides: Record<string, string | undefined> = {}): ClickConfig =>
  loadClickConfig(testEnv(overrides));

export const silentLogger = (): Logger => createLogger({ service: 'click-test', level: 'fatal' });

export const ORG = 42n;
export const MESSAGE = 1001n;
export const RECEIVED_AT = new Date('2026-11-05T10:00:00.000Z');

export function tokenFor(
  config: ClickConfig,
  claims: Partial<{
    organizationId: bigint;
    messageId: bigint;
    receivedAtMs: number;
    urlSeq: number;
    expiresAt: number;
  }> = {},
  key: 'current' | 'previous' = 'current',
): string {
  const signingKey = key === 'current' ? config.tokenKeys.current : config.tokenKeys.previous;
  if (!signingKey) throw new Error('no previous key configured');
  return signToken(
    {
      organizationId: claims.organizationId ?? ORG,
      messageId: claims.messageId ?? MESSAGE,
      receivedAtMs: claims.receivedAtMs ?? RECEIVED_AT.getTime(),
      urlSeq: claims.urlSeq ?? 0,
      expiresAt: claims.expiresAt ?? Math.floor(Date.now() / 1000) + 86_400,
    },
    signingKey,
  );
}

export function urlRow(url: string, overrides: Partial<UrlRow> = {}): UrlRow {
  const parsed = new URL(url);
  const host = parsed.hostname;
  const labels = host.split('.');
  return {
    organizationId: ORG,
    messageId: MESSAGE,
    receivedAt: RECEIVED_AT,
    urlSeq: 0,
    url,
    urlSha256: sha256Hex(url.replace(/#.*$/, '')),
    host,
    unicodeHost: null,
    registrableDomain: /^\d+\.\d+\.\d+\.\d+$/.test(host) ? null : labels.slice(-2).join('.'),
    hostKind: /^\d+\.\d+\.\d+\.\d+$/.test(host) ? 'ipv4' : 'domain',
    truncated: false,
    flags: [],
    ...overrides,
  };
}

export function scanRow(overrides: Partial<ScanResultRow> = {}): ScanResultRow {
  return {
    scanId: 7n,
    urlSha256: '',
    verdict: 'clean',
    reasonCodes: ['clean.no_findings'],
    lookalike: [],
    fetchStatus: 'not_attempted',
    fetchError: null,
    redirectChain: null,
    finalUrl: null,
    finalStatus: null,
    landing: null,
    ...overrides,
  };
}

const keyOf = (k: UrlKey): string =>
  `${k.organizationId}:${k.messageId}:${k.receivedAt.getTime()}:${k.urlSeq}`;

/** In-memory ClickRepository with failure and delay injection. */
export class MemoryClickRepository extends ClickRepository {
  readonly urls = new Map<string, UrlRow>();
  readonly scans = new Map<string, ScanResultRow>();
  readonly dynamics = new Map<string, DynamicRow>();
  readonly settings = new Map<bigint, unknown>();
  readonly domains = new Map<bigint, string[]>();
  /** `${kind}:${sha256}` → row. */
  readonly feed = new Map<string, FeedRow>();
  readonly events: ClickEventRecord[] = [];
  readonly outbox: OutboxRecord[] = [];
  readonly calls: string[] = [];
  fail: Partial<Record<string, 'error' | 'inconsistent' | 'inconsistent-once'>> = {};
  delayMs: Partial<Record<string, number>> = {};
  writeDelayMs = 0;

  addUrl(row: UrlRow): void {
    this.urls.set(keyOf(row), row);
  }

  addScan(row: UrlRow, scan: Partial<ScanResultRow>): void {
    this.scans.set(keyOf(row), scanRow({ urlSha256: row.urlSha256, ...scan }));
  }

  addFeed(kind: ReputationKind, value: string, severity: string, category: string | null): void {
    this.feed.set(`${kind}:${sha256Hex(value)}`, {
      valueSha256: sha256Hex(value),
      severity,
      category,
    });
  }

  private async gate(name: string): Promise<void> {
    this.calls.push(name);
    const delay = this.delayMs[name];
    if (delay) await new Promise((r) => setTimeout(r, delay));
    const mode = this.fail[name];
    if (mode === 'error') throw Object.assign(new Error('db down'), { code: 'P1001' });
    if (mode === 'inconsistent') throw new InconsistentReadError(name);
    if (mode === 'inconsistent-once') {
      delete this.fail[name];
      throw new InconsistentReadError(name);
    }
  }

  async findUrl(key: UrlKey): Promise<UrlRow | null> {
    await this.gate('findUrl');
    return this.urls.get(keyOf(key)) ?? null;
  }

  async latestScanResult(key: UrlKey): Promise<ScanResultRow | null> {
    await this.gate('latestScanResult');
    return this.scans.get(keyOf(key)) ?? null;
  }

  async latestDynamic(key: UrlKey): Promise<DynamicRow | null> {
    await this.gate('latestDynamic');
    return this.dynamics.get(keyOf(key)) ?? null;
  }

  async tenantUrlSettings(organizationId: bigint): Promise<unknown> {
    await this.gate('tenantUrlSettings');
    return this.settings.get(organizationId) ?? null;
  }

  async activeDomains(organizationId: bigint): Promise<string[]> {
    await this.gate('activeDomains');
    return this.domains.get(organizationId) ?? [];
  }

  async feedRows(kind: ReputationKind, hashes: readonly string[]): Promise<FeedRow[]> {
    await this.gate('feedRows');
    return hashes.flatMap((h) => {
      const row = this.feed.get(`${kind}:${h}`);
      return row ? [row] : [];
    });
  }

  async writeClick(event: ClickEventRecord, outbox: OutboxRecord): Promise<void> {
    await this.gate('writeClick');
    if (this.writeDelayMs) await new Promise((r) => setTimeout(r, this.writeDelayMs));
    this.events.push(event);
    this.outbox.push(outbox);
  }
}

/** In-memory Redis for the rate limiter (`eval` of its two scripts) and the URL cache. */
export class MemoryRedis {
  readonly store = new Map<string, string>();
  down = false;
  delayMs = 0;

  private async gate(): Promise<void> {
    if (this.delayMs) await new Promise((r) => setTimeout(r, this.delayMs));
    if (this.down) throw new Error('redis down');
  }

  async eval(script: string, numKeys: number, ...args: Array<string | number>): Promise<number[]> {
    await this.gate();
    const keys = args.slice(0, numKeys).map(String);
    if (script === INCR_SCRIPT) {
      return keys.map((key) => {
        const next = Number(this.store.get(key) ?? '0') + 1;
        this.store.set(key, String(next));
        return next;
      });
    }
    if (script === PEEK_SCRIPT) return keys.map((key) => Number(this.store.get(key) ?? '0'));
    throw new Error('unknown script');
  }

  async get(key: string): Promise<string | null> {
    await this.gate();
    return this.store.get(key) ?? null;
  }

  async set(key: string, value: string): Promise<unknown> {
    await this.gate();
    this.store.set(key, value);
    return 'OK';
  }

  async ping(): Promise<string> {
    await this.gate();
    return 'PONG';
  }
}

// --- assembled service ----------------------------------------------------------------------

export type FakeChain = (url: string, signal?: AbortSignal) => Promise<FetchResult>;

export const completedChain = (url: string, overrides: Partial<FetchResult> = {}): FetchResult => ({
  status: 'completed',
  error: null,
  blockedReason: null,
  hops: [{ host: new URL(url).hostname, port: null, status: 200, kind: 'initial', blocked: null }],
  finalUrl: url,
  finalStatus: 200,
  landing: null,
  durationMs: 5,
  ...overrides,
});

export interface ClickStack {
  config: ClickConfig;
  repository: MemoryClickRepository;
  redis: MemoryRedis;
  metrics: MetricsService;
  clickMetrics: ClickMetrics;
  runtime: UrlRuntime;
  service: ClickService;
  writer: ClickEventWriter;
  chainCalls: string[];
  /** Host lists passed to the address resolver (one entry per call). */
  addressCalls: string[][];
}

/** The real ClickService over the in-memory repository/Redis and a scripted fetcher. */
export function buildClickStack(
  options: {
    env?: Record<string, string | undefined>;
    chain?: FakeChain;
    now?: () => number;
    repository?: MemoryClickRepository;
    redis?: MemoryRedis;
    /** Host → public addresses (the HostAddressResolver contract); absent = none. */
    addresses?: Record<string, string[]>;
  } = {},
): ClickStack {
  const config = testConfig(options.env);
  const repository = options.repository ?? new MemoryClickRepository();
  const redis = options.redis ?? new MemoryRedis();
  const metrics = new MetricsService({ service: 'click-test' });
  const clickMetrics = new ClickMetrics(metrics);
  const runtime = buildUrlRuntime(config, {
    redis: redis,
    feedQuery: (kind, hashes) => repository.feedRows(kind, hashes),
    metrics: clickMetrics,
  });
  const chainCalls: string[] = [];
  const chain = options.chain ?? ((url: string) => Promise.resolve(completedChain(url)));
  (runtime as { fetcher: unknown }).fetcher = {
    fetchChain: (url: string, opts: { signal?: AbortSignal } = {}) => {
      chainCalls.push(url);
      return chain(url, opts.signal);
    },
  };
  const addressCalls: string[][] = [];
  const table = options.addresses ?? {};
  (runtime as { addresses: unknown }).addresses = {
    resolve: (hosts: Iterable<string>) => {
      const list = [...hosts];
      addressCalls.push(list);
      const out = new Map<string, string[]>();
      for (const host of list) if (table[host]) out.set(host, table[host]);
      return Promise.resolve(out);
    },
  };
  const logger = silentLogger();
  const limiter = new RateLimiter(
    redis,
    {
      ipPerMinute: config.CLICK_RATE_LIMIT_IP_PER_MINUTE,
      tokenPerMinute: config.CLICK_RATE_LIMIT_TOKEN_PER_MINUTE,
      invalidPerMinute: config.CLICK_RATE_LIMIT_INVALID_PER_MINUTE,
    },
    100,
  );
  const rechecker = new Rechecker(repository, runtime, clickMetrics, {
    budgetMs: config.CLICK_RECHECK_BUDGET_MS,
    suspiciousHops: config.URL_FETCH_SUSPICIOUS_HOPS,
    highScore: config.URL_LOOKALIKE_HIGH_SCORE,
  });
  const writer = new ClickEventWriter(repository, clickMetrics, logger, {
    waitMs: config.CLICK_EVENT_WRITE_WAIT_MS,
    maxPending: config.CLICK_EVENT_MAX_PENDING,
    txTimeoutMs: config.CLICK_DB_TX_TIMEOUT_MS,
    maxWaitMs: 10_000,
  });
  const service = new ClickService(repository, limiter, rechecker, writer, clickMetrics, logger, {
    tokenKeys: config.tokenKeys,
    platform: config.platform,
    continueTtlSeconds: config.CLICK_CONTINUE_TTL_SECONDS,
    storeClientNetwork: config.CLICK_STORE_CLIENT_NETWORK,
    ...(options.now ? { now: options.now } : {}),
  });
  return {
    config,
    repository,
    redis,
    metrics,
    clickMetrics,
    runtime,
    service,
    writer,
    chainCalls,
    addressCalls,
  };
}

/** The value of one series in the registry (labels as an exact `k="v"` list), or 0. */
export async function metricValue(
  metrics: MetricsService,
  name: string,
  labels: Record<string, string> = {},
): Promise<number> {
  const metric = metrics.registry.getSingleMetric(name);
  if (!metric) return 0;
  const data = await metric.get();
  const match = data.values.find((v) =>
    Object.entries(labels).every(
      ([k, value]) => String((v.labels as Record<string, unknown>)[k]) === value,
    ),
  );
  return match ? Number(match.value) : 0;
}
