import { resolve } from 'node:path';
import { AdvisoryLocks, MetricsService } from '@email-gateway/common';
import type { IdentityProviderAdapter } from '@email-gateway/ato-detection';
import { createLogger, type Logger } from '@email-gateway/logger';
import { type RestrictedResolver } from '@email-gateway/url-security';
import { Redis } from 'ioredis';
import { AtoComponents } from '../../src/components';
import { loadWorkerConfig, type WorkerConfig } from '../../src/config';
import { AtoMetrics } from '../../src/metrics/ato-metrics';
import { requireEnv, type Fixtures } from './fixtures';

const GEOIP = resolve(__dirname, '../../../../packages/ato-detection/test-fixtures/geoip');

/** A controllable clock: a fixed base (or real time) plus an offset. */
export class Clock {
  private base: number;
  private started = Date.now();

  constructor(
    base: Date | null = null,
    private readonly realTime = base === null,
  ) {
    this.base = (base ?? new Date()).getTime();
  }

  readonly now = (): Date => new Date(this.base + (this.realTime ? Date.now() - this.started : 0));

  advance(ms: number): void {
    this.base += ms;
  }

  set(at: Date): void {
    this.base = at.getTime();
    this.started = Date.now();
  }
}

export const silent: Logger = createLogger({
  service: 'ato-worker-it',
  level: process.env.IT_LOG_LEVEL ?? 'fatal',
});

/** The worker configuration of the suites: synthetic GeoIP, dns-sink DNSBL zone, fake adapter. */
export function testConfig(
  overrides: Record<string, string | undefined> = {},
): Readonly<WorkerConfig> {
  return loadWorkerConfig({
    ...process.env,
    APP_ENV: 'local',
    LOG_LEVEL: 'fatal',
    ATO_WORKER_ROLES: 'detect,respond,maintenance,provider',
    ATO_GEOIP_CITY_DB_PATH: `${GEOIP}/synthetic-city.mmdb`,
    ATO_GEOIP_ASN_DB_PATH: `${GEOIP}/synthetic-asn.mmdb`,
    ATO_GEOIP_ANONYMOUS_DB_PATH: `${GEOIP}/synthetic-anonymous.mmdb`,
    ATO_GEOIP_ALLOW_DOCUMENTATION_RANGES: 'true',
    // The dns-sink test zone lists 192.0.2.66 and 203.0.113.66 (infrastructure/dns-sink/scan.test.db).
    ATO_DNSBL_IP_ZONES: 'rbl.scan.test=127.0.0.2:other',
    ATO_DNS_SERVERS: `127.0.0.1:${process.env.DNS_SINK_HOST_PORT ?? '1053'}`,
    ATO_PROVIDER_FAKE_ENABLED: 'true',
    ATO_SETTINGS_CACHE_SECONDS: '1',
    ATO_IP_CAMPAIGN_MIN_ACCOUNTS: '5',
    ...overrides,
  });
}

export interface Harness {
  comps: AtoComponents;
  config: Readonly<WorkerConfig>;
  metrics: MetricsService;
  atoMetrics: AtoMetrics;
  redis: Redis;
  locks: AdvisoryLocks;
  clock: Clock;
  close(): Promise<void>;
  /** The value of a counter/gauge series (labels exact). */
  metric(name: string, labels?: Record<string, string>): Promise<number>;
}

/** Every role's components restricted to the suite's organizations. */
export async function harness(
  fx: Fixtures,
  options: {
    clock?: Clock;
    config?: Readonly<WorkerConfig>;
    fakeAdapter?: IdentityProviderAdapter;
    platformOrganizationId?: bigint;
    resolver?: RestrictedResolver;
  } = {},
): Promise<Harness> {
  const config = options.config ?? testConfig();
  const clock = options.clock ?? new Clock();
  const metrics = new MetricsService({ service: `ato-worker-it-${fx.suffix}` });
  const atoMetrics = new AtoMetrics(metrics);
  const redis = new Redis(requireEnv('REDIS_URL'), { maxRetriesPerRequest: 2 });
  const locks = new AdvisoryLocks(requireEnv('DATABASE_URL'));
  const comps = await AtoComponents.create(config, {
    prisma: fx.prisma,
    redis,
    locks,
    metrics: atoMetrics,
    logger: silent,
    now: clock.now,
    organizationIds: fx.organizationIds,
    lockPrefix: `eg:ato-it-${fx.suffix}:`,
    ...(options.fakeAdapter ? { fakeAdapter: options.fakeAdapter } : {}),
    ...(options.platformOrganizationId !== undefined
      ? { platformOrganizationId: options.platformOrganizationId }
      : {}),
    ...(options.resolver ? { resolver: options.resolver } : {}),
  });
  return {
    comps,
    config,
    metrics,
    atoMetrics,
    redis,
    locks,
    clock,
    async metric(name, labels = {}) {
      const text = await metrics.registry.getSingleMetricAsString(name).catch(() => '');
      let total = 0;
      for (const line of text.split('\n')) {
        if (!line.startsWith(name)) continue;
        const ok = Object.entries(labels).every(([k, v]) => line.includes(`${k}="${v}"`));
        if (ok) total += Number(line.slice(line.lastIndexOf(' ') + 1));
      }
      return total;
    },
    async close() {
      await comps.stop().catch(() => undefined);
      // Short-term keys of the suite's organizations (TTL-bound anyway).
      for (const org of fx.organizationIds) {
        for (const pattern of ['w', 's', 'att', 'seen', 'last', 'sub', 'sigdd', 't4']) {
          let cursor = '0';
          do {
            const [next, keys] = await redis.scan(
              cursor,
              'MATCH',
              `ato:${pattern}:${org}:*`,
              'COUNT',
              1000,
            );
            cursor = next;
            if (keys.length > 0) await redis.del(...keys);
          } while (cursor !== '0');
        }
      }
      await redis.quit().catch(() => undefined);
      await locks.close().catch(() => undefined);
    },
  };
}

/** Polls `condition` until true. */
export async function eventually(
  condition: () => Promise<boolean> | boolean,
  timeoutMs: number,
  what: string,
  intervalMs = 50,
): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    if (await condition()) return;
    if (Date.now() > deadline) throw new Error(`timed out after ${String(timeoutMs)} ms: ${what}`);
    await new Promise((r) => setTimeout(r, intervalMs));
  }
}
