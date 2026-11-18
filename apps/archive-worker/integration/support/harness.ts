import { AdvisoryLocks, MetricsService } from '@email-gateway/common';
import type { ArchiveRootKeyProvider } from '@email-gateway/archive';
import { createLogger, type Logger } from '@email-gateway/logger';
import { ArchiveComponents } from '../../src/components';
import type { CaptureFaults } from '../../src/capture/executor';
import { loadWorkerConfig, type WorkerConfig } from '../../src/config';
import { ArchiveMetrics } from '../../src/metrics/archive-metrics';
import { requireEnv } from './broker';
import type { Fixtures } from './fixtures';

/** A controllable clock: real time plus an offset (lease expiry, refresh schedule, orphans). */
export class Clock {
  offsetMs = 0;
  readonly now = (): Date => new Date(Date.now() + this.offsetMs);
  advance(ms: number): void {
    this.offsetMs += ms;
  }
}

export const silent: Logger = createLogger({
  service: 'archive-worker-it',
  level: process.env.IT_LOG_LEVEL ?? 'fatal',
});

/** The worker configuration of the suite (local seams, per-run index prefix, replica bucket). */
export function testConfig(
  fx: Fixtures,
  overrides: Record<string, string | undefined> = {},
): Readonly<WorkerConfig> {
  return loadWorkerConfig({
    ...process.env,
    APP_ENV: 'local',
    LOG_LEVEL: 'fatal',
    ARCHIVE_WORKER_ROLES: 'capture,index,lifecycle,ediscovery',
    ARCHIVE_SEARCH_INDEX_PREFIX: fx.prefix,
    ARCHIVE_REPLICA_TARGETS: fx.replicaBucket,
    ARCHIVE_SWEEP_SAFETY_LAG_SECONDS: '30',
    ARCHIVE_POLICY_RECONCILE_SAFETY_LAG_SECONDS: '60',
    ARCHIVE_JOURNAL_SWEEP_START: 'now',
    ARCHIVE_POLICY_RECONCILE_START: 'now',
    ARCHIVE_CAPTURE_RETRY_BASE_MS: '1000',
    ARCHIVE_CAPTURE_RETRY_MAX_MS: '2000',
    ARCHIVE_SETTINGS_CACHE_TTL_MS: '1000',
    ARCHIVE_KEY_CACHE_TTL_MS: '1000',
    ARCHIVE_CAPTURE_LEASE_SECONDS: '60',
    ARCHIVE_S3_PART_SIZE_BYTES: String(5 * 1_048_576),
    ARCHIVE_TEST_DAY_SECONDS: '',
    ...overrides,
  });
}

export interface Harness {
  comps: ArchiveComponents;
  metrics: MetricsService;
  locks: AdvisoryLocks;
  config: Readonly<WorkerConfig>;
  close(): Promise<void>;
}

/** Every role's components restricted to the suite's organizations, with per-run names. */
export async function harness(
  fx: Fixtures,
  options: {
    config?: Readonly<WorkerConfig>;
    clock?: Clock;
    faults?: CaptureFaults;
    rootKeys?: ArchiveRootKeyProvider;
  } = {},
): Promise<Harness> {
  const config = options.config ?? testConfig(fx);
  const metrics = new MetricsService({ service: `archive-worker-it-${fx.suffix}` });
  const locks = new AdvisoryLocks(requireEnv('DATABASE_URL'));
  const comps = new ArchiveComponents(config, {
    prisma: fx.prisma,
    s3: fx.s3,
    search: fx.search,
    locks,
    metrics: new ArchiveMetrics(metrics),
    logger: silent,
    organizationIds: fx.organizationIds,
    nameSuffix: `:it-${fx.suffix}`,
    ...(options.faults ? { faults: options.faults } : {}),
    ...(options.rootKeys ? { rootKeys: options.rootKeys } : {}),
    ...(options.clock ? { now: options.clock.now } : {}),
    random: () => 0,
  });
  await comps.ensureProbed();
  return {
    comps,
    metrics,
    locks,
    config,
    close: async () => {
      await comps.stop();
      await locks.close().catch(() => undefined);
    },
  };
}

/** Polls `condition` until true. */
export async function eventually(
  condition: () => Promise<boolean> | boolean,
  timeoutMs: number,
  what: string,
  intervalMs = 100,
): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    if (await condition()) return;
    if (Date.now() > deadline) throw new Error(`timed out after ${String(timeoutMs)} ms: ${what}`);
    await new Promise((r) => setTimeout(r, intervalMs));
  }
}

/** Runs the scheduler until no intent of the suite's organizations is due. */
export async function drainCapture(h: Harness, fx: Fixtures, now: () => Date = () => new Date()) {
  for (let i = 0; i < 200; i += 1) {
    await h.comps.capture!.scheduler.runOnce();
    const due = await fx.prisma.archiveCaptureIntent.count({
      where: {
        organizationId: { in: fx.organizationIds },
        status: { in: ['pending', 'captured_open'] },
        nextCheckAt: { lte: now() },
      },
    });
    if (due === 0) return;
  }
  throw new Error('capture did not drain');
}

/** Runs the index sync until the suite's queue rows are applied, then refreshes the indices. */
export async function drainIndex(h: Harness, fx: Fixtures) {
  for (let i = 0; i < 100; i += 1) {
    await h.comps.index!.sync.runOnce();
    const left = await fx.prisma.archiveIndexQueue.count({
      where: { organizationId: { in: fx.organizationIds }, availableAt: { lte: new Date() } },
    });
    if (left === 0) break;
  }
  await fx.search.request('POST', `/${fx.prefix}-*/_refresh`, { allowStatuses: [404] });
}
