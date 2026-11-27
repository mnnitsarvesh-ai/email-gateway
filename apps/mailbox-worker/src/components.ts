import type { S3Client } from '@aws-sdk/client-s3';
import type { PrismaClient } from '@email-gateway/database';
import type { RateBudget, Sleep } from '@email-gateway/idp-adapters';
import type { Logger } from '@email-gateway/logger';
import type { ThrottleEvent, ThrottleGate } from '@email-gateway/mailbox-api';
import { hasRole, notificationsAvailable, type WorkerConfig } from './config';
import { CopiesHandler } from './copies/copies.handler';
import { S3HeaderReader, type HeaderReader } from './copies/header-reader';
import { S3EmlSink, type EmlSink } from './feeds/eml-sink';
import { FeedRunner } from './feeds/feed-runner';
import { HEALTH_LOCK, HealthJob } from './health/health-job';
import { Maintenance } from './health/maintenance';
import { InventoryRunner } from './inventory/inventory-runner';
import type { MailboxMetrics } from './metrics/mailbox-metrics';
import { RemediationDecider } from './remediation/decide';
import { RemediationRunner } from './remediation/executor';
import { RemediationPolicyLoader } from './remediation/policy-loader';
import {
  createMailboxAccessTokens,
  ProviderRuntime,
  type MailboxAccessTokens,
} from './runtime/provider-runtime';
import {
  CounterStore,
  RedisRateBudget,
  RedisThrottleGate,
  type MailboxRedis,
} from './runtime/redis-stores';
import { errorFields } from './shared/errors';
import { LeaderJob, Periodic, type LeaderLock } from './shared/loops';

export interface ComponentDeps {
  prisma: PrismaClient;
  redis: MailboxRedis;
  locks: LeaderLock;
  s3: S3Client;
  mailBucket: string;
  metrics: MailboxMetrics | null;
  logger: Logger;
  now?: () => Date;
  /** TEST SEAMS (integration suites; never set in production). */
  organizationIds?: readonly bigint[];
  tokens?: MailboxAccessTokens;
  budget?: RateBudget;
  throttle?: ThrottleGate;
  sleep?: Sleep;
  headers?: HeaderReader;
  sink?: EmlSink;
  /** Per-run lock name prefix (suites run beside a paused live worker). */
  lockPrefix?: string;
  /** Feed pages per sync run (default `MAX_PAGES_PER_SYNC`). */
  maxPagesPerSync?: number;
}

/**
 * Every component of the mailbox-worker (design D5), built once per process and started per role
 * (`MAILBOX_WORKER_ROLES`): `copies` (the `email.mailbox` handler with the step API-2 remediation
 * decision; the consumer is started by the module), `feeds` (claim loop), `inventory` (claim
 * loop), `remediate` (claim loop over `api_remediation_actions`, step API-2 R5) and `health`
 * (leader-locked health, maintenance incl. mailbox entry expiry, and the counters flush). The provider runtime (credential key, token cache, provider
 * HTTPS) exists only where a provider-calling role runs.
 */
export class MailboxComponents {
  readonly now: () => Date;
  readonly counters: CounterStore;
  readonly throttle: ThrottleGate;
  readonly budget: RateBudget;
  readonly runtime: ProviderRuntime | null;
  readonly copies: CopiesHandler;
  readonly feeds: FeedRunner | null;
  readonly inventory: InventoryRunner | null;
  /** Step API-2 R5: the `remediate` role's claim loop (null without a provider runtime). */
  readonly remediation: RemediationRunner | null;
  readonly policies: RemediationPolicyLoader;
  readonly health: HealthJob;
  readonly maintenance: Maintenance;
  readonly healthLeader: LeaderJob;
  private readonly periodics: Periodic[] = [];
  private started = false;

  constructor(
    readonly config: Readonly<WorkerConfig>,
    readonly deps: ComponentDeps,
  ) {
    const now = deps.now ?? (() => new Date());
    this.now = now;
    const { prisma, logger, metrics } = deps;
    const orgs = deps.organizationIds ? { organizationIds: deps.organizationIds } : {};
    this.counters = new CounterStore(deps.redis, prisma, logger, now);
    this.budget =
      deps.budget ??
      new RedisRateBudget(deps.redis, {
        graph: config.API_MODE_GRAPH_REQUESTS_PER_SECOND,
        gmail: config.API_MODE_GMAIL_REQUESTS_PER_SECOND,
        google_directory: config.API_MODE_DIRECTORY_REQUESTS_PER_SECOND,
      });
    this.throttle =
      deps.throttle ??
      new RedisThrottleGate(deps.redis, (event) => this.recordThrottle(event), logger);
    const callsProviders =
      hasRole(config, 'feeds') || hasRole(config, 'inventory') || hasRole(config, 'remediate');
    this.runtime = callsProviders
      ? new ProviderRuntime(config, {
          tokens: deps.tokens ?? createMailboxAccessTokens(config, { prisma, logger, now }),
          budget: this.budget,
          throttle: this.throttle,
          logger,
          metrics,
          nowMs: () => now().getTime(),
          ...(deps.sleep ? { sleep: deps.sleep } : {}),
        })
      : null;
    this.policies = new RemediationPolicyLoader({
      now,
      logger: logger.child({ component: 'remediation-policies' }),
    });
    this.copies = new CopiesHandler({
      prisma,
      headers: deps.headers ?? new S3HeaderReader(deps.s3, deps.mailBucket),
      counters: this.counters,
      metrics,
      logger: logger.child({ role: 'copies' }),
      now,
      config: {
        hybridLinkWindowHours: config.API_MODE_HYBRID_LINK_WINDOW_HOURS,
        headerMaxBytes: config.INGEST_HEADER_MAX_BYTES,
      },
      decider: new RemediationDecider({
        policies: this.policies,
        hardDeleteEnabled: config.API_MODE_HARD_DELETE_ENABLED,
      }),
      ...orgs,
    });
    this.feeds = this.runtime
      ? new FeedRunner({
          prisma,
          runtime: this.runtime,
          throttle: this.throttle,
          sink: deps.sink ?? new S3EmlSink(deps.s3, deps.mailBucket),
          counters: this.counters,
          metrics,
          logger: logger.child({ role: 'feeds' }),
          now,
          config: {
            batch: config.API_MODE_FEED_BATCH,
            concurrency: config.API_MODE_FETCH_CONCURRENCY,
            concurrencyPerConnection: config.API_MODE_FETCH_CONCURRENCY_PER_CONNECTION,
            feedPollSeconds: config.API_MODE_FEED_POLL_SECONDS,
            safetyPollSeconds: config.API_MODE_FEED_SAFETY_POLL_SECONDS,
            maxMessageBytes: config.API_MODE_MAX_MESSAGE_BYTES,
            headerMaxBytes: config.INGEST_HEADER_MAX_BYTES,
            subscriptionMinutes: config.API_MODE_GRAPH_SUBSCRIPTION_MINUTES,
            renewBeforeMinutes: config.API_MODE_SUBSCRIPTION_RENEW_BEFORE_MINUTES,
            notificationUrl: notificationsAvailable(config)
              ? config.API_MODE_GRAPH_NOTIFICATION_URL!
              : null,
            notificationSecret: notificationsAvailable(config)
              ? config.API_MODE_NOTIFICATION_SECRET!
              : null,
          },
          ...orgs,
          ...(deps.maxPagesPerSync !== undefined ? { maxPagesPerSync: deps.maxPagesPerSync } : {}),
        })
      : null;
    this.inventory = this.runtime
      ? new InventoryRunner({
          prisma,
          runtime: this.runtime,
          counters: this.counters,
          metrics,
          logger: logger.child({ role: 'inventory' }),
          now,
          config: {
            intervalHours: config.API_MODE_INVENTORY_INTERVAL_HOURS,
            maxMailboxes: config.API_MODE_MAX_MAILBOXES_PER_CONNECTION,
          },
          ...orgs,
        })
      : null;
    this.remediation = this.runtime
      ? new RemediationRunner({
          prisma,
          runtime: this.runtime,
          throttle: this.throttle,
          counters: this.counters,
          metrics,
          logger: logger.child({ role: 'remediate' }),
          now,
          config: {
            batch: config.API_MODE_REMEDIATION_BATCH,
            leaseSeconds: config.API_MODE_REMEDIATION_LEASE_SECONDS,
            concurrency: config.API_MODE_REMEDIATION_CONCURRENCY,
            perConnection: config.API_MODE_REMEDIATION_CONCURRENCY_PER_CONNECTION,
            maxAttempts: config.API_MODE_REMEDIATION_MAX_ATTEMPTS,
            locateAttempts: config.API_MODE_REMEDIATION_LOCATE_ATTEMPTS,
            backoffMaxSeconds: config.API_MODE_REMEDIATION_BACKOFF_MAX_SECONDS,
            hardDeleteEnabled: config.API_MODE_HARD_DELETE_ENABLED,
            quarantineFolderName: config.API_MODE_QUARANTINE_FOLDER_NAME,
            quarantineFolderHidden: config.API_MODE_QUARANTINE_FOLDER_HIDDEN,
            gmailQuarantineLabel: config.API_MODE_GMAIL_QUARANTINE_LABEL,
            tagName: config.API_MODE_TAG_NAME,
            bounds: {
              maxHoldDays: config.QUARANTINE_MAX_HOLD_DAYS,
              maxReviewDays: config.QUARANTINE_MAX_REVIEW_DAYS,
            },
          },
          ...orgs,
        })
      : null;
    this.health = new HealthJob({
      prisma,
      metrics,
      logger: logger.child({ role: 'health' }),
      now,
      config: {
        coverageWarnPercent: config.API_MODE_COVERAGE_WARN_PERCENT,
        coverageFailPercent: config.API_MODE_COVERAGE_FAIL_PERCENT,
        lagWarnSeconds: config.API_MODE_LAG_WARN_SECONDS,
        lagFailSeconds: config.API_MODE_LAG_FAIL_SECONDS,
        throttleWarnPerHour: config.API_MODE_THROTTLE_WARN_PER_HOUR,
        alertMinIntervalHours: config.API_MODE_ALERT_MIN_INTERVAL_HOURS,
        journalCoverageDays: config.API_MODE_JOURNAL_COVERAGE_DAYS,
        feedPollSeconds: config.API_MODE_FEED_POLL_SECONDS,
        safetyPollSeconds: config.API_MODE_FEED_SAFETY_POLL_SECONDS,
        renewBeforeMinutes: config.API_MODE_SUBSCRIPTION_RENEW_BEFORE_MINUTES,
        notificationsAvailable: notificationsAvailable(config),
        remediation: {
          failureWarnPercent: config.API_MODE_REMEDIATION_FAILURE_WARN_PERCENT,
          failureFailPercent: config.API_MODE_REMEDIATION_FAILURE_FAIL_PERCENT,
          backlogWarnMinutes: config.API_MODE_REMEDIATION_BACKLOG_WARN_MINUTES,
          backlogFailMinutes: config.API_MODE_REMEDIATION_BACKLOG_FAIL_MINUTES,
        },
      },
      policies: this.policies,
      ...orgs,
    });
    this.maintenance = new Maintenance({
      prisma,
      runtime: this.runtime,
      logger: logger.child({ role: 'health' }),
      now,
      config: {
        dedupeWindowHours: config.API_MODE_DEDUPE_WINDOW_HOURS,
        remediationRetentionDays: config.API_MODE_REMEDIATION_RETENTION_DAYS,
      },
      ...orgs,
    });
    const lock = `${deps.lockPrefix ?? ''}${HEALTH_LOCK}`;
    this.healthLeader = new LeaderJob(
      'health',
      lock,
      config.API_MODE_HEALTH_INTERVAL_MS,
      async () => {
        await this.health.runOnce();
        await this.maintenance.runOnce();
      },
      {
        locks: deps.locks,
        logger,
        onLeadership: (leader) => metrics?.leader.set({ job: 'health' }, leader ? 1 : 0),
      },
    );
  }

  /**
   * The throttle gate's recorder (D10.6): `throttled_until = GREATEST(…, now + Retry-After)` on the
   * connection, the counters `throttled_429` / `throttled_503` and `api_mode_throttled_total`.
   */
  private async recordThrottle(event: ThrottleEvent): Promise<void> {
    const now = this.now();
    const until = new Date(now.getTime() + event.retryAfterMs);
    const rows = await this.deps.prisma.apiModeConnection.findMany({
      where: { publicId: event.apiConnectionPublicId },
      select: { id: true, provider: true },
      take: 1,
    });
    const row = rows[0];
    if (!row) return;
    await this.deps.prisma.$executeRaw`
      UPDATE api_mode_connections
      SET throttled_until = GREATEST(COALESCE(throttled_until, ${until}), ${until}),
          updated_at = ${now}
      WHERE id = ${row.id}`;
    await this.counters.add(
      row.id,
      event.status === 503 ? { throttled_503: 1 } : { throttled_429: 1 },
    );
    this.deps.metrics?.pause(row.provider, event.family);
    this.deps.logger.info(
      {
        apiConnectionId: event.apiConnectionPublicId,
        family: event.family,
        status: event.status,
        code: event.code,
        retryAfterMs: event.retryAfterMs,
      },
      'provider throttled; connection family paused',
    );
  }

  /** Starts the periodic work of this process's roles. */
  start(): void {
    if (this.started) return;
    this.started = true;
    const { config, deps } = this;
    if (hasRole(config, 'feeds') && this.feeds) {
      const feeds = this.feeds;
      this.periodics.push(
        new Periodic('feeds', config.API_MODE_FEED_TICK_MS, () => feeds.tick(), deps.logger),
      );
    }
    if (hasRole(config, 'remediate') && this.remediation) {
      const remediation = this.remediation;
      this.periodics.push(
        new Periodic(
          'remediate',
          config.API_MODE_REMEDIATION_TICK_MS,
          () => remediation.tick(),
          deps.logger,
        ),
      );
    }
    if (hasRole(config, 'inventory') && this.inventory) {
      const inventory = this.inventory;
      this.periodics.push(new Periodic('inventory', 30_000, () => inventory.tick(), deps.logger));
    }
    if (hasRole(config, 'health')) {
      this.healthLeader.start();
      this.periodics.push(
        new Periodic(
          'counters-flush',
          config.API_MODE_COUNTER_FLUSH_SECONDS * 1000,
          async () => {
            if (!this.healthLeader.isLeader) return;
            await this.counters.flush(deps.organizationIds).catch((error: unknown) => {
              deps.logger.warn({ ...errorFields(error) }, 'api-mode counters flush failed');
            });
          },
          deps.logger,
        ),
      );
    }
    for (const p of this.periodics) p.start();
  }

  async stop(): Promise<void> {
    await Promise.all(this.periodics.map((p) => p.stop()));
    this.periodics.length = 0;
    await this.healthLeader.stop();
    // A last flush keeps the counters of this process (the next leader would flush them too).
    if (hasRole(this.config, 'health')) {
      await this.counters.flush(this.deps.organizationIds).catch(() => undefined);
    }
    this.started = false;
  }
}
