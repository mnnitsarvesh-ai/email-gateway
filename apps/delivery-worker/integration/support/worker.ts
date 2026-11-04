import { RedisService, withTransactionDefaults } from '@email-gateway/common';
import { processOnce } from '@email-gateway/database';
import type { DeliveryApprovedV1, EventEnvelope } from '@email-gateway/event-contracts';
import type { WorkerConfig } from '../../src/config';
import { PLANNING_TX_TIMEOUT_MS, RECORDER_TX_TIMEOUT_MS } from '../../src/delivery.module';
import type { DeliveryMetrics } from '../../src/metrics/delivery-metrics';
import { DeliveryPlanner, type PlanResult } from '../../src/planning/delivery-planner';
import { OutboundRateLimiter } from '../../src/rate-limit/outbound-rate-limiter';
import { DeliveryReconciler } from '../../src/reconciler/delivery-reconciler';
import { ReinjectionScheduler } from '../../src/reinjection/reinjection-scheduler';
import { ReinjectionStore } from '../../src/reinjection/reinjection-store';
import { Reinjector } from '../../src/reinjection/reinjector';
import { type Fixtures, newMetrics, silentLogger } from './fixtures';

export interface TestWorker {
  config: Readonly<WorkerConfig>;
  metrics: DeliveryMetrics;
  planner: DeliveryPlanner;
  store: ReinjectionStore;
  reinjector: Reinjector;
  scheduler: ReinjectionScheduler;
  reconciler: DeliveryReconciler;
  /**
   * Plans an approval exactly as the planner consumer does (processOnce + planner), after issuing
   * it as the gateway does (its outbox row, the planner's provenance check).
   */
  plan(event: EventEnvelope<DeliveryApprovedV1>): Promise<PlanResult | 'duplicate'>;
  /** One claim round scoped to the fixture organizations; waits for the sessions. */
  reinjectOnce(): Promise<number>;
  close(): Promise<void>;
}

/**
 * The same component graph DeliveryModule wires, against the real writer, Redis and MinIO,
 * scoped to the fixture organizations (claims and reconciler scans never touch other rows of
 * the shared database).
 */
export function buildWorker(
  fx: Fixtures,
  config: Readonly<WorkerConfig>,
  options: { redisUrl?: string; logSourcePrefix?: string; now?: () => Date } = {},
): TestWorker {
  const prisma = fx.prisma;
  const metrics = newMetrics();
  const redis = options.redisUrl ? new RedisService({ url: options.redisUrl }) : fx.redis;
  const planner = new DeliveryPlanner({
    logger: silentLogger,
    metrics,
    config,
    recorderTimeoutMs: RECORDER_TX_TIMEOUT_MS,
  });
  const store = new ReinjectionStore(prisma);
  const reinjector = new Reinjector({
    prisma,
    store,
    s3: fx.s3.client,
    bucket: fx.s3.mailBucket,
    limiter: new OutboundRateLimiter(prisma, redis.client, config),
    metrics,
    logger: silentLogger,
    config,
    txTimeoutMs: RECORDER_TX_TIMEOUT_MS,
    ...(options.now ? { now: options.now } : {}),
  });
  const scope = { organizationIds: fx.organizationIds };
  const scheduler = new ReinjectionScheduler(
    store,
    reinjector,
    config,
    silentLogger,
    undefined,
    scope,
  );
  const reconciler = new DeliveryReconciler(
    prisma,
    metrics,
    config,
    silentLogger,
    RECORDER_TX_TIMEOUT_MS,
    undefined,
    {
      organizationIds: fx.organizationIds,
      logSourcePrefix: options.logSourcePrefix ?? `postfix-log:it-${fx.suffix}`,
    },
  );
  const txPrisma = withTransactionDefaults(prisma, { timeoutMs: PLANNING_TX_TIMEOUT_MS });
  const consumer = fx.consumer('planner');
  return {
    config,
    metrics,
    planner,
    store,
    reinjector,
    scheduler,
    reconciler,
    async plan(event) {
      await fx.issue(event);
      const result = await processOnce(txPrisma, consumer, event.eventId, (tx) =>
        planner.plan(event, tx),
      );
      return result.status === 'duplicate' ? 'duplicate' : result.result;
    },
    async reinjectOnce() {
      const rows = await scheduler.tick();
      await scheduler.drain();
      return rows.length;
    },
    async close() {
      await scheduler.stop(1000);
      if (options.redisUrl) await redis.onModuleDestroy().catch(() => undefined);
    },
  };
}

/** Test timing: fast timeouts and backoff, a 1 s lease. */
export const FAST = {
  DELIVERY_REINJECT_COMMAND_TIMEOUT_MS: '3000',
  DELIVERY_REINJECT_DATA_TIMEOUT_MS: '3000',
  DELIVERY_REINJECT_LEASE_SECONDS: '1',
  DELIVERY_REINJECT_RETRY_BASE_SECONDS: '1',
  DELIVERY_REINJECT_RETRY_MAX_SECONDS: '4',
  DELIVERY_REINJECT_CONCURRENCY: '4',
  DELIVERY_REINJECT_MAX_AGE_SECONDS: '432000',
  DELIVERY_RATE_TENANT_RCPT_PER_MINUTE: '600',
  DELIVERY_RATE_TENANT_DOMAIN_RCPT_PER_MINUTE: '300',
  DELIVERY_RATE_DESTINATION_DOMAIN_RCPT_PER_MINUTE: '6000',
  DELIVERY_BATCH_MAX_RECIPIENTS: '100',
  DELIVERY_DEV_PASSTHROUGH_ENABLED: 'false',
} as const;

/** Moves a reinjection's next attempt into the past (skip the backoff in tests). */
export async function makeDue(
  fx: Fixtures,
  ids: { id: bigint; receivedAt: Date }[],
): Promise<void> {
  for (const row of ids) {
    await fx.prisma.deliveryReinjection.update({
      where: { id_receivedAt: { id: row.id, receivedAt: row.receivedAt } },
      data: { nextAttemptAt: new Date(Date.now() - 1000) },
    });
  }
}
