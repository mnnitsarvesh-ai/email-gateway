import {
  type DynamicModule,
  Inject,
  Injectable,
  Module,
  type OnApplicationBootstrap,
  type InjectionToken,
  type OnModuleDestroy,
} from '@nestjs/common';
import {
  AdvisoryLocks,
  AmqpConnection,
  ConfirmPublisher,
  MetricsService,
  PrismaService,
} from '@email-gateway/common';
import type { Logger } from '@email-gateway/logger';
import type { RelayConfig } from './config';
import { RelayMetrics } from './metrics/relay-metrics';
import { OutboxReconciler } from './reconciler/outbox-reconciler';
import { AmqpQueueDepth } from './reconciler/queue-depth';
import { PrismaReconcilerStore } from './reconciler/reconciler-store';
import { OutboxRelay } from './relay/outbox-relay';
import { PrismaRelayStore } from './relay/relay-store';
import { RelayLifecycle } from './relay-lifecycle';

/** AMQP `appId` and connection name of every publish (Q2). */
export const RELAY_APP_ID = 'event-relay';

export const RELAY_CONFIG = Symbol('RELAY_CONFIG');
export const RELAY_LOGGER = Symbol('RELAY_LOGGER');

/** Options of the relay from the validated configuration (shared with the integration tests). */
export function relayOptions(config: Readonly<RelayConfig>) {
  return {
    shards: config.RELAY_SHARDS,
    maxHeldShards: config.RELAY_MAX_HELD_SHARDS,
    batchSize: config.RELAY_BATCH_SIZE,
    scanLimit: config.RELAY_SCAN_LIMIT,
    pollIntervalMs: config.RELAY_POLL_INTERVAL_MS,
    brokerBackoff: {
      baseMs: config.RELAY_BROKER_BACKOFF_BASE_MS,
      maxMs: config.RELAY_BROKER_BACKOFF_MAX_MS,
    },
    rowBackoff: {
      baseMs: config.RELAY_ROW_BACKOFF_BASE_MS,
      maxMs: config.RELAY_ROW_BACKOFF_MAX_MS,
    },
    maxAttempts: config.RELAY_MAX_ATTEMPTS,
    maxMessageBytes: config.RELAY_MAX_MESSAGE_BYTES,
    appId: RELAY_APP_ID,
  };
}

/** Options of the reconciler from the validated configuration (shared with the integration tests). */
export function reconcilerOptions(config: Readonly<RelayConfig>) {
  return {
    queues: config.RECONCILE_QUEUES,
    intervalMs: config.RECONCILE_INTERVAL_MS,
    unconsumedAfterSeconds: config.RECONCILE_UNCONSUMED_AFTER_SECONDS,
    maxRedrives: config.RECONCILE_MAX_REDRIVES,
    lookbackHours: config.RECONCILE_LOOKBACK_HOURS,
    batchSize: config.RECONCILE_BATCH_SIZE,
    startPosition: config.RECONCILE_START_POSITION,
    maxAttempts: config.RELAY_MAX_ATTEMPTS,
  };
}

/** Runs the lifecycle from Nest's hooks (non-global module: stopped before the database closes). */
@Injectable()
export class RelayRuntime implements OnApplicationBootstrap, OnModuleDestroy {
  constructor(@Inject(RelayLifecycle) private readonly lifecycle: RelayLifecycle) {}

  onApplicationBootstrap(): void {
    this.lifecycle.start();
  }

  async onModuleDestroy(): Promise<void> {
    await this.lifecycle.stop();
  }
}

/**
 * Shared providers of both roles: configuration, logger, the relay series and the dedicated
 * advisory-lock connection (one per process: shard locks and the reconciler lock).
 */
@Module({})
export class RelayCoreModule {
  static forRoot(config: Readonly<RelayConfig>, logger: Logger): DynamicModule {
    return {
      module: RelayCoreModule,
      providers: [
        { provide: RELAY_CONFIG, useValue: config },
        { provide: RELAY_LOGGER, useValue: logger },
        {
          provide: RelayMetrics,
          useFactory: (metrics: MetricsService) => new RelayMetrics(metrics),
          inject: [MetricsService],
        },
        { provide: AdvisoryLocks, useFactory: () => new AdvisoryLocks(config.DATABASE_URL) },
      ],
      exports: [RELAY_CONFIG, RELAY_LOGGER, RelayMetrics, AdvisoryLocks],
    };
  }
}

/** The outbox relay (Q11), when `RELAY_ENABLED`. */
@Module({})
export class RelayModule {
  static forRoot(
    core: DynamicModule,
    config: Readonly<RelayConfig>,
    logger: Logger,
  ): DynamicModule {
    return {
      module: RelayModule,
      imports: [core],
      providers: [
        {
          provide: OutboxRelay,
          useFactory: (
            prisma: PrismaService,
            locks: AdvisoryLocks,
            connection: AmqpConnection,
            publisher: ConfirmPublisher,
            metrics: RelayMetrics,
          ) =>
            new OutboxRelay({
              ...relayOptions(config),
              store: new PrismaRelayStore(prisma),
              locks,
              broker: connection,
              publisher,
              metrics,
              logger,
            }),
          inject: [PrismaService, AdvisoryLocks, AmqpConnection, ConfirmPublisher, RelayMetrics],
        },
      ],
      exports: [OutboxRelay],
    };
  }
}

/** The reconciliation service (Q12), when `RECONCILE_ENABLED`. */
@Module({})
export class ReconcilerModule {
  static forRoot(
    core: DynamicModule,
    config: Readonly<RelayConfig>,
    logger: Logger,
  ): DynamicModule {
    return {
      module: ReconcilerModule,
      imports: [core],
      providers: [
        {
          provide: OutboxReconciler,
          useFactory: (
            prisma: PrismaService,
            locks: AdvisoryLocks,
            metrics: RelayMetrics,
            connection: AmqpConnection,
          ) =>
            new OutboxReconciler({
              ...reconcilerOptions(config),
              store: new PrismaReconcilerStore(prisma),
              locks,
              metrics,
              logger,
              queueDepth: new AmqpQueueDepth(connection),
            }),
          inject: [PrismaService, AdvisoryLocks, RelayMetrics, AmqpConnection],
        },
      ],
      exports: [OutboxReconciler],
    };
  }
}

/**
 * The roles of this process (`RELAY_ENABLED`, `RECONCILE_ENABLED`) and their lifecycle.
 * Components are plain classes wired here, so the integration tests build the same graph
 * without Nest.
 */
@Module({})
export class EventRelayModule {
  static forRoot(config: Readonly<RelayConfig>, logger: Logger): DynamicModule {
    // One core module instance: one lock connection for the shard locks and the reconciler lock.
    const core = RelayCoreModule.forRoot(config, logger);
    const imports: DynamicModule[] = [core];
    if (config.RELAY_ENABLED) imports.push(RelayModule.forRoot(core, config, logger));
    if (config.RECONCILE_ENABLED) imports.push(ReconcilerModule.forRoot(core, config, logger));
    const inject: InjectionToken[] = [AdvisoryLocks, ConfirmPublisher, AmqpConnection];
    if (config.RELAY_ENABLED) inject.push(OutboxRelay);
    if (config.RECONCILE_ENABLED) inject.push(OutboxReconciler);
    return {
      module: EventRelayModule,
      imports,
      providers: [
        {
          provide: RelayLifecycle,
          useFactory: (
            locks: AdvisoryLocks,
            publisher: ConfirmPublisher,
            connection: AmqpConnection,
            ...roles: (OutboxRelay | OutboxReconciler)[]
          ) => {
            const relay = roles.find((r): r is OutboxRelay => r instanceof OutboxRelay);
            const reconciler = roles.find(
              (r): r is OutboxReconciler => r instanceof OutboxReconciler,
            );
            return new RelayLifecycle(
              {
                locks,
                publisher,
                connection,
                ...(relay ? { relay } : {}),
                ...(reconciler ? { reconciler } : {}),
              },
              logger,
            );
          },
          inject,
        },
        RelayRuntime,
      ],
      exports: [RelayLifecycle],
    };
  }
}
