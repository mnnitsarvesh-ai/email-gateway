import {
  type DynamicModule,
  Inject,
  Injectable,
  Module,
  type OnApplicationBootstrap,
  type OnModuleDestroy,
} from '@nestjs/common';
import { AdvisoryLocks, PrismaService, RedisService } from '@email-gateway/common';
import type { PrismaClient } from '@email-gateway/database';
import type { Logger } from '@email-gateway/logger';
import {
  ConcurrencyLimiter,
  GuardedPoster,
  type GuardedPosterOptions,
  parseDialMap,
  readCaFile,
  RestrictedResolver,
  SsrfGuard,
} from '@email-gateway/url-security';
import { WebhookSecretCipher } from '@email-gateway/webhooks';
import { webhookRetryConfig, type WorkerConfig } from '../config';
import { WebhookMetrics } from '../metrics/webhook-metrics';
import type { WebhookRead } from '../shared/errors';
import { Periodic } from '../shared/periodic';
import { DeliveryClaimer } from './claimer';
import { DeliveryLoop } from './delivery-loop';
import { type CounterRedis, InflightCounters } from './inflight';
import { type LeaderLock, WebhookMaintenance } from './maintenance';
import { DeliveryRecorder } from './recorder';
import { ReplayProcessor } from './replay';
import { SecretProvider } from './secrets';

/** Lease of a claimed delivery (W8): total timeout + 60 s. */
export const leaseMs = (config: Readonly<WorkerConfig>): number =>
  config.WEBHOOK_HTTP_TOTAL_TIMEOUT_MS + 60_000;

/** The guarded POST client of the worker from its configuration (W9). */
export function createPoster(
  config: Readonly<WorkerConfig>,
  overrides: Partial<GuardedPosterOptions> = {},
): GuardedPoster {
  const env = { nodeEnv: config.NODE_ENV, appEnv: config.APP_ENV };
  return new GuardedPoster({
    guard: new SsrfGuard({
      allowedPorts: config.WEBHOOK_ALLOWED_PORTS,
      testAllowCidrs: config.WEBHOOK_TEST_ALLOW_CIDRS,
      ...env,
    }),
    resolver: new RestrictedResolver({
      servers: config.WEBHOOK_DNS_SERVERS,
      timeoutMs: Math.min(2_000, config.WEBHOOK_HTTP_CONNECT_TIMEOUT_MS),
      tries: 2,
    }),
    connectTimeoutMs: config.WEBHOOK_HTTP_CONNECT_TIMEOUT_MS,
    totalTimeoutMs: config.WEBHOOK_HTTP_TOTAL_TIMEOUT_MS,
    maxResponseBytes: config.WEBHOOK_RESPONSE_MAX_BYTES,
    limiter: new ConcurrencyLimiter(config.WEBHOOK_DELIVERY_CONCURRENCY),
    allowHttp: config.WEBHOOK_ALLOW_HTTP,
    dialMap: parseDialMap(config.WEBHOOK_TEST_DIAL_MAP, env),
    ca: readCaFile(config.WEBHOOK_EXTRA_CA_PATH),
    env,
    ...overrides,
  });
}

export interface DeliveryComponents {
  loop: DeliveryLoop;
  claimer: DeliveryClaimer;
  recorder: DeliveryRecorder;
  counters: InflightCounters;
  secrets: SecretProvider;
  replays: ReplayProcessor;
  replayLoop: Periodic;
  maintenance: WebhookMaintenance;
}

/**
 * Builds the delivery role (W8–W13) from its dependencies; used by the Nest module and by the
 * integration suites (which pass a test poster, a per-run lock name and an organization filter).
 */
export function createDeliveryComponents(
  config: Readonly<WorkerConfig>,
  deps: {
    prisma: PrismaClient;
    redis: CounterRedis;
    locks: LeaderLock;
    metrics: WebhookMetrics;
    logger: Logger;
    poster?: Pick<GuardedPoster, 'post'>;
    organizationIds?: readonly bigint[];
    lockName?: string;
    random?: () => number;
  },
): DeliveryComponents {
  const sink = (read: WebhookRead) => deps.metrics.inconsistentReads.inc({ read });
  const counters = new InflightCounters(deps.redis, {
    leaseMs: leaseMs(config),
    maxPerOrganization: config.WEBHOOK_MAX_INFLIGHT_PER_ORG,
    ratePerMinute: config.WEBHOOK_RATE_PER_SUBSCRIPTION_PER_MINUTE,
  });
  const claimer = new DeliveryClaimer(deps.prisma, counters, {
    totalTimeoutMs: config.WEBHOOK_HTTP_TOTAL_TIMEOUT_MS,
    maxPerSubscription: config.WEBHOOK_MAX_INFLIGHT_PER_SUBSCRIPTION,
    sink,
    ...(deps.organizationIds ? { organizationIds: deps.organizationIds } : {}),
  });
  const recorder = new DeliveryRecorder(deps.prisma, {
    retry: webhookRetryConfig(config),
    autoDisable: {
      failures: config.WEBHOOK_DISABLE_AFTER_FAILURES,
      hours: config.WEBHOOK_DISABLE_AFTER_HOURS,
    },
    sink,
    ...(deps.random ? { random: deps.random } : {}),
  });
  const secrets = new SecretProvider(WebhookSecretCipher.fromConfig(config));
  const loop = new DeliveryLoop({
    prisma: deps.prisma,
    claimer,
    recorder,
    counters,
    poster: deps.poster ?? createPoster(config),
    secrets,
    metrics: deps.metrics,
    sink,
    logger: deps.logger,
    pollIntervalMs: config.WEBHOOK_DELIVERY_POLL_INTERVAL_MS,
    concurrency: config.WEBHOOK_DELIVERY_CONCURRENCY,
    maxPerOrganization: config.WEBHOOK_MAX_INFLIGHT_PER_ORG,
    ...(deps.random ? { random: deps.random } : {}),
  });
  const replays = new ReplayProcessor(deps.prisma, {
    maxEvents: config.WEBHOOK_REPLAY_MAX_EVENTS,
    maxPerDelivery: config.WEBHOOK_REPLAY_MAX_PER_DELIVERY,
    metrics: deps.metrics,
    sink,
    logger: deps.logger,
    ...(deps.organizationIds ? { organizationIds: deps.organizationIds } : {}),
  });
  const replayLoop = new Periodic(
    'webhook-replays',
    Math.max(1_000, config.WEBHOOK_DELIVERY_POLL_INTERVAL_MS),
    () => replays.runOnce(),
    deps.logger,
  );
  const maintenance = new WebhookMaintenance(deps.prisma, {
    locks: deps.locks,
    metrics: deps.metrics,
    logger: deps.logger,
    intervalMs: config.WEBHOOK_MAINTENANCE_INTERVAL_MS,
    deletedRetentionDays: config.WEBHOOK_DELETED_RETENTION_DAYS,
    ...(deps.lockName ? { lockName: deps.lockName } : {}),
    ...(deps.organizationIds ? { organizationIds: deps.organizationIds } : {}),
  });
  return { loop, claimer, recorder, counters, secrets, replays, replayLoop, maintenance };
}

/** The maintenance lock connection (GET_LOCK on its own connection; tests override it). */
export const MAINTENANCE_LOCKS = Symbol('WEBHOOK_MAINTENANCE_LOCKS');
export const DELIVERY_COMPONENTS = Symbol('WEBHOOK_DELIVERY_COMPONENTS');

/** Starts the loops after bootstrap; stops them (in-flight attempts recorded) before shutdown. */
@Injectable()
export class DeliveryRuntime implements OnApplicationBootstrap, OnModuleDestroy {
  constructor(
    @Inject(DELIVERY_COMPONENTS) private readonly components: DeliveryComponents,
    @Inject(MAINTENANCE_LOCKS) private readonly locks: AdvisoryLocks,
  ) {}

  onApplicationBootstrap(): void {
    this.components.loop.start();
    this.components.replayLoop.start();
    this.components.maintenance.start();
  }

  async onModuleDestroy(): Promise<void> {
    await this.components.loop.stop();
    await this.components.replayLoop.stop();
    await this.components.maintenance.stop();
    await this.locks.close().catch(() => undefined);
  }
}

/** The `delivery` role (W8–W13): needs the global DatabaseModule, RedisModule, MetricsModule. */
@Module({})
export class DeliveryModule {
  static forRoot(config: Readonly<WorkerConfig>, logger: Logger): DynamicModule {
    return {
      module: DeliveryModule,
      providers: [
        { provide: MAINTENANCE_LOCKS, useFactory: () => new AdvisoryLocks(config.DATABASE_URL) },
        {
          provide: DELIVERY_COMPONENTS,
          useFactory: (
            prisma: PrismaService,
            redis: RedisService,
            locks: AdvisoryLocks,
            metrics: WebhookMetrics,
          ) =>
            createDeliveryComponents(config, {
              prisma,
              redis: redis.client,
              locks,
              metrics,
              logger,
            }),
          inject: [PrismaService, RedisService, MAINTENANCE_LOCKS, WebhookMetrics],
        },
        DeliveryRuntime,
      ],
      exports: [DELIVERY_COMPONENTS],
    };
  }
}
