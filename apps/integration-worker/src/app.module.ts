import {
  type DynamicModule,
  Inject,
  Injectable,
  Module,
  type OnApplicationBootstrap,
  type OnModuleDestroy,
} from '@nestjs/common';
import {
  AdvisoryLocks,
  CorrelationModule,
  DatabaseModule,
  HealthModule,
  MetricsModule,
  MetricsService,
  PrismaReadService,
  PrismaService,
} from '@email-gateway/common';
import { createLogger, type Logger } from '@email-gateway/logger';
import { IntegrationComponents } from './components';
import type { WorkerConfig } from './config';
import { IntegrationMetrics } from './metrics/integration-metrics';

export const SERVICE_NAME = 'integration-worker';
export const INTEGRATION_COMPONENTS = Symbol('INTEGRATION_COMPONENTS');
/** The leader-lock connection (GET_LOCK on its own connection; tests override it). */
export const INTEGRATION_LOCKS = Symbol('INTEGRATION_LOCKS');

/** Starts the role loops after bootstrap; stops them (and releases the lock) on shutdown. */
@Injectable()
export class IntegrationRuntime implements OnApplicationBootstrap, OnModuleDestroy {
  constructor(
    @Inject(INTEGRATION_COMPONENTS) private readonly components: IntegrationComponents,
    @Inject(INTEGRATION_LOCKS) private readonly locks: AdvisoryLocks,
  ) {}

  onApplicationBootstrap(): void {
    this.components.start();
  }

  async onModuleDestroy(): Promise<void> {
    await this.components.stop();
    await this.locks.close().catch(() => undefined);
  }
}

/**
 * integration-worker (step 8.2 D11, ADR-0079; docs/plan/steps/25-m365-google-connectors.md).
 * Roles (`INTEGRATION_WORKER_ROLES`): `tasks` (grant verifications, provider domain checks,
 * validation runs and probe completion), `health` (periodic connection health, transitions with
 * the outbox event `integration.connection.health_changed.v1`) and `maintenance` (leader
 * `eg:integration:maintenance`: retention, consent/probe expiry, credential re-encryption,
 * platform gauges). HTTP port 3086 serves probes and `/metrics` only.
 *
 * Data plane: the MySQL writer (claims, updates, audit, outbox) and the reader (delivery
 * statistics only, with writer fallback); no RabbitMQ (events leave through `message_outbox`
 * and the event-relay), no Redis. Provider traffic: HTTPS to the configured endpoints only
 * (locally the provider-fake); SMTP probes to destination hosts (never DATA). Readiness: mysql
 * (the replica's state is reported, never fatal).
 */
@Module({})
export class AppModule {
  static forRoot(config: Readonly<WorkerConfig>): DynamicModule {
    const logger: Logger = createLogger({
      service: SERVICE_NAME,
      level: config.LOG_LEVEL,
      version: config.SERVICE_VERSION,
    });
    return {
      module: AppModule,
      imports: [
        CorrelationModule,
        DatabaseModule.forRoot({
          url: config.DATABASE_URL,
          read: {
            ...(config.DATABASE_READ_URL ? { url: config.DATABASE_READ_URL } : {}),
            maxLagSeconds: config.DATABASE_READ_MAX_LAG_SECONDS,
            lagCheckIntervalMs: config.DATABASE_READ_LAG_CHECK_INTERVAL_MS,
          },
        }),
        MetricsModule.forRoot({ service: SERVICE_NAME }),
        HealthModule.forRoot({
          service: { name: SERVICE_NAME, version: config.SERVICE_VERSION },
          indicators: [PrismaService, PrismaReadService],
        }),
      ],
      providers: [
        {
          provide: IntegrationMetrics,
          useFactory: (metrics: MetricsService) => new IntegrationMetrics(metrics),
          inject: [MetricsService],
        },
        { provide: INTEGRATION_LOCKS, useFactory: () => new AdvisoryLocks(config.DATABASE_URL) },
        {
          provide: INTEGRATION_COMPONENTS,
          useFactory: (
            writer: PrismaService,
            reader: PrismaReadService,
            locks: AdvisoryLocks,
            metrics: IntegrationMetrics,
          ) =>
            new IntegrationComponents(config, {
              writer,
              reader: () => reader.client,
              locks,
              metrics,
              logger,
            }),
          inject: [PrismaService, PrismaReadService, INTEGRATION_LOCKS, IntegrationMetrics],
        },
        IntegrationRuntime,
      ],
      exports: [INTEGRATION_COMPONENTS],
    };
  }
}
