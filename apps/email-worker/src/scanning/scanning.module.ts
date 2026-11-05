import {
  type DynamicModule,
  Inject,
  Injectable,
  Module,
  type OnApplicationBootstrap,
  type OnModuleDestroy,
  type OnModuleInit,
} from '@nestjs/common';
import {
  AdvisoryLocks,
  AmqpConnection,
  ConfirmPublisher,
  createMessagingMetrics,
  DEFAULT_MAX_MESSAGE_BYTES,
  type HealthIndicator,
  type MessagingMetrics,
  MetricsService,
  PrismaConsumerProgress,
  PrismaService,
  type QueueConsumer,
  S3Service,
} from '@email-gateway/common';
import type { PrismaClient } from '@email-gateway/database';
import type { Logger } from '@email-gateway/logger';
import { requiredEngines } from '@email-gateway/security-contracts';
import type { HealthDetails } from '@email-gateway/shared-types';
import type { WorkerConfig } from '../config';
import { errorFields } from '../mime-ingestion/error-fields';
import { CircuitBreaker } from './circuit-breaker';
import { DeadlineSweeper, type LeaderLock } from './deadline-sweeper';
import { createEngineConsumer, s3EmlOpener } from './engine-consumer';
import { enabledRegistrations, type ScanEngineRegistration } from './registry';
import {
  type EmlOpener,
  ScanRoundService,
  type ScanTriggerPayload,
  type SettingsLookup,
} from './round-service';
import { ScanMetrics } from './scan-metrics';
import { ScanRepository } from './scan-repository';
import { SettingsResolver } from './settings-resolver';

export const SCAN_LOGGER = Symbol('SCAN_LOGGER');
/** The scan role's own broker connection (role user `eg-scanner`, S1). */
export const SCANNER_AMQP_CONNECTION = Symbol('SCANNER_AMQP_CONNECTION');
export const SCANNER_PUBLISHER = Symbol('SCANNER_PUBLISHER');
export const SCANNER_MESSAGING_METRICS = Symbol('SCANNER_MESSAGING_METRICS');
/** The advisory-lock connection of the deadline sweeper's leader lock. */
export const SCAN_LOCKS = Symbol('SCAN_LOCKS');
export const SCAN_ENGINES = Symbol('SCAN_ENGINES');

/** `amqp_connection_up{connection}` of the scan role. */
export const SCANNER_CONNECTION_NAME = 'email-worker-scanner';
/** Exchanges the scan role publishes to (retry copies, dead letters), verified passively. */
export const SCANNER_EXCHANGES = ['email.security', 'email.events'];

/** One registered engine wired for this worker. */
export interface EngineRuntime {
  registration: ScanEngineRegistration;
  service: ScanRoundService;
  consumer: QueueConsumer<ScanTriggerPayload>;
  breaker: CircuitBreaker;
}

/** A circuit breaker per engine with the S10 settings, reporting into the S17 series. */
export function createEngineBreaker(
  config: Readonly<WorkerConfig>,
  engine: string,
  metrics: ScanMetrics,
  logger: Logger,
  now?: () => number,
): CircuitBreaker {
  return new CircuitBreaker({
    failureThreshold: config.SCAN_BREAKER_FAILURE_THRESHOLD,
    failureRatio: config.SCAN_BREAKER_FAILURE_RATIO,
    window: config.SCAN_BREAKER_WINDOW,
    openMs: config.SCAN_BREAKER_OPEN_MS,
    halfOpenProbes: config.SCAN_BREAKER_HALF_OPEN_PROBES,
    ...(now ? { now } : {}),
    onTransition: (from, to) => {
      metrics.circuit(engine, to);
      const log = { engine, from, to };
      if (to === 'open') logger.warn(log, 'scan engine circuit opened');
      else logger.info(log, 'scan engine circuit changed state');
    },
  });
}

/**
 * The round service of one engine (S5) on the writer, the S3 mail bucket and the shared
 * settings resolver. Also used by the integration tests (per-run consumer names).
 */
export function createRoundService(options: {
  config: Readonly<WorkerConfig>;
  registration: ScanEngineRegistration;
  store: ScanRepository;
  settings: SettingsLookup;
  openEml: EmlOpener;
  metrics: ScanMetrics;
  logger: Logger;
  breaker?: CircuitBreaker;
  consumer?: string;
}): { service: ScanRoundService; breaker: CircuitBreaker } {
  const { config, registration, metrics, logger } = options;
  const engine = registration.catalog.name;
  metrics.registerEngine(engine);
  const breaker = options.breaker ?? createEngineBreaker(config, engine, metrics, logger);
  const service = new ScanRoundService({
    registration,
    adapter: registration.create({ config, logger }),
    store: options.store,
    settings: options.settings,
    openEml: options.openEml,
    breaker,
    metrics,
    logger,
    budget: registration.budget(config),
    requiredEngines: requiredEngines(config.SCAN_ENGINES),
    deadlineSeconds: config.SCAN_ROUND_DEADLINE_SECONDS,
    ...(options.consumer ? { consumer: options.consumer } : {}),
  });
  return { service, breaker };
}

/** The scan role's writer store, settings resolver and EML reads (shared by every engine). */
export function createScanInfrastructure(options: {
  config: Readonly<WorkerConfig>;
  prisma: PrismaClient;
  s3: Pick<S3Service, 'client' | 'mailBucket'>;
  metrics: ScanMetrics;
  logger: Logger;
}): { store: ScanRepository; settings: SettingsResolver; openEml: EmlOpener } {
  const { config, metrics, logger } = options;
  const store = new ScanRepository(options.prisma, config.SCAN_DB_TIMEOUT_MS, metrics.lifecycle);
  const settings = new SettingsResolver({
    source: store,
    config,
    metrics,
    logger: logger.child({ component: 'scan-settings' }),
    ttlMs: config.SCAN_SETTINGS_CACHE_TTL_MS,
  });
  const openEml = s3EmlOpener(options.s3.client, options.s3.mailBucket, config.SCAN_S3_TIMEOUT_MS);
  return { store, settings, openEml };
}

/** Readiness of the scan role's broker connection, under its own indicator name (S1). */
@Injectable()
export class ScannerBrokerHealth implements HealthIndicator {
  readonly healthName = 'rabbitmq-scanner';
  constructor(@Inject(SCANNER_AMQP_CONNECTION) private readonly connection: AmqpConnection) {}

  checkHealth(): Promise<void | HealthDetails> {
    return this.connection.checkHealth();
  }
}

/**
 * Connects the scan role's broker connection at init (verifying `email.security`,
 * `email.events` and the engine queues passively), starts the engine consumers and the deadline
 * sweeper after the application bootstrapped, and on shutdown stops them (in-flight handlers
 * finish, held retries are requeued), then closes the publisher, the connection and the lock
 * connection, all before the database closes (non-global module, as MimeIngestionRuntime).
 */
@Injectable()
export class ScanningRuntime implements OnModuleInit, OnApplicationBootstrap, OnModuleDestroy {
  private started = false;

  constructor(
    @Inject(SCAN_ENGINES) private readonly engines: EngineRuntime[],
    @Inject(DeadlineSweeper) private readonly sweeper: DeadlineSweeper,
    @Inject(SCANNER_AMQP_CONNECTION) private readonly connection: AmqpConnection,
    @Inject(SCANNER_PUBLISHER) private readonly publisher: ConfirmPublisher,
    @Inject(SCAN_LOCKS) private readonly locks: LeaderLock & { close(): Promise<void> },
    @Inject(SCAN_LOGGER) private readonly logger: Logger,
  ) {}

  get running(): boolean {
    return this.started;
  }

  onModuleInit(): void {
    this.connection.requireTopology({
      exchanges: SCANNER_EXCHANGES,
      queues: this.engines.map((e) => e.registration.catalog.queue),
    });
    this.connection.start();
  }

  onApplicationBootstrap(): void {
    for (const engine of this.engines) {
      const { service } = engine;
      engine.consumer.start((event) => service.handle(event));
    }
    this.sweeper.start();
    this.started = true;
    this.logger.info(
      {
        engines: this.engines.map((e) => e.registration.catalog.name),
        queues: this.engines.map((e) => e.registration.catalog.queue),
      },
      'security scanning started',
    );
  }

  async onModuleDestroy(): Promise<void> {
    if (this.started) {
      this.started = false;
      for (const engine of this.engines) {
        try {
          await engine.consumer.stop();
        } catch (err) {
          this.logger.warn(errorFields(err), 'scan consumer did not stop cleanly');
        }
      }
      await this.sweeper.stop().catch(() => this.logger.warn('scan deadline sweeper stop failed'));
    }
    await this.publisher.close().catch(() => this.logger.warn('scanner publisher close failed'));
    await this.connection.close().catch(() => this.logger.warn('scanner connection close failed'));
    await this.locks.close().catch(() => this.logger.warn('scan lock connection close failed'));
  }
}

/**
 * The security scan stage of step 4.1 (docs/plan/steps/09-rspamd.md S1, S5): one
 * `QueueConsumer` per registered and enabled engine (`scan.spam` for Rspamd) on the scan role's
 * own AMQP connection and confirm publisher (`RABBITMQ_SCANNER_URL`, user `eg-scanner`), the
 * generic round service, the deadline sweeper and the S17 metrics. Imported by `AppModule` only
 * when `SCAN_ENABLED`; needs no global `AmqpModule`.
 */
@Module({})
export class ScanningModule {
  static forRoot(config: Readonly<WorkerConfig>, logger: Logger): DynamicModule {
    const scanLogger = logger.child({ role: 'scan' });
    return {
      module: ScanningModule,
      providers: [
        { provide: SCAN_LOGGER, useValue: scanLogger },
        {
          provide: ScanMetrics,
          useFactory: (metrics: MetricsService) => new ScanMetrics(metrics),
          inject: [MetricsService],
        },
        {
          provide: SCANNER_MESSAGING_METRICS,
          useFactory: (metrics: MetricsService): MessagingMetrics =>
            createMessagingMetrics(metrics),
          inject: [MetricsService],
        },
        {
          provide: SCANNER_AMQP_CONNECTION,
          useFactory: (metrics: MessagingMetrics) => {
            if (!config.RABBITMQ_SCANNER_URL) throw new Error('RABBITMQ_SCANNER_URL is not set');
            return new AmqpConnection({
              urls: config.RABBITMQ_SCANNER_URL,
              connectionName: SCANNER_CONNECTION_NAME,
              logger: scanLogger,
              metrics,
            });
          },
          inject: [SCANNER_MESSAGING_METRICS],
        },
        {
          provide: SCANNER_PUBLISHER,
          useFactory: (connection: AmqpConnection, metrics: MessagingMetrics) =>
            new ConfirmPublisher({
              connection,
              logger: scanLogger,
              metrics,
              appId: 'email-worker',
              confirmTimeoutMs: 15_000,
              maxMessageBytes: DEFAULT_MAX_MESSAGE_BYTES,
            }),
          inject: [SCANNER_AMQP_CONNECTION, SCANNER_MESSAGING_METRICS],
        },
        {
          provide: SCAN_LOCKS,
          useFactory: () => new AdvisoryLocks(config.DATABASE_URL),
        },
        {
          provide: SCAN_ENGINES,
          useFactory: (
            prisma: PrismaService,
            s3: S3Service,
            metrics: ScanMetrics,
            connection: AmqpConnection,
            publisher: ConfirmPublisher,
            messaging: MessagingMetrics,
          ): EngineRuntime[] => {
            const infra = createScanInfrastructure({
              config,
              prisma,
              s3,
              metrics,
              logger: scanLogger,
            });
            const progress = new PrismaConsumerProgress(prisma);
            return enabledRegistrations(config.SCAN_ENGINES).map((registration) => {
              const { service, breaker } = createRoundService({
                config,
                registration,
                ...infra,
                metrics,
                logger: scanLogger,
              });
              const consumer = createEngineConsumer({
                config,
                registration,
                connection,
                publisher,
                logger: scanLogger,
                metrics: messaging,
                progress,
              });
              return { registration, service, consumer, breaker };
            });
          },
          inject: [
            PrismaService,
            S3Service,
            ScanMetrics,
            SCANNER_AMQP_CONNECTION,
            SCANNER_PUBLISHER,
            SCANNER_MESSAGING_METRICS,
          ],
        },
        {
          provide: DeadlineSweeper,
          useFactory: (prisma: PrismaService, metrics: ScanMetrics, locks: LeaderLock) =>
            new DeadlineSweeper({
              store: new ScanRepository(prisma, config.SCAN_DB_TIMEOUT_MS, metrics.lifecycle),
              locks,
              metrics,
              logger: scanLogger,
              intervalMs: config.SCAN_SWEEP_INTERVAL_MS,
              lookbackHours: config.SCAN_SWEEP_LOOKBACK_HOURS,
              batchSize: config.SCAN_SWEEP_BATCH_SIZE,
            }),
          inject: [PrismaService, ScanMetrics, SCAN_LOCKS],
        },
        ScannerBrokerHealth,
        ScanningRuntime,
      ],
      exports: [ScanMetrics, ScanningRuntime, ScannerBrokerHealth],
    };
  }
}
