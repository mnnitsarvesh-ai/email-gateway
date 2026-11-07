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
  RedisService,
  S3Service,
} from '@email-gateway/common';
import type { PrismaClient } from '@email-gateway/database';
import type { Logger } from '@email-gateway/logger';
import { requiredEngines, stage2Engines } from '@email-gateway/security-contracts';
import type { HealthDetails } from '@email-gateway/shared-types';
import type { WorkerConfig } from '../config';
import { errorFields } from '../mime-ingestion/error-fields';
import { CircuitBreaker } from './circuit-breaker';
import { becPlatformFromConfig } from './bec-config';
import {
  attachmentScalingWarnings,
  consumerEngines,
  runsAttachmentConsumer,
  runsBecConsumer,
  runsDlpConsumer,
  runsUrlConsumer,
} from './config';
import { DlpMetrics } from './engines/dlp/dlp-metrics';
import { deleteUncommittedEvidence, S3EvidenceObjects } from './engines/dlp/evidence-objects';
import { DlpEvidenceSweeper } from './engines/dlp/evidence-sweeper';
import { BecMetrics } from './engines/bec/bec-metrics';
import { BecHistorySweeper } from './engines/bec/history-sweeper';
import type { EngineHealthCheck, ScanEngineAdapter } from './engine';
import { AttachmentEngine } from './engines/attachment/attachment.engine';
import { AttachmentMetrics } from './engines/attachment/attachment-metrics';
import { RescanJobRunner } from './engines/attachment/rescan-runner';
import { SignatureWatcher } from './engines/attachment/signature-watcher';
import { InspectionSweeper } from './engines/url/inspection-sweeper';
import { UrlEngine } from './engines/url/url.engine';
import { UrlMetrics } from './engines/url/url-metrics';
import {
  createUrlResultsConsumer,
  URL_RESULTS_QUEUE,
  UrlResultsService,
} from './engines/url/url-results';
import type { UrlInspectionCompletedV1 } from '@email-gateway/event-contracts';
import { DeadlineSweeper, type LeaderLock } from './deadline-sweeper';
import { createEngineConsumer, s3EmlOpener } from './engine-consumer';
import { type EngineDeps, enabledRegistrations, type ScanEngineRegistration } from './registry';
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
/** The attachment engine's background jobs (A13), or null on replicas without its consumer. */
export const ATTACHMENT_JOBS = Symbol('ATTACHMENT_JOBS');

export interface AttachmentJobs {
  watcher: SignatureWatcher;
  runner: RescanJobRunner;
}

/** The url engine's results consumer and pending-inspection sweeper (U15), or null. */
export const URL_JOBS = Symbol('URL_JOBS');

export interface UrlJobs {
  results: UrlResultsService;
  consumer: QueueConsumer<UrlInspectionCompletedV1>;
  sweeper: InspectionSweeper;
}

/** The bec engine's history retention sweeper (B12), or null on replicas without its consumer. */
export const BEC_JOBS = Symbol('BEC_JOBS');

export interface BecJobs {
  sweeper: BecHistorySweeper;
}

/** The dlp engine's evidence sweeper (D16), or null on replicas without its consumer. */
export const DLP_JOBS = Symbol('DLP_JOBS');

export interface DlpJobs {
  sweeper: DlpEvidenceSweeper;
}

/** `amqp_connection_up{connection}` of the scan role. */
export const SCANNER_CONNECTION_NAME = 'email-worker-scanner';
/** Exchanges the scan role publishes to (retry copies, dead letters), verified passively. */
export const SCANNER_EXCHANGES = ['email.security', 'email.events'];

/** One registered engine wired for this worker. */
export interface EngineRuntime {
  registration: ScanEngineRegistration;
  service: ScanRoundService;
  adapter: ScanEngineAdapter;
  consumer: QueueConsumer<ScanTriggerPayload>;
  breaker: CircuitBreaker;
}

/** The registrations whose consumers this replica runs (SCAN_CONSUMERS ⊆ SCAN_ENGINES, A1). */
export function consumerRegistrations(config: Readonly<WorkerConfig>): ScanEngineRegistration[] {
  const consumers = consumerEngines(config);
  return enabledRegistrations(config.SCAN_ENGINES).filter((r) =>
    consumers.includes(r.catalog.name),
  );
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
  /** What the registration builds its adapter from (step 4.2 A12). */
  deps: Omit<EngineDeps, 'config' | 'logger' | 'metrics'>;
  /** A prebuilt adapter (tests); default `registration.create(deps)`. */
  adapter?: ScanEngineAdapter;
  breaker?: CircuitBreaker;
  consumer?: string;
}): { service: ScanRoundService; breaker: CircuitBreaker; adapter: ScanEngineAdapter } {
  const { config, registration, metrics, logger } = options;
  const engine = registration.catalog.name;
  metrics.registerEngine(engine);
  const breaker = options.breaker ?? createEngineBreaker(config, engine, metrics, logger);
  const adapter =
    options.adapter ?? registration.create({ config, logger, metrics, ...options.deps });
  const service = new ScanRoundService({
    registration,
    adapter,
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
  return { service, breaker, adapter };
}

/** The adapter's readiness check `name`, or a check that fails (no such engine running). */
function engineHealthCheck(engines: EngineRuntime[], name: string): EngineHealthCheck | null {
  for (const engine of engines) {
    const check = engine.adapter.healthChecks?.().find((c) => c.name === name);
    if (check) return check;
  }
  return null;
}

/** Readiness `clamav` (clamd PING) on replicas running the attachment consumer (A12). */
@Injectable()
export class ClamavHealth implements HealthIndicator {
  readonly healthName = 'clamav';
  constructor(@Inject(SCAN_ENGINES) private readonly engines: EngineRuntime[]) {}

  async checkHealth(): Promise<void | HealthDetails> {
    const check = engineHealthCheck(this.engines, this.healthName);
    if (!check) throw new Error('the attachment engine does not run in this worker');
    return (await check.check()) as void | HealthDetails;
  }
}

/** Readiness `attachment-inspector` (pool ready, rlimit mode, bundle id; A4, A12). */
@Injectable()
export class InspectorHealth implements HealthIndicator {
  readonly healthName = 'attachment-inspector';
  constructor(@Inject(SCAN_ENGINES) private readonly engines: EngineRuntime[]) {}

  async checkHealth(): Promise<void | HealthDetails> {
    const check = engineHealthCheck(this.engines, this.healthName);
    if (!check) throw new Error('the attachment engine does not run in this worker');
    return (await check.check()) as void | HealthDetails;
  }
}

/** Readiness `url-engine` (Redis when the cache is on; DNS reachability as a detail; U3). */
@Injectable()
export class UrlEngineHealth implements HealthIndicator {
  readonly healthName = 'url-engine';
  constructor(@Inject(SCAN_ENGINES) private readonly engines: EngineRuntime[]) {}

  async checkHealth(): Promise<void | HealthDetails> {
    const check = engineHealthCheck(this.engines, this.healthName);
    if (!check) throw new Error('the url engine does not run in this worker');
    return (await check.check()) as void | HealthDetails;
  }
}

/** Readiness `bec-engine` (model manifest and lexicons loaded; the LLM is not required; B16). */
@Injectable()
export class BecEngineHealth implements HealthIndicator {
  readonly healthName = 'bec-engine';
  constructor(@Inject(SCAN_ENGINES) private readonly engines: EngineRuntime[]) {}

  async checkHealth(): Promise<void | HealthDetails> {
    const check = engineHealthCheck(this.engines, this.healthName);
    if (!check) throw new Error('the bec engine does not run in this worker');
    return (await check.check()) as void | HealthDetails;
  }
}

/** Readiness `dlp-engine` (versions, evidence mode) on replicas running the dlp engine (D22). */
@Injectable()
export class DlpEngineHealth implements HealthIndicator {
  readonly healthName = 'dlp-engine';
  constructor(@Inject(SCAN_ENGINES) private readonly engines: EngineRuntime[]) {}

  async checkHealth(): Promise<void | HealthDetails> {
    const check = engineHealthCheck(this.engines, this.healthName);
    if (!check) throw new Error('the dlp engine does not run in this worker');
    return (await check.check()) as void | HealthDetails;
  }
}

/** Readiness `dlp-extractor` (extractor children ready, rlimit and permission mode; D4). */
@Injectable()
export class DlpExtractorHealth implements HealthIndicator {
  readonly healthName = 'dlp-extractor';
  constructor(@Inject(SCAN_ENGINES) private readonly engines: EngineRuntime[]) {}

  async checkHealth(): Promise<void | HealthDetails> {
    const check = engineHealthCheck(this.engines, this.healthName);
    if (!check) throw new Error('the dlp engine does not run in this worker');
    return (await check.check()) as void | HealthDetails;
  }
}

/** The evidence retention sweeper of the dlp engine (D16). */
export function createDlpJobs(options: {
  config: Readonly<WorkerConfig>;
  prisma: PrismaClient;
  s3: Pick<S3Service, 'client' | 'mailBucket'>;
  locks: LeaderLock;
  registry: MetricsService;
  logger: Logger;
  lockName?: string;
  organizationIds?: readonly bigint[];
  now?: () => Date;
}): DlpJobs {
  const { config } = options;
  return {
    sweeper: new DlpEvidenceSweeper({
      prisma: options.prisma,
      objects: new S3EvidenceObjects(
        options.s3.client,
        options.s3.mailBucket,
        config.SCAN_S3_TIMEOUT_MS,
      ),
      locks: options.locks,
      metrics: DlpMetrics.for(options.registry),
      logger: options.logger,
      intervalMs: config.DLP_EVIDENCE_SWEEP_INTERVAL_MS,
      txTimeoutMs: config.SCAN_DB_TIMEOUT_MS,
      ...(options.lockName ? { lockName: options.lockName } : {}),
      ...(options.organizationIds ? { organizationIds: options.organizationIds } : {}),
      ...(options.now ? { now: options.now } : {}),
    }),
  };
}

/** The communication-history retention sweeper of the bec engine (B12). */
export function createBecJobs(options: {
  config: Readonly<WorkerConfig>;
  prisma: PrismaClient;
  locks: LeaderLock;
  registry: MetricsService;
  logger: Logger;
  lockName?: string;
  organizationIds?: readonly bigint[];
  now?: () => Date;
}): BecJobs {
  const { config } = options;
  return {
    sweeper: new BecHistorySweeper({
      prisma: options.prisma,
      locks: options.locks,
      metrics: BecMetrics.for(options.registry),
      logger: options.logger,
      platform: becPlatformFromConfig(config),
      intervalMs: config.BEC_HISTORY_SWEEP_INTERVAL_MS,
      txTimeoutMs: config.SCAN_DB_TIMEOUT_MS,
      ...(options.lockName ? { lockName: options.lockName } : {}),
      ...(options.organizationIds ? { organizationIds: options.organizationIds } : {}),
      ...(options.now ? { now: options.now } : {}),
    }),
  };
}

/** The results consumer and the sweeper of the url engine (U15), on the scan role's connection. */
export function createUrlJobs(options: {
  config: Readonly<WorkerConfig>;
  prisma: PrismaClient;
  engine: UrlEngine;
  locks: LeaderLock;
  registry: MetricsService;
  connection: AmqpConnection;
  publisher: ConfirmPublisher;
  messaging?: MessagingMetrics;
  logger: Logger;
  consumer?: string;
  lockName?: string;
  organizationIds?: readonly bigint[];
}): UrlJobs {
  const { config } = options;
  const metrics = UrlMetrics.for(options.registry);
  const results = new UrlResultsService({
    prisma: options.prisma,
    txTimeoutMs: config.SCAN_DB_TIMEOUT_MS,
    cache: options.engine.cache,
    metrics,
    logger: options.logger,
    highScore: config.URL_LOOKALIKE_HIGH_SCORE,
    ...(options.consumer ? { consumer: options.consumer } : {}),
  });
  return {
    results,
    consumer: createUrlResultsConsumer({
      connection: options.connection,
      publisher: options.publisher,
      service: results,
      prefetch: config.SCAN_URL_CONCURRENCY,
      retry: { baseDelayMs: config.SCAN_RETRY_BASE_MS, maxDelayMs: config.SCAN_RETRY_MAX_MS },
      logger: options.logger,
      ...(options.messaging ? { metrics: options.messaging } : {}),
    }),
    sweeper: new InspectionSweeper({
      prisma: options.prisma,
      locks: options.locks,
      metrics,
      logger: options.logger,
      intervalMs: config.URL_DYNAMIC_SWEEP_INTERVAL_MS,
      pendingTtlSeconds: config.URL_DYNAMIC_PENDING_TTL_SECONDS,
      txTimeoutMs: config.SCAN_DB_TIMEOUT_MS,
      ...(options.lockName ? { lockName: options.lockName } : {}),
      ...(options.organizationIds ? { organizationIds: options.organizationIds } : {}),
    }),
  };
}

/** The signature watcher and the rescan runner of the attachment engine (A13). */
export function createAttachmentJobs(options: {
  config: Readonly<WorkerConfig>;
  prisma: PrismaClient;
  engine: AttachmentEngine;
  locks: LeaderLock;
  registry: MetricsService;
  metrics: ScanMetrics;
  logger: Logger;
}): AttachmentJobs {
  const { config } = options;
  const attachmentMetrics = AttachmentMetrics.for(options.registry);
  return {
    watcher: new SignatureWatcher({
      prisma: options.prisma,
      locks: options.locks,
      source: options.engine.signatureSource(),
      metrics: attachmentMetrics,
      logger: options.logger,
      intervalMs: config.ATTACHMENT_SIGNATURE_POLL_MS,
      mode: config.ATTACHMENT_SIGNATURE_RESCAN,
      windowHours: config.ATTACHMENT_RESCAN_WINDOW_HOURS,
      maxMessages: config.ATTACHMENT_RESCAN_MAX_MESSAGES,
      txTimeoutMs: config.SCAN_DB_TIMEOUT_MS,
    }),
    runner: new RescanJobRunner({
      prisma: options.prisma,
      locks: options.locks,
      metrics: attachmentMetrics,
      lifecycleMetrics: options.metrics.lifecycle,
      logger: options.logger,
      intervalMs: config.ATTACHMENT_RESCAN_INTERVAL_MS,
      batchSize: config.ATTACHMENT_RESCAN_BATCH_SIZE,
      txTimeoutMs: config.SCAN_DB_TIMEOUT_MS,
    }),
  };
}

/** The scan role's writer store, settings resolver and EML reads (shared by every engine). */
export function createScanInfrastructure(options: {
  config: Readonly<WorkerConfig>;
  prisma: PrismaClient;
  s3: Pick<S3Service, 'client' | 'mailBucket'>;
  metrics: ScanMetrics;
  logger: Logger;
  /** The worker's registry (child-row metrics: `bec_history_updates_total`). */
  registry?: MetricsService;
}): { store: ScanRepository; settings: SettingsResolver; openEml: EmlOpener } {
  const { config, metrics, logger } = options;
  // Stage-2 engines are triggered by any replica's stage-1 finals: zero series everywhere.
  for (const engine of stage2Engines()) {
    if (config.SCAN_ENGINES.includes(engine)) metrics.stageTriggers.inc({ engine }, 0);
  }
  const registry = options.registry;
  // Step 4.5 D3 step 9: the evidence object of a dlp final whose row was not committed is
  // deleted (best effort; undecryptable either way).
  const evidenceObjects = new S3EvidenceObjects(
    options.s3.client,
    options.s3.mailBucket,
    config.SCAN_S3_TIMEOUT_MS,
  );
  const store = new ScanRepository(options.prisma, config.SCAN_DB_TIMEOUT_MS, metrics.lifecycle, {
    ...(registry ? { becHistory: (result) => BecMetrics.for(registry).historyUpdate(result) } : {}),
    dlpEvidenceUncommitted: async (key, organizationId) => {
      const deleted = await deleteUncommittedEvidence(
        evidenceObjects,
        (result) => (registry ? DlpMetrics.for(registry).evidence(result) : undefined),
        key,
        organizationId,
      );
      if (!deleted) {
        logger.warn(
          { organizationId: organizationId.toString() },
          'dlp evidence object without a committed row was left (undecryptable)',
        );
      }
    },
    dlpIncidentSkipped: () => logger.warn('dlp incident not written: the message row is gone'),
  });
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
    @Inject(ATTACHMENT_JOBS) private readonly jobs: AttachmentJobs | null,
    @Inject(URL_JOBS) private readonly urlJobs: UrlJobs | null,
    @Inject(BEC_JOBS) private readonly becJobs: BecJobs | null,
    @Inject(DLP_JOBS) private readonly dlpJobs: DlpJobs | null,
  ) {}

  get running(): boolean {
    return this.started;
  }

  onModuleInit(): void {
    this.connection.requireTopology({
      exchanges: SCANNER_EXCHANGES,
      queues: [
        ...this.engines.map((e) => e.registration.catalog.queue),
        ...(this.urlJobs ? [URL_RESULTS_QUEUE] : []),
      ],
    });
    this.connection.start();
  }

  async onApplicationBootstrap(): Promise<void> {
    // Adapter resources first (the inspector pool refuses to start without prlimit in
    // `required` mode or with another YARA bundle id): the worker fails its start instead of
    // consuming deliveries it cannot scan.
    for (const engine of this.engines) await engine.adapter.start?.();
    for (const engine of this.engines) {
      const { service } = engine;
      engine.consumer.start((event) => service.handle(event));
    }
    this.sweeper.start();
    this.jobs?.watcher.start();
    this.jobs?.runner.start();
    if (this.urlJobs) {
      const { results } = this.urlJobs;
      this.urlJobs.consumer.start((event) => results.handle(event));
      this.urlJobs.sweeper.start();
    }
    this.becJobs?.sweeper.start();
    this.dlpJobs?.sweeper.start();
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
      if (this.jobs) {
        await this.jobs.watcher
          .stop()
          .catch(() => this.logger.warn('attachment signature watcher stop failed'));
        await this.jobs.runner
          .stop()
          .catch(() => this.logger.warn('attachment rescan runner stop failed'));
      }
      if (this.urlJobs) {
        await this.urlJobs.consumer
          .stop()
          .catch(() => this.logger.warn('url results consumer stop failed'));
        await this.urlJobs.sweeper
          .stop()
          .catch(() => this.logger.warn('url inspection sweeper stop failed'));
      }
      if (this.becJobs) {
        await this.becJobs.sweeper
          .stop()
          .catch(() => this.logger.warn('bec history sweeper stop failed'));
      }
      if (this.dlpJobs) {
        await this.dlpJobs.sweeper
          .stop()
          .catch(() => this.logger.warn('dlp evidence sweeper stop failed'));
      }
    }
    // Kills the inspector children (graceful shutdown) after the consumers stopped.
    for (const engine of this.engines) {
      await engine.adapter
        .stop?.()
        .catch(() =>
          this.logger.warn({ engine: engine.registration.catalog.name }, 'scan engine stop failed'),
        );
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
            redis: RedisService,
            registry: MetricsService,
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
              registry,
            });
            const progress = new PrismaConsumerProgress(prisma);
            for (const warning of runsAttachmentConsumer(config)
              ? attachmentScalingWarnings(config)
              : []) {
              scanLogger.warn({ warning }, 'attachment scaling configuration warning');
            }
            return consumerRegistrations(config).map((registration) => {
              const { service, breaker, adapter } = createRoundService({
                config,
                registration,
                ...infra,
                metrics,
                logger: scanLogger,
                deps: { prisma, s3, redis, registry },
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
              return { registration, service, adapter, consumer, breaker };
            });
          },
          inject: [
            PrismaService,
            S3Service,
            RedisService,
            MetricsService,
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
        {
          provide: ATTACHMENT_JOBS,
          useFactory: (
            engines: EngineRuntime[],
            prisma: PrismaService,
            locks: LeaderLock,
            registry: MetricsService,
            metrics: ScanMetrics,
          ): AttachmentJobs | null => {
            const attachment = engines.find((e) => e.adapter instanceof AttachmentEngine);
            if (!attachment) return null;
            return createAttachmentJobs({
              config,
              prisma,
              engine: attachment.adapter as AttachmentEngine,
              locks,
              registry,
              metrics,
              logger: scanLogger,
            });
          },
          inject: [SCAN_ENGINES, PrismaService, SCAN_LOCKS, MetricsService, ScanMetrics],
        },
        {
          provide: URL_JOBS,
          useFactory: (
            engines: EngineRuntime[],
            prisma: PrismaService,
            locks: LeaderLock,
            registry: MetricsService,
            connection: AmqpConnection,
            publisher: ConfirmPublisher,
            messaging: MessagingMetrics,
          ): UrlJobs | null => {
            const url = engines.find((e) => e.adapter instanceof UrlEngine);
            if (!url || !runsUrlConsumer(config)) return null;
            return createUrlJobs({
              config,
              prisma,
              engine: url.adapter as UrlEngine,
              locks,
              registry,
              connection,
              publisher,
              messaging,
              logger: scanLogger,
            });
          },
          inject: [
            SCAN_ENGINES,
            PrismaService,
            SCAN_LOCKS,
            MetricsService,
            SCANNER_AMQP_CONNECTION,
            SCANNER_PUBLISHER,
            SCANNER_MESSAGING_METRICS,
          ],
        },
        {
          provide: BEC_JOBS,
          useFactory: (
            prisma: PrismaService,
            locks: LeaderLock,
            registry: MetricsService,
          ): BecJobs | null => {
            if (!runsBecConsumer(config)) return null;
            return createBecJobs({ config, prisma, locks, registry, logger: scanLogger });
          },
          inject: [PrismaService, SCAN_LOCKS, MetricsService],
        },
        {
          provide: DLP_JOBS,
          useFactory: (
            prisma: PrismaService,
            s3: S3Service,
            locks: LeaderLock,
            registry: MetricsService,
          ): DlpJobs | null => {
            if (!runsDlpConsumer(config)) return null;
            return createDlpJobs({ config, prisma, s3, locks, registry, logger: scanLogger });
          },
          inject: [PrismaService, S3Service, SCAN_LOCKS, MetricsService],
        },
        ScannerBrokerHealth,
        ClamavHealth,
        InspectorHealth,
        UrlEngineHealth,
        BecEngineHealth,
        DlpEngineHealth,
        DlpExtractorHealth,
        ScanningRuntime,
      ],
      exports: [
        ScanMetrics,
        ScanningRuntime,
        ScannerBrokerHealth,
        ClamavHealth,
        InspectorHealth,
        UrlEngineHealth,
        BecEngineHealth,
        DlpEngineHealth,
        DlpExtractorHealth,
      ],
    };
  }
}
