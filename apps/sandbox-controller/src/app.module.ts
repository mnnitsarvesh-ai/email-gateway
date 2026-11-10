import {
  type DynamicModule,
  Inject,
  Injectable,
  Module,
  type OnApplicationBootstrap,
  type OnModuleDestroy,
} from '@nestjs/common';
import {
  AMQP_MESSAGING_METRICS,
  AmqpConnection,
  AmqpModule,
  ConfirmPublisher,
  HealthModule,
  MetricsModule,
  resolveRetryPolicy,
  type MessagingMetrics,
} from '@email-gateway/common';
import { createLogger, type Logger } from '@email-gateway/logger';
import { parseArtifactPublicKey } from '@email-gateway/sandbox';
import { ArtifactSealer } from './artifacts/artifact-sealer';
import type { BackendSelfTest, SandboxBackend } from './backends/backend';
import { type ControllerConfig, controllerVersion, SANDBOX_S3_TIMEOUT_MS } from './config';
import { BackendHealth, SandboxStorageHealth } from './health/backend-health';
import { ControllerMetrics } from './metrics/controller-metrics';
import { ReaperService } from './reaper/reaper.service';
import type { ScratchArea } from './scratch/scratch';
import { SandboxS3 } from './storage/sandbox-s3';
import { TASK_QUEUE, TaskConsumer } from './task/task-consumer';
import { TaskHandler } from './task/task-handler';

export const SERVICE_NAME = 'sandbox-controller';

/** What `main.ts` built before Nest starts (X1 startup order: config → factory → self-test). */
export interface ControllerRuntime {
  backend: SandboxBackend;
  scratch: ScratchArea;
  selfTest: BackendSelfTest;
}

const RUNTIME = Symbol('SANDBOX_RUNTIME');
const LOGGER = Symbol('SANDBOX_LOGGER');
const STORE = Symbol('SANDBOX_STORE');
const SHUTDOWN = Symbol('SANDBOX_SHUTDOWN');

/** Backends that read samples and write artifacts (they need the sandbox bucket). */
export function needsSandboxBucket(backend: SandboxBackend): boolean {
  return backend.name === 'static' || backend.name === 'hardened-container';
}

/**
 * Startup and shutdown of the task pipeline (X1): reaper `startup` pass → periodic reaper and
 * self-test timers → the consumer (only while the backend self-test passes). Shutdown: stop
 * consuming and wait for in-flight tasks up to `SANDBOX_TASK_TIMEOUT_MS`, abort the rest (their
 * runner and scratch are removed in `finally`; anything left is reaped at the next start), close
 * the backend.
 */
@Injectable()
export class ControllerLifecycle implements OnApplicationBootstrap, OnModuleDestroy {
  private unsubscribe: (() => void) | undefined;

  constructor(
    @Inject(TaskConsumer) private readonly consumer: TaskConsumer,
    @Inject(TaskHandler) private readonly handler: TaskHandler,
    @Inject(ReaperService) private readonly reaper: ReaperService,
    @Inject(BackendHealth) private readonly health: BackendHealth,
    @Inject(RUNTIME) private readonly runtime: ControllerRuntime,
    @Inject(SHUTDOWN) private readonly shutdown: AbortController,
    @Inject(STORE) private readonly store: SandboxS3 | null,
    @Inject(LOGGER) private readonly logger: Logger,
  ) {}

  async onApplicationBootstrap(): Promise<void> {
    await this.reaper.run('startup');
    this.reaper.start();
    this.unsubscribe = this.health.onChange(
      (ok) => void (ok ? this.consumer.resume() : this.consumer.pause()),
    );
    this.health.start();
    if (this.health.ok) await this.consumer.resume();
    else
      this.logger.error(
        { selfTest: this.health.lastSelfTest.code },
        'sandbox backend not ready; consumer paused',
      );
  }

  async onModuleDestroy(): Promise<void> {
    this.unsubscribe?.();
    await this.health.stop();
    await this.reaper.stop();
    await this.consumer.stop();
    this.shutdown.abort(new Error('shutdown'));
    const deadline = Date.now() + 10_000;
    while (this.handler.inFlightCount > 0 && Date.now() < deadline) {
      await new Promise((resolve) => setTimeout(resolve, 100));
    }
    await this.runtime.backend.close();
    this.store?.close();
  }
}

@Module({})
export class ControllerModule {
  static forRoot(
    config: Readonly<ControllerConfig>,
    runtime: ControllerRuntime,
    logger: Logger,
  ): DynamicModule {
    const store = needsSandboxBucket(runtime.backend)
      ? new SandboxS3({
          bucket: config.SANDBOX_S3_BUCKET,
          region: config.SANDBOX_S3_REGION,
          endpoint: config.SANDBOX_S3_ENDPOINT,
          forcePathStyle: config.SANDBOX_S3_FORCE_PATH_STYLE,
          accessKeyId: config.SANDBOX_S3_ACCESS_KEY_ID ?? '',
          secretAccessKey: config.SANDBOX_S3_SECRET_ACCESS_KEY ?? '',
          timeoutMs: SANDBOX_S3_TIMEOUT_MS,
        })
      : null;
    const sealer =
      store && config.SANDBOX_ARTIFACT_PUBLIC_KEY
        ? new ArtifactSealer(parseArtifactPublicKey(config.SANDBOX_ARTIFACT_PUBLIC_KEY), store)
        : null;
    const retry = resolveRetryPolicy(TASK_QUEUE);
    const providers = [
      { provide: RUNTIME, useValue: runtime },
      { provide: LOGGER, useValue: logger },
      { provide: STORE, useValue: store },
      { provide: SHUTDOWN, useValue: new AbortController() },
      ControllerMetrics,
      {
        provide: TaskHandler,
        inject: [ControllerMetrics, ConfirmPublisher, SHUTDOWN],
        useFactory: (
          metrics: ControllerMetrics,
          publisher: ConfirmPublisher,
          shutdown: AbortController,
        ) =>
          new TaskHandler({
            backend: runtime.backend,
            store,
            sealer,
            scratch: runtime.scratch,
            publish: (envelope) => publisher.publish({ envelope }),
            metrics,
            logger,
            keys: {
              result: config.SANDBOX_RESULT_KEY ?? '',
              sample: config.SANDBOX_SAMPLE_KEY ?? null,
              samplePrevious: config.SANDBOX_SAMPLE_KEY_PREVIOUS ?? null,
            },
            maxima: config,
            controllerVersion: controllerVersion(config),
            retry,
            shutdown: shutdown.signal,
          }),
      },
      {
        provide: BackendHealth,
        inject: [ControllerMetrics],
        useFactory: (metrics: ControllerMetrics) =>
          new BackendHealth(
            runtime.backend,
            runtime.selfTest,
            metrics,
            logger,
            config.SANDBOX_SELF_TEST_INTERVAL_MS,
          ),
      },
      {
        provide: ReaperService,
        inject: [ControllerMetrics, TaskHandler],
        useFactory: (metrics: ControllerMetrics, handler: TaskHandler) =>
          new ReaperService({
            backend: runtime.backend,
            scratch: runtime.scratch,
            activeTaskIds: () => handler.activeTaskIds(),
            metrics,
            logger,
            intervalMs: config.SANDBOX_REAPER_INTERVAL_MS,
            taskTimeoutMs: config.SANDBOX_TASK_TIMEOUT_MS,
          }),
      },
      {
        provide: TaskConsumer,
        inject: [
          AmqpConnection,
          ConfirmPublisher,
          TaskHandler,
          { token: AMQP_MESSAGING_METRICS, optional: true },
        ],
        useFactory: (
          connection: AmqpConnection,
          publisher: ConfirmPublisher,
          handler: TaskHandler,
          messaging: MessagingMetrics | null,
        ) =>
          new TaskConsumer({
            connection,
            publisher,
            metrics: messaging ?? null,
            handler,
            prefetch: config.SANDBOX_CONCURRENCY,
            stopTimeoutMs: config.SANDBOX_TASK_TIMEOUT_MS,
            logger,
          }),
      },
      ...(store
        ? [
            {
              provide: SandboxStorageHealth,
              useValue: new SandboxStorageHealth(store, config.SANDBOX_S3_BUCKET),
            },
          ]
        : []),
      ControllerLifecycle,
    ];
    return {
      module: ControllerModule,
      providers,
      exports: [BackendHealth, TaskHandler, ...(store ? [SandboxStorageHealth] : [])],
    };
  }
}

/**
 * sandbox-controller (step 4.6 X1, ADR-0039): the isolated controller of the sandbox. Broker
 * user `eg-sandbox` (read `scan.sandbox`, publish its result keys only), the sandbox bucket
 * through its own S3 user (`samples/` read, `artifacts/` write) when the backend analyses, and
 * nothing else. Health (`rabbitmq`, `sandbox-backend`, `sandbox-s3` when used) and metrics on
 * `SANDBOX_HTTP_PORT`.
 */
@Module({})
export class AppModule {
  static forRoot(config: Readonly<ControllerConfig>, runtime: ControllerRuntime): DynamicModule {
    const logger = createLogger({
      service: SERVICE_NAME,
      level: config.LOG_LEVEL,
      version: config.SERVICE_VERSION,
    });
    // One module object for both imports: Nest deduplicates it (one TaskHandler, one BackendHealth).
    const controllerModule = ControllerModule.forRoot(config, runtime, logger);
    return {
      module: AppModule,
      imports: [
        AmqpModule.forRoot({
          urls: config.RABBITMQ_SANDBOX_URL,
          connectionName: SERVICE_NAME,
          appId: SERVICE_NAME,
          logger,
          verify: { exchanges: ['email.security', 'email.events'], queues: [TASK_QUEUE] },
        }),
        MetricsModule.forRoot({ service: SERVICE_NAME }),
        controllerModule,
        HealthModule.forRoot({
          service: { name: SERVICE_NAME, version: config.SERVICE_VERSION },
          indicators: [
            AmqpConnection,
            BackendHealth,
            ...(needsSandboxBucket(runtime.backend) ? [SandboxStorageHealth] : []),
          ],
          imports: [controllerModule],
        }),
      ],
    };
  }
}
