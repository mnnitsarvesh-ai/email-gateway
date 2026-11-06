import {
  type DynamicModule,
  Inject,
  Injectable,
  Module,
  type OnApplicationBootstrap,
  type OnModuleDestroy,
  Optional,
} from '@nestjs/common';
import {
  AMQP_MESSAGING_METRICS,
  AmqpConnection,
  ConfirmPublisher,
  QueueConsumer,
  uuidv7,
  type MessagingMetrics,
} from '@email-gateway/common';
import { EventTypes, type UrlInspectionRequestedV1 } from '@email-gateway/event-contracts';
import type { Logger } from '@email-gateway/logger';
import { loadBrands, ProtectedSet } from '@email-gateway/url-security';
import { BrowserPool } from '../browser/browser-pool';
import { inspectUrl } from '../browser/inspector';
import { SETTLE_MS, type WorkerConfig } from '../config';
import { inspectionHandler } from './inspection-handler';
import { WorkerMetrics } from './worker-metrics';

export const INSPECT_QUEUE = 'scan.url.inspect';
export const CONSUMER_NAME = 'url-browser-worker';
const WORKER_CONFIG = Symbol('WORKER_CONFIG');
const WORKER_LOGGER = Symbol('WORKER_LOGGER');

@Injectable()
class InspectionConsumer implements OnApplicationBootstrap, OnModuleDestroy {
  private consumer: QueueConsumer<UrlInspectionRequestedV1> | undefined;

  constructor(
    @Inject(AmqpConnection) private readonly connection: AmqpConnection,
    @Inject(ConfirmPublisher) private readonly publisher: ConfirmPublisher,
    @Optional() @Inject(AMQP_MESSAGING_METRICS) private readonly messaging: MessagingMetrics | null,
    @Inject(BrowserPool) private readonly pool: BrowserPool,
    @Inject(WorkerMetrics) private readonly metrics: WorkerMetrics,
    @Inject(WORKER_CONFIG) private readonly config: Readonly<WorkerConfig>,
    @Inject(WORKER_LOGGER) private readonly logger: Logger,
  ) {}

  onApplicationBootstrap(): void {
    // Launch (and probe the sandbox) before the first job; readiness reports the outcome.
    void this.pool.launch().catch(() => undefined);
    const protectedSet = new ProtectedSet({
      brands: loadBrands(this.config.URL_PROTECTED_BRANDS_FILE ?? null),
      extraDomains: this.config.URL_PROTECTED_EXTRA_DOMAINS,
    });
    const brands = protectedSet.titleEntries();
    this.consumer = new QueueConsumer<UrlInspectionRequestedV1>({
      connection: this.connection,
      publisher: this.publisher,
      queue: INSPECT_QUEUE,
      consumer: CONSUMER_NAME,
      eventTypes: [EventTypes.UrlInspectionRequested],
      prefetch: this.config.URL_BROWSER_CONCURRENCY,
      logger: this.logger,
      ...(this.messaging ? { metrics: this.messaging } : {}),
    });
    this.consumer.start(
      inspectionHandler({
        inspect: (url) =>
          this.pool.run(async (browser) => {
            const outcome = await inspectUrl(browser, url, {
              proxy: this.pool.proxySettings,
              navigationTimeoutMs: this.config.URL_BROWSER_NAVIGATION_TIMEOUT_MS,
              jobTimeoutMs: this.config.URL_BROWSER_JOB_TIMEOUT_MS,
              settleMs: SETTLE_MS,
              brands,
            });
            if (outcome.crashed) this.pool.markCrashed();
            return outcome;
          }),
        publish: (envelope) => this.publisher.publish({ envelope }),
        logger: this.logger,
        workerVersion: `url-browser-worker/${this.config.SERVICE_VERSION}`.slice(0, 64),
        browserVersion: () =>
          `chromium-headless-shell/${this.pool.browserVersion ?? 'unknown'}`.slice(0, 64),
        onJob: (result, seconds) => this.metrics.job(result, seconds),
        newEventId: () => uuidv7(),
      }),
    );
  }

  async onModuleDestroy(): Promise<void> {
    await this.consumer?.stop();
    await this.pool.close();
  }
}

/**
 * The isolated dynamic inspection (step 4.3 U15): consumes `scan.url.inspect` as `eg-url-browser`
 * with prefetch = URL_BROWSER_CONCURRENCY, inspects in headless Chromium behind the egress proxy
 * and publishes `mail.url.inspection_completed.v1` with publisher confirms.
 */
@Module({})
export class BrowserWorkerModule {
  static forRoot(config: Readonly<WorkerConfig>, logger: Logger): DynamicModule {
    return {
      module: BrowserWorkerModule,
      providers: [
        { provide: WORKER_CONFIG, useValue: config },
        { provide: WORKER_LOGGER, useValue: logger },
        WorkerMetrics,
        {
          provide: BrowserPool,
          inject: [WorkerMetrics],
          useFactory: (metrics: WorkerMetrics) =>
            new BrowserPool({
              proxyUrl: config.URL_BROWSER_PROXY_URL,
              proxyToken: config.URL_EGRESS_PROXY_TOKEN,
              maxJobs: config.URL_BROWSER_MAX_JOBS_PER_BROWSER,
              maxRssBytes: config.URL_BROWSER_MAX_RSS_MB * 1024 * 1024,
              logger,
              onRestart: (reason) => metrics.restart(reason),
              onRss: (bytes) => metrics.setRss(bytes),
            }),
        },
        InspectionConsumer,
      ],
      exports: [BrowserPool],
    };
  }
}
