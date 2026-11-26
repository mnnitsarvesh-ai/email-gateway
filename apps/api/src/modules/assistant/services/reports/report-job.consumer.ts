import {
  Inject,
  Injectable,
  type OnApplicationBootstrap,
  type OnModuleDestroy,
} from '@nestjs/common';
import {
  AmqpConnection,
  ConfirmPublisher,
  createMessagingMetrics,
  DEFAULT_MAX_MESSAGE_BYTES,
  defaultClassify,
  type FailureClass,
  MetricsService,
  QueueConsumer,
} from '@email-gateway/common';
import {
  type AssistantReportGenerateRequestedV1,
  EventTypes,
} from '@email-gateway/event-contracts';
import { createLogger, type Logger } from '@email-gateway/logger';
import { API_CONFIG } from '../../../../api-config.token';
import {
  type AssistantConfig,
  REPORT_JOB_LEDGER,
  REPORT_JOB_QUEUE,
} from '../../assistant.constants';
import { ReportJobsRepository } from '../../repositories/report-jobs.repository';
import { ReportJobBusyError, ReportJobProcessor } from './report-job.processor';

const CONNECT_TIMEOUT_MS = 10_000;
const CONFIRM_TIMEOUT_MS = 15_000;

/** Whether this process runs the consumer (D5: `ASSISTANT_REPORT_JOBS_CONSUMER` with its URL). */
export function reportJobConsumerEnabled(
  config: Pick<AssistantConfig, 'ASSISTANT_REPORT_JOBS_CONSUMER' | 'RABBITMQ_ASSISTANT_URL'>,
): boolean {
  return (
    config.ASSISTANT_REPORT_JOBS_CONSUMER === true &&
    (config.RABBITMQ_ASSISTANT_URL?.length ?? 0) > 0
  );
}

/**
 * The failure class of a report job delivery: a job held by another consumer's live lease
 * (`ReportJobBusyError`) is transient (no attempt spent; bounded by the retry age), everything
 * else by the default classification.
 */
export function classifyReportJobFailure(error: unknown): FailureClass {
  return error instanceof ReportJobBusyError ? 'transient' : defaultClassify(error);
}

/**
 * The `assistant.reports` consumer of the api-assistant Deployment (step AI-6 D5, ADR-0096;
 * topology v16): started after bootstrap only when ASSISTANT_REPORT_JOBS_CONSUMER=true (and
 * RABBITMQ_ASSISTANT_URL is set; config validation requires it), with the `eg-assistant` role
 * user (read `assistant.reports`, write its retry and dead-letter keys), prefetch
 * ASSISTANT_REPORT_JOB_CONCURRENCY, the ledger name `api-assistant.reports` and the topology's
 * retry policy (hold, 5 attempts, 10–60 s, 30 min). Each delivery runs `ReportJobProcessor`; its
 * `ReportJobRetryError` (and any unexpected error, after the processor released the claim) is a
 * retry hop by the default classification (bounded by the queue's attempts and the job's own
 * expiry); `ReportJobBusyError` (the job under another consumer's live lease) is a transient hop
 * (`classifyReportJobFailure`). Stopped (in-flight jobs awaited) and disconnected on shutdown.
 * The AMQP client logs tokens only, never URLs or credentials.
 */
@Injectable()
export class ReportJobConsumer implements OnApplicationBootstrap, OnModuleDestroy {
  private connection: AmqpConnection | undefined;
  private publisher: ConfirmPublisher | undefined;
  private consumer: QueueConsumer<AssistantReportGenerateRequestedV1> | undefined;
  private readonly logger: Logger;

  constructor(
    @Inject(API_CONFIG) private readonly config: AssistantConfig,
    private readonly processor: ReportJobProcessor,
    private readonly jobs: ReportJobsRepository,
    private readonly metrics: MetricsService,
  ) {
    this.logger = createLogger({
      service: 'api',
      level: config.LOG_LEVEL,
      version: config.SERVICE_VERSION,
    }).child({ component: 'assistant-report-jobs' });
  }

  /** True while the consumer runs in this process (tests, health). */
  get running(): boolean {
    return this.consumer !== undefined;
  }

  onApplicationBootstrap(): void {
    if (!reportJobConsumerEnabled(this.config)) return;
    const urls = [...(this.config.RABBITMQ_ASSISTANT_URL ?? [])];
    const messaging = createMessagingMetrics(this.metrics);
    this.connection = new AmqpConnection({
      urls,
      connectionName: 'api-assistant-reports',
      logger: this.logger,
      metrics: messaging,
    });
    this.connection.start();
    this.publisher = new ConfirmPublisher({
      connection: this.connection,
      logger: this.logger,
      metrics: messaging,
      appId: 'api-assistant',
      confirmTimeoutMs: CONFIRM_TIMEOUT_MS,
      maxMessageBytes: DEFAULT_MAX_MESSAGE_BYTES,
    });
    this.consumer = new QueueConsumer<AssistantReportGenerateRequestedV1>({
      connection: this.connection,
      publisher: this.publisher,
      queue: REPORT_JOB_QUEUE,
      consumer: REPORT_JOB_LEDGER,
      eventTypes: [EventTypes.AssistantReportGenerateRequested],
      prefetch: this.config.ASSISTANT_REPORT_JOB_CONCURRENCY,
      logger: this.logger,
      metrics: messaging,
      progress: this.jobs.consumerProgress(),
      classify: classifyReportJobFailure,
    });
    this.consumer.start((event) => this.processor.handle(event));
    void this.connection
      .waitUntilConnected(CONNECT_TIMEOUT_MS)
      .catch(() =>
        this.logger.warn(
          { queue: REPORT_JOB_QUEUE },
          'Assistant report job consumer not connected yet',
        ),
      );
  }

  async onModuleDestroy(): Promise<void> {
    await this.consumer?.stop();
    await this.publisher?.close().catch(() => undefined);
    await this.connection?.close().catch(() => undefined);
    this.consumer = undefined;
    this.publisher = undefined;
    this.connection = undefined;
  }
}
