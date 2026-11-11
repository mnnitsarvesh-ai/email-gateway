import type { S3Client } from '@aws-sdk/client-s3';
import type {
  AmqpConnection,
  ConfirmPublisher,
  MessagingMetrics,
  MetricsService,
  QueueConsumer,
} from '@email-gateway/common';
import type { PrismaClient } from '@email-gateway/database';
import type {
  AttachmentSandboxRequestedV1,
  SandboxTaskCompletedV1,
} from '@email-gateway/event-contracts';
import type { Logger } from '@email-gateway/logger';
import type { WorkerConfig } from '../../config';
import type { LeaderLock } from '../deadline-sweeper';
import { S3PartReader } from '../parts/part-reader';
import { RiskMetrics } from '../risk/risk-metrics';
import { createRiskScorer, type RiskScorer } from '../risk/risk-scorer';
import { createSandboxDispatchConsumer, SandboxDispatcher } from './sandbox-dispatcher';
import { sandboxPlatformFromConfig } from './sandbox-config';
import { SandboxMetrics } from './sandbox-metrics';
import { createSandboxResultsConsumer, SandboxResultsService } from './sandbox-results';
import { PrismaSandboxStore } from './sandbox-store';
import { SandboxSweeper } from './sandbox-sweeper';
import { S3SandboxObjects, SampleStager } from './sample-stager';

/** The sandbox engine of this replica (step 4.6 X13, X16), or null when it does not run here. */
export interface SandboxJobs {
  dispatcher: SandboxDispatcher;
  dispatchConsumer: QueueConsumer<AttachmentSandboxRequestedV1>;
  results: SandboxResultsService;
  resultsConsumer: QueueConsumer<SandboxTaskCompletedV1>;
  sweeper: SandboxSweeper;
  objects: S3SandboxObjects;
}

/** Staging of one sample may take a part read, the seal and a put (each bounded by SCAN_S3_TIMEOUT_MS). */
const STAGING_TIMEOUT_FACTOR = 4;

/**
 * Builds the sandbox engine from the worker configuration (X13, X16): the writer store, the
 * stager (mail-bucket part reads, the sandbox bucket with the worker's own S3 client), the
 * dispatcher and the results service with their consumers (topology retry policies, hold delays
 * SCAN_RETRY_BASE_MS / SCAN_RETRY_MAX_MS) and the sweeper. Also used by the integration tests
 * (per-run consumer and lock names, organization filter).
 */
export function createSandboxJobs(options: {
  config: Readonly<WorkerConfig>;
  prisma: PrismaClient;
  s3: { client: S3Client; mailBucket: string };
  locks: LeaderLock;
  registry: MetricsService;
  /** `scan_settings_invalid_total{engine}` of the scan metrics. */
  settingsInvalid: (engine: 'sandbox') => void;
  connection: AmqpConnection;
  publisher: ConfirmPublisher;
  messaging?: MessagingMetrics;
  logger: Logger;
  dispatchConsumer?: string;
  resultsConsumer?: string;
  lockName?: string;
  organizationIds?: readonly bigint[];
  now?: () => Date;
  /** The worker's risk scorer (step 5.1 R13 (a)); default: one on this registry. */
  risk?: RiskScorer;
}): SandboxJobs {
  const { config, logger } = options;
  const metrics = SandboxMetrics.for(options.registry);
  const store = new PrismaSandboxStore(options.prisma, {
    txTimeoutMs: config.SCAN_DB_TIMEOUT_MS,
    ...(options.organizationIds ? { organizationIds: options.organizationIds } : {}),
    risk:
      options.risk ??
      createRiskScorer({ config, metrics: RiskMetrics.for(options.registry), logger }),
  });
  const objects = new S3SandboxObjects(
    options.s3.client,
    config.SANDBOX_S3_BUCKET,
    config.SCAN_S3_TIMEOUT_MS,
  );
  const stager = new SampleStager({
    parts: new S3PartReader(options.s3.client, options.s3.mailBucket, config.SCAN_S3_TIMEOUT_MS),
    objects,
    sampleKey: config.SANDBOX_SAMPLE_KEY,
    previousSampleKey: config.SANDBOX_SAMPLE_KEY_PREVIOUS,
    timeoutMs: config.SCAN_S3_TIMEOUT_MS * STAGING_TIMEOUT_FACTOR,
  });
  const now = options.now ? { now: options.now } : {};
  const dispatcher = new SandboxDispatcher({
    store,
    stager,
    metrics,
    settingsInvalid: options.settingsInvalid,
    logger,
    platform: sandboxPlatformFromConfig(config),
    limits: {
      wallTimeoutMs: config.SANDBOX_RUN_TIMEOUT_MS,
      memoryMb: config.SANDBOX_RUN_MEMORY_MB,
      cpuMillis: config.SANDBOX_RUN_CPU_MILLIS,
      pids: config.SANDBOX_RUN_PIDS,
      scratchMb: config.SANDBOX_RUN_SCRATCH_MB,
      maxArtifacts: config.SANDBOX_MAX_ARTIFACTS,
      maxArtifactBytes: config.SANDBOX_MAX_ARTIFACT_BYTES,
      maxTotalArtifactBytes: config.SANDBOX_MAX_TOTAL_ARTIFACT_BYTES,
    },
    epoch: config.SANDBOX_ANALYSIS_EPOCH,
    deadlineSeconds: config.SANDBOX_TASK_DEADLINE_SECONDS,
    analysisRetentionDays: config.SANDBOX_ANALYSIS_RETENTION_DAYS,
    resultKey: config.SANDBOX_RESULT_KEY,
    ...(options.dispatchConsumer ? { consumer: options.dispatchConsumer } : {}),
    ...now,
  });
  const results = new SandboxResultsService({
    store,
    objects,
    metrics,
    logger,
    resultKey: config.SANDBOX_RESULT_KEY,
    reuse: {
      definiteSeconds: config.SANDBOX_REUSE_DEFINITE_SECONDS,
      unknownSeconds: config.SANDBOX_REUSE_UNKNOWN_SECONDS,
      notExecutedSeconds: config.SANDBOX_REUSE_NOT_EXECUTED_SECONDS,
    },
    artifactRetentionDays: config.SANDBOX_ARTIFACT_RETENTION_DAYS,
    publishHashes: config.SANDBOX_PUBLISH_HASHES,
    ...(options.resultsConsumer ? { consumer: options.resultsConsumer } : {}),
    ...now,
  });
  const retry = { baseDelayMs: config.SCAN_RETRY_BASE_MS, maxDelayMs: config.SCAN_RETRY_MAX_MS };
  const messaging = options.messaging ? { metrics: options.messaging } : {};
  return {
    dispatcher,
    dispatchConsumer: createSandboxDispatchConsumer({
      connection: options.connection,
      publisher: options.publisher,
      dispatcher,
      prefetch: config.SANDBOX_DISPATCH_CONCURRENCY,
      retry,
      logger,
      ...messaging,
    }),
    results,
    resultsConsumer: createSandboxResultsConsumer({
      connection: options.connection,
      publisher: options.publisher,
      service: results,
      prefetch: config.SANDBOX_RESULTS_CONCURRENCY,
      retry,
      logger,
      ...messaging,
    }),
    sweeper: new SandboxSweeper({
      store,
      objects,
      locks: options.locks,
      metrics,
      logger,
      intervalMs: config.SANDBOX_SWEEP_INTERVAL_MS,
      batchSize: config.SANDBOX_SWEEP_BATCH,
      submissionTtlSeconds: config.SANDBOX_SUBMISSION_TTL_SECONDS,
      ...(options.lockName ? { lockName: options.lockName } : {}),
      ...now,
    }),
    objects,
  };
}
