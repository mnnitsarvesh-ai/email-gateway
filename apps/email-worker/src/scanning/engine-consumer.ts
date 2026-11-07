import type { S3Client } from '@aws-sdk/client-s3';
import {
  type AmqpConnection,
  type ConfirmPublisher,
  type ConsumerProgressRecorder,
  type FailureClass,
  type MessagingMetrics,
  NonRetryableError,
  QueueConsumer,
} from '@email-gateway/common';
import { EventTypes, type QueueName } from '@email-gateway/event-contracts';
import type { Logger } from '@email-gateway/logger';
import { type EngineCatalogEntry, isStage2Engine } from '@email-gateway/security-contracts';
import type { WorkerConfig } from '../config';
import { EML_MISSING, S3EmlSource } from '../mime-ingestion/eml-source';
import { isTransientFailure } from '../mime-ingestion/error-fields';
import { EmlUnavailableError, EngineAttemptFailedError } from './engine';
import type { ScanEngineRegistration } from './registry';
import type { EmlOpener, ScanTriggerPayload } from './round-service';

/** The trigger events of a stage-1 engine queue (S2): parse results and administrative rescans. */
export const SCAN_EVENT_TYPES = [EventTypes.MessageParsed, EventTypes.MessageRescanRequested];

/** The trigger event of a stage-2 engine queue (step 4.4 B2). */
export const STAGE_EVENT_TYPES = [EventTypes.MessageScanStageReady];

/**
 * The event types an engine's consumer accepts, from its catalog entry (B2): an engine with
 * `dependsOn` (stage 2) consumes only `scan_stage_ready.v1`, every other engine `parsed.v1` and
 * `rescan_requested.v1`. Never names an engine.
 */
export function scanEventTypes(entry: Pick<EngineCatalogEntry, 'dependsOn'>): string[] {
  return isStage2Engine(entry) ? [...STAGE_EVENT_TYPES] : [...SCAN_EVENT_TYPES];
}

/**
 * How an engine consumer treats a failed delivery (S5): the stage's own
 * `EngineAttemptFailedError` (a non-final attempt row was written) → `retryable`
 * (`x-eg-attempt + 1`, backoff); `NonRetryableError` → fatal (dead-letter); a MySQL, S3 or
 * network outage → `transient` (no attempt consumed, bounded by the retry age); anything else
 * (an unexpected exception) → `retryable`, so it is dead-lettered after the queue's attempt
 * limit instead of looping.
 */
export function classifyScanFailure(error: unknown): FailureClass {
  if (error instanceof EngineAttemptFailedError) return 'retryable';
  if (error instanceof NonRetryableError) return 'fatal';
  return isTransientFailure(error) ? 'transient' : 'retryable';
}

/**
 * The `QueueConsumer` of one registered engine (S5): its catalog queue, its trigger types
 * (`scanEventTypes`),
 * prefetch = the engine's concurrency, `hold` retries with SCAN_RETRY_BASE_MS / SCAN_RETRY_MAX_MS,
 * `classifyScanFailure` and the progress recorder (the outbox reconciler re-drives `scan.spam`).
 */
export function createEngineConsumer(options: {
  config: Readonly<WorkerConfig>;
  registration: ScanEngineRegistration;
  connection: AmqpConnection;
  publisher: ConfirmPublisher;
  logger: Logger;
  metrics?: MessagingMetrics;
  consumer?: string;
  progress?: ConsumerProgressRecorder;
}): QueueConsumer<ScanTriggerPayload> {
  const { config, registration } = options;
  return new QueueConsumer<ScanTriggerPayload>({
    connection: options.connection,
    publisher: options.publisher,
    queue: registration.catalog.queue as QueueName,
    consumer: options.consumer ?? registration.consumerName,
    eventTypes: scanEventTypes(registration.catalog),
    prefetch: registration.budget(config).concurrency,
    retry: { baseDelayMs: config.SCAN_RETRY_BASE_MS, maxDelayMs: config.SCAN_RETRY_MAX_MS },
    classify: classifyScanFailure,
    logger: options.logger,
    ...(options.metrics ? { metrics: options.metrics } : {}),
    ...(options.progress ? { progress: options.progress } : {}),
  });
}

/**
 * Streaming EML reads for the engines (S4 `eml.open`): `GetObject` of the row's key with
 * SCAN_S3_TIMEOUT_MS per wait (request, then every body chunk). `NoSuchKey` →
 * `EmlUnavailableError` (not retryable); every other failure propagates (transient).
 */
export function s3EmlOpener(client: S3Client, bucket: string, timeoutMs: number): EmlOpener {
  const source = new S3EmlSource(client, bucket, timeoutMs);
  return async (key, signal) => {
    const opened = await source.open(key, signal);
    if (opened === EML_MISSING) throw new EmlUnavailableError();
    return opened;
  };
}
