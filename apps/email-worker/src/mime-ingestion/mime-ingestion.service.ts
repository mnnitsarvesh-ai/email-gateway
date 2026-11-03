import type { HandleOutcome } from '@email-gateway/common';
import type {
  EventEnvelope,
  MessageReceivedV1,
  ParseFailureReason,
} from '@email-gateway/event-contracts';
import type { Logger } from '@email-gateway/logger';
import {
  type MimeLimits,
  type MimeParseResult,
  parseMessage,
  PARSER_VERSION,
  type PartInfo,
  type PartSink,
  type PartWriter,
  type StoredPart,
} from '@email-gateway/mime-parser';
import type { Readable } from 'node:stream';
import { EML_MISSING, type EmlSource } from './eml-source';
import { errorFields, isTransientFailure, retryClassOf } from './error-fields';
import type { MimeMetrics } from './mime-metrics';
import type { FinalOutcome, MessageRecord, MimeStore } from './mime-store';
import { isOrganizationKey, type PartKeyTarget } from './part-keys';
import type { RecordingPartSink } from './s3-part-sink';
import {
  S3Stalled,
  type S3WaitSnapshot,
  S3WaitTracker,
  stalledOnS3,
  trackedInput,
} from './s3-waits';

/** `message_idempotency.consumer`, outbox cursor `outbox:<consumer>` and lock `ew:outbox:<consumer>`. */
export const MIME_CONSUMER = 'email-worker.mime-parser';

export interface MimeIngestionOptions {
  store: MimeStore;
  emlSource: EmlSource;
  /** A fresh part sink per attempt, keyed by the writer row (M11). */
  sinkFor: (target: PartKeyTarget) => RecordingPartSink;
  metrics: MimeMetrics;
  logger: Logger;
  limits: MimeLimits;
  /** MIME_MAX_ATTEMPTS (poison-message guard, M3.4). */
  maxAttempts: number;
  /** Default `MIME_CONSUMER`; the integration tests use a per-run name. */
  consumer?: string;
  now?: () => Date;
  /** Monotonic milliseconds for the S3 wait accounting (default `performance.now`; tests). */
  clock?: () => number;
}

const failed = (reason: ParseFailureReason): FinalOutcome => ({
  status: 'parse_failed',
  failureReason: reason,
  limitsExceeded: [],
  defects: [],
  result: null,
  stats: null,
});

/** The outcome recorded for a parse result (M4 status rules). */
export function outcomeOf(result: MimeParseResult): FinalOutcome {
  const common = {
    limitsExceeded: [...result.limitsExceeded],
    defects: [...result.defects],
    result,
    stats: result.stats,
  };
  return result.status === 'parse_failed'
    ? { status: 'parse_failed', failureReason: 'parser_error', ...common }
    : { status: result.status, failureReason: null, ...common };
}

/**
 * True when the bytes read are not the ingested object (M3.8): more bytes than `size_bytes`, or a
 * complete read whose size or SHA-256 differs. A read stopped early (message_size,
 * parse_timeout) cannot be compared beyond its length.
 */
export function integrityMismatch(result: MimeParseResult, message: MessageRecord): boolean {
  const { bytesRead, sha256, inputComplete } = result.stats;
  if (bytesRead > message.sizeBytes) return true;
  if (!inputComplete) return false;
  return bytesRead !== message.sizeBytes || sha256 !== message.emlSha256.toLowerCase();
}

/**
 * The post-queue MIME ingestion stage (step 3.1, docs/plan/steps/06-mime-ingestion.md M3): one
 * `mail.message.received.v1` event in, one finalized `email_message_parses` row plus headers,
 * attachments, the decoded subject, an `email_events` row and a `mail.message.parsed.v1` or
 * `mail.message.parse_failed.v1` outbox event out, all committed in one writer transaction.
 *
 * The handler is **staged** (not `processOnceHandler`): the download and parse run outside any
 * transaction. It is idempotent per event (ledger) and per message (final parse row, conditional
 * finalize). It throws when an attempt fails: a transient failure (MySQL, S3 or network outage)
 * gives its attempt back; any other exception counts toward MIME_MAX_ATTEMPTS, so a failure that
 * repeats on every attempt ends as `parse_failed / max_attempts_exceeded` (M3.10).
 *
 * Logs carry ids, codes, counts, durations and `errName`/`errCode` only (M15).
 */
export class MimeIngestionService {
  readonly consumer: string;
  private readonly logger: Logger;
  private readonly now: () => Date;

  constructor(private readonly options: MimeIngestionOptions) {
    this.consumer = options.consumer ?? MIME_CONSUMER;
    this.logger = options.logger.child({ component: 'mime-ingestion' });
    this.now = options.now ?? (() => new Date());
  }

  async handle(event: EventEnvelope<MessageReceivedV1>): Promise<HandleOutcome> {
    const { store, metrics } = this.options;
    const ids = {
      eventId: event.eventId,
      messageId: event.payload.messageId,
      organizationId: event.organizationId,
    };

    // 1. Ledger pre-check: no work for an event already applied.
    if (await store.isProcessed(this.consumer, event.eventId)) {
      metrics.outcome('duplicate');
      return 'duplicate';
    }

    // 2. The writer row of the envelope's organization (tenant from trusted context only).
    const message = await store.loadMessage(
      BigInt(event.payload.messageId),
      new Date(event.payload.receivedAt),
      BigInt(event.organizationId),
    );
    if (!message) {
      const outcome = await store.recordNoop(this.consumer, event.eventId);
      metrics.outcome(outcome === 'duplicate' ? 'duplicate' : 'message_missing');
      this.logger.warn(ids, 'received message not found for the organization; nothing parsed');
      return outcome;
    }

    // 3. Per-message idempotency: a final row is never parsed again.
    const existing = await store.loadParse(message);
    if (existing && existing.status !== 'parsing') return this.duplicate(event, ids);

    // 4. Mark parsing (attempts + 1).
    const startedAt = this.now();
    const mark = await store.markParsing(message, {
      eventId: event.eventId,
      parserVersion: PARSER_VERSION,
      startedAt,
    });
    if (mark.kind === 'final') return this.duplicate(event, ids);
    const attempts = mark.attempts;

    let phase: 's3' | 'db' = 'db';
    try {
      let outcome: FinalOutcome;
      let downloadStarted: number | null = null;
      if (attempts > this.options.maxAttempts) {
        outcome = failed('max_attempts_exceeded');
      } else if (!isOrganizationKey(message.emlObjectKey, message.organizationId)) {
        // 5. Pre-read checks.
        outcome = failed('eml_key_mismatch');
      } else if (message.sizeBytes > this.options.limits.maxMessageBytes) {
        outcome = {
          status: 'parse_limit_exceeded',
          failureReason: null,
          limitsExceeded: ['message_size'],
          defects: [],
          result: null,
          stats: null,
        };
      } else {
        // 6-8. Stream, parse, verify.
        phase = 's3';
        downloadStarted = performance.now();
        outcome = await this.parse(message, ids);
        phase = 'db';
      }

      // 9. Finalize.
      const completedAt = this.now();
      const finalized = await store.finalize({
        consumer: this.consumer,
        event: { eventId: event.eventId, correlationId: event.correlationId },
        message,
        attempts,
        parserVersion: PARSER_VERSION,
        outcome,
        completedAt,
        durationMs: completedAt.getTime() - startedAt.getTime(),
      });
      if (finalized.outcome === 'duplicate') return this.duplicate(event, ids);

      const seconds =
        downloadStarted === null ? null : (performance.now() - downloadStarted) / 1000;
      metrics.finalized(outcome, seconds);
      const log = {
        ...ids,
        status: outcome.status,
        limitsExceeded: outcome.limitsExceeded,
        defects: outcome.defects,
        attachmentCount: outcome.result?.attachments.length ?? 0,
        bytes: outcome.stats?.bytesRead ?? 0,
        durationMs: completedAt.getTime() - startedAt.getTime(),
        attempts,
        ...(outcome.failureReason ? { failureReason: outcome.failureReason } : {}),
      };
      if (outcome.status === 'parse_failed') this.logger.warn(log, 'message parse failed');
      else this.logger.info(log, 'message parsed');
      return 'handled';
    } catch (err) {
      // 10. The feed retries. Only a transient failure gives its attempt back: a deterministic
      // one (a data or contract error) would otherwise retry forever with the cursor frozen.
      const retryClass = retryClassOf(err, phase);
      const transient = isTransientFailure(err);
      metrics.retry(retryClass);
      if (transient) {
        try {
          await store.decrementAttempts(message);
        } catch (decrementError) {
          this.logger.warn(
            { ...ids, ...errorFields(decrementError) },
            'could not give back the parse attempt',
          );
        }
      }
      this.logger.warn(
        { ...ids, attempts, retryClass, transient, ...errorFields(err) },
        transient
          ? 'MIME ingestion attempt failed on infrastructure; it will be retried'
          : 'MIME ingestion attempt failed; it will be retried and counts toward MIME_MAX_ATTEMPTS',
      );
      throw err;
    }
  }

  /**
   * Steps 6-8: stream the EML, parse it into the part sink, verify the bytes.
   *
   * A parse timeout is a content verdict only when the message itself was slow: when the budget
   * ran out while the stage was waiting on S3 (or had spent half of it waiting), it is an
   * infrastructure retry (`S3Stalled`, invariant 4).
   */
  private async parse(message: MessageRecord, ids: Record<string, string>): Promise<FinalOutcome> {
    const { emlSource, limits } = this.options;
    const waits = new S3WaitTracker(this.options.clock);
    // Wall clock of the stage: from the start of the download to the end of the parse (M5).
    const signal = AbortSignal.timeout(limits.parseTimeoutMs);
    const timeout: { waits: S3WaitSnapshot | null } = { waits: null };
    // Registered before the parser's own listener, so it sees the S3 state of that moment.
    signal.addEventListener('abort', () => (timeout.waits = waits.snapshot()), { once: true });

    let opened: Readable | typeof EML_MISSING;
    try {
      opened = await waits.track(emlSource.open(message.emlObjectKey, signal));
    } catch (err) {
      // S3 did not answer within the parse budget: an outage, never parse_timeout.
      if (signal.aborted) throw new S3Stalled('S3 GetObject outlived the parse budget');
      throw err;
    }
    if (opened === EML_MISSING) return failed('eml_missing');
    const input = trackedInput(opened, waits);

    const sink = this.options.sinkFor({
      organizationId: message.organizationId,
      messageId: message.id,
      receivedAt: message.receivedAt,
    });
    let result: MimeParseResult;
    try {
      result = await parseMessage(input, { limits, sink: trackedSink(sink, waits), signal });
    } finally {
      input.destroy();
    }
    if (
      result.limitsExceeded.includes('parse_timeout') &&
      stalledOnS3(timeout.waits ?? waits.snapshot(), limits.parseTimeoutMs)
    ) {
      throw new S3Stalled('the parse budget ran out while waiting on S3');
    }

    if (integrityMismatch(result, message)) {
      // Never record a different object than the one ingested; drop what this attempt stored.
      const notDeleted = await sink.deleteWritten();
      if (notDeleted > 0) {
        this.logger.warn(
          { ...ids, objects: notDeleted },
          'part objects of a mismatched EML not deleted',
        );
      }
      return { ...failed('integrity_mismatch'), stats: result.stats };
    }
    return outcomeOf(result);
  }

  private async duplicate(
    event: EventEnvelope<MessageReceivedV1>,
    ids: Record<string, string>,
  ): Promise<HandleOutcome> {
    // Ledger row for this event, so a re-read stops at step 1.
    await this.options.store.recordNoop(this.consumer, event.eventId);
    this.options.metrics.outcome('duplicate');
    this.logger.info(ids, 'message already parsed; event ignored');
    return 'duplicate';
  }
}

/** The sink with every S3 call (write, finish, abort, ranged read) counted as S3 wait. */
function trackedSink(sink: RecordingPartSink, waits: S3WaitTracker): PartSink {
  return {
    async open(part: PartInfo): Promise<PartWriter> {
      const writer = await waits.track(sink.open(part));
      return {
        write: (chunk) => waits.track(writer.write(chunk)),
        abort: () => waits.track(writer.abort()),
        async finish(): Promise<StoredPart> {
          const stored = await waits.track(writer.finish());
          return {
            key: stored.key,
            readRange: (start, end, signal) => waits.track(stored.readRange(start, end, signal)),
          };
        },
      };
    },
  };
}
