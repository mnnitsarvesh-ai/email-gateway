import {
  type AmqpConnection,
  type ConfirmPublisher,
  type HandleOutcome,
  type MessagingMetrics,
  NonRetryableError,
  QueueConsumer,
  withTransactionDefaults,
} from '@email-gateway/common';
import { type Prisma, processOnce, type PrismaClient } from '@email-gateway/database';
import {
  type EventEnvelope,
  EventTypes,
  urlInspectionCompletedV1,
  type UrlInspectionCompletedV1,
} from '@email-gateway/event-contracts';
import type { Logger } from '@email-gateway/logger';
import {
  type DynamicCacheValue,
  type DynamicSignals,
  mapUrlVerdict,
  type UrlCache,
  type UrlVerdict,
} from '@email-gateway/url-security';
import { classifyScanFailure } from '../../engine-consumer';
import type { UrlMetrics } from './url-metrics';
import { InconsistentUrlReadError } from './url-store';

/** The results queue and its ledger consumer (topology v5, U2, U15). */
export const URL_RESULTS_QUEUE = 'scan.url.results';
export const URL_RESULTS_CONSUMER = 'email-worker.scan.url.results';

/**
 * Whether stored lookalike entries (`url_scan_results.lookalike`) make the URL a high-confidence
 * lookalike (U7): L1, L3, or L2 with a score at or above URL_LOOKALIKE_HIGH_SCORE.
 */
export function highConfidenceOf(stored: unknown, highScore: number): boolean {
  const parsed: unknown = typeof stored === 'string' ? JSON.parse(stored) : stored;
  if (!Array.isArray(parsed)) return false;
  return parsed.some((entry) => {
    if (typeof entry !== 'object' || entry === null) return false;
    const { rule, score } = entry as { rule?: unknown; score?: unknown };
    if (rule === 'L1' || rule === 'L3') return true;
    return rule === 'L2' && typeof score === 'number' && score >= highScore;
  });
}

/** The dynamic codes of `url-map/1` (M5, S9, U3) and `clean.no_findings`. */
const DYNAMIC_CODES: ReadonlySet<string> = new Set([
  'url.dynamic_phishing',
  'url.dynamic_download',
  'url.dynamic_cross_origin_form',
  'url.redirect_blocked_internal',
  'url.dynamic_failed',
  'clean.no_findings',
]);

/**
 * The dynamic verdict of one inspection (U15): `url-map/1` at click phase with only the dynamic
 * input and the stored lookalike confidence, so exactly the rules M5, S9 and U3 can fire.
 */
export function dynamicVerdict(
  status: 'completed' | 'failed',
  signals: DynamicSignals | null,
  highConfidence: boolean,
): { verdict: UrlVerdict; reasonCodes: string[] } {
  const result = mapUrlVerdict({
    phase: 'click',
    url: {
      host: 'inspection.invalid',
      hostKind: 'domain',
      registrableDomain: null,
      truncated: false,
    },
    flags: [],
    reputation: [],
    lookalike: { findings: [], mixedScript: false, idn: false, highConfidence },
    shortened: false,
    fetch: { required: false, skippedLimit: false, result: null },
    dynamic: { status, signals },
    tenant: { allowedDomains: [], blockedDomains: [] },
    suspiciousHops: Number.MAX_SAFE_INTEGER,
  });
  return {
    verdict: result.verdict,
    reasonCodes: result.reasonCodes.filter((code) => DYNAMIC_CODES.has(code)).slice(0, 16),
  };
}

type Applied =
  | { kind: 'dropped'; reason: 'unknown_inspection' | 'mismatch' }
  | { kind: 'noop' }
  | {
      kind: 'updated';
      urlSha256: string;
      cache: DynamicCacheValue;
      status: 'completed' | 'failed';
    };

export interface UrlResultsServiceOptions {
  prisma: PrismaClient;
  /** SCAN_DB_TIMEOUT_MS (timeout and maxWait of the transaction, step 4.2 §6). */
  txTimeoutMs: number;
  cache: UrlCache | null;
  metrics: UrlMetrics;
  logger: Logger;
  /** URL_LOOKALIKE_HIGH_SCORE. */
  highScore: number;
  /** Ledger consumer (default `email-worker.scan.url.results`; tests use a per-run name). */
  consumer?: string;
}

/**
 * The results consumer of U15 (`scan.url.results`): one `processOnce` transaction per event.
 * Loads the `url_dynamic_inspections` row by `inspectionId` (partition `receivedAt`), echo-checks
 * it (a row of another id is a wrong read: thrown, redelivered), drops a result whose
 * organization (from the envelope), message, `urlSeq` or `urlSha256` differ from the row (a
 * forged result cannot create or change rows; warning + `dropped`), ignores a row that is no
 * longer `pending` (duplicate), else updates it `WHERE status = 'pending'` to `completed` /
 * `failed` with the signals and the dynamic verdict (M5/S9/U3 with the stored lookalike
 * confidence), and afterwards writes the dynamic cache entry `eg:url:dyn:v1:<url sha256>`.
 */
export class UrlResultsService {
  readonly consumer: string;
  private readonly txPrisma: PrismaClient;
  private readonly logger: Logger;

  constructor(private readonly options: UrlResultsServiceOptions) {
    this.consumer = options.consumer ?? URL_RESULTS_CONSUMER;
    this.txPrisma = withTransactionDefaults(options.prisma, { timeoutMs: options.txTimeoutMs });
    this.logger = options.logger.child({ component: 'url-results' });
  }

  async handle(event: EventEnvelope<UrlInspectionCompletedV1>): Promise<HandleOutcome> {
    const parsed = urlInspectionCompletedV1.safeParse(event.payload);
    if (!parsed.success) throw new NonRetryableError('url_inspection_result_invalid');
    const payload = parsed.data;
    const organizationId = BigInt(event.organizationId);
    const ids = { inspectionId: payload.inspectionId, messageId: payload.messageId };
    let applied: Applied;
    try {
      const result = await processOnce(this.txPrisma, this.consumer, event.eventId, (tx) =>
        this.apply(tx, organizationId, payload),
      );
      if (result.status === 'duplicate') return 'duplicate';
      applied = result.result;
    } catch (error) {
      if (error instanceof InconsistentUrlReadError) this.options.metrics.inconsistent(error.read);
      throw error;
    }
    switch (applied.kind) {
      case 'dropped':
        this.options.metrics.dynamic('dropped');
        this.logger.warn(
          { ...ids, reason: applied.reason },
          'url inspection result dropped (no matching pending inspection of this organization)',
        );
        return 'handled';
      case 'noop':
        return 'handled';
      case 'updated':
        this.options.metrics.dynamic(applied.status);
        if (this.options.cache) {
          await this.options.cache.setDynamic(applied.urlSha256, applied.cache);
        }
        return 'handled';
    }
  }

  private async apply(
    tx: Prisma.TransactionClient,
    organizationId: bigint,
    payload: UrlInspectionCompletedV1,
  ): Promise<Applied> {
    const id = BigInt(payload.inspectionId);
    const receivedAt = new Date(payload.receivedAt);
    const row = await tx.urlDynamicInspection.findFirst({
      where: { id, receivedAt },
      select: {
        id: true,
        receivedAt: true,
        organizationId: true,
        messageId: true,
        scanId: true,
        urlSeq: true,
        urlSha256: true,
        status: true,
      },
    });
    if (!row) return { kind: 'dropped', reason: 'unknown_inspection' };
    if (row.id !== id || row.receivedAt.getTime() !== receivedAt.getTime()) {
      throw new InconsistentUrlReadError('inspection', 'identity echo');
    }
    if (
      row.organizationId !== organizationId ||
      row.messageId !== BigInt(payload.messageId) ||
      row.urlSeq !== payload.urlSeq ||
      row.urlSha256 !== payload.urlSha256
    ) {
      return { kind: 'dropped', reason: 'mismatch' };
    }
    if (row.status !== 'pending') return { kind: 'noop' };

    const scanResult = await tx.urlScanResult.findFirst({
      where: { scanId: row.scanId, urlSeq: row.urlSeq, receivedAt: row.receivedAt },
      select: {
        scanId: true,
        urlSeq: true,
        organizationId: true,
        messageId: true,
        urlSha256: true,
        lookalike: true,
      },
    });
    if (
      scanResult &&
      (scanResult.scanId !== row.scanId ||
        scanResult.urlSeq !== row.urlSeq ||
        scanResult.organizationId !== row.organizationId ||
        scanResult.messageId !== row.messageId ||
        scanResult.urlSha256 !== row.urlSha256)
    ) {
      throw new InconsistentUrlReadError('scan_result', 'identity echo');
    }
    const highConfidence = highConfidenceOf(scanResult?.lookalike ?? null, this.options.highScore);
    const signals: DynamicSignals | null = payload.status === 'completed' ? payload.signals : null;
    const { verdict, reasonCodes } = dynamicVerdict(payload.status, signals, highConfidence);
    const completedAt = new Date(payload.completedAt);
    const updated = await tx.urlDynamicInspection.updateMany({
      where: { id, receivedAt, status: 'pending' },
      data: {
        status: payload.status,
        verdict,
        reasonCodes: reasonCodes,
        signals: payload.signals,
        finalUrlSha256: payload.finalUrlSha256,
        finalHost: payload.finalHost,
        workerVersion: payload.workerVersion,
        errorCode: payload.errorCode,
        completedAt,
      },
    });
    if (updated.count === 0) return { kind: 'noop' };
    return {
      kind: 'updated',
      status: payload.status,
      urlSha256: row.urlSha256,
      cache: {
        inspectionId: payload.inspectionId,
        status: payload.status,
        verdict,
        reasonCodes,
        signals,
        finalUrlSha256: payload.finalUrlSha256,
        finalHost: payload.finalHost,
        completedAt: completedAt.toISOString(),
      },
    };
  }
}

/** The `QueueConsumer` of `scan.url.results` (prefetch SCAN_URL_CONCURRENCY, hold retries). */
export function createUrlResultsConsumer(options: {
  connection: AmqpConnection;
  publisher: ConfirmPublisher;
  service: UrlResultsService;
  prefetch: number;
  retry: { baseDelayMs: number; maxDelayMs: number };
  logger: Logger;
  metrics?: MessagingMetrics;
}): QueueConsumer<UrlInspectionCompletedV1> {
  return new QueueConsumer<UrlInspectionCompletedV1>({
    connection: options.connection,
    publisher: options.publisher,
    queue: URL_RESULTS_QUEUE,
    consumer: options.service.consumer,
    eventTypes: [EventTypes.UrlInspectionCompleted],
    prefetch: options.prefetch,
    retry: options.retry,
    classify: classifyScanFailure,
    logger: options.logger,
    ...(options.metrics ? { metrics: options.metrics } : {}),
  });
}
