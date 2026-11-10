import {
  type AmqpConnection,
  type ConfirmPublisher,
  type HandleOutcome,
  type MessagingMetrics,
  QueueConsumer,
} from '@email-gateway/common';
import {
  type EventEnvelope,
  EventTypes,
  sandboxTaskCompletedV1,
  type SandboxTaskCompletedV1,
} from '@email-gateway/event-contracts';
import type { Logger } from '@email-gateway/logger';
import {
  mapAnalysis,
  type SandboxMapResult,
  parseArtifactKey,
  verifyResultMac,
} from '@email-gateway/sandbox';
import {
  buildSandboxReportView,
  type NotExecutedReason,
  notExecutedReasonSchema,
  sandboxErrorCodeSchema,
  sandboxObservationsSchema,
  type SandboxObservations,
  type SandboxVerdict,
} from '@email-gateway/security-contracts';
import { classifyScanFailure } from '../engine-consumer';
import { finishSubmissions, outcomeFromAnalysis, SANDBOX_LINKED_BATCH } from './sandbox-finalizer';
import type { SandboxMetrics, SandboxRejectReason } from './sandbox-metrics';
import type { SandboxObjects } from './sample-stager';
import {
  type AnalysisRow,
  DUPLICATE,
  InconsistentSandboxReadError,
  type NewArtifact,
  type SandboxStore,
  type SandboxTx,
} from './sandbox-store';

/** The results queue and its ledger consumer (topology v8, X11, X13). */
export const SANDBOX_RESULTS_QUEUE = 'scan.sandbox.results';
export const SANDBOX_RESULTS_CONSUMER = 'email-worker.scan.sandbox.results';

const DAY_MS = 86_400_000;
/** `malware_signatures.expires_at` of a published sandbox hash (X13 results step 4). */
export const SANDBOX_HASH_TTL_DAYS = 90;

export interface SandboxReuseWindows {
  /** SANDBOX_REUSE_DEFINITE_SECONDS (malicious, suspicious). */
  definiteSeconds: number;
  /** SANDBOX_REUSE_UNKNOWN_SECONDS (unknown from a completed run). */
  unknownSeconds: number;
  /** SANDBOX_REUSE_NOT_EXECUTED_SECONDS. */
  notExecutedSeconds: number;
}

/**
 * `not_executed` reasons that are a property of the sample (or of what the controller can run
 * for it), so the answer holds for a byte-identical sample. `deadline_passed` (the task waited
 * in a backlog) and `backend_disabled` (the operator has not enabled a backend yet) describe the
 * platform at that moment: they are never reused.
 */
export const REUSABLE_NOT_EXECUTED_REASONS: ReadonlySet<NotExecutedReason> = new Set([
  'type_not_supported',
  'profile_not_supported',
  'size_exceeded',
]);

/**
 * `reuse_until` of a terminal analysis (X13 results step 3): definite `malicious`/`suspicious`
 * → the definite window; `unknown` from a completed run → the unknown window; `not_executed`
 * with a sample-dependent reason (`REUSABLE_NOT_EXECUTED_REASONS`) → its window, any other
 * reason never; `error` (and `timeout`) never. A window of 0 disables reuse. `clean`
 * (unreachable in 4.6) gets the unknown window, the most conservative non-zero one.
 */
export function reuseUntilFor(
  status: 'completed' | 'not_executed' | 'failed',
  verdict: SandboxVerdict,
  windows: SandboxReuseWindows,
  now: Date,
  notExecutedReason: NotExecutedReason | null = null,
): Date | null {
  let seconds = 0;
  if (status === 'failed' || verdict === 'error' || verdict === 'timeout') seconds = 0;
  else if (status === 'not_executed') {
    seconds =
      notExecutedReason !== null && REUSABLE_NOT_EXECUTED_REASONS.has(notExecutedReason)
        ? windows.notExecutedSeconds
        : 0;
  } else if (verdict === 'malicious' || verdict === 'suspicious') seconds = windows.definiteSeconds;
  else seconds = windows.unknownSeconds;
  return seconds > 0 ? new Date(now.getTime() + seconds * 1000) : null;
}

/** First month (UTC) of a date, for the artifact key prefix window. */
const monthStart = (at: Date): number => Date.UTC(at.getUTCFullYear(), at.getUTCMonth(), 1);

/**
 * Whether every artifact key belongs to this task (X13 results step 2): parses as
 * `artifacts/<yyyy>/<mm>/<taskId>/<runId>/<seq>-<kind>.bin` with the task id, seq and kind of its
 * entry, one run id for all of them (one run of the task wrote them; a retried run writes under
 * another run id, never over these objects), the month between the analysis's dispatch month and
 * now (the controller stores at its own clock), and the seqs unique.
 */
export function artifactKeysValid(
  artifacts: SandboxTaskCompletedV1['artifacts'],
  taskId: string,
  dispatchedAt: Date | null,
  now: Date,
): boolean {
  const seen = new Set<number>();
  let runId: string | null = null;
  const from = monthStart(dispatchedAt ?? now);
  const to = monthStart(now);
  for (const artifact of artifacts) {
    const parsed = parseArtifactKey(artifact.key);
    if (
      !parsed ||
      parsed.taskId !== taskId ||
      parsed.seq !== artifact.seq ||
      parsed.kind !== artifact.kind
    ) {
      return false;
    }
    if (runId !== null && parsed.runId !== runId) return false;
    runId = parsed.runId;
    const [, yyyy, mm] = /^artifacts\/(\d{4})\/(\d{2})\//.exec(artifact.key) ?? [];
    const month = Date.UTC(Number(yyyy), Number(mm) - 1, 1);
    if (!Number.isFinite(month) || month < from || month > to) return false;
    if (seen.has(artifact.seq)) return false;
    seen.add(artifact.seq);
  }
  return true;
}

type Applied =
  | { kind: 'rejected'; reason: SandboxRejectReason }
  | { kind: 'noop'; reason: 'duplicate' | 'late' }
  | {
      kind: 'applied';
      analysisId: bigint;
      status: 'completed' | 'not_executed' | 'failed';
      verdict: SandboxVerdict;
      submissions: number;
      finals: string[];
      artifacts: number;
      sampleKey: string | null;
    };

/** Semantic validation beyond the event schema: every code against the security-contracts enums. */
function validateCodes(
  payload: SandboxTaskCompletedV1,
): { ok: true; observations: SandboxObservations } | { ok: false } {
  const observations = sandboxObservationsSchema.safeParse(payload.observations);
  if (!observations.success) return { ok: false };
  if (
    payload.notExecutedReason !== null &&
    !notExecutedReasonSchema.safeParse(payload.notExecutedReason).success
  ) {
    return { ok: false };
  }
  if (payload.errorCode !== null && !sandboxErrorCodeSchema.safeParse(payload.errorCode).success) {
    return { ok: false };
  }
  return { ok: true, observations: observations.data };
}

export interface SandboxResultsServiceOptions {
  store: SandboxStore;
  objects: SandboxObjects;
  metrics: SandboxMetrics;
  logger: Logger;
  /** SANDBOX_RESULT_KEY (64 hex). */
  resultKey: string;
  reuse: SandboxReuseWindows;
  /** SANDBOX_ARTIFACT_RETENTION_DAYS. */
  artifactRetentionDays: number;
  /** SANDBOX_PUBLISH_HASHES. */
  publishHashes: boolean;
  /** Ledger consumer (default `email-worker.scan.sandbox.results`; tests use a per-run name). */
  consumer?: string;
  now?: () => Date;
}

/**
 * The sandbox results consumer (step 4.6 X13 results steps 1–5), per
 * `mail.sandbox.task_completed.v1` on `scan.sandbox.results` (ledger
 * `email-worker.scan.sandbox.results`):
 *
 * 1. ledger pre-check; the event schema **and** every code against the security-contracts enums
 *    (`invalid_result`). A rejection writes only the ledger no-op row,
 *    `scan_sandbox_results_rejected_total{reason}` and a warning with ids;
 * 2. one transaction (SCAN_DB_TIMEOUT_MS): the analysis `FOR UPDATE` (identity echo; unknown →
 *    `unknown_analysis`; another task id, hash or organization → `analysis_mismatch`; `pending` →
 *    `not_dispatched`); the result MAC over the whole payload and the envelope organization,
 *    keyed to the analysis's stored result token hash, timing-safe (`bad_mac`; X11); it must be
 *    `dispatched` (terminal → no-op `duplicate`; `expired` → no-op `late`); every artifact key
 *    must be the task's and of one run (`artifact_key_invalid`);
 * 3. `sandbox-map/1` → verdict and codes; the analysis update (status, verdict, codes, the
 *    bounded report view, backend, isolation, versions, reasons, duration, result event,
 *    `reuse_until` — none for `not_executed` with an operational reason —, the dedupe key cleared
 *    when there is no reuse window) and the
 *    `sandbox_artifacts` rows (their wrapped keys exist only there);
 * 4. up to 200 linked `submitted` submissions completed (X15; the sweeper does the rest); with
 *    SANDBOX_PUBLISH_HASHES a malicious hash into `malware_signatures`;
 * 5. the ledger row; after commit, best effort, the sample object is deleted and
 *    `sample_deleted_at` set (failures are left to the sweeper).
 *
 * A forged result therefore writes nothing but a ledger row. Logs carry ids and codes only.
 */
export class SandboxResultsService {
  readonly consumer: string;
  private readonly logger: Logger;
  private readonly now: () => Date;

  constructor(private readonly options: SandboxResultsServiceOptions) {
    this.consumer = options.consumer ?? SANDBOX_RESULTS_CONSUMER;
    this.logger = options.logger.child({ component: 'sandbox-results' });
    this.now = options.now ?? (() => new Date());
  }

  async handle(event: EventEnvelope<SandboxTaskCompletedV1>): Promise<HandleOutcome> {
    const { store, metrics } = this.options;
    if (await store.isProcessed(this.consumer, event.eventId)) return 'duplicate';
    const raw = event.payload as Partial<SandboxTaskCompletedV1> | undefined;
    const ids = {
      eventId: event.eventId,
      taskId: typeof raw?.taskId === 'string' ? raw.taskId.slice(0, 36) : null,
      analysisId: typeof raw?.analysisId === 'string' ? raw.analysisId.slice(0, 20) : null,
      organizationId: event.organizationId,
    };
    const parsed = sandboxTaskCompletedV1.safeParse(event.payload);
    if (!parsed.success) return this.reject(event, 'invalid_result', ids);
    const payload = parsed.data;
    const codes = validateCodes(payload);
    if (!codes.ok) return this.reject(event, 'invalid_result', ids);
    let mapped: SandboxMapResult;
    try {
      mapped = mapAnalysis({
        kind: 'result',
        status: payload.status,
        executed: payload.executed,
        isolation: payload.isolation,
        notExecutedReason:
          payload.notExecutedReason !== null
            ? notExecutedReasonSchema.parse(payload.notExecutedReason)
            : null,
        errorCode:
          payload.errorCode !== null ? sandboxErrorCodeSchema.parse(payload.errorCode) : null,
        durationMs: payload.durationMs,
        findings: codes.observations.findings,
        limitsHit: codes.observations.limitsHit,
      });
    } catch {
      return this.reject(event, 'invalid_result', ids);
    }

    let applied: Applied | typeof DUPLICATE;
    try {
      applied = await store.transaction((tx) =>
        this.apply(tx, event, payload, codes.observations, mapped),
      );
    } catch (error) {
      if (error instanceof InconsistentSandboxReadError) metrics.inconsistent(error.read);
      throw error;
    }
    if (applied === DUPLICATE) return 'duplicate';
    switch (applied.kind) {
      case 'rejected':
        metrics.reject(applied.reason);
        this.logger.warn({ ...ids, reason: applied.reason }, 'sandbox result rejected');
        return 'handled';
      case 'noop':
        if (applied.reason === 'late') {
          this.logger.info(ids, 'sandbox result arrived after the analysis expired; ignored');
        }
        return 'handled';
      case 'applied':
        metrics.analysis(applied.status);
        metrics.verdict(applied.verdict);
        if (applied.status === 'failed') metrics.submission('failed', applied.submissions);
        this.logger.info(
          {
            ...ids,
            status: applied.status,
            verdict: applied.verdict,
            submissions: applied.submissions,
            artifacts: applied.artifacts,
            finals: applied.finals.length,
          },
          'sandbox result applied',
        );
        if (applied.sampleKey) await this.deleteSample(applied.analysisId, applied.sampleKey);
        return 'handled';
    }
  }

  private async reject(
    event: EventEnvelope<unknown>,
    reason: SandboxRejectReason,
    ids: Record<string, string | null>,
  ): Promise<HandleOutcome> {
    const recorded = await this.options.store.recordNoop(this.consumer, event.eventId);
    if (!recorded) return 'duplicate';
    this.options.metrics.reject(reason);
    this.logger.warn({ ...ids, reason }, 'sandbox result rejected');
    return 'handled';
  }

  private async apply(
    tx: SandboxTx,
    event: EventEnvelope<SandboxTaskCompletedV1>,
    payload: SandboxTaskCompletedV1,
    observations: SandboxObservations,
    mapped: SandboxMapResult,
  ): Promise<Applied> {
    await tx.ledger(this.consumer, event.eventId);
    const now = this.now();
    const analysis = await tx.lockAnalysis(BigInt(payload.analysisId));
    if (!analysis) return { kind: 'rejected', reason: 'unknown_analysis' };
    if (
      analysis.publicId !== payload.taskId ||
      analysis.sha256 !== payload.sampleSha256 ||
      analysis.organizationId.toString() !== event.organizationId
    ) {
      return { kind: 'rejected', reason: 'analysis_mismatch' };
    }
    if (analysis.status === 'pending') return { kind: 'rejected', reason: 'not_dispatched' };
    // The MAC over the whole payload and the organization, keyed to this analysis's one-time
    // result token (X11): a modified body, a copied MAC or a result for a task its sender never
    // received does not verify. An analysis without a token hash (dispatched before tokens)
    // accepts no result and expires.
    if (
      analysis.resultTokenSha256 === null ||
      !verifyResultMac(
        this.options.resultKey,
        {
          organizationId: event.organizationId,
          tokenSha256: analysis.resultTokenSha256,
          payload: event.payload,
        },
        payload.resultMac,
      )
    ) {
      return { kind: 'rejected', reason: 'bad_mac' };
    }
    if (analysis.status === 'expired') return { kind: 'noop', reason: 'late' };
    if (analysis.status !== 'dispatched') return { kind: 'noop', reason: 'duplicate' };
    if (!artifactKeysValid(payload.artifacts, payload.taskId, analysis.dispatchedAt, now)) {
      return { kind: 'rejected', reason: 'artifact_key_invalid' };
    }

    const reuseUntil = reuseUntilFor(
      payload.status,
      mapped.verdict,
      this.options.reuse,
      now,
      payload.notExecutedReason !== null
        ? notExecutedReasonSchema.parse(payload.notExecutedReason)
        : null,
    );
    const changed = await tx.completeAnalysis(analysis.id, ['dispatched'], {
      status: payload.status,
      verdict: mapped.verdict,
      reasonCodes: mapped.reasonCodes,
      report: buildSandboxReportView(observations),
      backend: payload.backend,
      backendVersion: payload.backendVersion,
      isolation: payload.isolation,
      executed: payload.executed,
      controllerVersion: payload.controllerVersion,
      analyzerVersion: payload.analyzerVersion,
      mapVersion: mapped.mapVersion,
      notExecutedReason: payload.notExecutedReason,
      errorCode: payload.errorCode,
      durationMs: payload.durationMs,
      resultEventId: event.eventId,
      completedAt: now,
      reuseUntil,
      clearDedupeKey: reuseUntil === null,
    });
    if (!changed) return { kind: 'noop', reason: 'duplicate' };
    const expiresAt = new Date(now.getTime() + this.options.artifactRetentionDays * DAY_MS);
    const artifacts: NewArtifact[] = payload.artifacts.map((a) => ({
      seq: a.seq,
      kind: a.kind,
      contentType: a.contentType,
      objectKey: a.key,
      objectSha256: a.objectSha256,
      plainSha256: a.plainSha256,
      sizeBytes: a.sizeBytes,
      wrappedKey: a.wrappedKey,
      keyId: a.keyId,
      algorithm: a.algorithm,
      expiresAt,
    }));
    await tx.insertArtifacts(analysis.id, artifacts);

    const completed: AnalysisRow = {
      ...analysis,
      status: payload.status,
      verdict: mapped.verdict,
      reasonCodes: mapped.reasonCodes,
      executed: payload.executed,
      isolation: payload.isolation,
      controllerVersion: payload.controllerVersion,
      backend: payload.backend,
      backendVersion: payload.backendVersion,
    };
    const linked = await tx.linkedSubmitted(analysis.id, SANDBOX_LINKED_BATCH);
    const report = await finishSubmissions(
      tx,
      linked.map((submission) => ({ submission, outcome: outcomeFromAnalysis(completed) })),
      { now, correlationId: event.correlationId, metrics: this.options.metrics },
    );
    if (this.options.publishHashes && mapped.verdict === 'malicious') {
      await tx.publishHash(
        analysis.sha256,
        analysis.publicId,
        now,
        new Date(now.getTime() + SANDBOX_HASH_TTL_DAYS * DAY_MS),
      );
    }
    return {
      kind: 'applied',
      analysisId: analysis.id,
      status: payload.status,
      verdict: mapped.verdict,
      submissions: report.changed,
      finals: report.finals,
      artifacts: artifacts.length,
      sampleKey: analysis.sampleDeletedAt === null ? analysis.sampleObjectKey : null,
    };
  }

  /** After commit, best effort (X13 results step 5): the sweeper retries a failed delete. */
  private async deleteSample(analysisId: bigint, key: string): Promise<void> {
    try {
      await this.options.objects.delete(key);
      if (await this.options.store.markSampleDeleted(analysisId, key, this.now())) {
        this.options.metrics.purge('sample');
      }
    } catch {
      this.logger.warn(
        { analysisId: analysisId.toString() },
        'sandbox sample delete failed; the sweeper retries it',
      );
    }
  }
}

/** The `QueueConsumer` of `scan.sandbox.results` (prefetch SANDBOX_RESULTS_CONCURRENCY). */
export function createSandboxResultsConsumer(options: {
  connection: AmqpConnection;
  publisher: ConfirmPublisher;
  service: SandboxResultsService;
  prefetch: number;
  retry: { baseDelayMs: number; maxDelayMs: number };
  logger: Logger;
  metrics?: MessagingMetrics;
}): QueueConsumer<SandboxTaskCompletedV1> {
  return new QueueConsumer<SandboxTaskCompletedV1>({
    connection: options.connection,
    publisher: options.publisher,
    queue: SANDBOX_RESULTS_QUEUE,
    consumer: options.service.consumer,
    eventTypes: [EventTypes.SandboxTaskCompleted],
    prefetch: options.prefetch,
    retry: options.retry,
    classify: classifyScanFailure,
    logger: options.logger,
    ...(options.metrics ? { metrics: options.metrics } : {}),
  });
}
