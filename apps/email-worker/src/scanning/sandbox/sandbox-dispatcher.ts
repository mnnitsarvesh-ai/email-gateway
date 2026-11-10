import {
  type AmqpConnection,
  type ConfirmPublisher,
  type HandleOutcome,
  type MessagingMetrics,
  NonRetryableError,
  QueueConsumer,
  uuidv7,
} from '@email-gateway/common';
import {
  attachmentSandboxRequestedV1,
  type AttachmentSandboxRequestedV1,
  type EventEnvelope,
  EventTypes,
  organizationIdOfKey,
  sandboxTaskRequestedV1,
} from '@email-gateway/event-contracts';
import type { Logger } from '@email-gateway/logger';
import {
  analysisKey,
  dedupeKey,
  mapAnalysis,
  sampleObjectKey,
  sealResultToken,
} from '@email-gateway/sandbox';
import {
  resolveSandboxSettings,
  type SandboxEffectiveSettings,
  type SandboxPlatformSettings,
  type SandboxProfile,
  sandboxSettingsVersion,
  type SandboxSkipReason,
  type SandboxTaskLimits,
} from '@email-gateway/security-contracts';
import { classifyScanFailure } from '../engine-consumer';
import {
  finishSubmissions,
  outcomeFromAnalysis,
  SANDBOX_LINKED_BATCH,
  type SubmissionOutcome,
} from './sandbox-finalizer';
import type { SandboxMetrics } from './sandbox-metrics';
import {
  type AnalysisRow,
  DUPLICATE,
  InconsistentSandboxReadError,
  isTerminalAnalysis,
  type SandboxStore,
  type SandboxTx,
  type SubmissionRow,
} from './sandbox-store';
import { SANDBOX_BROWSER_MIN_MEMORY_MB, SANDBOX_BROWSER_MIN_PIDS } from './sandbox-config';
import type { SampleStager } from './sample-stager';

/** The submissions queue and its ledger consumer (topology v8, X11, X13). */
export const SANDBOX_SUBMISSIONS_QUEUE = 'scan.sandbox.submissions';
export const SANDBOX_DISPATCH_CONSUMER = 'email-worker.scan.sandbox';

const EXECUTE_TYPES: ReadonlySet<string> = new Set([
  'script_js',
  'script_vbs',
  'script_ps1',
  'script_batch',
  'script_shell',
  'hta',
  'pe_executable',
  'msi',
  'elf',
  'lnk',
]);
const BROWSER_TYPES: ReadonlySet<string> = new Set(['html', 'svg']);

/** The analysis profile of a detected type (X13 step 4). */
export function profileFor(detectedType: string, browserAnalysis: boolean): SandboxProfile {
  if (BROWSER_TYPES.has(detectedType) && browserAnalysis) return 'browser';
  if (EXECUTE_TYPES.has(detectedType) || detectedType.startsWith('script_')) return 'execute';
  return 'static';
}

/** The platform task limits (`SANDBOX_RUN_*`, `SANDBOX_MAX_ARTIFACT*`). */
export interface SandboxRunLimits {
  wallTimeoutMs: number;
  memoryMb: number;
  cpuMillis: number;
  pids: number;
  scratchMb: number;
  maxArtifacts: number;
  maxArtifactBytes: number;
  maxTotalArtifactBytes: number;
}

/** The task limits of a profile (X13 step 4: browser runners ≥ 1024 MiB and ≥ 256 pids). */
export function limitsFor(profile: SandboxProfile, base: SandboxRunLimits): SandboxTaskLimits {
  if (profile !== 'browser') return { ...base };
  return {
    ...base,
    memoryMb: Math.max(base.memoryMb, SANDBOX_BROWSER_MIN_MEMORY_MB),
    pids: Math.max(base.pids, SANDBOX_BROWSER_MIN_PIDS),
  };
}

export interface SandboxDispatcherOptions {
  store: SandboxStore;
  stager: SampleStager;
  metrics: SandboxMetrics;
  /** `scan_settings_invalid_total{engine="sandbox"}` (the shared invalid-settings metric). */
  settingsInvalid: (engine: 'sandbox') => void;
  logger: Logger;
  platform: SandboxPlatformSettings;
  limits: SandboxRunLimits;
  /** SANDBOX_ANALYSIS_EPOCH. */
  epoch: number;
  /** SANDBOX_TASK_DEADLINE_SECONDS. */
  deadlineSeconds: number;
  /** SANDBOX_ANALYSIS_RETENTION_DAYS. */
  analysisRetentionDays: number;
  /** SANDBOX_RESULT_KEY (64 hex): seals each task's one-time result token (X11). */
  resultKey: string;
  /** Ledger consumer (default `email-worker.scan.sandbox`; tests use a per-run name). */
  consumer?: string;
  now?: () => Date;
}

type Gate =
  | { kind: 'skip'; reason: SandboxSkipReason; settingsVersion: string }
  | { kind: 'go'; settings: SandboxEffectiveSettings; settingsVersion: string };

/** What transaction A decided. */
type PlanA =
  | { kind: 'noop'; reason: 'submission_missing' | 'duplicate' | 'analysis_missing' }
  | { kind: 'skipped'; reason: SandboxSkipReason }
  | { kind: 'linked' }
  | { kind: 'reused' }
  | { kind: 'stage'; analysis: AnalysisRow; submission: SubmissionRow };

type Result = 'dispatched' | 'not_dispatched' | 'failed';

const DAY_MS = 86_400_000;

/**
 * The sandbox dispatcher (step 4.6 X13 steps 1–7), per `mail.attachment.sandbox_requested.v1`
 * on `scan.sandbox.submissions` (ledger `email-worker.scan.sandbox`):
 *
 * 1. ledger pre-check; the key's organization must be the envelope's (else fatal
 *    `tenant_mismatch`);
 * 2. transaction A loads the submission on the writer (echo: organization, message, scan, part
 *    index, hash and key must equal the event, else `InconsistentSandboxReadError`, retried);
 *    missing → no-op; not `pending`/`submitted` → no-op;
 * 3. gates for a `pending` submission: plan feature `attachment_sandbox`, the tenant's
 *    `scan_engine_settings` row of engine `sandbox` (`resolveSandboxSettings`; an invalid row →
 *    platform settings + `scan_settings_invalid_total`), file type, size → `skipped` with the
 *    round check (X15);
 * 4. profile, limits, `analysisKey`, `dedupeKey`;
 * 5. dedup under `SELECT … FOR UPDATE` of the dedupe key: reusable (terminal, `reuse_until > now`)
 *    → link and complete from the analysis; in flight (`pending`/`dispatched`, deadline ahead) →
 *    link; stale → clear its dedupe key and create; none → create (`requested_event_id` = this
 *    event); a unique violation (a concurrent dispatcher) → re-read and link;
 * 6. staging (only by the event that created the analysis, or its redelivery while the analysis
 *    is `pending`): `SampleStager`; a missing or corrupt part fails the analysis
 *    (`dedupe_key = NULL`) and its submissions; an S3 outage is thrown (transient);
 * 7. transaction B: `pending → dispatched` with the SHA-256 of a fresh one-time result token
 *    and, only when that row changed, the `mail.sandbox.task_requested.v1` outbox row (aggregate
 *    `sandbox_analysis`, organization = the analysis's) carrying the token sealed (X11), then the
 *    ledger row.
 *
 * Lock order (sandbox-store): analysis → scan → submission in every branch; the reuse branch
 * locks the submission's `email_scans` row before it links the submission.
 *
 * Idempotent by state: a redelivery after A or after the put resumes at 6; after B it is a ledger
 * duplicate. Logs carry ids and codes only.
 */
export class SandboxDispatcher {
  readonly consumer: string;
  private readonly logger: Logger;
  private readonly now: () => Date;

  constructor(private readonly options: SandboxDispatcherOptions) {
    this.consumer = options.consumer ?? SANDBOX_DISPATCH_CONSUMER;
    this.logger = options.logger.child({ component: 'sandbox-dispatcher' });
    this.now = options.now ?? (() => new Date());
  }

  async handle(event: EventEnvelope<AttachmentSandboxRequestedV1>): Promise<HandleOutcome> {
    const { store, metrics } = this.options;
    if (await store.isProcessed(this.consumer, event.eventId)) return 'duplicate';
    const parsed = attachmentSandboxRequestedV1.safeParse(event.payload);
    if (!parsed.success) throw new NonRetryableError('sandbox_request_invalid');
    const payload = parsed.data;
    if (organizationIdOfKey(payload.attachment.objectKey) !== event.organizationId) {
      throw new NonRetryableError('tenant_mismatch');
    }
    const organizationId = BigInt(event.organizationId);
    const ids = {
      submissionId: payload.submissionId,
      messageId: payload.messageId,
      organizationId: event.organizationId,
    };
    let plan: PlanA | typeof DUPLICATE;
    try {
      plan = await store.transaction((tx) => this.planA(tx, event, payload, organizationId));
    } catch (error) {
      if (error instanceof InconsistentSandboxReadError) metrics.inconsistent(error.read);
      throw error;
    }
    if (plan === DUPLICATE) return 'duplicate';
    switch (plan.kind) {
      case 'noop':
        if (plan.reason !== 'duplicate') {
          this.logger.warn({ ...ids, reason: plan.reason }, 'sandbox submission not dispatched');
        }
        return 'handled';
      case 'skipped':
        metrics.skipped(plan.reason);
        this.logger.info({ ...ids, reason: plan.reason }, 'sandbox submission skipped');
        return 'handled';
      case 'linked':
        metrics.submission('linked');
        return 'handled';
      case 'reused':
        metrics.submission('reused');
        return 'handled';
      case 'stage': {
        const result = await this.stageAndDispatch(event, plan.analysis, plan.submission);
        if (result === DUPLICATE) return 'duplicate';
        this.logger.info(
          { ...ids, analysisId: plan.analysis.id.toString(), result },
          'sandbox submission dispatched',
        );
        return 'handled';
      }
    }
  }

  /** Transaction A (X13 steps 2–5). */
  private async planA(
    tx: SandboxTx,
    event: EventEnvelope<AttachmentSandboxRequestedV1>,
    payload: AttachmentSandboxRequestedV1,
    organizationId: bigint,
  ): Promise<PlanA> {
    const now = this.now();
    const submission = await tx.loadSubmission({
      id: BigInt(payload.submissionId),
      receivedAt: new Date(payload.receivedAt),
    });
    if (!submission) {
      await tx.ledger(this.consumer, event.eventId);
      return { kind: 'noop', reason: 'submission_missing' };
    }
    if (
      submission.organizationId !== organizationId ||
      submission.messageId !== BigInt(payload.messageId) ||
      submission.scanId !== BigInt(payload.scanId) ||
      submission.partIndex !== payload.attachment.partIndex ||
      submission.sha256 !== payload.attachment.sha256 ||
      submission.objectKey !== payload.attachment.objectKey
    ) {
      throw new InconsistentSandboxReadError('submission', 'event echo');
    }
    if (submission.status !== 'pending' && submission.status !== 'submitted') {
      await tx.ledger(this.consumer, event.eventId);
      return { kind: 'noop', reason: 'duplicate' };
    }
    const ctx = { now, correlationId: event.correlationId, metrics: this.options.metrics };

    // Resume (a redelivery after transaction A): the submission is linked already.
    if (submission.status === 'submitted') {
      const analysis =
        submission.analysisId !== null ? await tx.lockAnalysis(submission.analysisId) : null;
      if (!analysis) {
        await tx.ledger(this.consumer, event.eventId);
        return { kind: 'noop', reason: 'analysis_missing' };
      }
      if (isTerminalAnalysis(analysis.status)) {
        await finishSubmissions(tx, [{ submission, outcome: outcomeFromAnalysis(analysis) }], ctx);
        await tx.ledger(this.consumer, event.eventId);
        return { kind: 'reused' };
      }
      if (analysis.status === 'pending' && analysis.requestedEventId === event.eventId) {
        return { kind: 'stage', analysis, submission };
      }
      await tx.ledger(this.consumer, event.eventId);
      return { kind: 'linked' };
    }

    const gate = await this.gate(tx, submission, organizationId);
    if (gate.kind === 'skip') {
      const outcome: SubmissionOutcome = {
        status: 'skipped',
        skipReason: gate.reason,
        settingsVersion: gate.settingsVersion,
      };
      await finishSubmissions(tx, [{ submission, outcome }], ctx);
      await tx.ledger(this.consumer, event.eventId);
      return { kind: 'skipped', reason: gate.reason };
    }
    const profile = profileFor(submission.detectedType, gate.settings.browserAnalysis);
    const limits = limitsFor(profile, this.options.limits);
    const key = analysisKey({ profile, limits, epoch: this.options.epoch });
    const dedupe = dedupeKey(submission.sha256, key);

    let existing = await tx.lockAnalysisByDedupe(dedupe);
    for (let round = 0; round < 2; round += 1) {
      if (existing) {
        if (isTerminalAnalysis(existing.status)) {
          if (existing.reuseUntil !== null && existing.reuseUntil.getTime() > now.getTime()) {
            // analysis → scan → submission: the round's scan row before the submission row
            // (the results consumer and the sweeper hold the scan and read the round's
            // submissions FOR SHARE).
            await tx.lockScans([{ scanId: submission.scanId, receivedAt: submission.receivedAt }]);
            await this.link(tx, submission, existing, gate.settingsVersion);
            await finishSubmissions(
              tx,
              [{ submission, outcome: outcomeFromAnalysis(existing) }],
              ctx,
            );
            await tx.ledger(this.consumer, event.eventId);
            return { kind: 'reused' };
          }
        } else if (existing.deadlineAt.getTime() > now.getTime()) {
          await this.link(tx, submission, existing, gate.settingsVersion);
          if (existing.status === 'pending' && existing.requestedEventId === event.eventId) {
            // A concurrent delivery of the creating event: it stages too (an idempotent
            // overwrite); transaction B lets exactly one of them dispatch.
            return { kind: 'stage', analysis: existing, submission };
          }
          await tx.ledger(this.consumer, event.eventId);
          return { kind: 'linked' };
        }
        // Stale: it no longer holds the dedupe key; a new analysis is created.
        await tx.clearDedupeKey(existing.id, dedupe);
      }
      const publicId = uuidv7(now.getTime());
      const created = await tx.createAnalysis({
        publicId,
        sha256: submission.sha256,
        sizeBytes: submission.sizeBytes,
        detectedType: submission.detectedType,
        profile,
        analysisKey: key,
        dedupeKey: dedupe,
        organizationId: submission.organizationId,
        sampleObjectKey: sampleObjectKey(publicId, now),
        requestedEventId: event.eventId,
        deadlineAt: new Date(now.getTime() + this.options.deadlineSeconds * 1000),
        expiresAt: new Date(now.getTime() + this.options.analysisRetentionDays * DAY_MS),
      });
      if (created !== 'duplicate') {
        this.options.metrics.analysis('pending');
        await this.link(tx, submission, created, gate.settingsVersion);
        return { kind: 'stage', analysis: created, submission };
      }
      // A concurrent dispatcher created it first: re-read under the lock and decide again.
      existing = await tx.lockAnalysisByDedupe(dedupe);
      if (!existing) break;
    }
    throw new InconsistentSandboxReadError(
      'analysis',
      'dedupe key vanished after a unique violation',
    );
  }

  private async link(
    tx: SandboxTx,
    submission: SubmissionRow,
    analysis: AnalysisRow,
    settingsVersion: string,
  ): Promise<void> {
    if (!(await tx.linkSubmission(submission, analysis.id, settingsVersion))) {
      throw new InconsistentSandboxReadError('submission', 'link condition');
    }
  }

  /** X13 step 3: plan feature, tenant setting, type, size. */
  private async gate(
    tx: SandboxTx,
    submission: SubmissionRow,
    organizationId: bigint,
  ): Promise<Gate> {
    const { platform } = this.options;
    const rows = await tx.tenantGate(organizationId);
    let settings: SandboxEffectiveSettings;
    let rowVersion: number | null = rows.settings?.version ?? null;
    const resolution = resolveSandboxSettings(platform, rows.settings?.settings ?? null);
    if (resolution.ok) {
      settings = resolution.settings;
    } else {
      this.options.settingsInvalid('sandbox');
      this.logger.warn(
        {
          organizationId: organizationId.toString(),
          settingsRowVersion: rowVersion,
          violations: resolution.violations.map((v) => v.code),
        },
        'tenant sandbox settings are invalid; the platform settings are applied',
      );
      const fallback = resolveSandboxSettings(platform, null);
      if (!fallback.ok) throw new Error('platform sandbox settings are invalid');
      settings = fallback.settings;
      rowVersion = null;
    }
    const settingsVersion = sandboxSettingsVersion(platform, rowVersion);
    const skip = (reason: SandboxSkipReason): Gate => ({ kind: 'skip', reason, settingsVersion });
    if (!rows.feature) return skip('feature_disabled');
    if (!settings.enabled) return skip('tenant_disabled');
    if (!(settings.fileTypes as readonly string[]).includes(submission.detectedType)) {
      return skip('type_excluded');
    }
    // An empty part cannot be analysed (task samples are 1 … 64 MiB): size_excluded.
    if (submission.sizeBytes < 1 || submission.sizeBytes > settings.maxSampleBytes) {
      return skip('size_excluded');
    }
    return { kind: 'go', settings, settingsVersion };
  }

  /** X13 steps 6–7. */
  private async stageAndDispatch(
    event: EventEnvelope<AttachmentSandboxRequestedV1>,
    analysis: AnalysisRow,
    submission: SubmissionRow,
  ): Promise<Result | typeof DUPLICATE> {
    const { store, metrics } = this.options;
    const started = performance.now();
    let staged;
    try {
      staged = await this.options.stager.stage({
        organizationId: submission.organizationId,
        partKey: submission.objectKey,
        sizeBytes: submission.sizeBytes,
        sha256: submission.sha256,
        taskId: analysis.publicId,
        sampleKey: analysis.sampleObjectKey ?? '',
      });
    } catch (error) {
      if (!(error instanceof NonRetryableError)) metrics.stagingFailure('storage_unavailable');
      throw error;
    }
    if (staged.kind === 'failed') {
      metrics.stagingFailure(staged.errorCode);
      return this.failAnalysis(event, analysis.id, staged.errorCode);
    }
    metrics.staged((performance.now() - started) / 1000);

    const result = await store.transaction(async (tx) => {
      await tx.ledger(this.consumer, event.eventId);
      const now = this.now();
      if (analysis.deadlineAt.getTime() <= now.getTime()) {
        // The deadline passed while staging: no task; the sweeper expires it (timeout).
        return 'not_dispatched' as const;
      }
      // A fresh one-time token per dispatch; only its hash is stored (X11).
      const token = sealResultToken(this.options.resultKey, analysis.publicId);
      if (!(await tx.markDispatched(analysis.id, now, token.tokenSha256))) {
        return 'not_dispatched' as const;
      }
      const limits = limitsFor(analysis.profile, this.options.limits);
      const task = sandboxTaskRequestedV1.safeParse({
        taskId: analysis.publicId,
        analysisId: analysis.id.toString(),
        sample: {
          key: analysis.sampleObjectKey,
          sha256: analysis.sha256,
          sizeBytes: analysis.sizeBytes,
          detectedType: analysis.detectedType,
        },
        profile: analysis.profile,
        limits,
        requestedAt: now.toISOString(),
        deadlineAt: analysis.deadlineAt.toISOString(),
        resultToken: token.sealed,
      });
      if (!task.success) throw new NonRetryableError('sandbox_task_payload_invalid');
      await tx.writeOutbox({
        eventId: uuidv7(now.getTime()),
        organizationId: analysis.organizationId,
        eventType: EventTypes.SandboxTaskRequested,
        aggregateType: 'sandbox_analysis',
        aggregateId: analysis.id.toString(),
        correlationId: event.correlationId,
        payload: task.data,
      });
      return 'dispatched' as const;
    });
    if (result === 'dispatched') {
      metrics.analysis('dispatched');
      metrics.submission('dispatched');
    }
    return result;
  }

  /** A missing or corrupt part fails the analysis and its linked submissions (X13 step 6). */
  private async failAnalysis(
    event: EventEnvelope<AttachmentSandboxRequestedV1>,
    analysisId: bigint,
    errorCode: 'sample_unavailable' | 'sample_integrity',
  ): Promise<Result | typeof DUPLICATE> {
    const { store, metrics } = this.options;
    const mapped = mapAnalysis({
      kind: 'result',
      status: 'failed',
      executed: false,
      isolation: 'none',
      notExecutedReason: null,
      errorCode,
      durationMs: 0,
      findings: [],
      limitsHit: [],
    });
    const result = await store.transaction(async (tx) => {
      await tx.ledger(this.consumer, event.eventId);
      const now = this.now();
      const analysis = await tx.lockAnalysis(analysisId);
      if (!analysis) throw new InconsistentSandboxReadError('analysis', 'staged analysis vanished');
      const changed = await tx.completeAnalysis(analysis.id, ['pending'], {
        status: 'failed',
        verdict: mapped.verdict,
        reasonCodes: mapped.reasonCodes,
        errorCode,
        mapVersion: mapped.mapVersion,
        executed: false,
        completedAt: now,
        reuseUntil: null,
        clearDedupeKey: true,
      });
      if (!changed) return { analysis: false, submissions: 0 };
      const failed: AnalysisRow = {
        ...analysis,
        status: 'failed',
        verdict: mapped.verdict,
        reasonCodes: mapped.reasonCodes,
        executed: false,
        isolation: null,
      };
      const linked = await tx.linkedSubmitted(analysis.id, SANDBOX_LINKED_BATCH);
      const report = await finishSubmissions(
        tx,
        linked.map((submission) => ({ submission, outcome: outcomeFromAnalysis(failed) })),
        { now, correlationId: event.correlationId, metrics },
      );
      return { analysis: true, submissions: report.changed };
    });
    if (result === DUPLICATE) return DUPLICATE;
    if (result.analysis) {
      metrics.analysis('failed');
      metrics.verdict('error');
    }
    metrics.submission('failed', result.submissions);
    return 'failed';
  }
}

/** The `QueueConsumer` of `scan.sandbox.submissions` (prefetch SANDBOX_DISPATCH_CONCURRENCY). */
export function createSandboxDispatchConsumer(options: {
  connection: AmqpConnection;
  publisher: ConfirmPublisher;
  dispatcher: SandboxDispatcher;
  prefetch: number;
  retry: { baseDelayMs: number; maxDelayMs: number };
  logger: Logger;
  metrics?: MessagingMetrics;
}): QueueConsumer<AttachmentSandboxRequestedV1> {
  return new QueueConsumer<AttachmentSandboxRequestedV1>({
    connection: options.connection,
    publisher: options.publisher,
    queue: SANDBOX_SUBMISSIONS_QUEUE,
    consumer: options.dispatcher.consumer,
    eventTypes: [EventTypes.AttachmentSandboxRequested],
    prefetch: options.prefetch,
    retry: options.retry,
    classify: classifyScanFailure,
    logger: options.logger,
    ...(options.metrics ? { metrics: options.metrics } : {}),
  });
}
