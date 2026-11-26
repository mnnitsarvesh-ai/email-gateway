import { Inject, Injectable, Logger } from '@nestjs/common';
import { normalizeSections, REPORT_GENERATE } from '@email-gateway/assistant';
import type { HandleOutcome } from '@email-gateway/common';
import type {
  AssistantReportGenerateRequestedV1,
  EventEnvelope,
} from '@email-gateway/event-contracts';
import { API_CONFIG } from '../../../../api-config.token';
import { AuditService } from '../../../../audit/audit.service';
import type { UserPrincipal } from '../../../../auth-contracts/principal';
import { scopeFromPrincipal } from '../../../../auth-contracts/tenant-scope';
import { TransactionRunner } from '../../../../database/transaction-runner';
import { AccessTokenPrincipalResolver } from '../../../auth/services/access-token-principal-resolver.service';
import { type AuthMethod, TokenService } from '../../../auth/services/token.service';
import {
  ASSISTANT_AUDIT,
  ASSISTANT_PERMISSIONS,
  AUDIT_RESOURCE,
  type AssistantConfig,
  REPORT_JOB_COMPOSE_BUDGET_MS,
  REPORT_JOB_LEASE_MS,
  REPORT_JOB_LEASE_RENEW_MS,
  REPORT_JOB_LEDGER,
  REPORT_JOB_MAX_ATTEMPTS,
} from '../../assistant.constants';
import { REPORT_ERROR_CODES, REPORT_JOB_CODES } from '../../assistant.errors';
import { executionCorrelationId } from '../../domain/correlation';
import { lookupTool, nativeSwitchesOf, toolAvailability } from '../../domain/tool-catalog';
import {
  type ReportJobWithRefs,
  ReportJobsRepository,
} from '../../repositories/report-jobs.repository';
import { ReportsRepository } from '../../repositories/reports.repository';
import { AssistantAvailabilityService } from '../assistant-availability.service';
import { AssistantMetrics } from '../assistant-metrics';
import { isReportKeyOf, ReportObjectStore } from './report-object-store';
import { type ComposedReport, ReportGeneratorService } from './report-generator.service';

/** A composition failure that the queue retries (while attempts remain and before expiry). */
export class ReportJobRetryError extends Error {
  constructor(readonly code: string) {
    super(`assistant report job will be retried (${code})`);
    this.name = 'ReportJobRetryError';
  }
}

/**
 * The job is `running` under another consumer's live lease. A transient failure (the consumer's
 * classification): the delivery comes back after the backoff without spending an attempt, and
 * claims the job once the lease lapsed (the holder died) or acks it once it is terminal.
 */
export class ReportJobBusyError extends Error {
  readonly code = 'assistant_report_job_busy';
  constructor() {
    super('assistant report job is held by another consumer');
    this.name = 'ReportJobBusyError';
  }
}

/** Composition failures worth another attempt (D5 step 5: no data, storage, an aborted read). */
const RETRYABLE: ReadonlySet<string> = new Set([
  REPORT_ERROR_CODES.sourcesUnavailable,
  REPORT_ERROR_CODES.storageFailed,
  'tool_aborted',
]);

const AUTH_METHODS: ReadonlySet<string> = new Set(['pwd', 'otp']);

/** The renewed lease of one claimed attempt. */
interface JobLease {
  /** Aborted when the lease was lost (the composition stops). */
  readonly signal: AbortSignal;
  /** True once a renewal found the job taken over or moved on. */
  lost(): boolean;
  stop(): void;
}

/**
 * One `assistant.report.generate_requested.v1` of the `assistant.reports` queue (step AI-6 D5,
 * ADR-0096, I26), idempotent through the row CAS and the ledger `api-assistant.reports`:
 *
 * 1. the job by public id, scoped to the envelope's organization (missing or of another report →
 *    ack; terminal → ack; past `expires_at` → `failed` `assistant_report_job_expired` with its
 *    report);
 * 2. CAS `queued` (or `running` with an expired lease) → `running`, `attempts + 1`, a 60 s
 *    lease renewed every 20 s while this attempt runs (lost because another consumer holds a live
 *    lease → `ReportJobBusyError`, a transient retry that claims the job once the holder's lease
 *    lapsed; moved on → ack). A claim past REPORT_JOB_MAX_ATTEMPTS (crash loop) fails the job
 *    `assistant_report_job_failed`;
 * 3. a job token of the user's own session (`TokenService.issueAssistantJobAccess`: `ajb`,
 *    300 s; never stored or logged) resolved by the guard's `AccessTokenPrincipalResolver` (null:
 *    session revoked or ended, user disabled, override ended → `assistant_report_session_ended`);
 *    the principal must still be the job's user in the job's organization;
 * 4. authority now: the assistant's availability for the scope (platform switch, feature, tenant
 *    setting), `assistant:use` and the `report_generate` requirement (`report:read`), else
 *    `assistant_report_not_allowed`;
 * 5. the AI-R composition (`ReportGeneratorService.composeAndStore`) through the loopback with
 *    `authorization: Bearer <job token>` (GET-only: the guard refuses it anywhere else),
 *    correlation `<job correlation>.<n>`, the original execution id, no client IP; then one
 *    transaction: report `queued → available`, job `succeeded`, the ledger row and
 *    `assistant.report_generated` (actor the user, `{ async: true, jobId }`). "No data", a storage
 *    failure or an aborted read is retried (`ReportJobRetryError`, the job back to `queued`)
 *    while attempts < 5 and before `expires_at`; anything else, or the last attempt, fails the
 *    job and its report with the code.
 *
 * Any other error after the claim (principal resolution, availability, composition, the
 * finalize transaction) releases the claim (`queued`, code `assistant_report_job_failed`) and
 * is rethrown, so the queue's retry hop claims it again; at the last attempt or past the expiry
 * it fails the job with that code instead. A renewal that finds the lease taken over aborts the
 * attempt, which then changes nothing (the new holder decides). Logs carry ids and codes only,
 * never the token.
 */
@Injectable()
export class ReportJobProcessor {
  private readonly logger = new Logger(ReportJobProcessor.name);

  constructor(
    @Inject(API_CONFIG) private readonly config: AssistantConfig,
    private readonly jobs: ReportJobsRepository,
    private readonly reports: ReportsRepository,
    private readonly generator: ReportGeneratorService,
    private readonly store: ReportObjectStore,
    private readonly tokens: TokenService,
    private readonly resolver: AccessTokenPrincipalResolver,
    private readonly availability: AssistantAvailabilityService,
    private readonly runner: TransactionRunner,
    private readonly audit: AuditService,
    private readonly metrics: AssistantMetrics,
  ) {}

  now(): Date {
    return new Date();
  }

  async handle(event: EventEnvelope<AssistantReportGenerateRequestedV1>): Promise<HandleOutcome> {
    const organizationId = BigInt(event.organizationId);
    const payload = event.payload;
    // 1. The job (the envelope's organization only).
    const job = await this.jobs.findForConsumer(organizationId, payload.jobId);
    if (!job || job.reportPublicId !== payload.reportId) return 'duplicate';
    if (job.status !== 'queued' && job.status !== 'running') return 'duplicate';
    const now = this.now();
    if (job.expiresAt.getTime() <= now.getTime()) {
      return this.terminate(event, job, REPORT_JOB_CODES.expired, 'expired');
    }
    // 2. The claim.
    if (!(await this.jobs.claim(organizationId, job.id, now, REPORT_JOB_LEASE_MS))) {
      if (await this.jobs.leaseHeld(organizationId, job.id, now)) throw new ReportJobBusyError();
      return 'duplicate';
    }
    const attempt = job.attempts + 1;
    if (attempt > REPORT_JOB_MAX_ATTEMPTS) {
      return this.terminate(event, job, REPORT_JOB_CODES.failed, 'failed');
    }
    const lease = this.keepLease(organizationId, job.id, now);
    try {
      return await this.attempt(event, job, now, attempt, lease);
    } catch (error) {
      if (error instanceof ReportJobRetryError || lease.lost()) throw error;
      return this.unexpected(event, job, attempt, now, error);
    } finally {
      lease.stop();
    }
  }

  /** Steps 3-5 of one claimed attempt. */
  private async attempt(
    event: EventEnvelope<AssistantReportGenerateRequestedV1>,
    job: ReportJobWithRefs,
    now: Date,
    attempt: number,
    lease: JobLease,
  ): Promise<HandleOutcome> {
    const organizationId = job.organizationId;
    // 3. The job token and the principal of the user's live session.
    const principal = await this.principalOf(job);
    if (lease.lost()) return 'duplicate';
    if (!principal) return this.terminate(event, job, REPORT_JOB_CODES.sessionEnded, 'failed');

    // 4. Authority now.
    const scope = scopeFromPrincipal(principal.principal);
    if (
      scope.organizationId !== organizationId ||
      principal.principal.userId !== job.userId ||
      (principal.principal.override?.id ?? null) !== job.platformOverrideId ||
      !(await this.allowed(principal.principal, now))
    ) {
      if (lease.lost()) return 'duplicate';
      return this.terminate(event, job, REPORT_JOB_CODES.notAllowed, 'failed');
    }

    // 5. The composition with the job token.
    const args = (job.arguments ?? {}) as Record<string, unknown>;
    const resolved = this.generator.resolveWindow(args, job.createdAt);
    if (!resolved.ok) return this.terminate(event, job, resolved.code, 'failed');
    const budgetMs = Math.max(
      1_000,
      Math.min(job.expiresAt.getTime() - now.getTime(), REPORT_JOB_COMPOSE_BUDGET_MS),
    );
    const result = await this.generator.composeAndStore(
      {
        principal: principal.principal,
        owner: { scope, userId: principal.principal.userId },
        conversationId: job.conversationId,
        conversationPublicId: job.conversationPublicId,
        authorization: `Bearer ${principal.token}`,
        clientIp: null,
        signal: AbortSignal.any([AbortSignal.timeout(budgetMs), lease.signal]),
        organizationName: job.organizationLabel,
        executionId: job.executionPublicId ?? job.publicId,
        correlationOf: (n) => executionCorrelationId(job.correlationId, n),
      },
      resolved.window,
      normalizeSections(args.sections),
      now,
      { kind: 'job', reportRowId: job.reportId, reportId: job.reportPublicId },
    );
    if (lease.lost()) {
      // Another consumer took the job over: this attempt changes nothing.
      if (result.kind !== 'failed') await this.deleteObject(organizationId, result.objectKey);
      return 'duplicate';
    }
    if (result.kind === 'failed') {
      if (result.code === 'unauthorized') {
        return this.terminate(event, job, REPORT_JOB_CODES.sessionEnded, 'failed');
      }
      const retry =
        RETRYABLE.has(result.code) &&
        attempt < REPORT_JOB_MAX_ATTEMPTS &&
        this.now().getTime() < job.expiresAt.getTime();
      if (retry) {
        await this.jobs.requeue(organizationId, job.id, result.code, now);
        this.metrics.reportJobs.inc({ outcome: 'retried' });
        this.logger.warn({
          message: 'Assistant report job will be retried',
          jobId: job.publicId,
          attempt,
          code: result.code,
        });
        throw new ReportJobRetryError(result.code);
      }
      return this.terminate(event, job, result.code, 'failed');
    }
    try {
      return await this.finalize(event, job, principal.principal, result);
    } catch (error) {
      // Not finalized (the transaction rolled back): the stored object is orphaned.
      await this.deleteObject(organizationId, result.objectKey);
      throw error;
    }
  }

  /**
   * An unexpected error after the claim: release it (`queued`) and rethrow, so the queue's
   * retry hop (transient or retryable by the default classification) claims the job again; the
   * last attempt, or an expired job, fails with `assistant_report_job_failed` instead.
   */
  private async unexpected(
    event: EventEnvelope<AssistantReportGenerateRequestedV1>,
    job: ReportJobWithRefs,
    attempt: number,
    claimedAt: Date,
    error: unknown,
  ): Promise<HandleOutcome> {
    const code = REPORT_JOB_CODES.failed;
    const name = (error as { name?: unknown } | null)?.name;
    this.logger.warn({
      message: 'Assistant report job attempt failed unexpectedly',
      jobId: job.publicId,
      attempt,
      errName: typeof name === 'string' ? name.slice(0, 64) : 'error',
    });
    if (attempt >= REPORT_JOB_MAX_ATTEMPTS || this.now().getTime() >= job.expiresAt.getTime()) {
      return this.terminate(event, job, code, 'failed');
    }
    // A failed release (the database is down) leaves the lease to lapse within a minute.
    await this.jobs.requeue(job.organizationId, job.id, code, claimedAt).catch(() => undefined);
    this.metrics.reportJobs.inc({ outcome: 'retried' });
    throw error;
  }

  /**
   * Renews the claim's lease every REPORT_JOB_LEASE_RENEW_MS while the attempt runs. A renewal
   * that finds the job taken over (or moved on) marks the lease lost and aborts its signal; a
   * failed renewal (database error) is retried at the next tick.
   */
  private keepLease(organizationId: bigint, id: bigint, claimedAt: Date): JobLease {
    const controller = new AbortController();
    let lost = false;
    let renewing = false;
    const timer = setInterval(() => {
      if (renewing || lost) return;
      renewing = true;
      void this.jobs
        .renewLease(organizationId, id, claimedAt, this.now(), REPORT_JOB_LEASE_MS)
        .then((renewed) => {
          if (renewed) return;
          lost = true;
          controller.abort();
        })
        .catch(() => undefined)
        .finally(() => (renewing = false));
    }, REPORT_JOB_LEASE_RENEW_MS);
    timer.unref();
    return {
      signal: controller.signal,
      lost: () => lost,
      stop: () => clearInterval(timer),
    };
  }

  /** Step 3: mint the job token and resolve it as the guard would (null = session ended). */
  private async principalOf(
    job: ReportJobWithRefs,
  ): Promise<{ principal: UserPrincipal; token: string } | null> {
    if (job.userPublicId === null) return null;
    const amr = job.authMethods.split(',').filter((m): m is AuthMethod => AUTH_METHODS.has(m));
    if (amr.length === 0) return null;
    const { token } = await this.tokens.issueAssistantJobAccess({
      userPublicId: job.userPublicId,
      organizationPublicId: job.homeOrganizationPublicId,
      sessionId: job.sessionId,
      amr,
      ...(job.platformOverrideId !== null && { overrideId: job.platformOverrideId }),
      jobId: job.publicId,
    });
    const principal = await this.resolver.resolve(token);
    return principal ? { principal, token } : null;
  }

  /** Step 4: availability (switch, feature, tenant setting), `assistant:use`, `report:read`. */
  private async allowed(principal: UserPrincipal, now: Date): Promise<boolean> {
    const scope = scopeFromPrincipal(principal);
    const availability = await this.availability.evaluate(scope, now, false);
    if (!availability.available) return false;
    if (!principal.permissions.has(ASSISTANT_PERMISSIONS.use)) return false;
    const found = lookupTool(REPORT_GENERATE.name);
    return (
      found.kind === 'tool' &&
      toolAvailability(principal, found.tool, nativeSwitchesOf(this.config)).available
    );
  }

  /** Step 5's transaction: report available, job succeeded, the ledger and the audit. */
  private async finalize(
    event: EventEnvelope<AssistantReportGenerateRequestedV1>,
    job: ReportJobWithRefs,
    principal: UserPrincipal,
    composed: ComposedReport,
  ): Promise<HandleOutcome> {
    const organizationId = job.organizationId;
    const finishedAt = this.now();
    const outcome = await this.runner.run(async (tx) => {
      if (!(await this.jobs.recordLedger(tx, REPORT_JOB_LEDGER, event.eventId))) {
        return 'duplicate' as const;
      }
      const available = await this.reports.markJobReportAvailable(
        organizationId,
        job.reportId,
        {
          executionId: job.executionId,
          title: composed.report.title.slice(0, 200),
          sections: composed.sections,
          figures: composed.figures,
          objectKey: composed.objectKey,
          sizeBytes: composed.report.sizeBytes,
          sha256: composed.sha256,
        },
        tx,
      );
      if (!available || !(await this.jobs.succeed(organizationId, job.id, finishedAt, tx))) {
        // Purged (cancelled) meanwhile: nothing becomes available.
        return 'gone' as const;
      }
      await this.audit.record(
        {
          organizationId,
          actor: this.audit.actorFrom(principal),
          action: ASSISTANT_AUDIT.reportGenerated,
          resourceType: AUDIT_RESOURCE.report,
          resourceId: job.reportPublicId,
          sourceIp: null,
          metadata: { ...composed.audit, async: true, jobId: job.publicId },
        },
        tx,
      );
      return 'handled' as const;
    });
    if (outcome === 'gone') {
      await this.deleteObject(organizationId, composed.objectKey);
      return 'handled';
    }
    if (outcome === 'handled') {
      this.metrics.reportJobs.inc({ outcome: 'succeeded' });
      this.metrics.reportJobSeconds.observe(
        (finishedAt.getTime() - job.createdAt.getTime()) / 1000,
      );
      this.logger.log({
        message: 'Assistant report job succeeded',
        jobId: job.publicId,
        reportId: job.reportPublicId,
      });
    }
    return outcome;
  }

  /** A terminal failure of the job and its report (with the ledger row), audited by metrics. */
  private async terminate(
    event: EventEnvelope<AssistantReportGenerateRequestedV1>,
    job: ReportJobWithRefs,
    code: string,
    outcome: 'failed' | 'expired',
  ): Promise<HandleOutcome> {
    const now = this.now();
    const moved = await this.runner.run(async (tx) => {
      if (!(await this.jobs.recordLedger(tx, REPORT_JOB_LEDGER, event.eventId))) return null;
      return this.jobs.fail(job.organizationId, job, code, now, tx);
    });
    if (moved === null) return 'duplicate';
    if (moved) {
      this.metrics.reportJobs.inc({ outcome });
      this.metrics.reportJobSeconds.observe((now.getTime() - job.createdAt.getTime()) / 1000);
      this.logger.warn({ message: 'Assistant report job failed', jobId: job.publicId, code });
    }
    return 'handled';
  }

  private async deleteObject(organizationId: bigint, key: string): Promise<void> {
    if (!isReportKeyOf(key, organizationId)) return;
    await this.store.delete(organizationId, key).catch((error: unknown) =>
      this.logger.warn({
        message: 'Assistant report object of a purged job left to the retention job',
        code: (error as { name?: unknown }).name ?? 'error',
      }),
    );
  }
}
