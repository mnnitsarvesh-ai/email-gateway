import {
  Inject,
  Injectable,
  Logger,
  type OnApplicationBootstrap,
  type OnModuleDestroy,
} from '@nestjs/common';
import { PRECONDITION_MAX_READS } from '@email-gateway/assistant';
import type { Prisma } from '@email-gateway/database';
import { API_CONFIG } from '../../../api-config.token';
import { AuditService, SYSTEM_ACTOR } from '../../../audit/audit.service';
import { TransactionRunner } from '../../../database/transaction-runner';
import { KeyValueStore } from '../../../kv/key-value-store';
import { purgeInBatches } from '../../auth/services/session-purge.service';
import {
  ASSISTANT_AUDIT,
  AUDIT_RESOURCE,
  type AssistantConfig,
  assistantKeys,
  CONFIRMATION_EXECUTING_GRACE_MS,
  REPORT_DELIVERY_TIMEOUT_MS,
  REPORT_OBJECT_BATCH,
  REPORT_PENDING_MAX_AGE_MS,
  REPORT_ROW_CODES,
  RETENTION_CONVERSATION_BATCH,
  RETENTION_DELETE_BATCH,
  RETENTION_INTERVAL_MS,
  RETENTION_LOCK_SECONDS,
  TURN_ABANDON_GRACE_MS,
} from '../assistant.constants';
import { CONFIRMATION_ROW_CODES, TURN_FAILURE_CODES } from '../assistant.errors';
import {
  ConfirmationsRepository,
  type StaleExecutingCutoff,
  type SweptConfirmation,
} from '../repositories/confirmations.repository';
import { ConversationsRepository } from '../repositories/conversations.repository';
import { ExecutionsRepository } from '../repositories/executions.repository';
import { ReportDeliveriesRepository } from '../repositories/report-deliveries.repository';
import { ReportsRepository } from '../repositories/reports.repository';
import { UsageRepository } from '../repositories/usage.repository';
import { AssistantMetrics } from './assistant-metrics';
import { isReportKeyOf, ReportObjectStore } from './reports/report-object-store';
import { ReportsService } from './reports/reports.service';

export interface RetentionResult {
  /** Conversations whose content was purged at `purge_after`. */
  contentPurged: number;
  /** Rows hard-deleted after ASSISTANT_EXECUTION_RETENTION_DAYS. */
  executions: number;
  messages: number;
  turns: number;
  conversations: number;
  usage: number;
  /** Running turns past their deadline marked `failed` (`assistant_turn_abandoned`). */
  abandoned: number;
  /** Pending confirmations past `expires_at` marked `expired` (step AI-2 D7). */
  confirmationsExpired: number;
  /** Stale `executing` confirmations marked `failed` (outcome unknown, D7). */
  confirmationsOutcomeUnknown: number;
  /** Step AI-R D7: objects of purged reports deleted from the mail bucket. */
  reportObjects: number;
  /** Step AI-R D7: `pending` reports older than 1 hour marked `failed` (object deleted). */
  reportsAbandoned: number;
  /** Step AI-R D7: `queued` deliveries older than 25 hours marked `failed`. */
  deliveriesTimedOut: number;
}

const DAY_MS = 86_400_000;

/**
 * The assistant's background jobs (design D7, D12; the `SessionPurgeService` pattern): every
 * 10 minutes, one api replica at a time (Redis lock `as:jobs:lock`), unless
 * ASSISTANT_BACKGROUND_JOBS_ENABLED=false:
 *
 * - content purge: conversations past `purge_after` lose their title, message texts,
 *   transcripts, cards, refs and cursors (metadata stays), in batches;
 * - hard delete of executions, messages, turns, conversations and usage rows older than
 *   ASSISTANT_EXECUTION_RETENTION_DAYS, in batches;
 * - stale-turn sweeper: a turn still `running` past its deadline (a crashed api) becomes
 *   `failed` with `assistant_turn_abandoned` and its conversation lock is released;
 * - confirmations (step AI-2 D7): `pending` past `expires_at` → `expired`; `executing` whose
 *   write started longer ago than ASSISTANT_TOOL_TIMEOUT_MS + 60 s, or (no write started) whose
 *   precondition re-read began longer ago than (25 reads + 1) × ASSISTANT_TOOL_TIMEOUT_MS + 60 s
 *   (a crashed api) → `failed` with `assistant_confirmation_outcome_unknown`, never re-executed;
 *   each audited (system actor). A confirm request still running loses its write claim (nothing
 *   is sent) or, if its write was already sent, replaces the outcome with the real one.
 *   Their content is purged with the conversation's; hard deletes follow the executions (FK
 *   cascade).
 * - reports (step AI-R D7): the content purge moves a conversation's reports to `purged` (its
 *   deliveries lose the address, `queued` ones fail) in the purge transaction; after the commit
 *   the objects of purged reports are deleted in batches (`object_deleted_at`, key cleared); a
 *   `pending` report older than 1 hour (a crash between the put and the commit) loses its object
 *   and becomes `failed` (`assistant_report_abandoned`); a `queued` delivery older than 25 hours
 *   (beyond the notification queue's 24 h retry age) becomes `failed`
 *   (`assistant_report_email_timeout`). The hard delete skips a conversation whose report still
 *   has an object.
 *
 * Organization deletion purges everything separately (`AssistantTenantDataRepository`).
 */
@Injectable()
export class AssistantRetentionService implements OnApplicationBootstrap, OnModuleDestroy {
  private readonly logger = new Logger(AssistantRetentionService.name);
  private timer: NodeJS.Timeout | undefined;
  private running: Promise<unknown> | undefined;

  constructor(
    @Inject(API_CONFIG) private readonly config: AssistantConfig,
    private readonly kv: KeyValueStore,
    private readonly conversations: ConversationsRepository,
    private readonly executions: ExecutionsRepository,
    private readonly usage: UsageRepository,
    private readonly runner: TransactionRunner,
    private readonly metrics: AssistantMetrics,
    private readonly confirmations: ConfirmationsRepository,
    private readonly audit: AuditService,
    private readonly reports: ReportsRepository,
    private readonly deliveries: ReportDeliveriesRepository,
    private readonly store: ReportObjectStore,
    private readonly reportObjects: ReportsService,
  ) {}

  onApplicationBootstrap(): void {
    if (!this.config.ASSISTANT_BACKGROUND_JOBS_ENABLED) return;
    this.timer = setInterval(() => this.tick(), RETENTION_INTERVAL_MS);
    this.timer.unref();
  }

  async onModuleDestroy(): Promise<void> {
    if (this.timer) clearInterval(this.timer);
    this.timer = undefined;
    await this.running;
  }

  /** True when a timer is scheduled (tests). */
  get scheduled(): boolean {
    return this.timer !== undefined;
  }

  private tick(): void {
    this.running = this.runOnce().catch((err: unknown) =>
      this.logger.error({ message: 'Assistant retention run failed', err }),
    );
  }

  /** One run; null when another replica holds the lock. */
  async runOnce(now: Date = new Date()): Promise<RetentionResult | null> {
    const acquired = await this.kv.setIfAbsent(
      assistantKeys.jobsLock,
      now.toISOString(),
      RETENTION_LOCK_SECONDS,
    );
    if (!acquired) return null;
    const result: RetentionResult = {
      contentPurged: 0,
      executions: 0,
      messages: 0,
      turns: 0,
      conversations: 0,
      usage: 0,
      abandoned: 0,
      confirmationsExpired: 0,
      confirmationsOutcomeUnknown: 0,
      reportObjects: 0,
      reportsAbandoned: 0,
      deliveriesTimedOut: 0,
    };
    result.abandoned = await this.sweepStaleTurns(now);
    result.confirmationsExpired = await this.expireConfirmations(now);
    result.confirmationsOutcomeUnknown = await this.failStaleConfirmations(now);
    result.contentPurged = await this.purgeContent(now);
    result.reportObjects = await this.deletePurgedReportObjects(now);
    result.reportsAbandoned = await this.sweepPendingReports(now);
    result.deliveriesTimedOut = await this.sweepQueuedDeliveries(now);
    const before = new Date(
      now.getTime() - this.config.ASSISTANT_EXECUTION_RETENTION_DAYS * DAY_MS,
    );
    result.executions = await purgeInBatches(
      (n) => this.executions.deleteBefore(before, n),
      RETENTION_DELETE_BATCH,
    );
    result.messages = await purgeInBatches(
      (n) => this.conversations.deleteMessagesBefore(before, n),
      RETENTION_DELETE_BATCH,
    );
    result.turns = await purgeInBatches(
      (n) => this.conversations.deleteTurnsBefore(before, n),
      RETENTION_DELETE_BATCH,
    );
    result.conversations = await purgeInBatches(
      (n) => this.conversations.deleteConversationsBefore(before, n),
      RETENTION_DELETE_BATCH,
    );
    result.usage = await purgeInBatches(
      (n) => this.usage.deleteBefore(before, n),
      RETENTION_DELETE_BATCH,
    );
    this.logger.log({ message: 'Assistant retention run completed', ...result });
    return result;
  }

  /** Content purge at `purge_after`, one transaction per batch of conversations. */
  async purgeContent(now: Date, batch = RETENTION_CONVERSATION_BATCH): Promise<number> {
    let total = 0;
    for (let i = 0; i < 10_000; i += 1) {
      const due = await this.conversations.dueForContentPurge(now, batch);
      if (due.length === 0) break;
      const byOrganization = new Map<bigint, bigint[]>();
      for (const row of due) {
        const ids = byOrganization.get(row.organizationId) ?? [];
        ids.push(row.id);
        byOrganization.set(row.organizationId, ids);
      }
      total += await this.runner.run(async (tx) => {
        let purged = 0;
        for (const [organizationId, ids] of byOrganization) {
          // Re-checked under a row lock: a turn started since the read keeps its content.
          const still = await this.conversations.lockDueForContentPurge(
            organizationId,
            ids,
            now,
            tx,
          );
          await this.conversations.purgeContent(organizationId, still, now, tx);
          purged += still.length;
        }
        return purged;
      });
      if (due.length < batch) break;
    }
    return total;
  }

  /**
   * D7: deletes the objects of `purged` reports (batches of 100; a missing object counts as
   * deleted; a key outside the organization's prefix is never requested and only cleared). An
   * S3 error leaves the row for the next run.
   */
  async deletePurgedReportObjects(now: Date, batch = REPORT_OBJECT_BATCH): Promise<number> {
    let total = 0;
    for (let i = 0; i < 100; i += 1) {
      const rows = await this.reports.objectPurgeBatch(batch);
      if (rows.length === 0) break;
      let progressed = 0;
      for (const row of rows) {
        if (await this.reportObjects.deleteObject(row, now)) {
          total += 1;
          progressed += 1;
        }
      }
      if (rows.length < batch || progressed === 0) break;
    }
    return total;
  }

  /** D7: `pending` reports older than 1 hour → object deleted, row `failed` (abandoned). */
  async sweepPendingReports(now: Date, batch = REPORT_OBJECT_BATCH): Promise<number> {
    const before = new Date(now.getTime() - REPORT_PENDING_MAX_AGE_MS);
    let total = 0;
    for (const row of await this.reports.pendingBefore(before, batch)) {
      try {
        if (row.objectKey !== null && isReportKeyOf(row.objectKey, row.organizationId)) {
          await this.store.delete(row.organizationId, row.objectKey);
        }
      } catch (err) {
        this.logger.warn({
          message: 'Assistant report object delete failed',
          reportRowId: row.id.toString(),
          code: (err as { name?: unknown }).name ?? 'error',
        });
        continue;
      }
      if (await this.reports.abandon(row.organizationId, row.id, now)) total += 1;
    }
    return total;
  }

  /** D7: `queued` deliveries older than 25 hours → `failed` (`assistant_report_email_timeout`). */
  sweepQueuedDeliveries(now: Date, batch = RETENTION_DELETE_BATCH): Promise<number> {
    const before = new Date(now.getTime() - REPORT_DELIVERY_TIMEOUT_MS);
    return purgeInBatches(
      (n) => this.deliveries.failQueuedBefore(before, REPORT_ROW_CODES.emailTimeout, n),
      batch,
    );
  }

  /** Pending confirmations past `expires_at` → `expired` (one batch per run, audited). */
  async expireConfirmations(now: Date, batch = RETENTION_DELETE_BATCH): Promise<number> {
    let total = 0;
    for (const row of await this.confirmations.dueToExpire(now, batch)) {
      const moved = await this.runner.run(async (tx) => {
        if (!(await this.confirmations.expireById(row.id, now, tx))) return false;
        await this.auditSwept(row, ASSISTANT_AUDIT.confirmationExpired, 'expired', null, tx);
        return true;
      });
      if (moved) {
        total += 1;
        this.metrics.confirmations.inc({ risk: row.risk, outcome: 'expired' });
      }
    }
    return total;
  }

  /** The cutoffs of the outcome-unknown sweep at `now` (D7, step AI-2 review). */
  staleExecutingCutoff(now: Date): StaleExecutingCutoff {
    const timeout = this.config.ASSISTANT_TOOL_TIMEOUT_MS;
    return {
      decidedBefore: new Date(
        now.getTime() - (PRECONDITION_MAX_READS + 1) * timeout - CONFIRMATION_EXECUTING_GRACE_MS,
      ),
      startedBefore: new Date(now.getTime() - timeout - CONFIRMATION_EXECUTING_GRACE_MS),
    };
  }

  /**
   * `executing` confirmations of a crashed api (`staleExecutingCutoff`): `failed` with
   * `assistant_confirmation_outcome_unknown`, never re-executed.
   */
  async failStaleConfirmations(now: Date, batch = RETENTION_DELETE_BATCH): Promise<number> {
    const cutoff = this.staleExecutingCutoff(now);
    const code = CONFIRMATION_ROW_CODES.outcomeUnknown;
    let total = 0;
    for (const row of await this.confirmations.staleExecuting(cutoff, batch)) {
      const moved = await this.runner.run(async (tx) => {
        if (!(await this.confirmations.failStaleById(row.id, cutoff, code, tx))) return false;
        await this.auditSwept(row, ASSISTANT_AUDIT.confirmationFailed, 'failed', code, tx);
        return true;
      });
      if (moved) {
        total += 1;
        this.metrics.confirmations.inc({ risk: row.risk, outcome: 'outcome_unknown' });
        this.logger.warn({
          message: 'Assistant confirmation outcome unknown',
          confirmationId: row.publicId,
          code,
        });
      }
    }
    return total;
  }

  private auditSwept(
    row: SweptConfirmation,
    action: string,
    status: string,
    error: string | null,
    tx: Prisma.TransactionClient,
  ): Promise<void> {
    return this.audit.record(
      {
        organizationId: row.organizationId,
        actor: SYSTEM_ACTOR,
        action,
        resourceType: AUDIT_RESOURCE.confirmation,
        resourceId: row.publicId,
        metadata: {
          conversationId: row.conversationPublicId,
          executionId: row.executionPublicId,
          tool: row.toolName,
          operationId: row.operationId,
          risk: row.risk,
          requiresReauth: row.requiresReauth,
          status,
          error,
        },
      },
      tx,
    );
  }

  /** Abandoned turns (D7): `running` past the deadline plus a grace. */
  async sweepStaleTurns(now: Date): Promise<number> {
    const before = new Date(
      now.getTime() - this.config.ASSISTANT_TURN_DEADLINE_MS - TURN_ABANDON_GRACE_MS,
    );
    let total = 0;
    for (let i = 0; i < 100; i += 1) {
      const stale = await this.conversations.staleRunningTurns(
        before,
        RETENTION_CONVERSATION_BATCH,
      );
      if (stale.length === 0) break;
      for (const turn of stale) {
        if (await this.conversations.abandonTurn(turn.id, TURN_FAILURE_CODES.abandoned, now)) {
          total += 1;
          this.metrics.turns.inc({
            provider: this.config.ASSISTANT_PROVIDER,
            model: 'unknown',
            outcome: 'abandoned',
          });
        }
        // The lock holds the turn's public id: only that turn's lock is released.
        const key = assistantKeys.turnLock(turn.conversationPublicId);
        if ((await this.kv.get(key)) === turn.publicId) await this.kv.del(key);
      }
      if (stale.length < RETENTION_CONVERSATION_BATCH) break;
    }
    return total;
  }
}
