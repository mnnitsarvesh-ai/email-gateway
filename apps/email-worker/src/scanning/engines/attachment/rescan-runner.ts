import { sleep as defaultSleep, uuidv7, withTransactionDefaults } from '@email-gateway/common';
import { Prisma, type PrismaClient } from '@email-gateway/database';
import {
  EventTypes,
  messageRescanRequestedV1,
  type MessageRescanRequestedV1,
} from '@email-gateway/event-contracts';
import type { Logger } from '@email-gateway/logger';
import {
  isMessageState,
  type LifecycleMetrics,
  type MessageState,
  transitionMessage,
} from '@email-gateway/message-lifecycle';
import { errorFields, isTransientFailure } from '../../../mime-ingestion/error-fields';
import type { LeaderLock } from '../../deadline-sweeper';
import { SCAN_SERVICE } from '../../scan-repository';
import type { AttachmentMetrics } from './attachment-metrics';
import { DEFAULT_RESCAN_STATES } from './signature-watcher';

/** One cluster-wide executor of rescan jobs (A13). */
export const RESCAN_RUNNER_LOCK = 'scan:attachment-rescans';
/** States a rescan job may select (never `scanning`, delivery or terminal states, A13). */
export const RESCAN_SELECTABLE_STATES = [
  'scanned',
  'scan_failed',
  'quarantined',
  'held_for_review',
];

/**
 * `requestedBy` of a rescan the runner requests for a detector (signature-update) job: `system`
 * (added to the step 3.3 contract in step 4.2 WP5). An admin job (POST by a platform user) is
 * `user`. The lifecycle history carries the actor of both (role `scanner`, reason
 * `signature_rescan`).
 */
export const SYSTEM_REQUESTED_BY: MessageRescanRequestedV1['requestedBy'] = 'system';

export interface RescanJobRow {
  id: bigint;
  publicId: string;
  trigger: 'signature_update' | 'admin';
  status: string;
  organizationId: bigint | null;
  windowStart: Date;
  windowEnd: Date;
  states: unknown;
  maxMessages: number;
  cursorReceivedAt: Date | null;
  cursorMessageId: bigint | null;
  selectedCount: number;
  requestedCount: number;
  skippedCount: number;
}

export interface RescanCandidate {
  id: bigint;
  receivedAt: Date;
  organizationId: bigint;
  status: MessageState;
}

export interface RescanRunnerOptions {
  prisma: PrismaClient;
  locks: LeaderLock;
  metrics: AttachmentMetrics;
  lifecycleMetrics?: LifecycleMetrics;
  logger: Logger;
  /** ATTACHMENT_RESCAN_INTERVAL_MS. */
  intervalMs: number;
  /** ATTACHMENT_RESCAN_BATCH_SIZE. */
  batchSize: number;
  /** SCAN_DB_TIMEOUT_MS. */
  txTimeoutMs: number;
  lockName?: string;
  /** Restricts the runner to these jobs (integration tests on the shared writer). */
  jobIds?: readonly bigint[];
  now?: () => Date;
  sleep?: (ms: number, signal: AbortSignal) => Promise<boolean>;
}

export interface BatchReport {
  outcome: 'not_leader' | 'idle' | 'database_error' | 'batch' | 'completed' | 'cancelled';
  jobId: bigint | null;
  selected: number;
  requested: number;
  skipped: number;
}

const JOB_SELECT = {
  id: true,
  publicId: true,
  trigger: true,
  status: true,
  organizationId: true,
  windowStart: true,
  windowEnd: true,
  states: true,
  maxMessages: true,
  cursorReceivedAt: true,
  cursorMessageId: true,
  selectedCount: true,
  requestedCount: true,
  skippedCount: true,
} as const;

/** The job's states, restricted to the selectable ones (default when empty or invalid). */
export function jobStates(value: unknown): string[] {
  const parsed: unknown = typeof value === 'string' ? JSON.parse(value) : value;
  const list = Array.isArray(parsed)
    ? parsed.filter(
        (s): s is string => typeof s === 'string' && RESCAN_SELECTABLE_STATES.includes(s),
      )
    : [];
  return list.length > 0 ? [...new Set(list)] : [...DEFAULT_RESCAN_STATES];
}

/**
 * The rescan job executor (step 4.2 A13): while this process holds
 * `GET_LOCK('scan:attachment-rescans')`, every ATTACHMENT_RESCAN_INTERVAL_MS it continues the
 * oldest `running` job (or starts the oldest `pending` one) with one batch of at most
 * ATTACHMENT_RESCAN_BATCH_SIZE candidates selected **on the writer**: messages received in the
 * job's window, in its states, optionally of one organization, with at least one attachment,
 * whose latest round's attachment final is not `malicious` (a `scan_failed` message always
 * qualifies), after the job's `(received_at, id)` cursor. Per candidate one writer transaction:
 * E19 (`scanner`, `signature_rescan`, `sigrescan:<jobId>:<messageId>`, expected from the
 * candidate's state, new round) and the `mail.message.rescan_requested.v1` outbox row
 * (validated by its contract) — the existing rescan path: a new round on every engine queue.
 * Stale or invalid transitions are counted as skipped. Counts, cursor and status are updated
 * per batch (`completed` when nothing is left or `max_messages` is reached); a job cancelled by
 * the api is not continued (checked before each batch and on the batch update).
 */
export class RescanJobRunner {
  readonly lockName: string;
  private readonly logger: Logger;
  private readonly txPrisma: PrismaClient;
  private readonly now: () => Date;
  private readonly sleepFn: (ms: number, signal: AbortSignal) => Promise<boolean>;
  private abort = new AbortController();
  private loop: Promise<void> | undefined;

  constructor(private readonly options: RescanRunnerOptions) {
    this.lockName = options.lockName ?? RESCAN_RUNNER_LOCK;
    this.logger = options.logger.child({ component: 'attachment-rescan-runner' });
    this.txPrisma = withTransactionDefaults(options.prisma, { timeoutMs: options.txTimeoutMs });
    this.now = options.now ?? (() => new Date());
    this.sleepFn = options.sleep ?? defaultSleep;
  }

  get running(): boolean {
    return this.loop !== undefined;
  }

  start(): void {
    if (this.loop) return;
    this.abort = new AbortController();
    const signal = this.abort.signal;
    this.loop = (async () => {
      while (!signal.aborted) {
        await this.runBatch().catch((error: unknown) =>
          this.logger.warn(errorFields(error), 'rescan runner pass failed'),
        );
        if (!(await this.sleepFn(this.options.intervalMs, signal))) break;
      }
    })();
  }

  async stop(): Promise<void> {
    this.abort.abort();
    await this.loop;
    this.loop = undefined;
    await this.options.locks.release(this.lockName).catch(() => undefined);
  }

  /** One batch (also called directly by tests). */
  async runBatch(): Promise<BatchReport> {
    const report: BatchReport = {
      outcome: 'idle',
      jobId: null,
      selected: 0,
      requested: 0,
      skipped: 0,
    };
    let leader: boolean;
    try {
      leader = await this.options.locks.ensure(this.lockName);
    } catch {
      return { ...report, outcome: 'database_error' };
    }
    if (!leader) return { ...report, outcome: 'not_leader' };

    const job = await this.nextJob();
    if (!job) return report;
    report.jobId = job.id;
    const remaining = job.maxMessages - job.selectedCount;
    const limit = Math.min(this.options.batchSize, Math.max(0, remaining));
    const candidates = limit > 0 ? await this.candidates(job, limit) : [];
    const now = this.now();
    if (candidates.length === 0) {
      await this.finish(job, 'completed', now);
      this.logger.info(
        { jobId: job.publicId, requested: job.requestedCount, skipped: job.skippedCount },
        'rescan job completed',
      );
      return { ...report, outcome: 'completed' };
    }

    const trigger = job.trigger;
    for (const candidate of candidates) {
      const applied = await this.rescanOne(job, candidate).catch((error: unknown) => {
        if (isTransientFailure(error)) throw error;
        this.logger.warn(
          { jobId: job.publicId, messageId: candidate.id.toString(), ...errorFields(error) },
          'rescan of a candidate failed; skipped',
        );
        return false;
      });
      if (applied) report.requested += 1;
      else report.skipped += 1;
      this.options.metrics.rescanMessages.inc({
        result: applied ? 'requested' : 'skipped',
        trigger,
      });
    }
    report.selected = candidates.length;
    const last = candidates[candidates.length - 1]!;
    const selected = job.selectedCount + candidates.length;
    const done = selected >= job.maxMessages;
    const updated = await this.options.prisma.attachmentRescanJob.updateMany({
      where: { id: job.id, status: 'running' },
      data: {
        cursorReceivedAt: last.receivedAt,
        cursorMessageId: last.id,
        selectedCount: selected,
        requestedCount: job.requestedCount + report.requested,
        skippedCount: job.skippedCount + report.skipped,
        ...(done ? { status: 'completed', completedAt: now } : {}),
      },
    });
    if (updated.count === 0) return { ...report, outcome: 'cancelled' };
    return { ...report, outcome: done ? 'completed' : 'batch' };
  }

  /** The oldest running job, else the oldest pending one moved to `running`. */
  private async nextJob(): Promise<RescanJobRow | null> {
    const { prisma } = this.options;
    const scope = this.options.jobIds ? { id: { in: [...this.options.jobIds] } } : {};
    const running = await prisma.attachmentRescanJob.findFirst({
      where: { status: 'running', ...scope },
      orderBy: { createdAt: 'asc' },
      select: JOB_SELECT,
    });
    if (running) return running;
    const pending = await prisma.attachmentRescanJob.findFirst({
      where: { status: 'pending', ...scope },
      orderBy: [{ createdAt: 'asc' }, { id: 'asc' }],
      select: JOB_SELECT,
    });
    if (!pending) return null;
    const moved = await prisma.attachmentRescanJob.updateMany({
      where: { id: pending.id, status: 'pending' },
      data: { status: 'running', startedAt: this.now() },
    });
    if (moved.count === 0) return null;
    this.logger.info(
      { jobId: pending.publicId, trigger: pending.trigger, maxMessages: pending.maxMessages },
      'rescan job started',
    );
    return { ...(pending as RescanJobRow), status: 'running' };
  }

  private async finish(job: RescanJobRow, status: 'completed', now: Date): Promise<void> {
    await this.options.prisma.attachmentRescanJob.updateMany({
      where: { id: job.id, status: 'running' },
      data: { status, completedAt: now },
    });
  }

  /** The candidates of one batch, on the writer, in cursor order (A13). */
  async candidates(job: RescanJobRow, limit: number): Promise<RescanCandidate[]> {
    const states = jobStates(job.states);
    const cursor =
      job.cursorReceivedAt !== null && job.cursorMessageId !== null
        ? Prisma.sql`AND (m.received_at > ${job.cursorReceivedAt} OR (m.received_at = ${job.cursorReceivedAt} AND m.id > ${job.cursorMessageId}))`
        : Prisma.empty;
    const organization =
      job.organizationId !== null
        ? Prisma.sql`AND m.organization_id = ${job.organizationId}`
        : Prisma.empty;
    const rows = await this.options.prisma.$queryRaw<
      Array<{ id: bigint; received_at: Date; organization_id: bigint; status: string }>
    >`
      SELECT m.id, m.received_at, m.organization_id, m.status
      FROM email_messages m
      WHERE m.received_at >= ${job.windowStart} AND m.received_at <= ${job.windowEnd}
        AND m.status IN (${Prisma.join(states)})
        ${organization}
        ${cursor}
        AND EXISTS (
          SELECT 1 FROM email_attachments a
          WHERE a.message_id = m.id AND a.received_at = m.received_at
            AND a.organization_id = m.organization_id
        )
        AND (
          m.status = 'scan_failed'
          OR NOT EXISTS (
            SELECT 1 FROM email_scans s
            JOIN scan_engine_results r ON r.scan_id = s.id AND r.received_at = s.received_at
            WHERE s.message_id = m.id AND s.received_at = m.received_at
              AND s.lifecycle_round = m.lifecycle_round
              AND r.engine = 'attachment' AND r.is_final = 1 AND r.outcome = 'malicious'
          )
        )
      ORDER BY m.received_at, m.id
      LIMIT ${limit}`;
    return rows.flatMap((r) =>
      isMessageState(r.status)
        ? [
            {
              id: BigInt(r.id),
              receivedAt: r.received_at,
              organizationId: BigInt(r.organization_id),
              status: r.status,
            },
          ]
        : [],
    );
  }

  /** E19 + `rescan_requested.v1` in one writer transaction; true when the transition applied. */
  private rescanOne(job: RescanJobRow, candidate: RescanCandidate): Promise<boolean> {
    return this.txPrisma.$transaction(async (tx) => {
      const ref = {
        id: candidate.id,
        receivedAt: candidate.receivedAt,
        organizationId: candidate.organizationId,
      };
      const correlationId = `rescan-job:${job.publicId}`;
      const outcome = await transitionMessage(
        tx,
        {
          message: ref,
          to: 'scanning',
          reason: 'signature_rescan',
          actor: { role: 'scanner', service: SCAN_SERVICE, type: 'system' },
          transitionKey: `sigrescan:${job.id.toString()}:${candidate.id.toString()}`,
          correlationId,
          expectedFrom: [candidate.status],
        },
        this.options.lifecycleMetrics ? { metrics: this.options.lifecycleMetrics } : {},
      );
      if (outcome.result !== 'applied') return false;
      const now = this.now();
      const payload = messageRescanRequestedV1.parse({
        messageId: candidate.id.toString(),
        receivedAt: candidate.receivedAt.toISOString(),
        direction: outcome.snapshot.direction,
        emlS3Key: outcome.snapshot.emlObjectKey,
        lifecycleRound: outcome.round,
        scanKind: 'rescan',
        requestedAt: now.toISOString(),
        requestedBy: job.trigger === 'admin' ? 'user' : SYSTEM_REQUESTED_BY,
      });
      await tx.messageOutbox.create({
        data: {
          eventId: uuidv7(now.getTime()),
          organizationId: candidate.organizationId,
          eventType: EventTypes.MessageRescanRequested,
          aggregateType: 'message',
          aggregateId: candidate.id.toString(),
          correlationId,
          payload,
        },
        select: { id: true },
      });
      return true;
    });
  }
}
