import { Prisma, type PrismaClient } from '@email-gateway/database';
import type { Logger } from '@email-gateway/logger';
import { reconcileSignalKey, recordDeliverySignal } from '@email-gateway/mail-routing';
import type { DeliveryMetrics } from '../metrics/delivery-metrics';
import { SOURCE_SERVICE } from '../planning/delivery-planner';
import { type ActiveDelivery, ReinjectionStore } from '../reinjection/reinjection-store';
import { isUniqueViolation } from '../shared/db';

export interface ReconcilerConfig {
  DELIVERY_RECONCILE_INTERVAL_MS: number;
  DELIVERY_REINJECT_LEASE_SECONDS: number;
  DELIVERY_REINJECT_MAX_AGE_SECONDS: number;
  DELIVERY_STATUS_STALE_AFTER_SECONDS: number;
  DELIVERY_RECONCILE_UNCONFIRMED_SECONDS: number;
}

export interface ReconcilerOptions {
  /** `stream_cursors` name prefix of the log sources (default `postfix-log:`). */
  logSourcePrefix?: string;
  /** Restricts the scans to some organizations (integration tests on a shared database). */
  organizationIds?: readonly bigint[];
}

export interface ReconcileReport {
  /** Expired leases resolved to `queued` from delivery-log evidence of the bound queue file. */
  leaseQueued: number;
  /** Expired leases released to `pending` (the log passed the session without evidence). */
  leaseReleased: number;
  /** Expired leases still waiting for the delivery log. */
  leaseWaiting: number;
  /** Expired, ambiguous leases past DELIVERY_REINJECT_MAX_AGE_SECONDS: recipients `unknown`. */
  leaseUnknown: number;
  /** Recipients of queued reinjections never confirmed by the log, moved to a new reinjection. */
  unconfirmedReplanned: number;
  /** Queued/deferred (or never-confirmed) deliveries without a signal: `unknown`. */
  staleUnknown: number;
}

const BATCH = 200;
/** Delivery statuses that still wait for the worker's hop or for Postfix's first record. */
const WAITING = ['pending', 'in_progress'] as const;

interface ExpiredRow {
  id: bigint;
  receivedAt: Date;
  attempts: number;
  queueId: string | null;
  startedAt: Date | null;
  createdAt: Date;
  messageId: bigint;
  approvalEventId: string;
  direction: string;
}

/**
 * Repairs what no signal will ever repair (step 2.3 R12, review fixes), every
 * DELIVERY_RECONCILE_INTERVAL_MS:
 *
 * - **Expired lease** (`in_progress`, `lease_expires_at < now`: a worker crashed, or the session
 *   ended ambiguously). The `client=` binding of the token is a correlation only (smtpd logs it
 *   at the first accepted RCPT; Postfix discards the file if the session ends before the final
 *   dot), so it never queues by itself:
 *   1. qmgr `queue active` for the bound queue id already moved the row to `queued` (status
 *      tailer); a delivery-log line naming one of the row's recipients under the bound queue id
 *      is the same evidence here → `queued` (never re-sent); the recipients without a line are
 *      left to the unconfirmed scan below;
 *   2. else, once every log source has passed `started_at + lease` (`stream_cursors.
 *      last_event_at`, which the tailers also advance while idle at the end of the file) →
 *      `pending` with the stale binding cleared (Postfix never committed it: re-sent);
 *   3. else, once the approval is older than DELIVERY_REINJECT_MAX_AGE_SECONDS (a log that never
 *      advances) → the row fails and its waiting recipients become `unknown`
 *      (`status_signal_missing`): never a guessed outcome, never re-sent;
 *   4. else wait. With no log source at all (the log role disabled everywhere, not
 *      recommended) the row goes back to `pending` after the lease, accepting a possible
 *      duplicate delivery.
 * - **Unconfirmed recipients** of a `queued` reinjection (`pending`/`in_progress` after the
 *   worker crashed between the 250 and its commit, when qmgr's `nrcpt` did not cover the group:
 *   some recipients were refused or deferred at RCPT). Once DELIVERY_RECONCILE_UNCONFIRMED_SECONDS
 *   have passed since the file became active (and the log has passed that time too): if other
 *   recipients of the row are confirmed, the unconfirmed ones move to a new reinjection
 *   (`deferred`, re-sent: Postfix logs every accepted recipient's first attempt, so these were
 *   not in the file); if none is confirmed, they become `unknown` after the stale window.
 * - **Stale tracking**: `queued`/`deferred` deliveries without a signal for
 *   `DELIVERY_STATUS_STALE_AFTER_SECONDS` → `unknown`, reason `status_signal_missing` (error log
 *   + metric). Never guessed as delivered or bounced.
 */
export class DeliveryReconciler {
  private readonly logger: Logger;
  private readonly store: ReinjectionStore;
  private timer: NodeJS.Timeout | undefined;
  private running: Promise<void> | undefined;
  private stopped = false;

  constructor(
    private readonly prisma: PrismaClient,
    private readonly metrics: DeliveryMetrics,
    private readonly config: ReconcilerConfig,
    logger: Logger,
    private readonly recorderTimeoutMs: number,
    private readonly now: () => Date = () => new Date(),
    private readonly options: ReconcilerOptions = {},
  ) {
    this.logger = logger.child({ component: 'delivery-reconciler' });
    this.store = new ReinjectionStore(prisma);
  }

  start(): void {
    this.stopped = false;
    this.schedule(this.config.DELIVERY_RECONCILE_INTERVAL_MS);
  }

  async stop(): Promise<void> {
    this.stopped = true;
    if (this.timer) clearTimeout(this.timer);
    await this.running;
  }

  async reconcileOnce(): Promise<ReconcileReport> {
    const report: ReconcileReport = {
      leaseQueued: 0,
      leaseReleased: 0,
      leaseWaiting: 0,
      leaseUnknown: 0,
      unconfirmedReplanned: 0,
      staleUnknown: 0,
    };
    const log = await this.logHorizon();
    await this.expiredLeases(report, log);
    await this.unconfirmedRecipients(report, log);
    await this.staleDeliveries(report);
    return report;
  }

  /** The time every log source has read up to; null without any source (log role off). */
  private async logHorizon(): Promise<{ sources: number; horizon: Date | null }> {
    const cursors = await this.prisma.streamCursor.findMany({
      where: { name: { startsWith: this.options.logSourcePrefix ?? 'postfix-log:' } },
      select: { lastEventAt: true },
    });
    if (cursors.length === 0) return { sources: 0, horizon: null };
    let horizon: Date | null = null;
    for (const cursor of cursors) {
      if (cursor.lastEventAt === null) return { sources: cursors.length, horizon: null };
      if (horizon === null || cursor.lastEventAt < horizon) horizon = cursor.lastEventAt;
    }
    return { sources: cursors.length, horizon };
  }

  private async expiredLeases(
    report: ReconcileReport,
    { sources, horizon }: { sources: number; horizon: Date | null },
  ): Promise<void> {
    const now = this.now();
    const rows: ExpiredRow[] = await this.prisma.deliveryReinjection.findMany({
      where: { status: 'in_progress', leaseExpiresAt: { lt: now }, ...this.scope() },
      select: {
        id: true,
        receivedAt: true,
        attempts: true,
        queueId: true,
        startedAt: true,
        createdAt: true,
        messageId: true,
        approvalEventId: true,
        direction: true,
      },
      take: BATCH,
    });
    const leaseMs = this.config.DELIVERY_REINJECT_LEASE_SECONDS * 1000;
    for (const row of rows) {
      const guard = {
        id: row.id,
        receivedAt: row.receivedAt,
        status: 'in_progress' as const,
        attempts: row.attempts,
        leaseExpiresAt: { lt: now },
      };
      const ids = { reinjectionId: row.id.toString() };

      // 1. Evidence that the bound queue file exists: a log line for one of its recipients.
      if (row.queueId !== null && (await this.fileConfirmed(row, row.queueId))) {
        const { count } = await this.prisma.deliveryReinjection.updateMany({
          where: { ...guard, queueId: row.queueId },
          data: { status: 'queued', queuedAt: now, leaseExpiresAt: null },
        });
        if (count === 1) {
          report.leaseQueued += 1;
          this.metrics.reconcilerActions.inc({ action: 'lease_queued' });
          this.logger.info(ids, 'expired lease resolved from the delivery log: queued');
        }
        continue;
      }

      // 2. The log passed the session without evidence: Postfix never committed a file.
      const startedAt = row.startedAt ?? now;
      const logPassed = horizon !== null && horizon.getTime() >= startedAt.getTime() + leaseMs;
      if (sources === 0 || logPassed) {
        if (await this.release(row, guard, now)) {
          report.leaseReleased += 1;
          this.metrics.reconcilerActions.inc({ action: 'lease_released' });
          if (sources === 0) {
            this.logger.warn(
              ids,
              'expired lease released without a log source (possible duplicate delivery)',
            );
          } else {
            this.logger.info(
              ids,
              'expired lease released: the delivery log passed the session without evidence',
            );
          }
        }
        continue;
      }

      // 3. A log that never advances: bounded by the reinjection max age.
      const approvalAt = await this.approvalTime(row);
      if (
        now.getTime() - approvalAt.getTime() >=
        this.config.DELIVERY_REINJECT_MAX_AGE_SECONDS * 1000
      ) {
        const unknown = await this.expireAmbiguous(row, guard);
        if (unknown !== null) {
          report.leaseUnknown += 1;
          this.metrics.reconcilerActions.inc({ action: 'lease_unknown' });
          this.logger.error(
            { ...ids, deliveries: unknown },
            'ambiguous reinjection past the max age without log evidence; deliveries unknown',
          );
        }
        continue;
      }

      report.leaseWaiting += 1;
      this.metrics.reconcilerActions.inc({ action: 'lease_waiting' });
    }
  }

  /** True when a delivery of the row is tied to `queueId` (only log lines and 250s do that). */
  private async fileConfirmed(row: ExpiredRow, queueId: string): Promise<boolean> {
    const confirmed = await this.prisma.emailDelivery.findFirst({
      where: { reinjectionId: row.id, receivedAt: row.receivedAt, outboundQueueId: queueId },
      select: { id: true },
    });
    return confirmed !== null;
  }

  /** Back to `pending` now, the stale binding cleared (a new session binds its own queue id). */
  private async release(
    row: ExpiredRow,
    guard: Prisma.DeliveryReinjectionWhereInput,
    now: Date,
  ): Promise<boolean> {
    return this.prisma.$transaction(
      async (tx) => {
        const { count } = await tx.deliveryReinjection.updateMany({
          where: guard,
          data: {
            status: 'pending',
            nextAttemptAt: now,
            leaseExpiresAt: null,
            queueId: null,
            lastErrorClass: 'reinjection_error',
            lastError: 'lease expired without evidence that postfix-outbound queued the message',
          },
        });
        if (count === 1 && row.queueId !== null) {
          await tx.emailDelivery.updateMany({
            where: {
              reinjectionId: row.id,
              receivedAt: row.receivedAt,
              outboundQueueId: row.queueId,
              status: { in: ['pending', 'in_progress', 'deferred'] },
            },
            data: { outboundQueueId: null },
          });
        }
        return count === 1;
      },
      { timeout: this.recorderTimeoutMs, maxWait: this.recorderTimeoutMs },
    );
  }

  private async approvalTime(row: ExpiredRow): Promise<Date> {
    const oldest = await this.prisma.deliveryReinjection.findFirst({
      where: {
        messageId: row.messageId,
        receivedAt: row.receivedAt,
        approvalEventId: row.approvalEventId,
      },
      orderBy: { createdAt: 'asc' },
      select: { createdAt: true },
    });
    return oldest?.createdAt ?? row.createdAt;
  }

  /**
   * The row fails (never re-sent) and its waiting recipients become `unknown`; a late real
   * signal can still make them terminal. Null when the row changed meanwhile.
   */
  private async expireAmbiguous(
    row: ExpiredRow,
    guard: Prisma.DeliveryReinjectionWhereInput,
  ): Promise<number | null> {
    const { count } = await this.prisma.deliveryReinjection.updateMany({
      where: guard,
      data: {
        status: 'failed',
        leaseExpiresAt: null,
        lastErrorClass: 'reinjection_error',
        lastError: 'ambiguous session without log evidence before the max age',
      },
    });
    if (count !== 1) return null;
    const deliveries = await this.prisma.emailDelivery.findMany({
      where: {
        reinjectionId: row.id,
        receivedAt: row.receivedAt,
        status: { in: [...WAITING, 'deferred'] },
      },
      select: { id: true, receivedAt: true },
    });
    let applied = 0;
    for (const delivery of deliveries) {
      const result = await this.unknown(delivery, row.direction, 'lease_ambiguous_max_age');
      if (result === 'applied') applied += 1;
    }
    return applied;
  }

  /**
   * Recipients of `queued` reinjections that never got a delivery-log line (see the class
   * comment), once DELIVERY_RECONCILE_UNCONFIRMED_SECONDS passed since the row was queued and the
   * delivery log has passed that time.
   */
  private async unconfirmedRecipients(
    report: ReconcileReport,
    { sources, horizon }: { sources: number; horizon: Date | null },
  ): Promise<void> {
    const now = this.now();
    const boundMs = this.config.DELIVERY_RECONCILE_UNCONFIRMED_SECONDS * 1000;
    const before = new Date(now.getTime() - boundMs);
    const organizations = this.options.organizationIds ?? [];
    const scope =
      organizations.length > 0
        ? Prisma.sql`AND d.organization_id IN (${Prisma.join([...organizations])})`
        : Prisma.empty;
    const rows = await this.prisma.$queryRaw<
      { reinjection_id: bigint; received_at: Date; queued_at: Date }[]
    >`
      SELECT DISTINCT d.reinjection_id, d.received_at, r.queued_at
      FROM email_deliveries d
      JOIN delivery_reinjections r ON r.id = d.reinjection_id AND r.received_at = d.received_at
      WHERE d.status IN ('pending', 'in_progress')
        AND r.status = 'queued'
        AND r.queued_at < ${before}
        ${scope}
      LIMIT ${BATCH}`;
    const staleBefore = now.getTime() - this.config.DELIVERY_STATUS_STALE_AFTER_SECONDS * 1000;
    for (const row of rows) {
      // The log must have passed the bound too, so a lagging tailer is never mistaken for
      // Postfix not having the recipient.
      if (
        sources > 0 &&
        (horizon === null || horizon.getTime() < row.queued_at.getTime() + boundMs)
      ) {
        continue;
      }
      const result = await this.resolveUnconfirmed(
        BigInt(row.reinjection_id),
        row.received_at,
        row.queued_at.getTime() < staleBefore,
      );
      report.unconfirmedReplanned += result.replanned;
      report.staleUnknown += result.unknown;
    }
  }

  private async resolveUnconfirmed(
    reinjectionId: bigint,
    receivedAt: Date,
    pastStaleWindow: boolean,
  ): Promise<{ replanned: number; unknown: number }> {
    const row = await this.prisma.deliveryReinjection.findUnique({
      where: { id_receivedAt: { id: reinjectionId, receivedAt } },
    });
    if (!row || row.status !== 'queued') return { replanned: 0, unknown: 0 };
    const ids = { reinjectionId: row.id.toString(), messageId: row.messageId.toString() };
    const members = await this.prisma.emailDelivery.findMany({
      where: { reinjectionId: row.id, receivedAt: row.receivedAt },
      select: { id: true, receivedAt: true, recipientId: true, status: true },
    });
    const waiting = members.filter((d) => (WAITING as readonly string[]).includes(d.status));
    if (waiting.length === 0) return { replanned: 0, unknown: 0 };
    const confirmed = members.length - waiting.length;

    if (confirmed === 0) {
      // Postfix holds the file (qmgr took it) but logged nobody: never re-sent (it may still
      // deliver); after the stale window, unknown.
      if (!pastStaleWindow) return { replanned: 0, unknown: 0 };
      let unknown = 0;
      for (const delivery of waiting) {
        if ((await this.unknown(delivery, row.direction, 'unconfirmed_stale')) === 'applied') {
          unknown += 1;
        }
      }
      if (unknown > 0) {
        this.metrics.reconcilerActions.inc({ action: 'stale_unknown' }, unknown);
        this.logger.error(
          { ...ids, deliveries: unknown },
          'queued recipients never logged; unknown',
        );
      }
      return { replanned: 0, unknown };
    }

    const recipients = await this.prisma.emailRecipient.findMany({
      where: { id: { in: waiting.map((d) => d.recipientId) }, receivedAt: row.receivedAt },
      select: { id: true, rcptSeq: true, address: true },
    });
    const byId = new Map(recipients.map((r) => [r.id, r]));
    const moved: ActiveDelivery[] = waiting.flatMap((d) => {
      const recipient = byId.get(d.recipientId);
      return recipient ? [{ ...d, rcptSeq: recipient.rcptSeq, address: recipient.address }] : [];
    });
    if (moved.length === 0) return { replanned: 0, unknown: 0 };
    const now = this.now();
    try {
      const replanned = await this.prisma.$transaction(
        async (tx) => {
          const locked = await this.store.lockForResult(tx, row);
          if (locked?.status !== 'queued') return 0;
          // Re-read under the lock: only recipients still waiting move.
          const still = await tx.emailDelivery.findMany({
            where: {
              OR: moved.map((d) => ({ id: d.id, receivedAt: d.receivedAt })),
              reinjectionId: row.id,
              status: { in: [...WAITING] },
            },
            select: { id: true },
          });
          const stillIds = new Set(still.map((d) => d.id));
          const chunk = moved.filter((d) => stillIds.has(d.id));
          if (chunk.length === 0) return 0;
          await this.store.split(tx, row, [], [chunk], {
            nextAttemptAt: now,
            errorClass: 'reinjection_error',
            error: 'recipient not confirmed in the postfix-outbound queue; re-planned',
            now,
          });
          for (const delivery of chunk) {
            const result = await recordDeliverySignal(
              tx,
              {
                match: { deliveryId: delivery.id, receivedAt: delivery.receivedAt },
                status: 'deferred',
                occurredAt: now,
                source: 'reconciler',
                signalKey: reconcileSignalKey({
                  deliveryId: delivery.id,
                  toStatus: 'deferred',
                  reason: `unconfirmed:${row.id.toString()}`,
                }),
                errorClass: 'reinjection_error',
                detail:
                  'no postfix-outbound delivery record for this recipient of the queued ' +
                  'reinjection (not accepted at RCPT); re-planned',
              },
              {
                sourceService: SOURCE_SERVICE,
                timeoutMs: this.recorderTimeoutMs,
                logger: this.logger,
              },
            );
            this.metrics.signal('reconciler', result.result, {
              direction: row.direction,
              status: result.status,
            });
          }
          return chunk.length;
        },
        { timeout: this.recorderTimeoutMs, maxWait: this.recorderTimeoutMs },
      );
      if (replanned > 0) {
        this.metrics.reconcilerActions.inc({ action: 'unconfirmed_replanned' }, replanned);
        this.logger.warn(
          { ...ids, deliveries: replanned },
          'recipients of a queued reinjection never confirmed by the delivery log; re-planned',
        );
      }
      return { replanned, unknown: 0 };
    } catch (err) {
      if (isUniqueViolation(err)) {
        this.logger.error(ids, 're-planned recipient set already exists; left for the stale scan');
        return { replanned: 0, unknown: 0 };
      }
      throw err;
    }
  }

  private async unknown(
    delivery: { id: bigint; receivedAt: Date },
    direction: string,
    reason: string,
  ): Promise<string> {
    const result = await recordDeliverySignal(
      this.prisma,
      {
        match: { deliveryId: delivery.id, receivedAt: delivery.receivedAt },
        status: 'unknown',
        occurredAt: this.now(),
        source: 'reconciler',
        signalKey: reconcileSignalKey({ deliveryId: delivery.id, toStatus: 'unknown', reason }),
        failureReason: 'status_signal_missing',
        detail: 'no delivery status signal can resolve this recipient',
      },
      { sourceService: SOURCE_SERVICE, timeoutMs: this.recorderTimeoutMs, logger: this.logger },
    );
    this.metrics.signal('reconciler', result.result, { direction, status: result.status });
    return result.result;
  }

  private async staleDeliveries(report: ReconcileReport): Promise<void> {
    const now = this.now();
    const before = new Date(now.getTime() - this.config.DELIVERY_STATUS_STALE_AFTER_SECONDS * 1000);
    const stale = await this.prisma.emailDelivery.findMany({
      where: {
        status: { in: ['queued', 'deferred'] },
        lastSignalAt: { lt: before },
        ...this.scope(),
      },
      select: { id: true, receivedAt: true, direction: true, messageId: true },
      take: BATCH,
    });
    for (const delivery of stale) {
      const result = await recordDeliverySignal(
        this.prisma,
        {
          match: { deliveryId: delivery.id, receivedAt: delivery.receivedAt },
          status: 'unknown',
          occurredAt: now,
          source: 'reconciler',
          signalKey: reconcileSignalKey({
            deliveryId: delivery.id,
            toStatus: 'unknown',
            reason: 'status_signal_missing',
          }),
          failureReason: 'status_signal_missing',
          detail: 'no delivery status signal within the stale window',
        },
        { sourceService: SOURCE_SERVICE, timeoutMs: this.recorderTimeoutMs, logger: this.logger },
      );
      this.metrics.signal('reconciler', result.result, {
        direction: delivery.direction,
        status: result.status,
      });
      if (result.result === 'applied') {
        report.staleUnknown += 1;
        this.metrics.reconcilerActions.inc({ action: 'stale_unknown' });
        this.logger.error(
          { deliveryId: delivery.id.toString(), messageId: delivery.messageId.toString() },
          'delivery status signal missing; delivery unknown',
        );
      }
    }
  }

  private scope(): { organizationId?: { in: bigint[] } } {
    const ids = this.options.organizationIds;
    return ids && ids.length > 0 ? { organizationId: { in: [...ids] } } : {};
  }

  private schedule(delayMs: number): void {
    if (this.stopped) return;
    this.timer = setTimeout(() => {
      this.running = this.reconcileOnce()
        .then(() => undefined)
        .catch((err: unknown) => this.logger.warn({ err }, 'reconcile failed; retrying'))
        .finally(() => {
          this.running = undefined;
          this.schedule(this.config.DELIVERY_RECONCILE_INTERVAL_MS);
        });
    }, delayMs);
    this.timer.unref();
  }
}
