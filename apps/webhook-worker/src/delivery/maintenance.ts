import { backoffDelay, sleep as defaultSleep } from '@email-gateway/common';
import { Prisma, type PrismaClient } from '@email-gateway/database';
import type { Logger } from '@email-gateway/logger';
import type { WebhookMetrics } from '../metrics/webhook-metrics';
import { deliveryKeyMatch } from './keys';

/** One cluster-wide maintenance leader (W13). */
export const WEBHOOK_MAINTENANCE_LOCK = 'eg:webhook-maintenance';
const DAY_MS = 86_400_000;
/** Terminal replays are kept 30 days, alert windows 7 days (W13). */
const REPLAY_RETENTION_MS = 30 * DAY_MS;
const ALERT_WINDOW_RETENTION_MS = 7 * DAY_MS;
const SUBSCRIPTION_BATCH = 100;
const ROW_BATCH = 1000;
/** Batches per step and pass (bounded work per tick; the next pass continues). */
const MAX_BATCHES = 10;
/** `webhook_due_backlog` is capped (a bounded count). */
export const DUE_BACKLOG_CAP = 100_000;

/** The subset of `AdvisoryLocks` the maintenance needs (GET_LOCK on a dedicated connection). */
export interface LeaderLock {
  ensure(name: string): Promise<boolean>;
  release(name: string): Promise<void>;
}

export type MaintenanceStep =
  | 'cancel_pending'
  | 'unpark'
  | 'purge_subscriptions'
  | 'purge_replays'
  | 'purge_alert_windows'
  | 'gauges';

export interface MaintenanceReport {
  outcome: 'not_leader' | 'database_error' | 'done' | 'partial';
  cancelled: number;
  unparked: number;
  subscriptionsDeleted: number;
  replaysDeleted: number;
  windowsDeleted: number;
  dueBacklog: number;
  oldestDueAgeSeconds: number;
  failedSteps: MaintenanceStep[];
}

/**
 * Webhook maintenance (step 6.2 W13), `delivery` role, leader-elected with
 * `GET_LOCK('eg:webhook-maintenance')` on a dedicated connection, every
 * WEBHOOK_MAINTENANCE_INTERVAL_MS, in bounded batches:
 *
 * - pending deliveries of `disabled` / `deleted` subscriptions → `cancelled` (1 000 per batch);
 * - parked pending deliveries (`next_attempt_at IS NULL`: parked while their subscription was
 *   paused) of `active` subscriptions → due now (1 000 per batch; the api un-parks on resume,
 *   this catches what its bounded statements or a race with the claimer left behind);
 * - `deleted` subscriptions whose `deleted_at` is older than WEBHOOK_DELETED_RETENTION_DAYS
 *   (≥ 62: every partition referencing them has dropped) are hard-deleted with their replays
 *   (100 per batch);
 * - terminal `webhook_replays` older than 30 days and `notification_alert_windows` older than 7
 *   days are deleted (1 000 per batch);
 * - gauges `webhook_due_backlog` (capped 100 000) and `webhook_oldest_due_age_seconds`, both over
 *   deliveries that can be sent (rows of paused subscriptions are excluded: a legitimate pause
 *   never fires the backlog alerts).
 *
 * `webhook_events`, `webhook_deliveries` and `webhook_delivery_attempts` have no row purge: their
 * monthly partitions (retention 2) are dropped by `pnpm db:partitions apply`.
 */
export class WebhookMaintenance {
  readonly lockName: string;
  private readonly logger: Logger;
  private readonly now: () => Date;
  private readonly sleepFn: (ms: number, signal: AbortSignal) => Promise<boolean>;
  private abort = new AbortController();
  private loop: Promise<void> | undefined;
  private failures = 0;
  private leader = false;

  constructor(
    private readonly prisma: PrismaClient,
    private readonly options: {
      locks: LeaderLock;
      metrics: WebhookMetrics;
      logger: Logger;
      intervalMs: number;
      deletedRetentionDays: number;
      lockName?: string;
      organizationIds?: readonly bigint[];
      now?: () => Date;
      sleep?: (ms: number, signal: AbortSignal) => Promise<boolean>;
    },
  ) {
    this.lockName = options.lockName ?? WEBHOOK_MAINTENANCE_LOCK;
    this.logger = options.logger.child({ component: 'webhook-maintenance' });
    this.now = options.now ?? (() => new Date());
    this.sleepFn = options.sleep ?? defaultSleep;
  }

  get isLeader(): boolean {
    return this.leader;
  }

  start(): void {
    if (this.loop) return;
    this.abort = new AbortController();
    this.loop = this.run(this.abort.signal);
  }

  async stop(): Promise<void> {
    this.abort.abort();
    await this.loop;
    this.loop = undefined;
    await this.options.locks.release(this.lockName).catch(() => undefined);
    this.setLeader(false);
  }

  private setLeader(leader: boolean): void {
    this.leader = leader;
    this.options.metrics.maintenanceLeader.set(leader ? 1 : 0);
    if (!leader) {
      // Non-leaders export 0 so `max()` over replicas is the leader's value.
      this.options.metrics.dueBacklog.set(0);
      this.options.metrics.oldestDueAge.set(0);
    }
  }

  private orgFilter(column: string): Prisma.Sql {
    const ids = this.options.organizationIds;
    if (ids === undefined) return Prisma.empty;
    // A restriction to no organization matches nothing (never every tenant).
    return ids.length === 0
      ? Prisma.sql`AND 1 = 0`
      : Prisma.sql`AND ${Prisma.raw(column)} IN (${Prisma.join(ids)})`;
  }

  async runOnce(): Promise<MaintenanceReport> {
    const report: MaintenanceReport = {
      outcome: 'done',
      cancelled: 0,
      unparked: 0,
      subscriptionsDeleted: 0,
      replaysDeleted: 0,
      windowsDeleted: 0,
      dueBacklog: 0,
      oldestDueAgeSeconds: 0,
      failedSteps: [],
    };
    try {
      this.setLeader(await this.options.locks.ensure(this.lockName));
    } catch (error) {
      this.setLeader(false);
      this.logger.warn({ errName: (error as Error).name }, 'maintenance lock check failed');
      return { ...report, outcome: 'database_error' };
    }
    if (!this.leader) return { ...report, outcome: 'not_leader' };
    const now = this.now();
    const steps: Array<[MaintenanceStep, () => Promise<void>]> = [
      ['cancel_pending', async () => void (report.cancelled = await this.cancelPending(now))],
      ['unpark', async () => void (report.unparked = await this.unpark(now))],
      [
        'purge_subscriptions',
        async () => void (report.subscriptionsDeleted = await this.purgeSubscriptions(now)),
      ],
      ['purge_replays', async () => void (report.replaysDeleted = await this.purgeReplays(now))],
      [
        'purge_alert_windows',
        async () => void (report.windowsDeleted = await this.purgeWindows(now)),
      ],
      ['gauges', () => this.gauges(now, report)],
    ];
    for (const [name, step] of steps) {
      try {
        await step();
      } catch (error) {
        report.failedSteps.push(name);
        this.logger.warn(
          {
            step: name,
            errName: (error as Error).name,
            errCode: (error as { code?: string }).code,
          },
          'webhook maintenance step failed; retried next pass',
        );
      }
    }
    if (report.failedSteps.length > 0) report.outcome = 'partial';
    else this.options.metrics.maintenanceLastSuccess.set(Math.floor(now.getTime() / 1000));
    return report;
  }

  /** Pending deliveries of disabled/deleted subscriptions → `cancelled`. */
  private async cancelPending(now: Date): Promise<number> {
    let total = 0;
    for (let batch = 0; batch < MAX_BATCHES; batch += 1) {
      const rows = await this.prisma.$queryRaw<
        Array<{ id: bigint; event_occurred_at: Date; status: string }>
      >`
        SELECT d.id, d.event_occurred_at, s.status
        FROM webhook_deliveries d
        JOIN webhook_subscriptions s ON s.id = d.subscription_id
          AND s.organization_id = d.organization_id
        WHERE d.status = 'pending' AND s.status IN ('disabled', 'deleted')
          ${this.orgFilter('d.organization_id')}
        LIMIT ${ROW_BATCH}`;
      if (rows.length === 0) break;
      for (const reason of ['disabled', 'deleted'] as const) {
        const keys = rows.filter((r) => r.status === reason);
        if (keys.length === 0) continue;
        const n = await this.prisma.$executeRaw`
          UPDATE webhook_deliveries
          SET status = 'cancelled', next_attempt_at = NULL, completed_at = ${now},
              last_error = ${`subscription_${reason}`}
          WHERE status = 'pending'
            AND ${deliveryKeyMatch(keys)}`;
        total += n;
        if (n > 0) this.options.metrics.cancelled.inc({ reason: `subscription_${reason}` }, n);
      }
      if (rows.length < ROW_BATCH) break;
    }
    return total;
  }

  /** Parked pending deliveries of active subscriptions → due now. */
  private async unpark(now: Date): Promise<number> {
    let total = 0;
    for (let batch = 0; batch < MAX_BATCHES; batch += 1) {
      const rows = await this.prisma.$queryRaw<Array<{ id: bigint; event_occurred_at: Date }>>`
        SELECT d.id, d.event_occurred_at
        FROM webhook_deliveries d
        JOIN webhook_subscriptions s ON s.id = d.subscription_id
          AND s.organization_id = d.organization_id
        WHERE d.status = 'pending' AND d.next_attempt_at IS NULL AND s.status = 'active'
          ${this.orgFilter('d.organization_id')}
        LIMIT ${ROW_BATCH}`;
      if (rows.length === 0) break;
      total += await this.prisma.$executeRaw`
        UPDATE webhook_deliveries SET next_attempt_at = ${now}
        WHERE status = 'pending' AND next_attempt_at IS NULL
          AND ${deliveryKeyMatch(rows)}`;
      if (rows.length < ROW_BATCH) break;
    }
    return total;
  }

  /** Hard delete of deleted subscriptions past the retention (with their replays). */
  private async purgeSubscriptions(now: Date): Promise<number> {
    const cutoff = new Date(now.getTime() - this.options.deletedRetentionDays * DAY_MS);
    let total = 0;
    for (let batch = 0; batch < MAX_BATCHES; batch += 1) {
      const ids = this.options.organizationIds;
      const rows = await this.prisma.webhookSubscription.findMany({
        where: {
          status: 'deleted',
          deletedAt: { lt: cutoff },
          ...(ids !== undefined ? { organizationId: { in: [...ids] } } : {}),
        },
        select: { id: true },
        orderBy: { id: 'asc' },
        take: SUBSCRIPTION_BATCH,
      });
      if (rows.length === 0) break;
      const subscriptionIds = rows.map((r) => r.id);
      const deleted = await this.prisma.$transaction(async (tx) => {
        await tx.webhookReplay.deleteMany({ where: { subscriptionId: { in: subscriptionIds } } });
        return (
          await tx.webhookSubscription.deleteMany({
            where: { id: { in: subscriptionIds }, status: 'deleted', deletedAt: { lt: cutoff } },
          })
        ).count;
      });
      total += deleted;
      if (rows.length < SUBSCRIPTION_BATCH) break;
    }
    return total;
  }

  private async purgeReplays(now: Date): Promise<number> {
    const cutoff = new Date(now.getTime() - REPLAY_RETENTION_MS);
    let total = 0;
    for (let batch = 0; batch < MAX_BATCHES; batch += 1) {
      const n = await this.prisma.$executeRaw`
        DELETE FROM webhook_replays
        WHERE status IN ('completed', 'failed', 'cancelled') AND created_at < ${cutoff}
          ${this.orgFilter('organization_id')}
        ORDER BY id
        LIMIT ${ROW_BATCH}`;
      total += n;
      if (n < ROW_BATCH) break;
    }
    return total;
  }

  private async purgeWindows(now: Date): Promise<number> {
    const cutoff = new Date(now.getTime() - ALERT_WINDOW_RETENTION_MS);
    let total = 0;
    for (let batch = 0; batch < MAX_BATCHES; batch += 1) {
      const n = await this.prisma.$executeRaw`
        DELETE FROM notification_alert_windows
        WHERE created_at < ${cutoff} ${this.orgFilter('organization_id')}
        ORDER BY id
        LIMIT ${ROW_BATCH}`;
      total += n;
      if (n < ROW_BATCH) break;
    }
    return total;
  }

  private async gauges(now: Date, report: MaintenanceReport): Promise<void> {
    // Rows of paused subscriptions not parked yet (in flight when the pause happened) are not
    // sendable: they never count as backlog.
    const sendable = Prisma.sql`NOT EXISTS (
      SELECT 1 FROM webhook_subscriptions s
      WHERE s.id = d.subscription_id AND s.status = 'paused')`;
    const [count] = await this.prisma.$queryRaw<Array<{ n: bigint | number }>>`
      SELECT COUNT(*) AS n FROM (
        SELECT 1 FROM webhook_deliveries d
        WHERE d.status = 'pending' AND d.next_attempt_at <= ${now} AND ${sendable}
          ${this.orgFilter('d.organization_id')}
        LIMIT ${DUE_BACKLOG_CAP}
      ) AS due`;
    const [oldest] = await this.prisma.$queryRaw<Array<{ at: Date | null }>>`
      SELECT d.next_attempt_at AS at FROM webhook_deliveries d
      WHERE d.status = 'pending' AND d.next_attempt_at <= ${now} AND ${sendable}
        ${this.orgFilter('d.organization_id')}
      ORDER BY d.next_attempt_at
      LIMIT 1`;
    report.dueBacklog = Number(count?.n ?? 0);
    report.oldestDueAgeSeconds =
      oldest?.at instanceof Date ? Math.max(0, (now.getTime() - oldest.at.getTime()) / 1000) : 0;
    this.options.metrics.dueBacklog.set(report.dueBacklog);
    this.options.metrics.oldestDueAge.set(report.oldestDueAgeSeconds);
  }

  private async run(signal: AbortSignal): Promise<void> {
    while (!signal.aborted) {
      const report = await this.runOnce();
      let delay = this.options.intervalMs;
      if (report.outcome === 'database_error' || report.outcome === 'partial') {
        this.failures += 1;
        delay = Math.max(delay, backoffDelay(this.failures, { baseMs: 1_000, maxMs: 60_000 }));
      } else {
        this.failures = 0;
      }
      if (!(await this.sleepFn(delay, signal))) break;
    }
  }
}
