import { buildDayCountQuery, tenantAliasName } from '@email-gateway/archive';
import type { OpenSearchService } from '@email-gateway/common';
import { Prisma, type PrismaClient } from '@email-gateway/database';
import type { Logger } from '@email-gateway/logger';
import type { ArchiveMetrics } from '../metrics/archive-metrics';
import { archiveOrganizations, big, readCursor, writeCursor } from '../shared/db';
import { errorFields } from '../shared/errors';
import type { IndexManager } from './index-manager';

export const INDEX_RECONCILE_LOCK = 'eg:archive-index-reconcile';
/** Rotating position of the older days per organization (`stream_cursors`). */
export const reconcileCursorName = (organizationId: bigint): string =>
  `archive:index-reconcile:${organizationId.toString()}`;

const DAY_MS = 86_400_000;
/** Older days checked per organization and run (rotating backwards). */
export const ROTATING_DAYS_PER_RUN = 7;
const REPAIR_PAGE = 1_000;

export const utcDay = (date: Date): string => date.toISOString().slice(0, 10);
const dayStart = (day: string): Date => new Date(`${day}T00:00:00.000Z`);

export type DayResult = 'ok' | 'mismatch' | 'skipped';

export interface ReconcileReport {
  organizations: number;
  days: number;
  ok: number;
  mismatch: number;
  skipped: number;
}

/**
 * Per-day index reconciliation (A15, index role, leader `GET_LOCK('eg:archive-index-reconcile')`
 * every `ARCHIVE_RECONCILE_INTERVAL_MS`): per organization and UTC day, the MySQL count of
 * `active` + `expiry_review` records (`(organization_id, received_at)`) against `_count` on the
 * tenant alias. The last `ARCHIVE_RECONCILE_RECENT_DAYS` days every run, older days rotating back
 * to the organization's first record. A day with queued index operations is skipped (lag, not
 * drift). A mismatch re-enqueues every record of the day (upsert) and deletes the day's documents
 * that have no live record; the result is kept in `archive_index_checks` (`ok`, `mismatch` →
 * `repairing` until a later run counts equal).
 */
export class IndexReconciler {
  private readonly now: () => Date;

  constructor(
    private readonly prisma: PrismaClient,
    private readonly options: {
      search: OpenSearchService;
      manager: IndexManager;
      metrics: ArchiveMetrics;
      logger: Logger;
      recentDays: number;
      rotatingDays?: number;
      organizationIds?: readonly bigint[];
      now?: () => Date;
    },
  ) {
    this.now = options.now ?? (() => new Date());
  }

  async runOnce(): Promise<ReconcileReport> {
    const report: ReconcileReport = { organizations: 0, days: 0, ok: 0, mismatch: 0, skipped: 0 };
    const orgs = await archiveOrganizations(this.prisma, this.options.organizationIds);
    for (const org of orgs) {
      report.organizations += 1;
      try {
        for (const day of await this.daysOf(org)) {
          const result = await this.checkDay(org, day);
          report.days += 1;
          report[result] += 1;
          this.options.metrics.reconcileDays.inc({ result });
        }
      } catch (error) {
        this.options.logger.warn(
          { organizationId: org.toString(), ...errorFields(error) },
          'archive index reconciliation failed for an organization; retried next run',
        );
      }
    }
    return report;
  }

  /** The recent days plus the next rotating older days (cursor walks back to the first record). */
  async daysOf(organizationId: bigint): Promise<string[]> {
    const today = dayStart(utcDay(this.now()));
    const days: string[] = [];
    for (let i = 0; i < this.options.recentDays; i += 1) {
      days.push(utcDay(new Date(today.getTime() - i * DAY_MS)));
    }
    const [first] = await this.prisma.$queryRaw<Array<{ at: Date | null }>>`
      SELECT MIN(received_at) AS at FROM email_archives WHERE organization_id = ${organizationId}`;
    if (!(first?.at instanceof Date)) return days;
    const firstDay = dayStart(utcDay(first.at));
    const newestOld = new Date(today.getTime() - this.options.recentDays * DAY_MS);
    if (newestOld.getTime() < firstDay.getTime()) return days;
    const name = reconcileCursorName(organizationId);
    const cursor = await readCursor(this.prisma, name);
    let next =
      cursor?.lastEventAt instanceof Date
        ? new Date(cursor.lastEventAt.getTime() - DAY_MS)
        : newestOld;
    const rotating = this.options.rotatingDays ?? ROTATING_DAYS_PER_RUN;
    for (let i = 0; i < rotating; i += 1) {
      if (next.getTime() < firstDay.getTime() || next.getTime() > newestOld.getTime()) {
        next = newestOld;
      }
      const day = utcDay(next);
      if (!days.includes(day)) days.push(day);
      next = new Date(next.getTime() - DAY_MS);
    }
    await writeCursor(this.prisma, name, null, new Date(next.getTime() + DAY_MS));
    return days;
  }

  async checkDay(organizationId: bigint, day: string): Promise<DayResult> {
    const from = dayStart(day);
    const to = new Date(from.getTime() + DAY_MS);
    const [queued] = await this.prisma.$queryRaw<Array<{ n: bigint | number }>>`
      SELECT COUNT(*) AS n FROM archive_index_queue
      WHERE organization_id = ${organizationId} AND received_at >= ${from} AND received_at < ${to}`;
    if (Number(queued?.n ?? 0) > 0) return 'skipped';
    const [mysql] = await this.prisma.$queryRaw<Array<{ n: bigint | number }>>`
      SELECT COUNT(*) AS n FROM email_archives
      WHERE organization_id = ${organizationId} AND received_at >= ${from} AND received_at < ${to}
        AND status IN ('active', 'expiry_review')`;
    const mysqlCount = Number(mysql?.n ?? 0);
    const prefix = this.options.manager.options.prefix;
    const indexCount = await this.options.search.count(
      tenantAliasName(prefix, organizationId),
      buildDayCountQuery(organizationId, day),
      { routing: organizationId.toString() },
    );
    const now = this.now();
    const ok = mysqlCount === indexCount;
    if (!ok) await this.repair(organizationId, from, to);
    const state = ok ? 'ok' : 'repairing';
    await this.prisma.$executeRaw`
      INSERT INTO archive_index_checks
        (organization_id, day, mysql_count, index_count, state, checked_at, repaired_at)
      VALUES (${organizationId}, ${day}, ${mysqlCount}, ${indexCount}, ${state}, ${now},
        ${ok ? null : now})
      AS new ON DUPLICATE KEY UPDATE mysql_count = new.mysql_count,
        index_count = new.index_count, state = new.state, checked_at = new.checked_at,
        repaired_at = IF(new.state = 'repairing', new.repaired_at, archive_index_checks.repaired_at)`;
    return ok ? 'ok' : 'mismatch';
  }

  /** Re-enqueues every record of the day and deletes stray documents of the day. */
  private async repair(organizationId: bigint, from: Date, to: Date): Promise<void> {
    const live = new Set<string>();
    let after: { receivedAt: Date; id: bigint } | null = null;
    for (;;) {
      const page: Array<{
        id: bigint | number;
        received_at: Date;
        message_id: bigint | number;
        message_public_id: string;
        status: string;
      }> = await this.prisma.$queryRaw`
        SELECT id, received_at, message_id, message_public_id, status FROM email_archives
        WHERE organization_id = ${organizationId} AND received_at >= ${from} AND received_at < ${to}
          ${after === null ? Prisma.empty : Prisma.sql`AND (received_at, id) > (${after.receivedAt}, ${after.id})`}
        ORDER BY received_at, id LIMIT ${REPAIR_PAGE}`;
      if (page.length === 0) break;
      const ops = page.map(
        (r) => Prisma.sql`(${organizationId}, ${big(r.message_id)}, ${r.received_at},
          ${r.message_public_id}, ${r.status === 'disposing' ? 'delete' : 'upsert'}, 0, NOW(3), NOW(3))`,
      );
      await this.prisma.$executeRaw`
        INSERT INTO archive_index_queue
          (organization_id, message_id, received_at, message_public_id, op, attempts, available_at,
           created_at)
        VALUES ${Prisma.join(ops)}`;
      for (const r of page) if (r.status !== 'disposing') live.add(r.message_public_id);
      const last = page[page.length - 1]!;
      after = { receivedAt: last.received_at, id: big(last.id) };
      if (page.length < REPAIR_PAGE) break;
    }
    // Stray documents: indexed for the day but without a live record.
    const prefix = this.options.manager.options.prefix;
    const alias = tenantAliasName(prefix, organizationId);
    let searchAfter: unknown[] | undefined;
    const stray: Array<{ index: string; id: string }> = [];
    for (;;) {
      const res = await this.options.search.search<{ message_id?: string }>(
        alias,
        {
          ...buildDayCountQuery(organizationId, utcDay(from)),
          size: REPAIR_PAGE,
          sort: [{ message_id: 'asc' }],
          _source: ['message_id'],
          track_total_hits: false,
          ...(searchAfter ? { search_after: searchAfter } : {}),
        },
        { routing: organizationId.toString() },
      );
      for (const hit of res.hits)
        if (!live.has(hit._id)) stray.push({ index: hit._index, id: hit._id });
      if (res.hits.length < REPAIR_PAGE) break;
      searchAfter = res.hits[res.hits.length - 1]!.sort;
      if (!searchAfter) break;
    }
    if (stray.length > 0) {
      const result = await this.options.search.bulk(
        stray.map((s) => ({
          action: 'delete' as const,
          index: s.index,
          id: s.id,
          routing: organizationId.toString(),
        })),
      );
      for (const item of result.items) {
        this.options.metrics.indexOps.inc({ op: 'delete', result: item.ok ? 'ok' : 'failed' });
      }
    }
  }
}
