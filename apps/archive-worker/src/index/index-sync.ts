import {
  type ArchiveIndexExtraFacts,
  buildArchiveSearchDocument,
  buildOrganizationPurgeQuery,
  indexPattern,
  yearlyIndexName,
} from '@email-gateway/archive';
import {
  backoffDelay,
  type OpenSearchBulkOperation,
  type OpenSearchService,
} from '@email-gateway/common';
import { type EmailArchive, Prisma, type PrismaClient } from '@email-gateway/database';
import type { Logger } from '@email-gateway/logger';
import type { ArchiveMetrics } from '../metrics/archive-metrics';
import { big, orgFilter } from '../shared/db';
import { errorCode, errorFields } from '../shared/errors';
import { mapLimit } from '../shared/loops';
import type { RecordObjects } from '../storage/record-objects';
import type { IndexManager } from './index-manager';

/** Leader lock of the index sync (one ordered writer of the index; WP3 deviation D3). */
export const INDEX_SYNC_LOCK = 'eg:archive-index-sync';
const DEPTH_CAP = 1_000_000;
const EXTRA_CACHE_MAX = 10_000;

interface QueueRow {
  id: bigint;
  organizationId: bigint;
  messageId: bigint;
  receivedAt: Date;
  messagePublicId: string;
  op: 'upsert' | 'delete' | 'purge_org';
  attempts: number;
}

export interface IndexSyncReport {
  claimed: number;
  indexed: number;
  deleted: number;
  purged: number;
  failed: number;
  more: boolean;
}

/** Live records are indexed; gone, shredded or disposing records are deleted from the index. */
export function isIndexable(
  record: Pick<EmailArchive, 'status' | 'deletedAt' | 'wrappedDek'> | null,
): boolean {
  return (
    record !== null &&
    record.status !== 'disposing' &&
    record.deletedAt === null &&
    record.wrappedDek !== null
  );
}

/** The search facts of a record's own objects: attachment names/hashes, DLP, authentication. */
export async function extraFacts(
  objects: RecordObjects,
  record: EmailArchive,
): Promise<ArchiveIndexExtraFacts> {
  const journal = await objects.journal(record);
  const scan = await objects.latestScan(record);
  const auth = scan?.rows.auth[0];
  const dlp = scan?.rows.dlp ?? [];
  return {
    attachmentNames: journal.attachments.map((a) => a.fileName),
    attachmentSha256s: journal.attachments.map((a) => a.sha256),
    dlpMatched: dlp.some((d) => d.matchedRuleId !== null && d.matchedRuleId !== undefined),
    spf: typeof auth?.spf === 'string' ? auth.spf : null,
    dkim: typeof auth?.dkim === 'string' ? auth.dkim : null,
    dmarc: typeof auth?.dmarc === 'string' ? auth.dmarc : null,
  };
}

/**
 * The index sync (A16): claims `archive_index_queue` rows in id order (`ARCHIVE_INDEX_BATCH_SIZE`),
 * coalesces them per message, builds each document from the CURRENT `email_archives` row
 * (`buildArchiveSearchDocument`; metadata only, plus attachment names/hashes, DLP and
 * authentication results read from the record's own encrypted objects), deletes the document
 * when the row is gone or disposing, sends one `_bulk` with routing = organization, deletes the
 * applied rows and sets `indexed_at`; failed rows back off (`available_at`). `purge_org` ops run
 * `_delete_by_query` (routing + tenant term) and remove the tenant alias. OpenSearch errors are
 * logged by status and type only; while OpenSearch is down the queue just grows (capture is never
 * blocked).
 */
export class IndexSync {
  private readonly extraCache = new Map<string, ArchiveIndexExtraFacts>();
  private readonly now: () => Date;

  constructor(
    private readonly prisma: PrismaClient,
    private readonly options: {
      search: OpenSearchService;
      manager: IndexManager;
      objects: RecordObjects;
      metrics: ArchiveMetrics;
      logger: Logger;
      batchSize: number;
      organizationIds?: readonly bigint[];
      random?: () => number;
      now?: () => Date;
    },
  ) {
    this.now = options.now ?? (() => new Date());
  }

  async runOnce(): Promise<IndexSyncReport> {
    const report: IndexSyncReport = {
      claimed: 0,
      indexed: 0,
      deleted: 0,
      purged: 0,
      failed: 0,
      more: false,
    };
    const now = this.now();
    await this.options.manager.refreshVersion();
    const rows = await this.claim(now);
    report.claimed = rows.length;
    report.more = rows.length === this.options.batchSize;
    if (rows.length > 0) {
      const purges = rows.filter((r) => r.op === 'purge_org');
      for (const p of purges) {
        if (await this.purge(p)) report.purged += 1;
        else report.failed += 1;
      }
      const others = rows.filter((r) => r.op !== 'purge_org');
      if (others.length > 0) await this.apply(others, report);
    }
    await this.gauges(now);
    return report;
  }

  private async claim(now: Date): Promise<QueueRow[]> {
    const rows = await this.prisma.$queryRaw<
      Array<{
        id: bigint | number;
        organization_id: bigint | number;
        message_id: bigint | number;
        received_at: Date;
        message_public_id: string;
        op: QueueRow['op'];
        attempts: number | bigint;
      }>
    >`
      SELECT id, organization_id, message_id, received_at, message_public_id, op, attempts
      FROM archive_index_queue
      WHERE available_at <= ${now} ${orgFilter('organization_id', this.options.organizationIds)}
      ORDER BY id LIMIT ${this.options.batchSize}`;
    return rows.map((r) => ({
      id: big(r.id),
      organizationId: big(r.organization_id),
      messageId: big(r.message_id),
      receivedAt: r.received_at,
      messagePublicId: r.message_public_id,
      op: r.op,
      attempts: Number(r.attempts),
    }));
  }

  private async apply(rows: QueueRow[], report: IndexSyncReport): Promise<void> {
    const now = this.now();
    // Coalesce: one document per message, built from the current row.
    const byMessage = new Map<string, QueueRow[]>();
    for (const r of rows) {
      const k = `${r.messageId.toString()}:${r.receivedAt.getTime()}`;
      byMessage.set(k, [...(byMessage.get(k) ?? []), r]);
    }
    const heads = [...byMessage.values()].map((group) => group[0]!);
    const records = await this.prisma.emailArchive.findMany({
      where: {
        OR: heads.map((h) => ({ messageId: h.messageId, receivedAt: h.receivedAt })),
      },
    });
    const recordOf = new Map(
      records.map((r) => [`${r.messageId.toString()}:${r.receivedAt.getTime()}`, r]),
    );
    const prefix = this.options.manager.options.prefix;
    const version = this.options.manager.version;
    const ops: Array<{
      op: OpenSearchBulkOperation;
      group: QueueRow[];
      record: EmailArchive | null;
    }> = [];
    const failedGroups: QueueRow[][] = [];
    const prepared = await mapLimit([...byMessage.entries()], 8, async ([k, group]) => {
      const head = group[0]!;
      const record = recordOf.get(k) ?? null;
      const mine = record !== null && record.organizationId === head.organizationId ? record : null;
      if (!isIndexable(mine)) {
        return {
          op: {
            action: 'delete' as const,
            index: yearlyIndexName(prefix, head.receivedAt, version),
            id: head.messagePublicId,
            routing: head.organizationId.toString(),
          },
          group,
          record: null,
        };
      }
      try {
        const extra = await this.extra(mine!);
        const built = buildArchiveSearchDocument(mine!, { prefix, now, version, extra });
        return {
          op: {
            action: 'index' as const,
            index: built.index,
            id: built.id,
            routing: built.routing,
            document: built.document,
          },
          group,
          record: mine,
        };
      } catch (error) {
        this.options.logger.warn({ ...errorFields(error) }, 'archive index document not built');
        failedGroups.push(group);
        return null;
      }
    });
    for (const p of prepared) if (p !== null) ops.push(p);
    for (const g of failedGroups) await this.backoff(g, 'document_invalid');
    report.failed += failedGroups.length;
    if (ops.length === 0) return;
    try {
      const upserts = ops.filter((o) => o.op.action === 'index');
      for (const index of new Set(upserts.map((o) => o.op.index))) {
        await this.options.manager.ensureIndex(
          index,
          upserts.filter((o) => o.op.index === index).map((o) => o.record!.organizationId),
        );
      }
      for (const org of new Set(upserts.map((o) => o.record!.organizationId))) {
        await this.options.manager.ensureTenantAlias(org);
      }
      const started = process.hrtime.bigint();
      const result = await this.options.search.bulk(ops.map((o) => o.op));
      this.options.metrics.indexBulkDuration.observe(
        Number(process.hrtime.bigint() - started) / 1e9,
      );
      const done: QueueRow[] = [];
      const indexed: EmailArchive[] = [];
      for (let i = 0; i < ops.length; i += 1) {
        const o = ops[i]!;
        const item = result.items[i]!;
        const op = o.op.action === 'index' ? 'upsert' : 'delete';
        if (item.ok) {
          done.push(...o.group);
          this.options.metrics.indexOps.inc({ op, result: 'ok' });
          if (o.record !== null) indexed.push(o.record);
          if (op === 'upsert') report.indexed += 1;
          else report.deleted += 1;
        } else {
          this.options.metrics.indexOps.inc({ op, result: 'failed' });
          report.failed += 1;
          this.options.logger.warn(
            { status: item.status, errorType: item.errorType },
            'archive index operation failed; retried',
          );
          await this.backoff(o.group, item.errorType ?? `http_${item.status}`);
        }
      }
      await this.complete(done, indexed, now);
    } catch (error) {
      this.options.logger.warn({ ...errorFields(error) }, 'archive index bulk failed; retried');
      for (const o of ops) {
        this.options.metrics.indexOps.inc({
          op: o.op.action === 'index' ? 'upsert' : 'delete',
          result: 'failed',
        });
        await this.backoff(o.group, errorCode(error, 'bulk_failed'));
      }
      report.failed += ops.length;
    }
  }

  private async extra(record: EmailArchive): Promise<ArchiveIndexExtraFacts> {
    const key = `${record.messagePublicId}:${record.updatedAt.getTime()}`;
    const hit = this.extraCache.get(key);
    if (hit) return hit;
    const facts = await extraFacts(this.options.objects, record);
    if (this.extraCache.size >= EXTRA_CACHE_MAX) this.extraCache.clear();
    this.extraCache.set(key, facts);
    return facts;
  }

  /** Deletes applied queue rows and stamps `indexed_at` on the indexed records. */
  private async complete(done: QueueRow[], indexed: EmailArchive[], now: Date): Promise<void> {
    if (done.length > 0) {
      await this.prisma.archiveIndexQueue.deleteMany({
        where: { id: { in: done.map((d) => d.id) } },
      });
    }
    for (const r of indexed) {
      await this.prisma.$executeRaw`
        UPDATE email_archives SET indexed_at = ${now}
        WHERE id = ${r.id} AND received_at = ${r.receivedAt}`;
    }
  }

  private async backoff(group: QueueRow[], code: string): Promise<void> {
    const now = this.now();
    for (const row of group) {
      const attempts = Math.min(row.attempts + 1, 65_535);
      const delay = backoffDelay(attempts, { baseMs: 2_000, maxMs: 300_000 }, this.options.random);
      await this.prisma.$executeRaw`
        UPDATE archive_index_queue SET attempts = ${attempts},
          available_at = ${new Date(now.getTime() + delay)},
          last_error_code = ${code.slice(0, 64)}
        WHERE id = ${row.id}`;
    }
  }

  /** `purge_org` (A16, A24): delete every document of the tenant, then remove its alias. */
  private async purge(row: QueueRow): Promise<boolean> {
    const manager = this.options.manager;
    try {
      await this.options.search.deleteByQuery(
        indexPattern(manager.options.prefix, manager.version),
        buildOrganizationPurgeQuery(row.organizationId),
        { routing: row.organizationId.toString(), refresh: true },
      );
      await manager.removeTenantAlias(row.organizationId);
      await this.prisma.archiveIndexQueue.deleteMany({ where: { id: row.id } });
      this.options.metrics.indexOps.inc({ op: 'purge_org', result: 'ok' });
      return true;
    } catch (error) {
      this.options.metrics.indexOps.inc({ op: 'purge_org', result: 'failed' });
      this.options.logger.warn({ ...errorFields(error) }, 'archive organization purge failed');
      await this.backoff([row], errorCode(error, 'purge_failed'));
      return false;
    }
  }

  private async gauges(now: Date): Promise<void> {
    const [depth] = await this.prisma.$queryRaw<Array<{ n: bigint | number }>>`
      SELECT COUNT(*) AS n FROM (SELECT 1 FROM archive_index_queue
        ${this.options.organizationIds === undefined ? Prisma.empty : Prisma.sql`WHERE 1 = 1 ${orgFilter('organization_id', this.options.organizationIds)}`}
        LIMIT ${DEPTH_CAP}) AS bounded`;
    // Queue ids are allocated in insertion order: the lowest id is the oldest operation.
    const [oldest] = await this.prisma.$queryRaw<Array<{ at: Date | null }>>`
      SELECT created_at AS at FROM archive_index_queue
      ${this.options.organizationIds === undefined ? Prisma.empty : Prisma.sql`WHERE 1 = 1 ${orgFilter('organization_id', this.options.organizationIds)}`}
      ORDER BY id LIMIT 1`;
    this.options.metrics.indexQueueDepth.set(Number(depth?.n ?? 0));
    this.options.metrics.indexOldest.set(
      oldest?.at instanceof Date ? Math.max(0, (now.getTime() - oldest.at.getTime()) / 1000) : 0,
    );
  }
}
