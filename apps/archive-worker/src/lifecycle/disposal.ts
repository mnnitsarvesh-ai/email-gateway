import {
  archivePrefixOf,
  assertKeyOfOrganization,
  type DisposalObjects,
  type DisposalReplicaStatus,
  disposalReplicaStatusOf,
  readDisposalObjects,
  readDisposalReplicaStatus,
  recordVersions,
  tenantAliasName,
} from '@email-gateway/archive';
import { backoffDelay, type OpenSearchService } from '@email-gateway/common';
import {
  type ArchiveDisposalReason,
  type EmailArchive,
  Prisma,
  type PrismaClient,
  REGISTRY_WATERMARK,
} from '@email-gateway/database';
import type { Logger } from '@email-gateway/logger';
import type { ReplicaTarget } from '../config';
import type { ArchiveMetrics } from '../metrics/archive-metrics';
import { big, type Db, orgFilter } from '../shared/db';
import { errorCode, errorFields } from '../shared/errors';
import type { ArchiveStorage } from '../storage/archive-storage';
import { disposalObjectsWithMerged, recordVersionsWithMerged } from '../storage/record-versions';

// One builder for every disposal writer (worker expiry, api manual dispose and purge).
export type { DisposalObjects, DisposalReplicaStatus };
export { recordVersions };

const OPEN_STATES = ['shredded', 'objects_deleted', 'index_deleted'] as const;
const LEASE_MS = 10 * 60_000;
const INDEX_WAIT_MS = 30_000;
const PENDING_CAP = 1_000_000;

/**
 * The disposal decision (A14 step 1), inside the caller's transaction with the record row locked
 * and holds/retention already re-checked: an `archive_disposals` row (`shredded`, reason, message
 * public id and `received_at`, original SHA-256 and size, object references, replica targets,
 * requester), the record `disposing` with `wrapped_dek = NULL` (crypto-shred: every version and
 * replica becomes undecryptable at this commit) and `deleted_at = now`, and an index `delete` op.
 */
export async function decideDisposal(
  tx: Prisma.TransactionClient,
  record: EmailArchive,
  input: {
    reason: ArchiveDisposalReason;
    requestedByUserId: bigint | null;
    replicaTargets: readonly ReplicaTarget[];
    now: Date;
  },
): Promise<void> {
  // Step 8.6 D7: the merged copies' journal objects and variants are disposed with the record.
  const objects = disposalObjectsWithMerged(record);
  const replica = disposalReplicaStatusOf(input.replicaTargets.map((t) => t.bucket));
  await tx.archiveDisposal.create({
    data: {
      requestedAt: input.now,
      organizationId: record.organizationId,
      messageId: record.messageId,
      messagePublicId: record.messagePublicId,
      messageReceivedAt: record.receivedAt,
      archiveRecordId: record.id,
      reason: input.reason,
      sha256: record.sha256,
      sizeBytes: record.sizeBytes,
      objects,
      replicaStatus: replica,
      state: 'shredded',
      nextAttemptAt: input.now,
      requestedByUserId: input.requestedByUserId,
    },
    select: { id: true },
  });
  const updated = await tx.$executeRaw`
    UPDATE email_archives SET status = 'disposing', wrapped_dek = NULL, deleted_at = ${input.now},
      updated_at = NOW(3)
    WHERE id = ${record.id} AND received_at = ${record.receivedAt} AND status <> 'disposing'`;
  if (updated !== 1) throw new Error('record changed during the disposal decision');
  await tx.archiveIndexQueue.create({
    data: {
      organizationId: record.organizationId,
      messageId: record.messageId,
      receivedAt: record.receivedAt,
      messagePublicId: record.messagePublicId,
      op: 'delete',
    },
    select: { id: true },
  });
}

interface ClaimedDisposal {
  id: bigint;
  requestedAt: Date;
  organizationId: bigint;
  messageId: bigint;
  messagePublicId: string;
  messageReceivedAt: Date;
  archiveRecordId: bigint;
  state: (typeof OPEN_STATES)[number];
  attempts: number;
  objects: DisposalObjects;
  replica: DisposalReplicaStatus;
  leaseUntil: Date;
}

export type DisposalStepResult = 'completed' | 'waiting' | 'locked' | 'retry' | 'failed';

/**
 * The disposal pipeline (A14 steps 2–5), lifecycle role, claims by `(state, next_attempt_at)`
 * with `FOR UPDATE SKIP LOCKED` and a lease: (2) delete the recorded versions, then every other
 * version under the record prefix (orphans of failed attempts; governance bypass only for those,
 * `ARCHIVE_GOVERNANCE_BYPASS_ORPHANS`), then every version under the same prefix in each replica
 * target (S3 replication never replicates version deletes); a version still locked is recorded
 * with its retain-until and retried after it → `objects_deleted`; (3) the index document is gone
 * (no longer visible through the tenant alias) and no index op is queued → `index_deleted`; (4) the `email_archives` row is hard-
 * deleted and, in the same transaction, the `message_identities` row when the registry purge
 * contract requires it (below the purge watermark, no quarantine entry, no message row) →
 * `completed`. Failures: attempts and backoff, `failed` after `ARCHIVE_DISPOSAL_MAX_ATTEMPTS`
 * (already crypto-shredded: no readable data remains).
 */
export class DisposalPipeline {
  private readonly now: () => Date;

  constructor(
    private readonly prisma: PrismaClient,
    private readonly options: {
      storage: ArchiveStorage;
      search: OpenSearchService | null;
      indexPrefix: string;
      replicaTargets: readonly ReplicaTarget[];
      governanceBypassOrphans: boolean;
      maxAttempts: number;
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

  /** One pass; true when the claim was full. */
  async runOnce(): Promise<boolean> {
    const claimed = await this.claim();
    for (const d of claimed) await this.process(d);
    // Gauges are written by the lifecycle leader only (`gauges()`), never by every replica.
    return claimed.length === this.options.batchSize;
  }

  private async claim(): Promise<ClaimedDisposal[]> {
    const now = this.now();
    const lease = new Date(now.getTime() + LEASE_MS);
    return this.prisma.$transaction(async (tx) => {
      const rows = await tx.$queryRaw<
        Array<{
          id: bigint | number;
          requested_at: Date;
          organization_id: bigint | number;
          message_id: bigint | number;
          message_public_id: string;
          message_received_at: Date;
          archive_record_id: bigint | number;
          state: ClaimedDisposal['state'];
          attempts: number | bigint;
          objects: unknown;
          replica_status: unknown;
        }>
      >`
        SELECT id, requested_at, organization_id, message_id, message_public_id,
          message_received_at, archive_record_id, state, attempts, objects, replica_status
        FROM archive_disposals
        WHERE state IN ('shredded', 'objects_deleted', 'index_deleted') AND next_attempt_at <= ${now}
          ${orgFilter('organization_id', this.options.organizationIds)}
        ORDER BY next_attempt_at LIMIT ${this.options.batchSize}
        FOR UPDATE SKIP LOCKED`;
      if (rows.length === 0) return [];
      // AUTO_INCREMENT ids are unique across partitions; the requested_at range prunes them.
      const times = rows.map((r) => r.requested_at.getTime());
      const keys = Prisma.sql`id IN (${Prisma.join(rows.map((r) => big(r.id)))})
        AND requested_at BETWEEN ${new Date(Math.min(...times))} AND ${new Date(Math.max(...times))}`;
      await tx.$executeRaw`
        UPDATE archive_disposals SET next_attempt_at = ${lease}, updated_at = NOW(3)
        WHERE ${keys}`;
      return rows.map((r) => {
        const ids = {
          organizationId: big(r.organization_id),
          receivedAt: r.message_received_at,
          messagePublicId: r.message_public_id,
        };
        const read = readDisposalObjects(r.objects, ids);
        if (read.shape !== 'disposal') {
          this.options.logger.warn(
            { disposalId: big(r.id).toString(), shape: read.shape },
            'archive disposal objects not in the disposal shape; derived from the record',
          );
        }
        return {
          id: big(r.id),
          requestedAt: r.requested_at,
          organizationId: big(r.organization_id),
          messageId: big(r.message_id),
          messagePublicId: r.message_public_id,
          messageReceivedAt: r.message_received_at,
          archiveRecordId: big(r.archive_record_id),
          state: r.state,
          attempts: Number(r.attempts),
          objects: read.objects,
          replica: readDisposalReplicaStatus(r.replica_status),
          leaseUntil: lease,
        };
      });
    });
  }

  async process(d: ClaimedDisposal): Promise<DisposalStepResult> {
    try {
      let state: ClaimedDisposal['state'] | 'completed' = d.state;
      if (state === 'shredded') {
        const pending = await this.deleteObjects(d);
        if (pending.length > 0) {
          const until = Math.max(
            ...pending.map((p) =>
              p.retainUntil ? Date.parse(p.retainUntil) : this.now().getTime() + 3_600_000,
            ),
          );
          await this.save(d, {
            state: 'shredded',
            replica: { ...d.replica, pending },
            nextAttemptAt: new Date(until + 1_000),
          });
          this.options.metrics.disposals.inc({ stage: 'objects', result: 'locked' });
          return 'locked';
        }
        state = 'objects_deleted';
        await this.save(d, {
          state,
          replica: { ...d.replica, pending: [] },
          nextAttemptAt: this.now(),
        });
        this.options.metrics.disposals.inc({ stage: 'objects', result: 'ok' });
      }
      if (state === 'objects_deleted') {
        if (!(await this.indexGone(d))) {
          await this.save(d, {
            state,
            nextAttemptAt: new Date(this.now().getTime() + INDEX_WAIT_MS),
          });
          this.options.metrics.disposals.inc({ stage: 'index', result: 'retry' });
          return 'waiting';
        }
        state = 'index_deleted';
        await this.save(d, { state, nextAttemptAt: this.now() });
        this.options.metrics.disposals.inc({ stage: 'index', result: 'ok' });
      }
      if (state === 'index_deleted') {
        await this.deleteRow(d);
        this.options.metrics.disposals.inc({ stage: 'row', result: 'ok' });
        return 'completed';
      }
      return 'completed';
    } catch (error) {
      const attempts = d.attempts + 1;
      const failed = attempts >= this.options.maxAttempts;
      const delay = backoffDelay(
        attempts,
        { baseMs: 30_000, maxMs: 6 * 3_600_000 },
        this.options.random,
      );
      this.options.logger.warn(
        { disposalId: d.id.toString(), state: d.state, ...errorFields(error) },
        failed ? 'archive disposal failed permanently' : 'archive disposal step failed; retried',
      );
      this.options.metrics.disposals.inc({
        stage: d.state === 'shredded' ? 'objects' : d.state === 'objects_deleted' ? 'index' : 'row',
        result: failed ? 'failed' : 'retry',
      });
      await this.prisma.$executeRaw`
        UPDATE archive_disposals SET attempts = ${Math.min(attempts, 65_535)},
          last_error_code = ${errorCode(error, 'disposal_error')},
          ${failed ? Prisma.sql`state = 'failed',` : Prisma.empty}
          next_attempt_at = ${new Date(this.now().getTime() + delay)}, updated_at = NOW(3)
        WHERE id = ${d.id} AND requested_at = ${d.requestedAt}`;
      return failed ? 'failed' : 'retry';
    }
  }

  /** Step 2: every version of the record in the archive bucket and each replica target. */
  private async deleteObjects(d: ClaimedDisposal): Promise<DisposalReplicaStatus['pending']> {
    const storage = this.options.storage;
    const pending: DisposalReplicaStatus['pending'] = [];
    const recorded = new Set(
      d.objects.versions.filter((v) => v.versionId !== null).map((v) => `${v.key}\0${v.versionId}`),
    );
    // The prefix ends with '/': check it without the trailing separator.
    if (!d.objects.prefix.endsWith('/')) throw new Error('disposal prefix malformed');
    const prefix = `${assertKeyOfOrganization(d.objects.prefix.slice(0, -1), d.organizationId, 'archive')}/`;
    const remove = async (
      bucket: string,
      key: string,
      versionId: string,
      orphan: boolean,
    ): Promise<void> => {
      const result = await storage.deleteVersion(bucket, key, versionId, {
        bypassGovernance: orphan && this.options.governanceBypassOrphans,
      });
      if (result === 'locked') {
        const retention = await storage.getRetention(bucket, key, versionId);
        pending.push({
          bucket,
          key,
          versionId,
          retainUntil: retention?.until.toISOString() ?? null,
        });
      }
    };
    // Step 8.6 D7: the merged copies of the record (a disposal decided before 8.6 or by the api's
    // shared builder may not list their versions): their recorded versions and their prefixes.
    const merged = await this.mergedOf(d);
    for (const v of merged.versions) {
      if (v.versionId !== null) recorded.add(`${v.key}\0${v.versionId}`);
    }
    const versions = [
      ...d.objects.versions,
      ...merged.versions.filter(
        (v) => !d.objects.versions.some((x) => x.key === v.key && x.versionId === v.versionId),
      ),
    ];
    for (const v of versions) {
      if (v.versionId === null) continue;
      await remove(
        storage.buckets.archive,
        assertKeyOfOrganization(v.key, d.organizationId, 'archive'),
        v.versionId,
        false,
      );
    }
    const sweep = async (bucket: string, sweepPrefix: string): Promise<void> => {
      for await (const v of storage.listVersions(bucket, sweepPrefix)) {
        if (!v.key.startsWith(sweepPrefix)) continue;
        if (
          bucket === storage.buckets.archive &&
          recorded.has(`${v.key}\0${v.versionId}`) &&
          !v.deleteMarker
        ) {
          // Already handled above (its result is in `pending` when locked).
          if (
            pending.some(
              (p) => p.bucket === bucket && p.key === v.key && p.versionId === v.versionId,
            )
          )
            continue;
        }
        await remove(bucket, v.key, v.versionId, !recorded.has(`${v.key}\0${v.versionId}`));
      }
    };
    const buckets = [storage.buckets.archive, ...this.options.replicaTargets.map((t) => t.bucket)];
    for (const bucket of buckets) {
      for (const p of [prefix, ...merged.prefixes]) await sweep(bucket, p);
    }
    // De-duplicate (a recorded locked version is seen twice).
    const seen = new Set<string>();
    return pending.filter((p) => {
      const k = `${p.bucket}\0${p.key}\0${p.versionId}`;
      if (seen.has(k)) return false;
      seen.add(k);
      return true;
    });
  }

  /**
   * The merged copies of a disposal's record (step 8.6 D7): every version its `objects.merged`
   * names (the row still exists, `disposing`, until step 4) and the prefix of every merged message
   * (`archive_record_sources`) that has no record of its own (a separate record's prefix is never
   * swept here).
   */
  private async mergedOf(
    d: ClaimedDisposal,
  ): Promise<{ versions: Array<{ key: string; versionId: string | null }>; prefixes: string[] }> {
    const record = await this.prisma.emailArchive.findUnique({
      where: { id_receivedAt: { id: d.archiveRecordId, receivedAt: d.messageReceivedAt } },
      select: { organizationId: true, objects: true },
    });
    const versions =
      record !== null && record.organizationId === d.organizationId
        ? recordVersionsWithMerged(record)
        : [];
    const sources = await this.prisma.archiveRecordSource.findMany({
      where: {
        organizationId: d.organizationId,
        archiveId: d.archiveRecordId,
        archiveReceivedAt: d.messageReceivedAt,
      },
      select: { organizationId: true, messagePublicId: true, messageReceivedAt: true },
      take: 64,
    });
    const prefixes: string[] = [];
    for (const src of sources) {
      if (src.organizationId !== d.organizationId) continue;
      const own = await this.prisma.emailArchive.count({
        where: {
          organizationId: d.organizationId,
          messagePublicId: src.messagePublicId,
          receivedAt: src.messageReceivedAt,
        },
      });
      if (own > 0) continue;
      prefixes.push(
        archivePrefixOf({
          organizationId: d.organizationId,
          receivedAt: src.messageReceivedAt,
          messagePublicId: src.messagePublicId,
        }),
      );
    }
    return { versions, prefixes };
  }

  /** Step 3: the document is gone (not visible through the alias) and no index op is queued. */
  private async indexGone(d: ClaimedDisposal): Promise<boolean> {
    const queued = await this.prisma.archiveIndexQueue.count({
      where: {
        organizationId: d.organizationId,
        messageId: d.messageId,
        receivedAt: d.messageReceivedAt,
      },
    });
    if (queued > 0) return false;
    if (this.options.search === null) return true;
    return !(await documentVisible(this.options.search, this.options.indexPrefix, d));
  }

  /** Step 4: the record row and, when the registry contract requires it, its registry row. */
  private async deleteRow(d: ClaimedDisposal): Promise<void> {
    const now = this.now();
    await this.prisma.$transaction(async (tx) => {
      await tx.$executeRaw`
        DELETE FROM email_archives
        WHERE id = ${d.archiveRecordId} AND received_at = ${d.messageReceivedAt}
          AND organization_id = ${d.organizationId} AND status = 'disposing'`;
      // Step 8.6 D7: the record's merged-copy rows and dedupe rows go with it; the registry rows
      // of merged messages follow the purge contract like the record's own.
      const merged = await tx.archiveRecordSource.findMany({
        where: {
          organizationId: d.organizationId,
          archiveId: d.archiveRecordId,
          archiveReceivedAt: d.messageReceivedAt,
        },
        select: { messageId: true, messageReceivedAt: true },
      });
      await tx.$executeRaw`
        DELETE FROM archive_record_sources
        WHERE organization_id = ${d.organizationId} AND archive_id = ${d.archiveRecordId}
          AND archive_received_at = ${d.messageReceivedAt}`;
      await tx.$executeRaw`
        DELETE FROM archive_dedupe_keys
        WHERE organization_id = ${d.organizationId} AND archive_id = ${d.archiveRecordId}
          AND archive_received_at = ${d.messageReceivedAt}`;
      for (const copy of merged) {
        await deleteRegistryRowIfUnreferenced(tx, {
          messageId: copy.messageId,
          messageReceivedAt: copy.messageReceivedAt,
          organizationId: d.organizationId,
        });
      }
      await deleteRegistryRowIfUnreferenced(tx, d);
      const done = await tx.$executeRaw`
        UPDATE archive_disposals SET state = 'completed', completed_at = ${now},
          last_error_code = NULL, updated_at = NOW(3)
        WHERE id = ${d.id} AND requested_at = ${d.requestedAt} AND state = 'index_deleted'`;
      if (done !== 1) throw new Error('disposal changed during completion');
    });
  }

  private async save(
    d: ClaimedDisposal,
    next: { state: ClaimedDisposal['state']; replica?: DisposalReplicaStatus; nextAttemptAt: Date },
  ): Promise<void> {
    await this.prisma.$executeRaw`
      UPDATE archive_disposals SET state = ${next.state},
        ${next.replica ? Prisma.sql`replica_status = ${JSON.stringify(next.replica)},` : Prisma.empty}
        next_attempt_at = ${next.nextAttemptAt}, updated_at = NOW(3)
      WHERE id = ${d.id} AND requested_at = ${d.requestedAt}`;
    d.state = next.state;
    if (next.replica) d.replica = next.replica;
  }

  async gauges(): Promise<{ pending: number; oldestSeconds: number }> {
    const now = this.now();
    const [count] = await this.prisma.$queryRaw<Array<{ n: bigint | number }>>`
      SELECT COUNT(*) AS n FROM (SELECT 1 FROM archive_disposals
        WHERE state IN ('shredded', 'objects_deleted', 'index_deleted')
          ${orgFilter('organization_id', this.options.organizationIds)}
        LIMIT ${PENDING_CAP}) AS bounded`;
    const [oldest] = await this.prisma.$queryRaw<Array<{ at: Date | null }>>`
      SELECT MIN(requested_at) AS at FROM archive_disposals
      WHERE state IN ('shredded', 'objects_deleted', 'index_deleted')
        ${orgFilter('organization_id', this.options.organizationIds)}`;
    const pending = Number(count?.n ?? 0);
    const oldestSeconds =
      oldest?.at instanceof Date ? Math.max(0, (now.getTime() - oldest.at.getTime()) / 1000) : 0;
    this.options.metrics.disposalsPending.set(pending);
    this.options.metrics.disposalOldestPending.set(oldestSeconds);
    return { pending, oldestSeconds };
  }
}

/**
 * The registry purge contract (step 1.1, `packages/database/src/partitioning/executor.ts`):
 * whoever deletes the last reference to a message below the purge watermark deletes its
 * `message_identities` row in the same transaction — when no `email_messages` row, no
 * `quarantine_messages` row and no live `email_archives` row references it (step 8.6: nor an
 * `archive_record_sources` row of a merged copy).
 */
export async function deleteRegistryRowIfUnreferenced(
  tx: Db,
  d: { messageId: bigint; messageReceivedAt: Date; organizationId: bigint },
): Promise<boolean> {
  const [mark] = await tx.$queryRaw<Array<{ value: bigint | number | null }>>`
    SELECT value FROM maintenance_watermarks WHERE name = ${REGISTRY_WATERMARK}`;
  if (mark?.value === null || mark?.value === undefined) return false;
  if (d.messageId >= big(mark.value)) return false;
  const deleted = await tx.$executeRaw`
    DELETE FROM message_identities
    WHERE id = ${d.messageId} AND organization_id = ${d.organizationId}
      AND NOT EXISTS (SELECT 1 FROM email_messages m
        WHERE m.id = ${d.messageId} AND m.received_at = ${d.messageReceivedAt})
      AND NOT EXISTS (SELECT 1 FROM quarantine_messages q WHERE q.message_id = ${d.messageId})
      AND NOT EXISTS (SELECT 1 FROM email_archives a
        WHERE a.message_id = ${d.messageId} AND a.deleted_at IS NULL)
      AND NOT EXISTS (SELECT 1 FROM archive_record_sources s
        WHERE s.message_id = ${d.messageId})`;
  return deleted === 1;
}

/**
 * Whether the record's document is still searchable: an `ids` count through the tenant alias
 * (routing = organization), which spans every index of the active version (a GET by id cannot
 * address an alias over several indices). A missing alias counts 0.
 */
export async function documentVisible(
  search: OpenSearchService,
  prefix: string,
  d: { organizationId: bigint; messagePublicId: string },
): Promise<boolean> {
  const n = await search.count(
    tenantAliasName(prefix, d.organizationId),
    { query: { bool: { filter: [{ ids: { values: [d.messagePublicId] } }] } } },
    { routing: d.organizationId.toString() },
  );
  return n > 0;
}

export { OPEN_STATES };
