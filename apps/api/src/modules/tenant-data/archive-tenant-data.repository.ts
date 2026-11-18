import { Injectable } from '@nestjs/common';
import { PrismaService } from '@email-gateway/common';
import type { Prisma } from '@email-gateway/database';
import type { TenantScope } from '../../auth-contracts/tenant-scope';
import {
  ArchiveRecordsRepository,
  recordSelect,
} from '../archive/repositories/archive-records.repository';

/**
 * The organization's archive and eDiscovery tables in the order phase 2 of the purge deletes
 * them (step 8.1 A24): every `organization_id` is RESTRICT; hits before their searches, exports
 * (grants cascade) before searches and cases, searches and custodians and released holds before
 * their cases, settings before the retention policies they point to. `archive_disposals` and
 * `audit_logs` are kept (compliance tier); `archive_index_queue` keeps the `purge_org` op for the
 * archive-worker; tenant keys are destroyed last (`wrapped_key = NULL`), not deleted.
 */
export const ARCHIVE_PURGE_ORDER = [
  'archive_capture_intents',
  'archive_index_checks',
  'archive_download_grants',
  'ediscovery_search_hits',
  'ediscovery_exports',
  'ediscovery_searches',
  'ediscovery_custodians',
  'archive_legal_holds',
  'ediscovery_cases',
  'archive_settings',
  'archive_retention_policies',
] as const;
export type ArchivePurgeTable = (typeof ARCHIVE_PURGE_ORDER)[number];

/** Rows one purge statement (or one disposal transaction) handles. */
export const ARCHIVE_PURGE_BATCH = 200;

export interface ArchivePurgeCounts {
  /** Records sent through the disposal decision by this call (phase 1). */
  disposalsRequested: number;
  /** Rows deleted per table (phase 2). */
  deleted: Record<ArchivePurgeTable, number>;
  /** Tenant key versions destroyed (phase 2). */
  keysDestroyed: number;
}

export interface ArchivePurgeResult {
  /** True when phase 2 ran: nothing of the organization's archive remains but the logs. */
  complete: boolean;
  counts: ArchivePurgeCounts;
}

/** Why the purge refused (nothing was changed). */
export class ArchivePurgeRefusedError extends Error {
  override readonly name = 'ArchivePurgeRefusedError';
  constructor(
    readonly reason: 'legal_hold' | 'retention',
    readonly count: number,
  ) {
    super(`archive purge refused: ${count} record(s) or hold(s) (${reason})`);
  }
}

type Tx = Prisma.TransactionClient;

/**
 * Deletes the archive of one organization for the organization purge (step 8.1 A24; the deferred
 * purge job of docs/runbooks/organization-deletion.md calls it next to the BEC, DLP, risk, policy
 * and quarantine purges). Resumable: call it until `complete`.
 *
 * - Refused (`ArchivePurgeRefusedError`, nothing changed) while an active legal hold exists or a
 *   live record's effective retention (stored retain-until, a running Object Lock, or the live
 *   policy's current days) is in the future.
 * - Phase 1: every remaining live record goes through the disposal decision (reason
 *   `organization_deleted`; crypto-shred, `archive_disposals`, index delete) in batches, each
 *   batch one writer transaction with the records locked, plus one `purge_org` index op. The
 *   archive-worker completes the disposals (objects, replica targets, index documents, rows).
 * - Phase 2 (no record and no unfinished disposal left): deletes the intents, index checks,
 *   grants, eDiscovery rows, released holds, cases, settings and policies in RESTRICT-safe order,
 *   then destroys every tenant key version (`wrapped_key = NULL`, `destroyed`). Export objects
 *   under `org/<org>/exports/` expire with their bucket tag rule; the disposal log and the audit
 *   trail stay.
 *
 * Writer only, `systemScope` of the organization being purged; never another organization's
 * rows.
 */
@Injectable()
export class ArchiveTenantDataRepository {
  constructor(
    private readonly prisma: PrismaService,
    private readonly records: ArchiveRecordsRepository,
  ) {}

  async purgeOrganization(
    scope: TenantScope,
    options: { now?: Date; batch?: number } = {},
  ): Promise<ArchivePurgeResult> {
    const batch = options.batch ?? ARCHIVE_PURGE_BATCH;
    if (!Number.isSafeInteger(batch) || batch < 1) throw new Error('batch must be positive');
    const now = options.now ?? new Date();
    const org = scope.organizationId;
    const holds = await this.prisma.archiveLegalHold.count({
      where: { organizationId: org, status: 'active' },
    });
    if (holds > 0) throw new ArchivePurgeRefusedError('legal_hold', holds);
    const retained = await this.retainedRecords(org, now);
    if (retained > 0) throw new ArchivePurgeRefusedError('retention', retained);

    const counts: ArchivePurgeCounts = {
      disposalsRequested: 0,
      deleted: Object.fromEntries(ARCHIVE_PURGE_ORDER.map((t) => [t, 0])) as Record<
        ArchivePurgeTable,
        number
      >,
      keysDestroyed: 0,
    };
    // Phase 1: the disposal decision for every live record, in batches.
    for (;;) {
      const done = await this.prisma.$transaction(
        async (tx) => {
          // Organization (shared with hold creation), then the records; holds re-checked inside
          // every batch, so a hold committed after the pre-check stops the purge (A12/A14).
          await this.records.lockOrganizationForHolds(tx, scope);
          const held = await tx.archiveLegalHold.count({
            where: { organizationId: org, status: 'active' },
          });
          if (held > 0) throw new ArchivePurgeRefusedError('legal_hold', held);
          const rows = await tx.$queryRaw<Array<{ id: bigint; received_at: Date }>>`
            SELECT id, received_at FROM email_archives
            WHERE organization_id = ${org} AND status IN ('active', 'expiry_review')
            ORDER BY id LIMIT ${batch}
            FOR UPDATE`;
          for (const row of rows) {
            const record = await tx.emailArchive.findFirst({
              where: { organizationId: org, id: row.id, receivedAt: row.received_at },
              select: recordSelect,
            });
            if (record === null || record.organizationId !== org) continue;
            await this.records.writeDisposalDecision(tx, scope, {
              record,
              reason: 'organization_deleted',
              requestedByUserId: null,
              now,
            });
          }
          return rows.length;
        },
        { timeout: 60_000 },
      );
      counts.disposalsRequested += done;
      if (done < batch) break;
    }
    if (counts.disposalsRequested > 0) await this.enqueuePurgeIndex(org, now);

    const [remainingRecords, openDisposals] = await Promise.all([
      this.prisma.emailArchive.count({ where: { organizationId: org } }),
      this.prisma.archiveDisposal.count({
        where: {
          organizationId: org,
          state: { in: ['shredded', 'objects_deleted', 'index_deleted'] },
        },
      }),
    ]);
    if (remainingRecords > 0 || openDisposals > 0) return { complete: false, counts };

    // Phase 2: the organization's archive configuration and eDiscovery rows.
    for (const table of ARCHIVE_PURGE_ORDER) {
      for (;;) {
        const deleted = await this.deleteBatch(this.prisma, table, org, batch);
        counts.deleted[table] += deleted;
        if (deleted < batch) break;
      }
    }
    counts.keysDestroyed = await this.prisma.$executeRaw`
      UPDATE archive_encryption_keys
      SET status = 'destroyed', wrapped_key = NULL, destroyed_at = ${now}
      WHERE organization_id = ${org} AND status <> 'destroyed'`;
    return { complete: true, counts };
  }

  /** Live records whose effective retention is in the future (A11 lazy extension, A10 locks). */
  private async retainedRecords(organizationId: bigint, now: Date): Promise<number> {
    const rows = await this.prisma.$queryRaw<Array<{ n: bigint }>>`
      SELECT COUNT(*) AS n FROM email_archives a
      LEFT JOIN archive_retention_policies p
        ON p.id = a.retention_policy_id AND p.organization_id = a.organization_id
       AND p.deleted_at IS NULL
      WHERE a.organization_id = ${organizationId} AND a.status IN ('active', 'expiry_review')
        AND (a.retain_until > ${now}
          OR (a.lock_until IS NOT NULL AND a.lock_until > ${now})
          OR (p.id IS NOT NULL AND DATE_ADD(a.received_at, INTERVAL p.retention_days DAY) > ${now}))`;
    return Number(rows[0]?.n ?? 0);
  }

  /** One `purge_org` op for the index role (alias and documents of the organization). */
  private async enqueuePurgeIndex(organizationId: bigint, now: Date): Promise<void> {
    const queued = await this.prisma.archiveIndexQueue.count({
      where: { organizationId, op: 'purge_org' },
    });
    if (queued > 0) return;
    await this.prisma.archiveIndexQueue.create({
      data: {
        organizationId,
        messageId: 0n,
        receivedAt: now,
        messagePublicId: '00000000-0000-0000-0000-000000000000',
        op: 'purge_org',
        availableAt: now,
      },
      select: { id: true },
    });
  }

  /** One batch; the table name comes from the fixed order list, never from input. */
  private deleteBatch(
    db: Tx | PrismaService,
    table: ArchivePurgeTable,
    organizationId: bigint,
    batch: number,
  ): Promise<number> {
    switch (table) {
      // Partitioned: no ORDER BY on a multi-partition DELETE.
      case 'archive_capture_intents':
        return db.$executeRaw`DELETE FROM archive_capture_intents
          WHERE organization_id = ${organizationId} LIMIT ${batch}`;
      case 'archive_index_checks':
        return db.$executeRaw`DELETE FROM archive_index_checks
          WHERE organization_id = ${organizationId} ORDER BY id LIMIT ${batch}`;
      case 'archive_download_grants':
        return db.$executeRaw`DELETE FROM archive_download_grants
          WHERE organization_id = ${organizationId} ORDER BY id LIMIT ${batch}`;
      case 'ediscovery_search_hits':
        return db.$executeRaw`DELETE FROM ediscovery_search_hits
          WHERE organization_id = ${organizationId} ORDER BY id LIMIT ${batch}`;
      case 'ediscovery_exports':
        return db.$executeRaw`DELETE FROM ediscovery_exports
          WHERE organization_id = ${organizationId} ORDER BY id LIMIT ${batch}`;
      case 'ediscovery_searches':
        return db.$executeRaw`DELETE FROM ediscovery_searches
          WHERE organization_id = ${organizationId} ORDER BY id LIMIT ${batch}`;
      case 'ediscovery_custodians':
        return db.$executeRaw`DELETE FROM ediscovery_custodians
          WHERE organization_id = ${organizationId} ORDER BY id LIMIT ${batch}`;
      case 'archive_legal_holds':
        return db.$executeRaw`DELETE FROM archive_legal_holds
          WHERE organization_id = ${organizationId} AND status = 'released'
          ORDER BY id LIMIT ${batch}`;
      case 'ediscovery_cases':
        return db.$executeRaw`DELETE FROM ediscovery_cases
          WHERE organization_id = ${organizationId} ORDER BY id LIMIT ${batch}`;
      case 'archive_settings':
        return db.$executeRaw`DELETE FROM archive_settings
          WHERE organization_id = ${organizationId} ORDER BY id LIMIT ${batch}`;
      case 'archive_retention_policies':
        return db.$executeRaw`DELETE FROM archive_retention_policies
          WHERE organization_id = ${organizationId} ORDER BY id LIMIT ${batch}`;
    }
  }
}
