import {
  archiveDayPrefixOf,
  disposalObjectsSchema,
  type ObjectLockMode,
  readDisposalObjects,
} from '@email-gateway/archive';
import type { OpenSearchService } from '@email-gateway/common';
import type { PrismaClient } from '@email-gateway/database';
import type { Logger } from '@email-gateway/logger';
import type { ReplicaTarget } from '../config';
import type { ArchiveMetrics } from '../metrics/archive-metrics';
import {
  archiveOrganizations,
  deleteCursor,
  orgAllowed,
  readCursor,
  writeCursor,
} from '../shared/db';
import { errorFields } from '../shared/errors';
import {
  type ArchiveStorage,
  LOCK_FLOOR_MS,
  type ObjectLockState,
} from '../storage/archive-storage';
import { recordVersionsWithMerged } from '../storage/record-versions';
import { type DisposalObjects, documentVisible } from './disposal';

const DAY_MS = 86_400_000;
/** Orphans are versions older than this that no record or open disposal references (A15). */
export const ORPHAN_MIN_AGE_MS = DAY_MS;
const LOCK_RANK: Record<ObjectLockMode, number> = { none: 0, governance: 1, compliance: 2 };

export const LOCK_PASS_PREFIX = 'archive:lock:';
export const lockPassCursor = (organizationId: bigint): string =>
  `${LOCK_PASS_PREFIX}${organizationId.toString()}`;
export const orphanCursor = (organizationId: bigint): string =>
  `archive:orphans:${organizationId.toString()}`;
/** A day prefix holding locked orphans, retried after their lock (`last_event_at`). */
export const orphanDayCursor = (organizationId: bigint, day: string): string =>
  `archive:orphans:${organizationId.toString()}:${day}`;
export const DISPOSAL_VERIFY_CURSOR = 'archive:disposal-verify';

const utcDay = (d: Date): string => d.toISOString().slice(0, 10);

export interface LockPassReport {
  organizations: number;
  applied: number;
  finished: number;
  unavailable: number;
}

/**
 * The "apply lock" pass (A10): after a tenant moved to a stricter Object Lock mode, the api
 * writes the `stream_cursors` row `archive:lock:<organizationId>` (position = last record id
 * done, NULL/0 = from the start). In bounded batches, every `active`/`expiry_review` record with a
 * weaker `lock_mode` gets every recorded version locked in the tenant's mode until its retention
 * (`PutObjectRetention`; `governance → compliance` needs `BypassGovernanceRetention`, WP1
 * deviation 6) before its row is updated, and an index upsert. The cursor row is deleted when the
 * pass is done.
 */
export class LockPass {
  constructor(
    private readonly prisma: PrismaClient,
    private readonly options: {
      storage: ArchiveStorage;
      lockState: ObjectLockState;
      metrics: ArchiveMetrics;
      logger: Logger;
      batchSize: number;
      organizationIds?: readonly bigint[];
      now?: () => Date;
    },
  ) {}

  async runOnce(): Promise<LockPassReport> {
    const report: LockPassReport = { organizations: 0, applied: 0, finished: 0, unavailable: 0 };
    const cursors = await this.prisma.streamCursor.findMany({
      where: { name: { startsWith: LOCK_PASS_PREFIX } },
      select: { name: true, positionId: true },
      take: 1_000,
    });
    for (const c of cursors) {
      const match = /^archive:lock:([1-9][0-9]{0,19})$/.exec(c.name);
      if (!match) continue;
      const org = BigInt(match[1]!);
      if (!orgAllowed(org, this.options.organizationIds)) continue;
      report.organizations += 1;
      if (this.options.lockState.available !== true) {
        report.unavailable += 1;
        this.options.metrics.objectLock.inc({ op: 'apply', result: 'unavailable' });
        continue;
      }
      try {
        const done = await this.runOrganization(org, c.positionId ?? 0n, report);
        if (done) report.finished += 1;
      } catch (error) {
        this.options.metrics.objectLock.inc({ op: 'apply', result: 'failed' });
        this.options.logger.warn(
          { organizationId: org.toString(), ...errorFields(error) },
          'archive lock pass failed; retried next run',
        );
      }
    }
    return report;
  }

  private async runOrganization(
    organizationId: bigint,
    position: bigint,
    report: LockPassReport,
  ): Promise<boolean> {
    const settings = await this.prisma.archiveSetting.findUnique({
      where: { organizationId },
      select: { organizationId: true, objectLockMode: true },
    });
    const mode: ObjectLockMode = settings?.objectLockMode ?? 'none';
    const name = lockPassCursor(organizationId);
    if (mode === 'none') {
      await deleteCursor(this.prisma, name);
      return true;
    }
    const records = await this.prisma.emailArchive.findMany({
      where: {
        organizationId,
        id: { gt: position },
        status: { in: ['active', 'expiry_review'] },
      },
      orderBy: { id: 'asc' },
      take: this.options.batchSize,
    });
    const now = this.options.now?.() ?? new Date();
    for (const record of records) {
      if (record.organizationId !== organizationId) continue;
      if (LOCK_RANK[record.lockMode] >= LOCK_RANK[mode]) continue;
      const until = new Date(
        Math.max(
          record.retainUntil.getTime(),
          record.lockUntil?.getTime() ?? 0,
          now.getTime() + LOCK_FLOOR_MS,
        ),
      );
      for (const v of recordVersionsWithMerged(record)) {
        await this.options.storage.putRetention(
          this.options.storage.buckets.archive,
          v.key,
          v.versionId,
          { mode: mode, until },
          { bypassGovernance: record.lockMode === 'governance' },
        );
      }
      await this.prisma.$transaction(async (tx) => {
        await tx.$executeRaw`
          UPDATE email_archives SET lock_mode = ${mode}, lock_until = ${until}, updated_at = NOW(3)
          WHERE id = ${record.id} AND received_at = ${record.receivedAt}
            AND status IN ('active', 'expiry_review')`;
        await tx.archiveIndexQueue.create({
          data: {
            organizationId,
            messageId: record.messageId,
            receivedAt: record.receivedAt,
            messagePublicId: record.messagePublicId,
            op: 'upsert',
          },
          select: { id: true },
        });
      });
      report.applied += 1;
      this.options.metrics.objectLock.inc({ op: 'apply', result: 'ok' });
    }
    const last = records[records.length - 1];
    if (records.length < this.options.batchSize) {
      await deleteCursor(this.prisma, name);
      return true;
    }
    await writeCursor(this.prisma, name, last!.id, now);
    return false;
  }
}

export interface OrphanReport {
  days: number;
  scanned: number;
  deleted: number;
  locked: number;
  failed: number;
}

/**
 * Orphan reconciliation (A15, lifecycle role): per organization and capture-day prefix
 * (`org/<org>/archive/<yyyy>/<mm>/<dd>/`), object versions older than 24 h that are referenced
 * neither by a record's `objects` nor by an open disposal are deleted (governance bypass for
 * governance orphans, `ARCHIVE_GOVERNANCE_BYPASS_ORPHANS`); a compliance orphan is recorded
 * (`stream_cursors` `archive:orphans:<org>:<day>`, `last_event_at` = its retain-until) and the day
 * is scanned again after its lock. Days scanned per run: today and yesterday, one rotating day of
 * the capture window (intent max age + outcome window), and every recorded day whose lock ended.
 */
export class OrphanReconciler {
  constructor(
    private readonly prisma: PrismaClient,
    private readonly options: {
      storage: ArchiveStorage;
      metrics: ArchiveMetrics;
      logger: Logger;
      governanceBypass: boolean;
      windowDays: number;
      organizationIds?: readonly bigint[];
      now?: () => Date;
    },
  ) {}

  private now(): Date {
    return this.options.now?.() ?? new Date();
  }

  async runOnce(): Promise<OrphanReport> {
    const report: OrphanReport = { days: 0, scanned: 0, deleted: 0, locked: 0, failed: 0 };
    for (const org of await archiveOrganizations(this.prisma, this.options.organizationIds)) {
      try {
        for (const day of await this.daysOf(org)) await this.scanDay(org, day, report);
      } catch (error) {
        report.failed += 1;
        this.options.logger.warn(
          { organizationId: org.toString(), ...errorFields(error) },
          'archive orphan reconciliation failed for an organization; retried next run',
        );
      }
    }
    return report;
  }

  private async daysOf(organizationId: bigint): Promise<string[]> {
    const now = this.now();
    const today = new Date(`${utcDay(now)}T00:00:00.000Z`);
    const days = new Set([utcDay(today), utcDay(new Date(today.getTime() - DAY_MS))]);
    const name = orphanCursor(organizationId);
    const cursor = await readCursor(this.prisma, name);
    const oldest = new Date(today.getTime() - this.options.windowDays * DAY_MS);
    let next =
      cursor?.lastEventAt instanceof Date
        ? new Date(cursor.lastEventAt.getTime() - DAY_MS)
        : new Date(today.getTime() - 2 * DAY_MS);
    if (next.getTime() < oldest.getTime()) next = new Date(today.getTime() - 2 * DAY_MS);
    days.add(utcDay(next));
    await writeCursor(this.prisma, name, null, next);
    const due = await this.prisma.streamCursor.findMany({
      where: {
        name: { startsWith: `${name}:` },
        lastEventAt: { lte: now },
      },
      select: { name: true },
      take: 100,
    });
    for (const d of due) {
      const day = d.name.slice(name.length + 1);
      if (/^\d{4}-\d{2}-\d{2}$/.test(day)) days.add(day);
      await deleteCursor(this.prisma, d.name);
    }
    return [...days];
  }

  async scanDay(organizationId: bigint, day: string, report: OrphanReport): Promise<void> {
    const storage = this.options.storage;
    const dayStart = new Date(`${day}T00:00:00.000Z`);
    const prefix = archiveDayPrefixOf(organizationId, dayStart);
    const cutoff = this.now().getTime() - ORPHAN_MIN_AGE_MS;
    report.days += 1;
    const candidates: Array<{
      key: string;
      versionId: string;
      deleteMarker: boolean;
      message: string;
    }> = [];
    for await (const v of storage.listVersions(storage.buckets.archive, prefix)) {
      report.scanned += 1;
      if (!v.key.startsWith(prefix)) continue;
      if (v.lastModified !== null && v.lastModified.getTime() > cutoff) continue;
      const message = v.key.slice(prefix.length).split('/')[0] ?? '';
      candidates.push({ ...v, message });
    }
    if (candidates.length === 0) return;
    const messages = [...new Set(candidates.map((c) => c.message))];
    const dayEnd = new Date(dayStart.getTime() + DAY_MS);
    const records = await this.prisma.emailArchive.findMany({
      where: {
        organizationId,
        receivedAt: { gte: dayStart, lt: dayEnd },
        messagePublicId: { in: messages },
      },
      select: { organizationId: true, objects: true },
    });
    const referenced = new Set<string>();
    for (const r of records) {
      for (const v of recordVersionsWithMerged(r)) referenced.add(`${v.key}\0${v.versionId}`);
    }
    // Step 8.6 D7: objects of a merged copy lie under the merged message's prefix and are named
    // by the record it was merged into (`archive_record_sources` → the record's `objects`).
    const mergedSources = await this.prisma.archiveRecordSource.findMany({
      where: {
        organizationId,
        messageReceivedAt: { gte: dayStart, lt: dayEnd },
        messagePublicId: { in: messages },
      },
      select: { organizationId: true, archiveId: true, archiveReceivedAt: true },
    });
    const owners = mergedSources.filter((x) => x.organizationId === organizationId);
    if (owners.length > 0) {
      const ownerRecords = await this.prisma.emailArchive.findMany({
        where: {
          organizationId,
          OR: owners.map((o) => ({ id: o.archiveId, receivedAt: o.archiveReceivedAt })),
        },
        select: { organizationId: true, objects: true },
      });
      for (const r of ownerRecords) {
        for (const v of recordVersionsWithMerged(r)) referenced.add(`${v.key}\0${v.versionId}`);
      }
    }
    const open = await this.prisma.archiveDisposal.findMany({
      where: {
        organizationId,
        messagePublicId: { in: messages },
        state: { in: ['shredded', 'objects_deleted', 'index_deleted'] },
      },
      select: { messagePublicId: true, objects: true },
    });
    const disposing = new Set(open.map((d) => d.messagePublicId));
    // A disposal in progress of a record with merged copies covers their prefixes too.
    const disposingKeys = new Set<string>();
    for (const d of await this.prisma.archiveDisposal.findMany({
      where: { organizationId, state: { in: ['shredded', 'objects_deleted', 'index_deleted'] } },
      select: { objects: true },
      take: 1_000,
    })) {
      const parsed = disposalObjectsSchema.safeParse(
        typeof d.objects === 'string' ? (JSON.parse(d.objects) as unknown) : d.objects,
      );
      if (parsed.success) for (const v of parsed.data.versions) disposingKeys.add(v.key);
    }
    let lockedUntil = 0;
    for (const c of candidates) {
      if (disposing.has(c.message) || disposingKeys.has(c.key)) continue;
      if (!c.deleteMarker && referenced.has(`${c.key}\0${c.versionId}`)) continue;
      try {
        const result = await storage.deleteVersion(storage.buckets.archive, c.key, c.versionId, {
          bypassGovernance: this.options.governanceBypass,
        });
        if (result === 'locked') {
          const retention = await storage.getRetention(storage.buckets.archive, c.key, c.versionId);
          lockedUntil = Math.max(lockedUntil, retention?.until.getTime() ?? Date.now() + DAY_MS);
          report.locked += 1;
          this.options.metrics.orphans.inc({ result: 'locked' });
        } else {
          report.deleted += 1;
          this.options.metrics.orphans.inc({ result: 'deleted' });
        }
      } catch (error) {
        report.failed += 1;
        this.options.metrics.orphans.inc({ result: 'failed' });
        this.options.logger.warn({ ...errorFields(error) }, 'archive orphan not deleted');
      }
    }
    if (lockedUntil > 0) {
      await writeCursor(
        this.prisma,
        orphanDayCursor(organizationId, day),
        null,
        new Date(lockedUntil + 1_000),
      );
    }
  }
}

/** Keeps the type of a disposal's objects JSON for verification readers. */
export type { DisposalObjects };

/**
 * Disposal verification (A15, lifecycle role): a rotating sample of completed disposals is
 * checked — every recorded version must be gone from the archive bucket and each replica target
 * (HEAD), and the index document absent. A survivor re-opens the disposal at `shredded` (objects)
 * or `objects_deleted` (document).
 */
export class DisposalVerifier {
  constructor(
    private readonly prisma: PrismaClient,
    private readonly options: {
      storage: ArchiveStorage;
      search: OpenSearchService | null;
      indexPrefix: string;
      replicaTargets: readonly ReplicaTarget[];
      metrics: ArchiveMetrics;
      logger: Logger;
      sampleSize: number;
      cursorName?: string;
      organizationIds?: readonly bigint[];
      now?: () => Date;
    },
  ) {}

  async runOnce(): Promise<{ checked: number; reopened: number }> {
    const cursorName = this.options.cursorName ?? DISPOSAL_VERIFY_CURSOR;
    const cursor = await readCursor(this.prisma, cursorName);
    const after = cursor?.positionId ?? 0n;
    const rows = await this.prisma.archiveDisposal.findMany({
      where: {
        state: 'completed',
        id: { gt: after },
        ...(this.options.organizationIds
          ? { organizationId: { in: [...this.options.organizationIds] } }
          : {}),
      },
      orderBy: { id: 'asc' },
      take: this.options.sampleSize,
      select: {
        id: true,
        requestedAt: true,
        organizationId: true,
        messagePublicId: true,
        messageReceivedAt: true,
        objects: true,
      },
    });
    let reopened = 0;
    for (const d of rows) {
      const versions = readDisposalObjects(d.objects, {
        organizationId: d.organizationId,
        receivedAt: d.messageReceivedAt,
        messagePublicId: d.messagePublicId,
      }).objects.versions;
      let objectSurvived = false;
      const storage = this.options.storage;
      for (const bucket of [
        storage.buckets.archive,
        ...this.options.replicaTargets.map((t) => t.bucket),
      ]) {
        for (const v of versions) {
          if (v.versionId === null) continue;
          if (bucket !== storage.buckets.archive) {
            // Replica version ids differ from the source; check the key prefix instead.
            for await (const listed of storage.listVersions(bucket, v.key)) {
              if (listed.key === v.key && !listed.deleteMarker) objectSurvived = true;
            }
          } else if (await storage.exists(bucket, v.key, v.versionId)) {
            objectSurvived = true;
          }
        }
      }
      let docSurvived = false;
      if (!objectSurvived && this.options.search !== null) {
        docSurvived = await documentVisible(this.options.search, this.options.indexPrefix, d);
      }
      if (objectSurvived || docSurvived) {
        reopened += 1;
        const state = objectSurvived ? 'shredded' : 'objects_deleted';
        await this.prisma.$executeRaw`
          UPDATE archive_disposals SET state = ${state}, attempts = 0, completed_at = NULL,
            next_attempt_at = NOW(3), last_error_code = 'verification_reopened', updated_at = NOW(3)
          WHERE id = ${d.id} AND requested_at = ${d.requestedAt} AND state = 'completed'`;
        this.options.metrics.disposals.inc({ stage: 'verify', result: 'reopened' });
        this.options.logger.warn(
          { disposalId: d.id.toString(), state },
          'completed archive disposal re-opened by verification',
        );
      } else {
        this.options.metrics.disposals.inc({ stage: 'verify', result: 'ok' });
      }
    }
    const last = rows[rows.length - 1];
    await writeCursor(
      this.prisma,
      cursorName,
      rows.length < this.options.sampleSize ? 0n : last!.id,
      this.options.now?.() ?? new Date(),
    );
    return { checked: rows.length, reopened };
  }
}
