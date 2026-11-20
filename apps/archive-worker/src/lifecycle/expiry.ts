import {
  archivePartiesSchema,
  decideExpiry,
  type ExpiryDecision,
  type LegalHoldFacts,
  type LegalHoldRow,
  normalizeAddress,
} from '@email-gateway/archive';
import { type EmailArchive, Prisma, type PrismaClient } from '@email-gateway/database';
import type { Logger } from '@email-gateway/logger';
import type { ReplicaTarget } from '../config';
import type { ArchiveMetrics } from '../metrics/archive-metrics';
import { archiveOrganizations, type Db, systemAudit } from '../shared/db';
import { errorFields } from '../shared/errors';
import type { ArchiveStorage } from '../storage/archive-storage';
import { recordVersionsWithMerged } from '../storage/record-versions';
import { decideDisposal } from './disposal';

export const LIFECYCLE_LOCK = 'eg:archive-lifecycle';
export const LIFECYCLE_RUN_ACTION = 'archive.lifecycle_run';

export type ExpiryOutcomeLabel = ExpiryDecision['outcome'] | 'failed' | 'skipped';

export interface LifecycleCounts {
  policy_extended: number;
  held: number;
  review: number;
  disposed: number;
  failed: number;
  skipped: number;
}

const emptyCounts = (): LifecycleCounts => ({
  policy_extended: 0,
  held: 0,
  review: 0,
  disposed: 0,
  failed: 0,
  skipped: 0,
});

/** The hold facts of a record from its writer row (A12): parties JSON, direction, received_at. */
export function holdFactsOf(
  record: Pick<
    EmailArchive,
    'receivedAt' | 'direction' | 'envelopeFrom' | 'headerFrom' | 'parties'
  >,
): LegalHoldFacts {
  const parties = archivePartiesSchema.safeParse(record.parties);
  const recipients = parties.success ? parties.data.recipients : [];
  const senders = [record.envelopeFrom, record.headerFrom]
    .map((a) => normalizeAddress(a))
    .filter((a): a is string => a !== null);
  return {
    receivedAt: record.receivedAt,
    direction: record.direction,
    recipientDirections: recipients.map((r) => r.direction),
    senderAddresses: senders,
    recipientAddresses: recipients
      .map((r) => normalizeAddress(r.address))
      .filter((a): a is string => a !== null),
  };
}

/**
 * Serializes a disposal decision with legal hold creation (A12/A14: the hold check at disposal is
 * authoritative). Hold creation (api `LegalHoldsService.create`) locks the organization row
 * `FOR UPDATE` before it inserts the hold; a decision takes the same row `FOR SHARE` before it
 * locks the record and reads the holds. A hold being created makes the decision wait for its
 * commit (and the following read, READ COMMITTED, sees it); a decision in progress makes the hold
 * creation wait until the record is decided. Lock order everywhere: organization, then record.
 * Returns false when the organization row is gone.
 */
export async function lockOrganizationForHolds(db: Db, organizationId: bigint): Promise<boolean> {
  const rows = await db.$queryRaw<Array<{ id: bigint | number }>>`
    SELECT id FROM organizations WHERE id = ${organizationId} FOR SHARE`;
  return rows.length === 1;
}

/** Active holds of the organization (authoritative, on the writer, inside the transaction). */
export async function activeHolds(db: Db, organizationId: bigint): Promise<LegalHoldRow[]> {
  const rows = await db.archiveLegalHold.findMany({
    where: { organizationId, status: 'active' },
    select: { organizationId: true, publicId: true, criteria: true, criteriaVersion: true },
    take: 10_000,
  });
  return rows
    .filter((h) => h.organizationId === organizationId)
    .map((h) => ({ id: h.publicId, criteria: h.criteria, criteriaVersion: h.criteriaVersion }));
}

/**
 * The expiry job (A13, lifecycle role, leader `GET_LOCK('eg:archive-lifecycle')`): organization
 * by organization, batches of `ARCHIVE_LIFECYCLE_BATCH_SIZE` from `(organization_id, status,
 * retain_until)` (`active`, `retain_until <= now`); per record ONE writer transaction with the row
 * locked (`SELECT … FOR UPDATE`), `decideExpiry` with the live policy and the active holds (legacy
 * and `archive-hold/1`; unparsable = match all): extended retention (`policy_extended`), a hold
 * (`held`, `legal_hold = 1`), `review` (`expiry_review`), or the disposal decision of A14. Object
 * Lock retention of every version is extended with `PutObjectRetention` BEFORE the row is updated
 * (extend-only). One system audit row `archive.lifecycle_run` per organization and run with the
 * counts (never per record; the per-record trail is `archive_disposals`).
 */
export class ExpiryJob {
  private readonly now: () => Date;

  constructor(
    private readonly prisma: PrismaClient,
    private readonly options: {
      storage: ArchiveStorage;
      metrics: ArchiveMetrics;
      logger: Logger;
      batchSize: number;
      maxBatches?: number;
      holdExtensionDays: number;
      reviewExtensionDays: number;
      daySeconds: number;
      replicaTargets: readonly ReplicaTarget[];
      organizationIds?: readonly bigint[];
      now?: () => Date;
    },
  ) {
    this.now = options.now ?? (() => new Date());
  }

  async runOnce(): Promise<Map<string, LifecycleCounts>> {
    const out = new Map<string, LifecycleCounts>();
    for (const org of await archiveOrganizations(this.prisma, this.options.organizationIds)) {
      const counts = await this.runOrganization(org);
      out.set(org.toString(), counts);
    }
    return out;
  }

  async runOrganization(organizationId: bigint): Promise<LifecycleCounts> {
    const counts = emptyCounts();
    const failed = new Set<string>();
    const maxBatches = this.options.maxBatches ?? 10;
    const runAt = this.now();
    for (let batch = 0; batch < maxBatches; batch += 1) {
      const now = this.now();
      const due = await this.prisma.$queryRaw<Array<{ id: bigint | number; received_at: Date }>>`
        SELECT id, received_at FROM email_archives
        WHERE organization_id = ${organizationId} AND status = 'active' AND retain_until <= ${now}
        ORDER BY retain_until LIMIT ${this.options.batchSize + failed.size}`;
      const work = due.filter((d) => !failed.has(`${String(d.id)}:${d.received_at.getTime()}`));
      if (work.length === 0) break;
      for (const d of work.slice(0, this.options.batchSize)) {
        const label = await this.decideRecord(organizationId, BigInt(d.id), d.received_at);
        counts[label] += 1;
        this.options.metrics.expiry.inc({ outcome: label });
        if (label === 'failed' || label === 'skipped') {
          failed.add(`${String(d.id)}:${d.received_at.getTime()}`);
        }
      }
      if (work.length < this.options.batchSize) break;
    }
    const total =
      counts.policy_extended + counts.held + counts.review + counts.disposed + counts.failed;
    if (total > 0) {
      await systemAudit(this.prisma, {
        organizationId,
        action: LIFECYCLE_RUN_ACTION,
        resourceType: 'archive_lifecycle',
        resourceId: null,
        correlationId: `archive-lifecycle:${runAt.toISOString()}`,
        metadata: { ...counts },
      });
    }
    return counts;
  }

  /** One record, one transaction (A13): lock the row, decide, extend locks, apply. */
  async decideRecord(
    organizationId: bigint,
    id: bigint,
    receivedAt: Date,
  ): Promise<ExpiryOutcomeLabel> {
    try {
      return await this.prisma.$transaction(async (tx) => {
        // Organization first (shared with hold creation), then the record (lock order).
        if (!(await lockOrganizationForHolds(tx, organizationId))) return 'skipped';
        const now = this.now();
        const [locked] = await tx.$queryRaw<Array<{ id: bigint | number }>>`
          SELECT id FROM email_archives
          WHERE id = ${id} AND received_at = ${receivedAt} AND organization_id = ${organizationId}
          FOR UPDATE`;
        if (locked === undefined) return 'skipped';
        const record = await tx.emailArchive.findUnique({
          where: { id_receivedAt: { id, receivedAt } },
        });
        if (
          record === null ||
          record.organizationId !== organizationId ||
          record.status !== 'active' ||
          record.retainUntil.getTime() > now.getTime()
        ) {
          return 'skipped';
        }
        const decision = await decideRecordExpiry(tx, record, {
          now,
          mode: 'expiry',
          holdExtensionDays: this.options.holdExtensionDays,
          reviewExtensionDays: this.options.reviewExtensionDays,
          daySeconds: this.options.daySeconds,
        });
        await applyExpiryDecision(tx, record, decision, {
          storage: this.options.storage,
          metrics: this.options.metrics,
          replicaTargets: this.options.replicaTargets,
          reason: 'retention_expired',
          requestedByUserId: null,
          now,
        });
        return decision.outcome;
      });
    } catch (error) {
      this.options.logger.warn(
        { organizationId: organizationId.toString(), ...errorFields(error) },
        'archive expiry decision failed; retried next run',
      );
      return 'failed';
    }
  }
}

/** `decideExpiry` on writer facts: the record's live policy and the organization's active holds. */
export async function decideRecordExpiry(
  tx: Db,
  record: EmailArchive,
  input: {
    now: Date;
    mode: 'expiry' | 'manual_dispose';
    holdExtensionDays: number;
    reviewExtensionDays: number;
    daySeconds: number;
  },
): Promise<ExpiryDecision> {
  const policy =
    record.retentionPolicyId === null
      ? null
      : await tx.archiveRetentionPolicy.findUnique({
          where: { id: record.retentionPolicyId },
          select: { organizationId: true, retentionDays: true, onExpiry: true, deletedAt: true },
        });
  const live = policy !== null && policy.organizationId === record.organizationId;
  return decideExpiry({
    now: input.now,
    mode: input.mode,
    record: {
      receivedAt: record.receivedAt,
      retainUntil: record.retainUntil,
      expiryAction: record.expiryAction,
      lockMode: record.lockMode,
      lockUntil: record.lockUntil,
      status: record.status === 'expiry_review' ? 'expiry_review' : 'active',
    },
    policy: live
      ? {
          retentionDays: policy.retentionDays,
          onExpiry: policy.onExpiry,
          live: policy.deletedAt === null,
        }
      : null,
    holds: await activeHolds(tx, record.organizationId),
    holdFacts: holdFactsOf(record),
    holdExtensionDays: input.holdExtensionDays,
    reviewExtensionDays: input.reviewExtensionDays,
    daySeconds: input.daySeconds,
  });
}

/**
 * Applies a decision inside the record's transaction: Object Lock extension of every recorded
 * version first (extend-only), then the row (retention, hold flag, review state) and an index
 * upsert — or the disposal decision (A14 step 1).
 */
export async function applyExpiryDecision(
  tx: Prisma.TransactionClient,
  record: EmailArchive,
  decision: ExpiryDecision,
  input: {
    storage: ArchiveStorage;
    metrics: ArchiveMetrics;
    replicaTargets: readonly ReplicaTarget[];
    reason: 'retention_expired' | 'review_disposed' | 'organization_deleted';
    requestedByUserId: bigint | null;
    now: Date;
  },
): Promise<void> {
  if (decision.outcome === 'disposed') {
    await decideDisposal(tx, record, {
      reason: input.reason,
      requestedByUserId: input.requestedByUserId,
      replicaTargets: input.replicaTargets,
      now: input.now,
    });
    input.metrics.disposals.inc({ stage: 'decided', result: 'ok' });
    return;
  }
  if (decision.lockUntil !== null && record.lockMode !== 'none') {
    for (const v of recordVersionsWithMerged(record)) {
      try {
        await input.storage.putRetention(input.storage.buckets.archive, v.key, v.versionId, {
          mode: record.lockMode,
          until: decision.lockUntil,
        });
        input.metrics.objectLock.inc({ op: 'extend', result: 'ok' });
      } catch (error) {
        input.metrics.objectLock.inc({ op: 'extend', result: 'failed' });
        throw error;
      }
    }
  }
  await tx.$executeRaw`
    UPDATE email_archives SET retain_until = ${decision.retainUntil},
      ${decision.lockUntil !== null && record.lockMode !== 'none' ? Prisma.sql`lock_until = ${decision.lockUntil},` : Prisma.empty}
      ${decision.legalHold ? Prisma.sql`legal_hold = 1,` : Prisma.empty}
      ${decision.status === 'expiry_review' ? Prisma.sql`status = 'expiry_review',` : Prisma.empty}
      updated_at = NOW(3)
    WHERE id = ${record.id} AND received_at = ${record.receivedAt}`;
  await tx.archiveIndexQueue.create({
    data: {
      organizationId: record.organizationId,
      messageId: record.messageId,
      receivedAt: record.receivedAt,
      messagePublicId: record.messagePublicId,
      op: 'upsert',
    },
    select: { id: true },
  });
}
