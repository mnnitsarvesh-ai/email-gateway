import { Injectable } from '@nestjs/common';
import { disposalObjectsOf, disposalReplicaStatusOf } from '@email-gateway/archive';
import { PrismaReadService, PrismaService } from '@email-gateway/common';
import {
  type ArchiveDisposalReason,
  type ArchiveDisposalState,
  type ArchiveIntentStatus,
  type JournalIntakeSourceKind,
  type MessageIngestSource,
  Prisma,
} from '@email-gateway/database';
import { tenantWhere, type TenantScope } from '../../../auth-contracts/tenant-scope';
import { assertEcho } from '../../../http/listing/echo-check';
import type { TimeIdKey } from '../../messages/domain/v1-list';
import { clampTake } from '../../tenant-data/page';

type Tx = Prisma.TransactionClient;

/** The registry key of a message public id (`message_identities`). */
export interface MessageKeyRow {
  id: bigint;
  publicId: string;
  receivedAt: Date;
  organizationId: bigint;
}

export const recordSelect = {
  id: true,
  receivedAt: true,
  messageId: true,
  organizationId: true,
  messagePublicId: true,
  direction: true,
  capturedByJournal: true,
  capturedByPolicy: true,
  policyRuleRef: true,
  category: true,
  status: true,
  messageState: true,
  messageStateReason: true,
  envelopeFrom: true,
  headerFrom: true,
  subject: true,
  internetMessageId: true,
  parties: true,
  recipientCount: true,
  attachmentCount: true,
  archiveObjectKey: true,
  sha256: true,
  sizeBytes: true,
  objects: true,
  storedBytes: true,
  encryptionFormat: true,
  keyVersion: true,
  wrappedDek: true,
  lockMode: true,
  lockUntil: true,
  retentionPolicyId: true,
  retainUntil: true,
  expiryAction: true,
  legalHold: true,
  finalVerdict: true,
  finalAction: true,
  riskScore: true,
  malicious: true,
  scanRounds: true,
  settingsGeneration: true,
  outcomeRefreshedAt: true,
  archivedAt: true,
  deletedAt: true,
  // Step 8.6 D6/D7: copy sources, the intake source and merged copies.
  sourceGateway: true,
  sourceJournalIntake: true,
  intakeSourceId: true,
  mergedCount: true,
} satisfies Prisma.EmailArchiveSelect;

/** An `email_archives` row as the api reads it (the wrapped DEK only reaches the writer paths). */
export type RecordRow = Prisma.EmailArchiveGetPayload<{ select: typeof recordSelect }>;

/** A legal hold row (organization-wide holds of the matcher and the detail route). */
export interface HoldRefRow {
  id: bigint;
  publicId: string;
  name: string;
  criteria: unknown;
  criteriaVersion: string | null;
  casePublicId: string | null;
}

export interface CaptureIssueRow {
  id: bigint;
  receivedAt: Date;
  messageId: bigint;
  messagePublicId: string | null;
  status: ArchiveIntentStatus;
  skipReason: string | null;
  lastErrorCode: string | null;
  attempts: number;
  sourceJournal: boolean;
  sourcePolicy: boolean;
  nextCheckAt: Date;
  createdAt: Date;
}

export interface DisposalRow {
  id: bigint;
  requestedAt: Date;
  messagePublicId: string;
  messageReceivedAt: Date;
  reason: ArchiveDisposalReason;
  state: ArchiveDisposalState;
  sha256: string;
  sizeBytes: number;
  attempts: number;
  completedAt: Date | null;
}

export interface StatusCounts {
  intents: Partial<Record<ArchiveIntentStatus, number>>;
  oldestPendingAt: Date | null;
  records: { active: number; expiryReview: number; disposing: number };
  indexQueued: number;
  oldestQueuedAt: Date | null;
  disposalsInProgress: number;
  disposalsFailed: number;
  keys: { activeVersion: number | null; versions: number };
}

/** The decision transaction of a disposal (A14 step 1) for one record. */
export interface DisposalDecision {
  record: RecordRow;
  reason: ArchiveDisposalReason;
  requestedByUserId: bigint | null;
  now: Date;
}

const OPEN_DISPOSAL_STATES: ArchiveDisposalState[] = [
  'shredded',
  'objects_deleted',
  'index_deleted',
];

/** Step 8.6: merged copies of one record (`ARCHIVE_MAX_MERGED_COPIES` ≤ 8; bounded read). */
const MAX_RECORD_SOURCES = 16;

/** Step 8.6: one merged copy of a record (`archive_record_sources`). */
export interface RecordSourceRow {
  organizationId: bigint;
  archiveId: bigint;
  messageId: bigint;
  messageReceivedAt: Date;
  messagePublicId: string;
  source: MessageIngestSource;
  emlSha256: string;
  sizeBytes: number;
  contentVariant: boolean;
  recipientsAdded: number;
  mergedAt: Date;
}

/** Most active holds an organization can have (ARCHIVE_HOLDS_MAX_ACTIVE_PER_ORG upper bound). */
const MAX_HOLDS = 1_000;

/**
 * Archive records and their operational rows (step 8.1 A12–A15, A17, A19): `email_archives`
 * located through the registry (`message_identities`: public id → `(message_id, received_at)`),
 * the capture intents, the index queue and the disposal log. Replica reads for metadata views,
 * writer reads for every content and deciding path (A14 replica rule), writes inside the
 * caller's transaction. Every row is echo-checked on the organization and its key (D15).
 */
@Injectable()
export class ArchiveRecordsRepository {
  constructor(
    private readonly reader: PrismaReadService,
    private readonly writer: PrismaService,
  ) {}

  private get db() {
    return this.reader.client;
  }

  /** The registry key of a public id in the organization, or null (replica or writer). */
  async messageKey(
    scope: TenantScope,
    publicId: string,
    on: 'replica' | 'writer' | Tx = 'replica',
  ): Promise<MessageKeyRow | null> {
    const client = on === 'replica' ? this.db : on === 'writer' ? this.writer : on;
    const row = await client.messageIdentity.findFirst({
      where: tenantWhere(scope, { publicId }),
      select: { id: true, publicId: true, receivedAt: true, organizationId: true },
    });
    if (row === null) return null;
    assertEcho('archive.registry', [row], { organizationId: scope.organizationId, publicId });
    return row;
  }

  /** The live record of a message (`deleted_at` NULL), or null. */
  async record(
    scope: TenantScope,
    key: MessageKeyRow,
    on: 'replica' | 'writer' | Tx = 'replica',
  ): Promise<RecordRow | null> {
    const client = on === 'replica' ? this.db : on === 'writer' ? this.writer : on;
    const row = await client.emailArchive.findFirst({
      where: tenantWhere(scope, { messageId: key.id, receivedAt: key.receivedAt }),
      select: recordSelect,
    });
    if (row === null) return null;
    assertEcho('archive.record', [row], {
      organizationId: scope.organizationId,
      messageId: key.id,
      receivedAt: key.receivedAt,
    });
    return row;
  }

  /**
   * The organization row `FOR SHARE` (writer): serializes a disposal decision with legal hold
   * creation, which locks the same row `FOR UPDATE` before inserting the hold (A12/A14; review
   * finding of step 8.1). Take it BEFORE `lockRecord` (lock order: organization, then record, as
   * in the archive-worker's expiry); the active holds read afterwards include any hold committed
   * while this waited.
   */
  async lockOrganizationForHolds(tx: Tx, scope: TenantScope): Promise<void> {
    await tx.$queryRaw<Array<{ id: bigint }>>`
      SELECT id FROM organizations WHERE id = ${scope.organizationId} FOR SHARE`;
  }

  /** `SELECT … FOR UPDATE` on the record (writer; the disposal decision). */
  async lockRecord(tx: Tx, scope: TenantScope, key: MessageKeyRow): Promise<RecordRow | null> {
    const ids = await tx.$queryRaw<Array<{ id: bigint }>>`
      SELECT id FROM email_archives
      WHERE organization_id = ${scope.organizationId} AND message_id = ${key.id}
        AND received_at = ${key.receivedAt}
      FOR UPDATE`;
    if (ids.length === 0) return null;
    return this.record(scope, key, tx);
  }

  /** Records by their `(message_id, received_at)` keys (replica; hits of a case search). */
  async recordsByKeys(
    scope: TenantScope,
    keys: ReadonlyArray<{ messageId: bigint; receivedAt: Date }>,
  ): Promise<RecordRow[]> {
    if (keys.length === 0) return [];
    const rows = await this.db.emailArchive.findMany({
      where: tenantWhere(scope, {
        OR: keys.map((k) => ({ messageId: k.messageId, receivedAt: k.receivedAt })),
      }),
      select: recordSelect,
      take: keys.length,
    });
    assertEcho('archive.records.keys', rows, { organizationId: scope.organizationId });
    return rows;
  }

  /** The current retention policy of a record (name, days, expiry action, live), any client. */
  async policyFacts(
    scope: TenantScope,
    policyId: bigint,
    on: 'replica' | 'writer' | Tx = 'replica',
  ): Promise<{
    publicId: string;
    name: string;
    retentionDays: number;
    onExpiry: 'delete' | 'review';
    live: boolean;
  } | null> {
    const client = on === 'replica' ? this.db : on === 'writer' ? this.writer : on;
    const row = await client.archiveRetentionPolicy.findFirst({
      where: tenantWhere(scope, { id: policyId }),
      select: {
        organizationId: true,
        publicId: true,
        name: true,
        retentionDays: true,
        onExpiry: true,
        deletedAt: true,
      },
    });
    if (row === null) return null;
    assertEcho('archive.record.policy', [row], { organizationId: scope.organizationId });
    return {
      publicId: row.publicId,
      name: row.name,
      retentionDays: row.retentionDays,
      onExpiry: row.onExpiry,
      live: row.deletedAt === null,
    };
  }

  /** Step 8.6: the journal intake source of a record (public id, name, kind), any client. */
  async intakeSourceRef(
    scope: TenantScope,
    sourceId: bigint,
  ): Promise<{ publicId: string; displayName: string; kind: JournalIntakeSourceKind } | null> {
    const row = await this.db.journalIntakeSource.findFirst({
      where: tenantWhere(scope, { id: sourceId }),
      select: { organizationId: true, publicId: true, displayName: true, kind: true },
    });
    if (row === null) return null;
    assertEcho('archive.record.intake_source', [row], { organizationId: scope.organizationId });
    return { publicId: row.publicId, displayName: row.displayName, kind: row.kind };
  }

  /**
   * Step 8.6 D7: the copies merged into a record (`archive_record_sources`, ≤ 8 by the capture
   * rule; partition key `archive_received_at` = the record's `received_at`), oldest first.
   */
  async recordSources(
    scope: TenantScope,
    record: Pick<RecordRow, 'id' | 'receivedAt'>,
    on: 'replica' | 'writer' | Tx = 'replica',
  ): Promise<RecordSourceRow[]> {
    const client = on === 'replica' ? this.db : on === 'writer' ? this.writer : on;
    const rows = await client.archiveRecordSource.findMany({
      where: tenantWhere(scope, {
        archiveId: record.id,
        archiveReceivedAt: record.receivedAt,
      }),
      select: {
        organizationId: true,
        archiveId: true,
        messageId: true,
        messageReceivedAt: true,
        messagePublicId: true,
        source: true,
        emlSha256: true,
        sizeBytes: true,
        contentVariant: true,
        recipientsAdded: true,
        mergedAt: true,
      },
      orderBy: [{ mergedAt: 'asc' }, { id: 'asc' }],
      take: MAX_RECORD_SOURCES,
    });
    assertEcho('archive.record.sources', rows, {
      organizationId: scope.organizationId,
      archiveId: record.id,
    });
    return rows;
  }

  /**
   * Step 8.6: the record a merged copy belongs to, by the copy's registry key (writer or tx):
   * the `archive_record_sources` row and the record's key, or null.
   */
  async recordOfMergedCopy(
    scope: TenantScope,
    copy: MessageKeyRow,
    on: 'writer' | Tx = 'writer',
  ): Promise<{ source: RecordSourceRow; record: MessageKeyRow } | null> {
    const client = on === 'writer' ? this.writer : on;
    const source = await client.archiveRecordSource.findFirst({
      where: tenantWhere(scope, { messageId: copy.id, messageReceivedAt: copy.receivedAt }),
      select: {
        organizationId: true,
        archiveId: true,
        archiveReceivedAt: true,
        messageId: true,
        messageReceivedAt: true,
        messagePublicId: true,
        source: true,
        emlSha256: true,
        sizeBytes: true,
        contentVariant: true,
        recipientsAdded: true,
        mergedAt: true,
      },
    });
    if (source === null) return null;
    assertEcho('archive.record.merged_copy', [source], {
      organizationId: scope.organizationId,
      messageId: copy.id,
    });
    const record = await client.emailArchive.findFirst({
      where: tenantWhere(scope, { id: source.archiveId, receivedAt: source.archiveReceivedAt }),
      select: { organizationId: true, messageId: true, receivedAt: true, messagePublicId: true },
    });
    if (record === null) return null;
    assertEcho('archive.record.merged_parent', [record], { organizationId: scope.organizationId });
    return {
      source,
      record: {
        id: record.messageId,
        publicId: record.messagePublicId,
        receivedAt: record.receivedAt,
        organizationId: record.organizationId,
      },
    };
  }

  /** The organization's active legal holds (≤ the per-organization bound), any client. */
  async activeHolds(
    scope: TenantScope,
    on: 'replica' | 'writer' | Tx = 'replica',
  ): Promise<HoldRefRow[]> {
    const client = on === 'replica' ? this.db : on === 'writer' ? this.writer : on;
    const rows = await client.archiveLegalHold.findMany({
      where: tenantWhere(scope, { status: 'active' as const }),
      select: {
        id: true,
        publicId: true,
        organizationId: true,
        status: true,
        name: true,
        criteria: true,
        criteriaVersion: true,
        case: { select: { publicId: true } },
      },
      orderBy: { id: 'asc' },
      take: MAX_HOLDS,
    });
    assertEcho('archive.holds.active', rows, {
      organizationId: scope.organizationId,
      status: 'active',
    });
    return rows.map((r) => ({
      id: r.id,
      publicId: r.publicId,
      name: r.name,
      criteria: r.criteria,
      criteriaVersion: r.criteriaVersion,
      casePublicId: r.case?.publicId ?? null,
    }));
  }

  /**
   * A14 step 1 for one locked record: the `archive_disposals` row (state `shredded`), the record
   * set `disposing` with `wrapped_dek = NULL` (crypto-shred) and `deleted_at`, and an index
   * `delete` op, in the caller's transaction. The archive-worker's lifecycle role completes it
   * (objects, replica targets, index, row).
   */
  async writeDisposalDecision(tx: Tx, scope: TenantScope, d: DisposalDecision): Promise<void> {
    const r = d.record;
    await tx.archiveDisposal.create({
      data: {
        requestedAt: d.now,
        organizationId: scope.organizationId,
        messageId: r.messageId,
        messagePublicId: r.messagePublicId,
        messageReceivedAt: r.receivedAt,
        archiveRecordId: r.id,
        reason: d.reason,
        sha256: r.sha256,
        sizeBytes: r.sizeBytes,
        // The lifecycle pipeline's shape (prefix + exact versions), built exactly as the
        // archive-worker's expiry builds it; replica targets are the worker's configuration.
        objects: disposalObjectsOf({
          organizationId: scope.organizationId,
          receivedAt: r.receivedAt,
          messagePublicId: r.messagePublicId,
          objects: r.objects,
        }),
        replicaStatus: disposalReplicaStatusOf([]),
        state: 'shredded',
        nextAttemptAt: d.now,
        requestedByUserId: d.requestedByUserId,
      },
      select: { id: true },
    });
    const updated = await tx.emailArchive.updateMany({
      where: tenantWhere(scope, {
        id: r.id,
        receivedAt: r.receivedAt,
        status: { in: ['active' as const, 'expiry_review' as const] },
      }),
      data: { status: 'disposing', wrappedDek: null, deletedAt: d.now },
    });
    if (updated.count !== 1) throw new Error('archive record changed during its disposal decision');
    await tx.archiveIndexQueue.create({
      data: {
        organizationId: scope.organizationId,
        messageId: r.messageId,
        receivedAt: r.receivedAt,
        messagePublicId: r.messagePublicId,
        op: 'delete',
        availableAt: d.now,
      },
      select: { id: true },
    });
  }

  // ---- capture issues ---------------------------------------------------------------------------

  /**
   * `failed` and `lost` intents, `skipped` ones that aged out (`skip_reason = 'max_age'`: mail
   * that was never archived), plus `pending` ones created before `agedBefore` that are not
   * waiting in quarantine (a wait in quarantine is expected, `category = 'quarantined'`), newest
   * `received_at` first (keyset `(received_at, id)` over `(organization_id, status,
   * received_at)`), with the message public ids from the registry (replica).
   */
  async captureIssues(
    scope: TenantScope,
    page: {
      take: number;
      statuses: readonly ('failed' | 'lost' | 'pending' | 'skipped')[];
      agedBefore: Date;
      before?: TimeIdKey | undefined;
    },
  ): Promise<CaptureIssueRow[]> {
    const b = page.before;
    const statusOr: Prisma.ArchiveCaptureIntentWhereInput[] = [];
    const terminal = page.statuses.filter((s) => s === 'failed' || s === 'lost');
    if (terminal.length > 0) statusOr.push({ status: { in: terminal } });
    if (page.statuses.includes('skipped')) {
      statusOr.push({ status: 'skipped', skipReason: 'max_age' });
    }
    if (page.statuses.includes('pending')) {
      statusOr.push({
        status: 'pending',
        createdAt: { lte: page.agedBefore },
        OR: [{ category: null }, { category: { not: 'quarantined' } }],
      });
    }
    const rows = await this.db.archiveCaptureIntent.findMany({
      where: tenantWhere(scope, {
        AND: [
          { OR: statusOr },
          ...(b
            ? [
                {
                  OR: [{ receivedAt: { lt: b.at } }, { receivedAt: b.at, id: { lt: b.id } }],
                },
              ]
            : []),
        ],
      }),
      select: {
        id: true,
        receivedAt: true,
        messageId: true,
        organizationId: true,
        status: true,
        skipReason: true,
        lastErrorCode: true,
        attempts: true,
        sourceJournal: true,
        sourcePolicy: true,
        nextCheckAt: true,
        createdAt: true,
      },
      orderBy: [{ receivedAt: 'desc' }, { id: 'desc' }],
      take: clampTake(page.take),
    });
    assertEcho('archive.intents.issues', rows, {
      organizationId: scope.organizationId,
      status: [...page.statuses],
    });
    const ids = await this.db.messageIdentity.findMany({
      where: tenantWhere(scope, { id: { in: rows.map((r) => r.messageId) } }),
      select: { id: true, publicId: true, organizationId: true },
    });
    assertEcho('archive.intents.registry', ids, { organizationId: scope.organizationId });
    const byId = new Map(ids.map((i) => [i.id, i.publicId]));
    return rows.map(({ organizationId: _o, ...r }) => ({
      ...r,
      messagePublicId: byId.get(r.messageId) ?? null,
    }));
  }

  /** The intent of a message, locked (writer). */
  async lockIntent(
    tx: Tx,
    scope: TenantScope,
    key: MessageKeyRow,
  ): Promise<{ id: bigint; status: ArchiveIntentStatus } | null> {
    const rows = await tx.$queryRaw<Array<{ id: bigint; status: ArchiveIntentStatus }>>`
      SELECT id, status FROM archive_capture_intents
      WHERE organization_id = ${scope.organizationId} AND message_id = ${key.id}
        AND received_at = ${key.receivedAt}
      FOR UPDATE`;
    return rows[0] ?? null;
  }

  /** `failed` → `pending`, due now, lease cleared (the capture scheduler picks it up). */
  async retryIntent(
    tx: Tx,
    scope: TenantScope,
    key: MessageKeyRow,
    intentId: bigint,
    now: Date,
  ): Promise<boolean> {
    const result = await tx.archiveCaptureIntent.updateMany({
      where: tenantWhere(scope, {
        id: intentId,
        receivedAt: key.receivedAt,
        status: 'failed' as const,
      }),
      data: { status: 'pending', nextCheckAt: now, leaseUntil: null },
    });
    return result.count === 1;
  }

  // ---- disposal log -------------------------------------------------------------------------------

  /** `archive_disposals` of the organization, newest first (keyset `(requested_at, id)`). */
  async disposals(
    scope: TenantScope,
    page: {
      take: number;
      from: Date;
      to: Date;
      reasons?: readonly ArchiveDisposalReason[] | undefined;
      states?: readonly ArchiveDisposalState[] | undefined;
      before?: TimeIdKey | undefined;
    },
  ): Promise<DisposalRow[]> {
    const b = page.before;
    const rows = await this.db.archiveDisposal.findMany({
      where: tenantWhere(scope, {
        requestedAt: { gte: page.from, lt: page.to },
        ...(page.reasons && { reason: { in: [...page.reasons] } }),
        ...(page.states && { state: { in: [...page.states] } }),
        ...(b && {
          OR: [{ requestedAt: { lt: b.at } }, { requestedAt: b.at, id: { lt: b.id } }],
        }),
      }),
      select: {
        id: true,
        requestedAt: true,
        organizationId: true,
        messagePublicId: true,
        messageReceivedAt: true,
        reason: true,
        state: true,
        sha256: true,
        sizeBytes: true,
        attempts: true,
        completedAt: true,
      },
      orderBy: [{ requestedAt: 'desc' }, { id: 'desc' }],
      take: clampTake(page.take),
    });
    assertEcho('archive.disposals', rows, { organizationId: scope.organizationId });
    return rows.map(({ organizationId: _o, ...r }) => r);
  }

  // ---- status and freshness -----------------------------------------------------------------------

  /** The oldest queued index op of the organization (`X-EG-Index-Lag-Seconds`), replica. */
  async oldestIndexOpAt(scope: TenantScope): Promise<Date | null> {
    const row = await this.db.archiveIndexQueue.findFirst({
      where: tenantWhere(scope),
      select: { createdAt: true, organizationId: true },
      orderBy: { createdAt: 'asc' },
    });
    if (row === null) return null;
    assertEcho('archive.index.oldest', [row], { organizationId: scope.organizationId });
    return row.createdAt;
  }

  /** Counts of the organization for `GET /archive/status` (replica, index-only where possible). */
  async statusCounts(scope: TenantScope): Promise<StatusCounts> {
    const org = scope.organizationId;
    const [intents, oldestPending, records, queued, oldestQueued, disposals, keys] =
      await Promise.all([
        this.db.archiveCaptureIntent.groupBy({
          by: ['status'],
          where: {
            organizationId: org,
            status: { in: ['pending', 'captured_open', 'failed', 'lost'] },
          },
          _count: { _all: true },
        }),
        this.db.archiveCaptureIntent.findFirst({
          where: { organizationId: org, status: 'pending' },
          select: { createdAt: true, organizationId: true },
          orderBy: { createdAt: 'asc' },
        }),
        this.db.emailArchive.groupBy({
          by: ['status'],
          where: { organizationId: org },
          _count: { _all: true },
        }),
        this.db.archiveIndexQueue.count({ where: { organizationId: org } }),
        this.oldestIndexOpAt(scope),
        this.db.archiveDisposal.groupBy({
          by: ['state'],
          where: { organizationId: org, state: { in: [...OPEN_DISPOSAL_STATES, 'failed'] } },
          _count: { _all: true },
        }),
        this.db.archiveEncryptionKey.findMany({
          where: { organizationId: org },
          select: { version: true, status: true, organizationId: true },
          orderBy: { version: 'desc' },
          take: 10_000,
        }),
      ]);
    if (oldestPending !== null) {
      assertEcho('archive.status.pending', [oldestPending], { organizationId: org });
    }
    assertEcho('archive.status.keys', keys, { organizationId: org });
    const intentCounts: Partial<Record<ArchiveIntentStatus, number>> = {};
    for (const g of intents) intentCounts[g.status] = g._count._all;
    const recordCount = (s: string) => records.find((g) => g.status === s)?._count._all ?? 0;
    const disposalCount = (states: readonly string[]) =>
      disposals.filter((g) => states.includes(g.state)).reduce((n, g) => n + g._count._all, 0);
    return {
      intents: intentCounts,
      oldestPendingAt: oldestPending?.createdAt ?? null,
      records: {
        active: recordCount('active'),
        expiryReview: recordCount('expiry_review'),
        disposing: recordCount('disposing'),
      },
      indexQueued: queued,
      oldestQueuedAt: oldestQueued,
      disposalsInProgress: disposalCount(OPEN_DISPOSAL_STATES),
      disposalsFailed: disposalCount(['failed']),
      keys: {
        activeVersion: keys.find((k) => k.status === 'active')?.version ?? null,
        versions: keys.length,
      },
    };
  }
}
