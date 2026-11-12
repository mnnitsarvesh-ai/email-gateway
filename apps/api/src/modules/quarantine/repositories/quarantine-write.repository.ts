import { Injectable } from '@nestjs/common';
import type {
  ActorType,
  Prisma,
  QuarantineActionType,
  QuarantineApprovalKind,
  QuarantineApprovalStatus,
  QuarantineReleaseMode,
  QuarantineStatus,
  RecipientStatus,
} from '@email-gateway/database';
import type { MessageRef } from '@email-gateway/message-lifecycle';
import { tenantWhere, type TenantScope } from '../../../auth-contracts/tenant-scope';
import type { ApprovalRow, EntryRow } from '../domain/entry';
import { InconsistentQuarantineReadError } from '../quarantine.errors';
import { approvalSelect, entrySelect, toApprovalRow, toEntryRow } from './entry-select';

type Tx = Prisma.TransactionClient;

/** Where an entry is addressed from: public id, scope and (self routes) the caller's address. */
export interface EntryRefRow {
  id: bigint;
  publicId: string;
  messageId: bigint;
  messageReceivedAt: Date;
}

export interface EntryUpdate {
  state: QuarantineStatus;
  stateChangedAt: Date;
  kind?: 'quarantine' | 'review';
  approvalRequestId?: bigint | null;
  decidedAt?: Date | null;
  decidedByUserId?: bigint | null;
  decidedByType?: ActorType | null;
  terminalReason?: string | null;
}

export interface ActionInsert {
  organizationId: bigint;
  quarantineMessageId: bigint;
  action: QuarantineActionType;
  actorType: ActorType;
  actorUserId: bigint | null;
  actorId: string | null;
  reason: string | null;
  result: string | null;
  details: Prisma.InputJsonValue | null;
  approvalRequestId?: bigint | null;
  /** Hex SHA-256 of the request's Idempotency-Key (unique per organization) or null. */
  idempotencyKey: string | null;
}

export interface ReleaseLogInsert {
  organizationId: bigint;
  quarantineMessageId: bigint;
  actionId: bigint;
  releasePublicId: string;
  mode: QuarantineReleaseMode;
  approvalRequestId: bigint | null;
  requestedByType: ActorType;
  requestedById: string | null;
  releasedTo: string;
  precheck: Prisma.InputJsonValue;
}

export interface ApprovalInsert {
  organizationId: bigint;
  quarantineMessageId: bigint;
  kind: QuarantineApprovalKind;
  approvalReasons: string[];
  requestedByType: ActorType;
  requestedByUserId: bigint | null;
  requestedByApiKeyId: bigint | null;
  requestReason: string | null;
  expiresAt: Date;
}

export interface ApprovalUpdate {
  status: QuarantineApprovalStatus;
  decidedByUserId?: bigint | null;
  decisionReason?: string | null;
  approvedReasons?: string[] | null;
  deciderPermissionsHash?: string | null;
  decidedAt: Date;
}

export interface OutboxRow {
  eventId: string;
  organizationId: bigint;
  eventType: string;
  aggregateType: 'message' | 'quarantine';
  aggregateId: string;
  correlationId: string;
  payload: Prisma.InputJsonValue;
}

export interface EntryStateRow {
  id: bigint;
  state: QuarantineStatus;
  kind: 'quarantine' | 'review';
  lifecycleRound: number;
  rcptSeq: number;
}

/** Facts of Q17 (`decideObjectDisposal`) read on the writer. */
export interface DisposalFactRows {
  legalHolds: Array<{ id: bigint; criteria: unknown }>;
  archive: { enabled: boolean; scope: 'all' | 'inbound' | 'outbound' | 'internal' } | null;
  retentionPolicyDays: number[];
  emailArchives: Array<{ retainUntil: Date | null; legalHold: boolean }>;
  evaluationActions: unknown[];
}

/** The message row the writer paths read (manual quarantine, sender notices). */
export interface MessageRow {
  id: bigint;
  publicId: string;
  receivedAt: Date;
  organizationId: bigint;
  direction: 'inbound' | 'outbound' | 'internal';
  status: string;
  statusReason: string | null;
  lifecycleRound: number;
  envelopeFrom: string;
  headerFrom: string | null;
  sizeBytes: number;
  attachmentCount: number;
  emlObjectKey: string;
  emlSha256: string;
  finalVerdict: string | null;
  riskScore: number | null;
}

const NON_TERMINAL: QuarantineStatus[] = ['held', 'pending_approval', 'releasing'];

/**
 * Writer-side, tenant-scoped queries of the quarantine mutations (step 5.3 Q3, Q7, Q12–Q18,
 * Q24), always in the caller's transaction. Lock order (Q3): the message lifecycle lock first
 * (LifecycleGateway), then `quarantine_messages` rows (`FOR UPDATE`), then
 * `quarantine_approval_requests` rows. Every entry and request write is a compare-and-set on
 * `row_version`; every deciding read is echo-checked (§6) and a mismatch throws the retryable
 * `InconsistentQuarantineReadError`. Message lifecycle columns are never written here (one-door
 * rule); `email_recipients.status` is (Q5).
 */
@Injectable()
export class QuarantineWriteRepository {
  // ------------------------------------------------------------------ entries

  /** The entry's address in the scope (and, on self routes, of the caller's own address). */
  async findEntryRef(
    tx: Tx,
    scope: TenantScope,
    publicId: string,
    selfAddress: string | null = null,
  ): Promise<EntryRefRow | null> {
    return tx.quarantineMessage.findFirst({
      where: tenantWhere(scope, {
        publicId,
        ...(selfAddress !== null && { recipientAddress: selfAddress }),
      }),
      select: { id: true, publicId: true, messageId: true, messageReceivedAt: true },
    });
  }

  /** `SELECT … FOR UPDATE` of one entry (after the message lock), echo-checked. */
  async lockEntry(tx: Tx, scope: TenantScope, ref: EntryRefRow): Promise<EntryRow> {
    const locked = await tx.$queryRaw<Array<{ id: bigint }>>`
      SELECT id FROM quarantine_messages
      WHERE id = ${ref.id} AND organization_id = ${scope.organizationId}
      FOR UPDATE`;
    if (locked.length !== 1 || BigInt(locked[0]!.id) !== ref.id) {
      throw new InconsistentQuarantineReadError('entry_lock');
    }
    const row = await tx.quarantineMessage.findFirst({
      where: tenantWhere(scope, { id: ref.id }),
      select: entrySelect,
    });
    if (
      row === null ||
      row.id !== ref.id ||
      row.organizationId !== scope.organizationId ||
      row.messageId !== ref.messageId ||
      row.publicId !== ref.publicId ||
      !Number.isInteger(row.rowVersion)
    ) {
      throw new InconsistentQuarantineReadError('entry');
    }
    return toEntryRow(row);
  }

  /** Compare-and-set on `row_version`; false when another writer changed the row. */
  async updateEntry(
    tx: Tx,
    scope: TenantScope,
    entry: Pick<EntryRow, 'id' | 'rowVersion'>,
    update: EntryUpdate,
  ): Promise<boolean> {
    const result = await tx.quarantineMessage.updateMany({
      where: tenantWhere(scope, { id: entry.id, rowVersion: entry.rowVersion }),
      data: {
        status: update.state,
        stateChangedAt: update.stateChangedAt,
        rowVersion: { increment: 1 },
        ...(update.kind !== undefined && { kind: update.kind }),
        ...(update.approvalRequestId !== undefined && {
          approvalRequestId: update.approvalRequestId,
        }),
        ...(update.decidedAt !== undefined && { decidedAt: update.decidedAt }),
        ...(update.decidedByUserId !== undefined && { decidedByUserId: update.decidedByUserId }),
        ...(update.decidedByType !== undefined && { decidedByType: update.decidedByType }),
        ...(update.terminalReason !== undefined && { terminalReason: update.terminalReason }),
      },
    });
    return result.count === 1;
  }

  /** Every entry of the message (all rounds), for the E17/E18 rule and Q17 rule 4. */
  entriesOfMessage(tx: Tx, scope: TenantScope, message: MessageRef): Promise<EntryStateRow[]> {
    return tx.quarantineMessage
      .findMany({
        where: tenantWhere(scope, {
          messageId: message.id,
          messageReceivedAt: message.receivedAt,
        }),
        select: { id: true, status: true, kind: true, lifecycleRound: true, rcptSeq: true },
        orderBy: { id: 'asc' },
        take: 5000,
      })
      .then((rows) => rows.map(({ status, ...r }) => ({ ...r, state: status })));
  }

  /** Non-terminal review entries of one round of the message, locked (manual quarantine, Q7). */
  async lockReviewEntries(
    tx: Tx,
    scope: TenantScope,
    message: MessageRef,
    round: number,
  ): Promise<EntryRow[]> {
    const ids = await tx.$queryRaw<Array<{ id: bigint }>>`
      SELECT id FROM quarantine_messages
      WHERE organization_id = ${scope.organizationId} AND message_id = ${message.id}
        AND lifecycle_round = ${round} AND kind = 'review' AND status = 'pending_approval'
      ORDER BY id
      FOR UPDATE`;
    if (ids.length === 0) return [];
    const rows = await tx.quarantineMessage.findMany({
      where: tenantWhere(scope, {
        id: { in: ids.map((r) => BigInt(r.id)) },
        messageId: message.id,
      }),
      select: entrySelect,
      orderBy: { id: 'asc' },
    });
    if (rows.length !== ids.length) throw new InconsistentQuarantineReadError('review_entries');
    return rows.map(toEntryRow);
  }

  /** Inserts new entries (manual quarantine from a rejection); returns them in rcptSeq order. */
  async createEntries(
    tx: Tx,
    rows: Prisma.QuarantineMessageCreateManyInput[],
    scope: TenantScope,
    message: MessageRef,
    round: number,
  ): Promise<EntryRow[]> {
    if (rows.length === 0) return [];
    await tx.quarantineMessage.createMany({ data: rows, skipDuplicates: true });
    const created = await tx.quarantineMessage.findMany({
      where: tenantWhere(scope, {
        messageId: message.id,
        lifecycleRound: round,
        rcptSeq: { in: rows.map((r) => r.rcptSeq ?? 0) },
      }),
      select: entrySelect,
      orderBy: { rcptSeq: 'asc' },
    });
    return created.map(toEntryRow);
  }

  // ------------------------------------------------------------------ actions, releases

  async insertAction(tx: Tx, row: ActionInsert): Promise<bigint> {
    const created = await tx.quarantineAction.create({
      data: {
        organizationId: row.organizationId,
        quarantineMessageId: row.quarantineMessageId,
        action: row.action,
        actorType: row.actorType,
        actorUserId: row.actorUserId,
        actorId: row.actorId,
        reason: row.reason,
        result: row.result,
        details: row.details ?? undefined,
        approvalRequestId: row.approvalRequestId ?? null,
        idempotencyKey: row.idempotencyKey,
      },
      select: { id: true },
    });
    return created.id;
  }

  async insertReleaseLog(tx: Tx, row: ReleaseLogInsert): Promise<bigint> {
    const created = await tx.quarantineReleaseLog.create({
      data: { ...row, status: 'pending' },
      select: { id: true },
    });
    await tx.quarantineAction.update({
      where: { id: row.actionId },
      data: { releaseLogId: created.id },
      select: { id: true },
    });
    return created.id;
  }

  // ------------------------------------------------------------------ approval requests

  async createApproval(tx: Tx, row: ApprovalInsert): Promise<{ id: bigint; publicId: string }> {
    return tx.quarantineApprovalRequest.create({
      data: { ...row, status: 'pending' },
      select: { id: true, publicId: true },
    });
  }

  findApprovalRef(
    tx: Tx,
    scope: TenantScope,
    publicId: string,
  ): Promise<{ id: bigint; quarantineMessageId: bigint } | null> {
    return tx.quarantineApprovalRequest.findFirst({
      where: tenantWhere(scope, { publicId }),
      select: { id: true, quarantineMessageId: true },
    });
  }

  /** `SELECT … FOR UPDATE` of one request (after the entry lock), echo-checked. */
  async lockApproval(
    tx: Tx,
    scope: TenantScope,
    id: bigint,
    entryId: bigint,
  ): Promise<ApprovalRow> {
    const locked = await tx.$queryRaw<Array<{ id: bigint }>>`
      SELECT id FROM quarantine_approval_requests
      WHERE id = ${id} AND organization_id = ${scope.organizationId}
      FOR UPDATE`;
    if (locked.length !== 1) throw new InconsistentQuarantineReadError('approval_lock');
    const row = await tx.quarantineApprovalRequest.findFirst({
      where: tenantWhere(scope, { id }),
      select: approvalSelect,
    });
    if (
      row === null ||
      row.id !== id ||
      row.organizationId !== scope.organizationId ||
      row.quarantineMessageId !== entryId
    ) {
      throw new InconsistentQuarantineReadError('approval');
    }
    return toApprovalRow(row);
  }

  /**
   * Q14: `api_keys.created_by_user_id` of the API key that requested an approval (the user
   * accountable for the key's requests), read on the writer inside the decision transaction.
   * Null when the key or its creator no longer exists.
   */
  async apiKeyCreator(tx: Tx, scope: TenantScope, apiKeyId: bigint): Promise<bigint | null> {
    const key = await tx.apiKey.findFirst({
      where: tenantWhere(scope, { id: apiKeyId }),
      select: { id: true, organizationId: true, createdByUserId: true },
    });
    if (key === null) return null;
    if (key.id !== apiKeyId || key.organizationId !== scope.organizationId) {
      throw new InconsistentQuarantineReadError('approval');
    }
    return key.createdByUserId;
  }

  async updateApproval(
    tx: Tx,
    scope: TenantScope,
    approval: Pick<ApprovalRow, 'id' | 'rowVersion'>,
    update: ApprovalUpdate,
  ): Promise<boolean> {
    const result = await tx.quarantineApprovalRequest.updateMany({
      where: tenantWhere(scope, { id: approval.id, rowVersion: approval.rowVersion }),
      data: {
        status: update.status,
        decidedAt: update.decidedAt,
        rowVersion: { increment: 1 },
        ...(update.decidedByUserId !== undefined && { decidedByUserId: update.decidedByUserId }),
        ...(update.decisionReason !== undefined && { decisionReason: update.decisionReason }),
        ...(update.approvedReasons !== undefined && {
          approvedReasons: update.approvedReasons ?? undefined,
        }),
        ...(update.deciderPermissionsHash !== undefined && {
          deciderPermissionsHash: update.deciderPermissionsHash,
        }),
      },
    });
    return result.count === 1;
  }

  /** Cancels the entry's pending requests (reject, delete, manual quarantine); returns them. */
  async cancelPendingApprovals(
    tx: Tx,
    scope: TenantScope,
    entryId: bigint,
    now: Date,
  ): Promise<string[]> {
    const pending = await tx.$queryRaw<Array<{ id: bigint; public_id: string }>>`
      SELECT id, public_id FROM quarantine_approval_requests
      WHERE organization_id = ${scope.organizationId} AND quarantine_message_id = ${entryId}
        AND status = 'pending'
      FOR UPDATE`;
    if (pending.length === 0) return [];
    await tx.quarantineApprovalRequest.updateMany({
      where: tenantWhere(scope, {
        id: { in: pending.map((p) => BigInt(p.id)) },
        status: 'pending' as const,
      }),
      data: { status: 'cancelled', decidedAt: now, rowVersion: { increment: 1 } },
    });
    return pending.map((p) => p.public_id);
  }

  // ------------------------------------------------------------------ recipients

  /** Sets one recipient's status when it is currently one of `from` (Q5); returns the count. */
  async setRecipientStatus(
    tx: Tx,
    scope: TenantScope,
    message: MessageRef,
    rcptSeq: number,
    from: RecipientStatus[],
    to: RecipientStatus,
    finalAction?: 'quarantine' | 'discard' | 'reject',
  ): Promise<number> {
    const result = await tx.emailRecipient.updateMany({
      where: tenantWhere(scope, {
        messageId: message.id,
        receivedAt: message.receivedAt,
        rcptSeq,
        status: { in: from },
      }),
      data: { status: to, ...(finalAction !== undefined && { finalAction }) },
    });
    return result.count;
  }

  async recipients(
    tx: Tx,
    scope: TenantScope,
    message: MessageRef,
  ): Promise<Array<{ id: bigint; rcptSeq: number; address: string; status: RecipientStatus }>> {
    return tx.emailRecipient.findMany({
      where: tenantWhere(scope, { messageId: message.id, receivedAt: message.receivedAt }),
      select: { id: true, rcptSeq: true, address: true, status: true },
      orderBy: { rcptSeq: 'asc' },
      take: 5000,
    });
  }

  // ------------------------------------------------------------------ disposal (Q17)

  async disposalFacts(tx: Tx, scope: TenantScope, message: MessageRef): Promise<DisposalFactRows> {
    const [legalHolds, archive, policies, archives, evaluations] = await Promise.all([
      tx.archiveLegalHold.findMany({
        where: tenantWhere(scope, { status: 'active' as const }),
        select: { id: true, criteria: true, organizationId: true },
        take: 1000,
      }),
      tx.archiveSetting.findFirst({
        where: tenantWhere(scope),
        select: { enabled: true, scope: true, organizationId: true },
      }),
      tx.archiveRetentionPolicy.findMany({
        where: tenantWhere(scope),
        select: { retentionDays: true, organizationId: true },
        take: 1000,
      }),
      tx.emailArchive.findMany({
        where: tenantWhere(scope, { messageId: message.id, receivedAt: message.receivedAt }),
        select: { retainUntil: true, legalHold: true, organizationId: true },
      }),
      tx.policyExecutionLog.findMany({
        where: tenantWhere(scope, { messageId: message.id, receivedAt: message.receivedAt }),
        select: { actions: true, organizationId: true },
        take: 100,
      }),
    ]);
    const foreign = [...legalHolds, ...policies, ...archives, ...evaluations].some(
      (r) => r.organizationId !== scope.organizationId,
    );
    if (foreign || (archive !== null && archive.organizationId !== scope.organizationId)) {
      throw new InconsistentQuarantineReadError('disposal');
    }
    return {
      legalHolds: legalHolds.map((h) => ({ id: h.id, criteria: h.criteria })),
      archive: archive === null ? null : { enabled: archive.enabled, scope: archive.scope },
      retentionPolicyDays: policies.map((p) => p.retentionDays),
      emailArchives: archives.map((a) => ({ retainUntil: a.retainUntil, legalHold: a.legalHold })),
      evaluationActions: evaluations.flatMap((e) => (Array.isArray(e.actions) ? e.actions : [])),
    };
  }

  /** The message's purge row (Q17): created, or updated while not purged yet. */
  async upsertPurge(
    tx: Tx,
    scope: TenantScope,
    message: MessageRef,
    purge: { status: 'pending' | 'retained'; reason: string | null; purgeAfter: Date },
  ): Promise<void> {
    const existing = await tx.quarantineObjectPurge.findFirst({
      where: tenantWhere(scope, { messageId: message.id, messageReceivedAt: message.receivedAt }),
      select: { id: true, status: true },
    });
    if (existing === null) {
      await tx.quarantineObjectPurge.create({
        data: {
          organizationId: scope.organizationId,
          messageId: message.id,
          messageReceivedAt: message.receivedAt,
          status: purge.status,
          reason: purge.reason,
          purgeAfter: purge.purgeAfter,
        },
        select: { id: true },
      });
      return;
    }
    if (existing.status === 'purged') return;
    await tx.quarantineObjectPurge.update({
      where: { id: existing.id },
      data: { status: purge.status, reason: purge.reason, purgeAfter: purge.purgeAfter },
      select: { id: true },
    });
  }

  // ------------------------------------------------------------------ outbox

  async insertOutbox(tx: Tx, row: OutboxRow): Promise<void> {
    await tx.messageOutbox.create({ data: row, select: { id: true } });
  }

  // ------------------------------------------------------------------ messages and users

  /** The message by its registry public id (manual quarantine). */
  async message(tx: Tx, scope: TenantScope, publicId: string): Promise<MessageRow | null> {
    const identity = await tx.messageIdentity.findFirst({
      where: tenantWhere(scope, { publicId }),
      select: { id: true, publicId: true, receivedAt: true },
    });
    if (identity === null) return null;
    return this.messageById(tx, scope, { ...identity, organizationId: scope.organizationId });
  }

  async messageById(
    tx: Tx,
    scope: TenantScope,
    ref: MessageRef & { publicId?: string },
  ): Promise<MessageRow | null> {
    const row = await tx.emailMessage.findFirst({
      where: tenantWhere(scope, { id: ref.id, receivedAt: ref.receivedAt }),
      select: {
        id: true,
        receivedAt: true,
        organizationId: true,
        direction: true,
        status: true,
        statusReason: true,
        lifecycleRound: true,
        envelopeFrom: true,
        headerFrom: true,
        sizeBytes: true,
        attachmentCount: true,
        emlObjectKey: true,
        emlSha256: true,
        finalVerdict: true,
        riskScore: true,
      },
    });
    if (row === null) return null;
    if (row.id !== ref.id || row.organizationId !== scope.organizationId) {
      throw new InconsistentQuarantineReadError('message');
    }
    const publicId =
      ref.publicId ??
      (
        await tx.messageIdentity.findFirst({
          where: tenantWhere(scope, { id: ref.id }),
          select: { publicId: true },
        })
      )?.publicId;
    if (publicId === undefined) return null;
    return { ...row, publicId };
  }

  /** The round's latest evaluation row and its risk rows (facts of manual entries, Q7). */
  async roundFacts(
    tx: Tx,
    scope: TenantScope,
    message: MessageRef,
    round: number,
  ): Promise<{
    scanId: bigint | null;
    evaluation: {
      evaluationSeq: number;
      decisionSource: 'tenant_rule' | 'platform_default' | 'floor';
      decisivePolicyPublicId: string | null;
      decisivePolicyVersionId: bigint | null;
      decisiveRuleId: string | null;
      reasonCodes: unknown;
      floor: unknown;
      explanation: unknown;
      explanationText: string;
      riskScore: number | null;
      finalVerdict: string | null;
      policyVersions: unknown;
    } | null;
    risk: Array<{ level: string; recommendedAction: string; hardBlocks: unknown; score: number }>;
  }> {
    const scan = await tx.emailScan.findFirst({
      where: tenantWhere(scope, {
        messageId: message.id,
        receivedAt: message.receivedAt,
        lifecycleRound: round,
      }),
      select: { id: true },
    });
    if (scan === null) return { scanId: null, evaluation: null, risk: [] };
    const [evaluation, risk] = await Promise.all([
      tx.policyExecutionLog.findFirst({
        where: tenantWhere(scope, {
          messageId: message.id,
          receivedAt: message.receivedAt,
          scanId: scan.id,
        }),
        select: {
          evaluationSeq: true,
          decisionSource: true,
          decisivePolicyPublicId: true,
          decisivePolicyVersionId: true,
          decisiveRuleId: true,
          reasonCodes: true,
          floor: true,
          explanation: true,
          explanationText: true,
          riskScore: true,
          finalVerdict: true,
          policyVersions: true,
        },
        orderBy: { evaluationSeq: 'desc' },
      }),
      tx.messageRiskScore.findMany({
        where: tenantWhere(scope, {
          messageId: message.id,
          receivedAt: message.receivedAt,
          scanId: scan.id,
        }),
        select: { level: true, recommendedAction: true, hardBlocks: true, score: true },
        take: 4,
      }),
    ]);
    return { scanId: scan.id, evaluation, risk };
  }

  /** The organization's active, not deleted user whose email is the address (Q6; informational). */
  async userIdByEmail(tx: Tx, scope: TenantScope, address: string): Promise<bigint | null> {
    const user = await tx.user.findFirst({
      where: tenantWhere(scope, { email: address, status: 'active' as const, deletedAt: null }),
      select: { id: true },
    });
    return user?.id ?? null;
  }

  /** `organization_settings` of the hold period (Q19). */
  orgSettings(
    tx: Tx,
    scope: TenantScope,
  ): Promise<{
    quarantineRetentionDays: number;
    digestEnabled: boolean;
    digestSchedule: string;
    timezone: string;
  } | null> {
    return tx.organizationSetting.findFirst({
      where: tenantWhere(scope),
      select: {
        quarantineRetentionDays: true,
        digestEnabled: true,
        digestSchedule: true,
        timezone: true,
      },
    });
  }

  // ------------------------------------------------------------------ settings, preferences

  async lockSettings(
    tx: Tx,
    scope: TenantScope,
  ): Promise<{ id: bigint; settings: unknown; rowVersion: number } | null> {
    const rows = await tx.$queryRaw<Array<{ id: bigint }>>`
      SELECT id FROM quarantine_settings WHERE organization_id = ${scope.organizationId}
      FOR UPDATE`;
    if (rows.length === 0) return null;
    const row = await tx.quarantineSettings.findFirst({
      where: tenantWhere(scope),
      select: { id: true, settings: true, rowVersion: true, organizationId: true },
    });
    if (row === null || row.organizationId !== scope.organizationId) {
      throw new InconsistentQuarantineReadError('settings');
    }
    return { id: row.id, settings: row.settings, rowVersion: row.rowVersion };
  }

  /** The tenant settings document on the writer (echo-checked; null without a row). */
  async settingsDocument(tx: Tx, scope: TenantScope): Promise<unknown> {
    const row = await tx.quarantineSettings.findFirst({
      where: tenantWhere(scope),
      select: { settings: true, organizationId: true },
    });
    if (row !== null && row.organizationId !== scope.organizationId) {
      throw new InconsistentQuarantineReadError('settings');
    }
    return row?.settings ?? null;
  }

  async insertSettings(
    tx: Tx,
    scope: TenantScope,
    data: { settings: Prisma.InputJsonValue; sha256: string; userId: bigint | null },
  ): Promise<number> {
    const row = await tx.quarantineSettings.create({
      data: {
        organizationId: scope.organizationId,
        settings: data.settings,
        settingsSha256: data.sha256,
        updatedByUserId: data.userId,
      },
      select: { rowVersion: true },
    });
    return row.rowVersion;
  }

  async updateSettings(
    tx: Tx,
    scope: TenantScope,
    rowVersion: number,
    data: { settings: Prisma.InputJsonValue; sha256: string; userId: bigint | null },
  ): Promise<boolean> {
    const result = await tx.quarantineSettings.updateMany({
      where: tenantWhere(scope, { rowVersion }),
      data: {
        settings: data.settings,
        settingsSha256: data.sha256,
        updatedByUserId: data.userId,
        rowVersion: { increment: 1 },
      },
    });
    return result.count === 1;
  }

  async upsertPreferences(
    tx: Tx,
    scope: TenantScope,
    userId: bigint,
    digestOptOut: boolean,
  ): Promise<void> {
    await tx.quarantineUserPreference.upsert({
      where: { userId },
      create: { organizationId: scope.organizationId, userId, digestOptOut },
      update: { digestOptOut },
      select: { id: true },
    });
  }

  // ------------------------------------------------------------------ download grants (Q12)

  async insertGrant(
    tx: Tx,
    row: {
      jti: string;
      organizationId: bigint;
      userId: bigint;
      quarantineMessageId: bigint;
      object: 'eml' | 'attachment';
      partIndex: number | null;
      expiresAt: Date;
      sourceIp: string | null;
    },
  ): Promise<void> {
    await tx.quarantineDownloadGrant.create({ data: row, select: { id: true } });
  }

  /**
   * Atomic single-use consume (Q12.3): one row expected. Otherwise `used` when the grant exists
   * for the caller and was consumed, `invalid` for anything else (unknown, another user or
   * organization, expired).
   */
  async consumeGrant(
    tx: Tx,
    scope: TenantScope,
    jti: string,
    userId: bigint,
    now: Date,
  ): Promise<'consumed' | 'used' | 'invalid'> {
    const count = await tx.$executeRaw`
      UPDATE quarantine_download_grants SET consumed_at = ${now}
      WHERE jti = ${jti} AND organization_id = ${scope.organizationId} AND user_id = ${userId}
        AND consumed_at IS NULL AND expires_at > ${now}`;
    if (count === 1) return 'consumed';
    const row = await tx.quarantineDownloadGrant.findFirst({
      where: tenantWhere(scope, { jti, userId }),
      select: { consumedAt: true },
    });
    return row !== null && row.consumedAt !== null ? 'used' : 'invalid';
  }

  grantByJti(
    tx: Tx,
    scope: TenantScope,
    jti: string,
  ): Promise<{
    quarantineMessageId: bigint;
    object: 'eml' | 'attachment';
    partIndex: number | null;
    userId: bigint;
  } | null> {
    return tx.quarantineDownloadGrant.findFirst({
      where: tenantWhere(scope, { jti }),
      select: { quarantineMessageId: true, object: true, partIndex: true, userId: true },
    });
  }

  entryRefById(tx: Tx, scope: TenantScope, id: bigint): Promise<EntryRefRow | null> {
    return tx.quarantineMessage.findFirst({
      where: tenantWhere(scope, { id }),
      select: { id: true, publicId: true, messageId: true, messageReceivedAt: true },
    });
  }

  /** Non-terminal entry states (E17/E18 and Q17 rule 4). */
  static readonly NON_TERMINAL = NON_TERMINAL;
}
