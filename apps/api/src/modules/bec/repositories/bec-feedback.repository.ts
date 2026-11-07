import { Injectable } from '@nestjs/common';
import { PrismaReadService } from '@email-gateway/common';
import type { Prisma } from '@email-gateway/database';
import { tenantWhere, type TenantScope } from '../../../auth-contracts/tenant-scope';
import { Prisma as PrismaRuntime } from '@email-gateway/database';
import { InconsistentBecReadError } from '../bec.errors';
import { lockOrganizationRow } from './bec-profiles.repository';

type Client = Prisma.TransactionClient;

/** The one-feedback-per-(scan, user, kind) unique key of `bec_feedback` (B11). */
const FEEDBACK_UNIQUE_KEY = 'bec_feedback_scan_id_created_by_user_id_kind_key';

/**
 * A `P2002` on the `bec_feedback (scan_id, created_by_user_id, kind)` key: an identical
 * feedback of the same user was stored first. Any other unique violation (e.g. a suppression
 * key) is not `feedback_exists`.
 */
export function isFeedbackKeyViolation(error: unknown): boolean {
  if (!(error instanceof PrismaRuntime.PrismaClientKnownRequestError) || error.code !== 'P2002') {
    return false;
  }
  const target = (error.meta as { target?: unknown } | undefined)?.target;
  if (typeof target === 'string') return target === FEEDBACK_UNIQUE_KEY;
  if (Array.isArray(target)) {
    const fields = new Set(target.filter((t): t is string => typeof t === 'string'));
    return (
      (fields.has('scan_id') || fields.has('scanId')) &&
      (fields.has('created_by_user_id') || fields.has('createdByUserId')) &&
      fields.has('kind')
    );
  }
  return false;
}

export interface FeedbackMessage {
  id: bigint;
  publicId: string;
  receivedAt: Date;
}

const resultSelect = {
  id: true,
  organizationId: true,
  messageId: true,
  receivedAt: true,
  scanId: true,
  rules: true,
  identity: true,
  verdict: true,
} satisfies Prisma.BecScanResultSelect;

export type FeedbackResultRow = Prisma.BecScanResultGetPayload<{ select: typeof resultSelect }>;

const feedbackSelect = {
  id: true,
  publicId: true,
  organizationId: true,
  messageId: true,
  messageReceivedAt: true,
  scanId: true,
  becResultId: true,
  kind: true,
  reasonCodes: true,
  note: true,
  createdAt: true,
  createdBy: { select: { publicId: true } },
} satisfies Prisma.BecFeedbackSelect;

export type FeedbackRow = Prisma.BecFeedbackGetPayload<{ select: typeof feedbackSelect }>;

const suppressionSelect = {
  id: true,
  publicId: true,
  organizationId: true,
  reasonCode: true,
  senderScope: true,
  senderValue: true,
  feedbackId: true,
  expiresAt: true,
  createdAt: true,
  createdBy: { select: { publicId: true } },
} satisfies Prisma.BecSuppressionRuleSelect;

export type SuppressionRow = Prisma.BecSuppressionRuleGetPayload<{
  select: typeof suppressionSelect;
}>;

const exportResultSelect = {
  id: true,
  receivedAt: true,
  organizationId: true,
  rulesVersion: true,
  engineVersion: true,
  deterministicScore: true,
  score: true,
  verdict: true,
  deterministicVerdict: true,
  rules: true,
  features: true,
  ai: true,
  aiShadow: true,
} satisfies Prisma.BecScanResultSelect;

export type ExportResultRow = Prisma.BecScanResultGetPayload<{
  select: typeof exportResultSelect;
}>;

export interface NewFeedback {
  publicId: string;
  message: FeedbackMessage;
  scanId: bigint;
  becResultId: bigint;
  kind: 'false_positive' | 'false_negative';
  reasonCodes: string[] | null;
  note: string | null;
  userId: bigint | null;
}

export interface NewSuppression {
  publicId: string;
  reasonCode: string;
  senderScope: 'address' | 'domain';
  senderValue: string;
  expiresAt: Date;
  feedbackId: bigint;
  userId: bigint | null;
}

/** Rows one purge batch deletes (B12). */
export const HISTORY_PURGE_BATCH = 5_000;

/**
 * Tenant-scoped access to the BEC feedback, suppression rules, the result rows feedback refers
 * to and the communication history (step 4.4 B11, B12, B18). Reads that decide a write run on
 * the writer transaction the service passes and are echo-checked (organization, message,
 * `received_at`, scan); lists and the export read the replica. Partitioned tables are matched on
 * `(message_id, received_at)` or `(scan_id, received_at)` so they are pruned.
 */
@Injectable()
export class BecFeedbackRepository {
  constructor(private readonly reader: PrismaReadService) {}

  /**
   * Serializes the feedback of one organization (B11): the suppression cap is counted and the
   * `(organization, code, scope, sender)` key looked up under the organization row lock, so two
   * concurrent feedbacks never gap-lock the same absent key (deadlock) or exceed the cap.
   */
  lockOrganization(tx: Client, scope: TenantScope): Promise<void> {
    return lockOrganizationRow(tx, scope);
  }

  private get db() {
    return this.reader.client;
  }

  /** The message of the scope by public id (`message_identities`), on the writer; echo-checked. */
  async findMessage(
    tx: Client,
    scope: TenantScope,
    publicId: string,
  ): Promise<FeedbackMessage | null> {
    const row = await tx.messageIdentity.findFirst({
      where: tenantWhere(scope, { publicId }),
      select: { id: true, publicId: true, receivedAt: true, organizationId: true },
    });
    if (row === null) return null;
    if (row.organizationId !== scope.organizationId || row.publicId !== publicId) {
      throw new InconsistentBecReadError('message');
    }
    return { id: row.id, publicId: row.publicId, receivedAt: row.receivedAt };
  }

  /** True when the scan is a round of the message (writer; echo-checked). */
  async scanExists(
    tx: Client,
    scope: TenantScope,
    message: FeedbackMessage,
    scanId: bigint,
  ): Promise<boolean> {
    const row = await tx.emailScan.findFirst({
      where: tenantWhere(scope, {
        id: scanId,
        messageId: message.id,
        receivedAt: message.receivedAt,
      }),
      select: { id: true, messageId: true, receivedAt: true, organizationId: true },
    });
    if (row === null) return false;
    if (
      row.id !== scanId ||
      row.messageId !== message.id ||
      row.receivedAt.getTime() !== message.receivedAt.getTime() ||
      row.organizationId !== scope.organizationId
    ) {
      throw new InconsistentBecReadError('scan');
    }
    return true;
  }

  /** The `bec_scan_results` row of the scan (writer; echo-checked). */
  async findResult(
    tx: Client,
    scope: TenantScope,
    message: FeedbackMessage,
    scanId: bigint,
  ): Promise<FeedbackResultRow | null> {
    const row = await tx.becScanResult.findFirst({
      where: tenantWhere(scope, {
        scanId,
        receivedAt: message.receivedAt,
        messageId: message.id,
      }),
      select: resultSelect,
    });
    if (row === null) return null;
    if (
      row.scanId !== scanId ||
      row.messageId !== message.id ||
      row.receivedAt.getTime() !== message.receivedAt.getTime() ||
      row.organizationId !== scope.organizationId
    ) {
      throw new InconsistentBecReadError('bec_result');
    }
    return row;
  }

  /** The reason codes of the scan's `bec` final row (writer; echo-checked). */
  async finalReasonCodes(
    tx: Client,
    scope: TenantScope,
    message: FeedbackMessage,
    scanId: bigint,
  ): Promise<unknown> {
    const row = await tx.scanEngineResult.findFirst({
      where: tenantWhere(scope, {
        scanId,
        receivedAt: message.receivedAt,
        messageId: message.id,
        engine: 'bec',
        isFinal: true,
      }),
      select: {
        scanId: true,
        engine: true,
        isFinal: true,
        organizationId: true,
        reasonCodes: true,
      },
    });
    if (row === null) return null;
    if (
      row.scanId !== scanId ||
      row.engine !== 'bec' ||
      !row.isFinal ||
      row.organizationId !== scope.organizationId
    ) {
      throw new InconsistentBecReadError('bec_final');
    }
    return row.reasonCodes;
  }

  createFeedback(tx: Client, scope: TenantScope, input: NewFeedback): Promise<FeedbackRow> {
    return tx.becFeedback.create({
      data: {
        publicId: input.publicId,
        organizationId: scope.organizationId,
        messageId: input.message.id,
        messageReceivedAt: input.message.receivedAt,
        scanId: input.scanId,
        becResultId: input.becResultId,
        kind: input.kind,
        ...(input.reasonCodes !== null && { reasonCodes: input.reasonCodes }),
        note: input.note,
        createdByUserId: input.userId,
      },
      select: feedbackSelect,
    });
  }

  /** The caller's feedback of that kind on the scan (unique `(scan, user, kind)`), writer. */
  async findOwnFeedback(
    tx: Client,
    scope: TenantScope,
    scanId: bigint,
    userId: bigint,
    kind: 'false_positive' | 'false_negative',
  ): Promise<{ id: bigint } | null> {
    const row = await tx.becFeedback.findFirst({
      where: tenantWhere(scope, { scanId, createdByUserId: userId, kind }),
      select: { id: true, scanId: true, kind: true, organizationId: true },
    });
    if (row === null) return null;
    if (row.scanId !== scanId || row.kind !== kind || row.organizationId !== scope.organizationId) {
      throw new InconsistentBecReadError('feedback');
    }
    return { id: row.id };
  }

  listFeedback(
    scope: TenantScope,
    page: {
      take: number;
      beforeId?: bigint;
      kind?: 'false_positive' | 'false_negative';
      from?: Date;
      to?: Date;
    },
  ): Promise<FeedbackRow[]> {
    return this.db.becFeedback.findMany({
      where: tenantWhere(scope, {
        ...(page.beforeId !== undefined && { id: { lt: page.beforeId } }),
        ...(page.kind !== undefined && { kind: page.kind }),
        ...((page.from !== undefined || page.to !== undefined) && {
          createdAt: {
            ...(page.from !== undefined && { gte: page.from }),
            ...(page.to !== undefined && { lt: page.to }),
          },
        }),
      }),
      select: feedbackSelect,
      orderBy: { id: 'desc' },
      take: page.take,
    });
  }

  /** Public ids of messages of the scope by internal id (replica). */
  async messagePublicIds(scope: TenantScope, ids: readonly bigint[]): Promise<Map<bigint, string>> {
    if (ids.length === 0) return new Map();
    const rows = await this.db.messageIdentity.findMany({
      where: tenantWhere(scope, { id: { in: [...new Set(ids)] } }),
      select: { id: true, publicId: true },
    });
    return new Map(rows.map((row) => [row.id, row.publicId]));
  }

  /** Public ids of the scope's feedback by internal id (replica, or the writer client given). */
  async feedbackPublicIds(
    scope: TenantScope,
    ids: readonly bigint[],
    client?: Client,
  ): Promise<Map<bigint, string>> {
    if (ids.length === 0) return new Map();
    const rows = await (client ?? this.db).becFeedback.findMany({
      where: tenantWhere(scope, { id: { in: [...new Set(ids)] } }),
      select: { id: true, publicId: true },
    });
    return new Map(rows.map((row) => [row.id, row.publicId]));
  }

  // ------------------------------------------------------------------------------- export (B11)

  /** Ids of the feedback oldest first after `afterId` within the window (replica). */
  async exportIds(
    scope: TenantScope,
    page: { take: number; afterId?: bigint; from?: Date; to?: Date },
  ): Promise<bigint[]> {
    const rows = await this.db.becFeedback.findMany({
      where: tenantWhere(scope, {
        ...(page.afterId !== undefined && { id: { gt: page.afterId } }),
        ...((page.from !== undefined || page.to !== undefined) && {
          createdAt: {
            ...(page.from !== undefined && { gte: page.from }),
            ...(page.to !== undefined && { lt: page.to }),
          },
        }),
      }),
      select: { id: true },
      orderBy: { id: 'asc' },
      take: page.take,
    });
    return rows.map((row) => row.id);
  }

  /** The feedback rows of the given ids, oldest first (replica). */
  exportFeedback(scope: TenantScope, ids: readonly bigint[]): Promise<FeedbackRow[]> {
    if (ids.length === 0) return Promise.resolve([]);
    return this.db.becFeedback.findMany({
      where: tenantWhere(scope, { id: { in: [...ids] } }),
      select: feedbackSelect,
      orderBy: { id: 'asc' },
    });
  }

  /** The result rows of a feedback batch, matched on the primary key `(id, received_at)`. */
  async exportResults(
    scope: TenantScope,
    keys: ReadonlyArray<{ id: bigint; receivedAt: Date }>,
  ): Promise<ExportResultRow[]> {
    if (keys.length === 0) return [];
    return this.db.becScanResult.findMany({
      where: tenantWhere(scope, {
        OR: keys.map((key) => ({ id: key.id, receivedAt: key.receivedAt })),
      }),
      select: exportResultSelect,
    });
  }

  // ------------------------------------------------------------------------- suppressions (B11)

  listSuppressions(
    scope: TenantScope,
    page: { take: number; beforeId?: bigint; active?: boolean; now: Date },
  ): Promise<SuppressionRow[]> {
    return this.db.becSuppressionRule.findMany({
      where: tenantWhere(scope, {
        ...(page.beforeId !== undefined && { id: { lt: page.beforeId } }),
        ...(page.active === true && { expiresAt: { gt: page.now } }),
        ...(page.active === false && { expiresAt: { lte: page.now } }),
      }),
      select: suppressionSelect,
      orderBy: { id: 'desc' },
      take: page.take,
    });
  }

  countActiveSuppressions(tx: Client, scope: TenantScope, now: Date): Promise<number> {
    return tx.becSuppressionRule.count({ where: tenantWhere(scope, { expiresAt: { gt: now } }) });
  }

  /** The rule of (code, scope, value) on the writer, locked; echo-checked. */
  async findSuppressionByKey(
    tx: Client,
    scope: TenantScope,
    key: { reasonCode: string; senderScope: 'address' | 'domain'; senderValue: string },
  ): Promise<SuppressionRow | null> {
    await tx.$queryRaw`SELECT id FROM bec_suppression_rules
      WHERE organization_id = ${scope.organizationId} AND reason_code = ${key.reasonCode}
        AND sender_scope = ${key.senderScope} AND sender_value = ${key.senderValue} FOR UPDATE`;
    // Only the unique-key columns: a planned suppression also carries `expiresAt`, which must
    // never narrow the lookup (otherwise an existing rule is not renewed and the insert hits
    // the unique key).
    const row = await tx.becSuppressionRule.findFirst({
      where: tenantWhere(scope, {
        reasonCode: key.reasonCode,
        senderScope: key.senderScope,
        senderValue: key.senderValue,
      }),
      select: suppressionSelect,
    });
    if (
      row !== null &&
      (row.organizationId !== scope.organizationId ||
        row.reasonCode !== key.reasonCode ||
        row.senderScope !== key.senderScope ||
        row.senderValue !== key.senderValue)
    ) {
      throw new InconsistentBecReadError('suppression_key');
    }
    return row;
  }

  async findSuppressionForUpdate(
    tx: Client,
    scope: TenantScope,
    publicId: string,
  ): Promise<SuppressionRow | null> {
    await tx.$queryRaw`SELECT id FROM bec_suppression_rules
      WHERE organization_id = ${scope.organizationId} AND public_id = ${publicId} FOR UPDATE`;
    const row = await tx.becSuppressionRule.findFirst({
      where: tenantWhere(scope, { publicId }),
      select: suppressionSelect,
    });
    if (
      row !== null &&
      (row.organizationId !== scope.organizationId || row.publicId !== publicId)
    ) {
      throw new InconsistentBecReadError('suppression');
    }
    return row;
  }

  createSuppression(
    tx: Client,
    scope: TenantScope,
    input: NewSuppression,
  ): Promise<SuppressionRow> {
    return tx.becSuppressionRule.create({
      data: {
        publicId: input.publicId,
        organizationId: scope.organizationId,
        reasonCode: input.reasonCode,
        senderScope: input.senderScope,
        senderValue: input.senderValue,
        expiresAt: input.expiresAt,
        feedbackId: input.feedbackId,
        createdByUserId: input.userId,
      },
      select: suppressionSelect,
    });
  }

  /** Renews a rule (new expiry and feedback); returns the row as it is now. */
  async renewSuppression(
    tx: Client,
    scope: TenantScope,
    id: bigint,
    expiresAt: Date,
    feedbackId: bigint,
  ): Promise<SuppressionRow> {
    await tx.becSuppressionRule.updateMany({
      where: tenantWhere(scope, { id }),
      data: { expiresAt, feedbackId },
    });
    const row = await tx.becSuppressionRule.findFirst({
      where: tenantWhere(scope, { id }),
      select: suppressionSelect,
    });
    if (row === null || row.id !== id || row.organizationId !== scope.organizationId) {
      throw new InconsistentBecReadError('suppression_renewed');
    }
    return row;
  }

  async deleteSuppression(tx: Client, scope: TenantScope, id: bigint): Promise<void> {
    await tx.becSuppressionRule.deleteMany({ where: tenantWhere(scope, { id }) });
  }

  // ------------------------------------------------------------------------------ history (B12)

  /** Deletes up to HISTORY_PURGE_BATCH of the scope's `bec_contact_history` rows. */
  purgeHistoryBatch(tx: Client, scope: TenantScope, batch = HISTORY_PURGE_BATCH): Promise<number> {
    return tx.$executeRaw`DELETE FROM bec_contact_history
      WHERE organization_id = ${scope.organizationId} ORDER BY id LIMIT ${batch}`;
  }
}
