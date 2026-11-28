import { Injectable } from '@nestjs/common';
import { PrismaReadService, uuidv7 } from '@email-gateway/common';
import {
  type ActorType,
  type ApiClawbackAction,
  type ApiClawbackApprovalStatus,
  type ApiClawbackDecisionMode,
  type ApiClawbackRestoreStatus,
  type ApiClawbackSignalLevel,
  type ApiClawbackStatus,
  type ApiClawbackTargetRestoreStatus,
  type ApiClawbackTargetStatus,
  type ApiClawbackTrigger,
  type ApiCopyRemediationAction,
  type ApiCopyRemediationState,
  type ApiMailboxCoverageState,
  type ApiMailboxStatus,
  type ApiModeAutoClawback,
  type ApiUserReportAssessment,
  type ApiUserReportFeedback,
  type ApiUserReportIdentification,
  type ApiUserReportStatus,
  type ApiUserReportVerdict,
  type IntegrationProvider,
  type MessageVerdict,
  Prisma,
  type RiskLevel,
} from '@email-gateway/database';
import { tenantWhere, type TenantScope } from '../../../auth-contracts/tenant-scope';
import { API_MODE_AUDIT, API_MODE_RESOURCES } from '../api-mode.constants';

type Tx = Prisma.TransactionClient;

const num = (v: unknown): number => Number(v ?? 0);
const big = (v: unknown): bigint => BigInt(v as bigint | number | string);
const nullableBig = (v: unknown): bigint | null =>
  v === null || v === undefined ? null : BigInt(v as bigint | number | string);
const nullableNum = (v: unknown): number | null => (v === null || v === undefined ? null : num(v));
const date = (v: unknown): Date | null => (v === null || v === undefined ? null : (v as Date));

/** A JSON column read through `$queryRaw` (a string on some drivers). */
export function jsonOf(value: unknown): unknown {
  if (typeof value !== 'string') return value ?? null;
  try {
    return JSON.parse(value) as unknown;
  } catch {
    return null;
  }
}

// ---- rows ---------------------------------------------------------------------------------------

/** `api_mode_org_settings` as the api reads it (absent = defaults). */
export interface OrgSettingsRow {
  internalMailEnabled: boolean;
  autoClawback: ApiModeAutoClawback;
  autoMaxMailboxes: number;
  purgeApprovalMailboxes: number;
  clawbackLookbackDays: number;
  tiMinConfidence: number;
  reportAckEnabled: boolean;
  reportFeedbackEnabled: boolean;
  /** Step API-4 (A1, A6); optional for API-3 callers (absent = the default, on). */
  policyEvaluationEnabled?: boolean;
  outboundDetectionEnabled?: boolean;
  rowVersion: number;
  updatedAt: Date;
  /** P2 separation of duties: who last raised `purgeApprovalMailboxes` (a principal key). */
  purgeApprovalRaisedBy: string | null;
  /** The threshold before that raise (the raiser's own purges are checked against it). */
  purgeApprovalBeforeRaise: number | null;
}

export type OrgSettingsWrite = Omit<OrgSettingsRow, 'rowVersion' | 'updatedAt'> & {
  updatedByUserId: bigint | null;
};

/** The facts of a seed detection (C2.4): keys only, never content. */
export interface SeedCopyRow {
  id: bigint;
  publicId: string;
  receivedAt: Date;
  messageId: bigint;
  messageIdHash: string | null;
  sender: string | null;
  subjectKey: string | null;
  attachmentSha256: string[];
  urlSha256: string[];
}

/** One clawback as the views and the writes read it. */
export interface ClawbackRow {
  id: bigint;
  publicId: string;
  trigger: ApiClawbackTrigger;
  status: ApiClawbackStatus;
  signal: unknown;
  criteria: unknown;
  decisionMode: ApiClawbackDecisionMode | null;
  action: ApiClawbackAction | null;
  signalVerdict: MessageVerdict | null;
  signalLevel: ApiClawbackSignalLevel | null;
  signalHardBlocks: unknown;
  cancelRequestedAt: Date | null;
  restoreStatus: ApiClawbackRestoreStatus;
  targetsTotal: number;
  mailboxesTotal: number;
  targetsEligible: number;
  mailboxesEligible: number;
  targetsSkipped: number;
  targetsSimulated: number;
  targetsQueued: number;
  targetsSucceeded: number;
  targetsFailed: number;
  targetsCancelled: number;
  restoresQueued: number;
  restoresSucceeded: number;
  restoresFailed: number;
  restoresSkipped: number;
  requiresApproval: boolean;
  approvalReasons: unknown;
  approvalStatus: ApiClawbackApprovalStatus | null;
  approvalRequestedAt: Date | null;
  approvalExpiresAt: Date | null;
  approvalDecidedAt: Date | null;
  approvedByUserId: bigint | null;
  approvalDecisionReason: string | null;
  requestedByType: ActorType;
  requestedByUserId: bigint | null;
  submittedByUserId: bigint | null;
  requestReason: string | null;
  submittedAt: Date | null;
  reportId: bigint | null;
  seedCopyId: bigint | null;
  seedCopyReceivedAt: Date | null;
  signalAt: Date;
  lastErrorCode: string | null;
  rowVersion: number;
  startedAt: Date | null;
  completedAt: Date | null;
  createdAt: Date;
  updatedAt: Date;
  /** Joined public ids. */
  reportPublicId: string | null;
  requestedByUserPublicId: string | null;
  submittedByUserPublicId: string | null;
  approvedByUserPublicId: string | null;
  seedCopyPublicId: string | null;
}

export interface ClawbackFilter {
  status?: ApiClawbackStatus[];
  trigger?: ApiClawbackTrigger[];
  approvalStatus?: ApiClawbackApprovalStatus[];
}

export interface CreateClawbackRow {
  publicId: string;
  trigger: ApiClawbackTrigger;
  signal: Prisma.InputJsonValue;
  criteria: Prisma.InputJsonValue;
  criteriaSha256: string;
  requestedByType: ActorType;
  requestedByUserId: bigint | null;
  requestReason: string;
  reportId: bigint | null;
  seedCopyId: bigint | null;
  seedCopyReceivedAt: Date | null;
  now: Date;
}

/** Fields a write changes on a clawback (CAS on `row_version`, +1). */
export type ClawbackUpdate = Partial<{
  status: ApiClawbackStatus;
  decisionMode: ApiClawbackDecisionMode;
  action: ApiClawbackAction | null;
  signalVerdict: MessageVerdict;
  signalLevel: ApiClawbackSignalLevel;
  signalHardBlocks: Prisma.InputJsonValue;
  requiresApproval: boolean;
  approvalReasons: Prisma.InputJsonValue | typeof Prisma.DbNull;
  approvalStatus: ApiClawbackApprovalStatus | null;
  approvalRequestedAt: Date | null;
  approvalExpiresAt: Date | null;
  approvalDecidedAt: Date | null;
  approvedByUserId: bigint | null;
  approvalDecisionReason: string | null;
  approverPermissionsHash: string | null;
  submittedByUserId: bigint | null;
  submittedAt: Date;
  requestReason: string;
  cancelRequestedAt: Date;
  restoreStatus: ApiClawbackRestoreStatus;
  nextStepAt: Date | null;
  completedAt: Date;
}>;

export interface TargetRow {
  id: bigint;
  mailboxPublicId: string;
  mailboxAddress: string;
  connectionPublicId: string;
  detectionPublicId: string | null;
  receivedAt: Date;
  headerFrom: string | null;
  subject: string | null;
  matchKeys: unknown;
  copyRemediationState: ApiCopyRemediationState | null;
  status: ApiClawbackTargetStatus;
  plannedAction: ApiCopyRemediationAction | null;
  reasonCode: string | null;
  remediationPublicId: string | null;
  restoreStatus: ApiClawbackTargetRestoreStatus;
  restoreReasonCode: string | null;
}

export interface TargetFilter {
  status?: ApiClawbackTargetStatus[];
  restoreStatus?: ApiClawbackTargetRestoreStatus[];
  mailboxPublicId?: string;
}

/** One report as the views and the writes read it. */
export interface ReportRow {
  id: bigint;
  publicId: string;
  apiConnectionId: bigint;
  status: ApiUserReportStatus;
  reporterAddress: string;
  reportedAt: Date;
  identification: ApiUserReportIdentification | null;
  original: unknown;
  groupKey: string | null;
  originalIngested: boolean;
  scanVerdict: MessageVerdict | null;
  scanRiskScore: number | null;
  scanLevel: RiskLevel | null;
  assessment: ApiUserReportAssessment | null;
  analystVerdict: ApiUserReportVerdict | null;
  analystNote: string | null;
  triagedAt: Date | null;
  clawbackId: bigint | null;
  ackFeedback: ApiUserReportFeedback;
  resultFeedback: ApiUserReportFeedback;
  rejectReason: string | null;
  rowVersion: number;
  updatedAt: Date;
  /** Joined public ids and addresses. */
  clawbackPublicId: string | null;
  reportMailboxPublicId: string;
  reportMailboxAddress: string;
  reporterMailboxPublicId: string | null;
  reporterUserPublicId: string | null;
  triagedByUserPublicId: string | null;
  originalCopyPublicId: string | null;
}

export interface ReportFilter {
  status?: ApiUserReportStatus[];
  assessment?: ApiUserReportAssessment[];
  analystVerdict?: ApiUserReportVerdict[];
  reporter?: string;
}

export type ReportUpdate = Partial<{
  status: ApiUserReportStatus;
  analystVerdict: ApiUserReportVerdict | null;
  analystNote: string | null;
  triagedByUserId: bigint | null;
  triagedAt: Date;
  rejectReason: string | null;
  resultFeedback: ApiUserReportFeedback;
  clawbackId: bigint;
}>;

export interface HistoryRow {
  at: Date;
  actorType: string;
  actorId: string | null;
  metadata: unknown;
}

/** A mailbox as the report-mailbox routes read it. */
export interface ReportMailboxRow {
  id: bigint;
  publicId: string;
  primaryAddress: string;
  apiConnectionId: bigint;
  connectionPublicId: string;
  provider: IntegrationProvider;
  status: ApiMailboxStatus;
  coverageState: ApiMailboxCoverageState;
  domain: { id: bigint; publicId: string; name: string; apiSide: boolean } | null;
  reportMailbox: boolean;
  reportMailboxAt: Date | null;
  lastReportAt: Date | null;
}

export interface ClawbackOverviewCounts {
  active: number;
  reviewRequired: number;
  pendingApproval: number;
  completed24h: number;
  oldestActiveCreatedAt: Date | null;
}

export interface ReportOverviewCounts {
  pendingTriage: number;
  inReview: number;
  oldestPendingReportedAt: Date | null;
  reportMailboxes: number;
}

export interface ClawbackCounterRow {
  apiConnectionId: bigint;
  hour: Date;
  internalCopies: number;
  clawbackTargetsQueued: number;
  clawbackTargetsSucceeded: number;
  clawbackTargetsFailed: number;
  reportsReceived: number;
  reportsResolved: number;
  /** Step API-4 (A3, A6): detect-mode evaluations, their failures and outbound detections. */
  policyEvaluations?: number;
  policyErrors?: number;
  outboundDetections?: number;
}

export interface OutboxRow {
  eventId: string;
  organizationId: bigint;
  eventType: string;
  aggregateType: string;
  aggregateId: string;
  correlationId: string;
  payload: Prisma.InputJsonValue;
}

const ACTIVE_STATUSES = [
  'searching',
  'ready',
  'review_required',
  'pending_approval',
  'queued',
  'running',
] as const;

/**
 * Data access of the API-mode clawback, report and settings routes (step API-3 §3, C6, C9, C11,
 * C13, C14, docs/plan/steps/37-api-mode-clawback-reporting.md; ADR-0103, ADR-0104): clawbacks
 * and their frozen targets, user reports with their groups and triage history (audit rows),
 * report-mailbox designation, the organization's API-mode settings (CAS on `row_version`), the
 * outbox rows and the purge-approval alert window, and the overview's live counts. Every query is
 * filtered by the scope's organization (foreign ids read as missing); lists read the replica,
 * writes lock their rows (`FOR UPDATE`) in the caller's writer transaction.
 */
@Injectable()
export class ApiClawbackRepository {
  constructor(private readonly reader: PrismaReadService) {}

  // ---- settings (C14 #18, #19) ---------------------------------------------------------------

  private readonly settingsSelect = {
    internalMailEnabled: true,
    autoClawback: true,
    autoMaxMailboxes: true,
    purgeApprovalMailboxes: true,
    clawbackLookbackDays: true,
    tiMinConfidence: true,
    reportAckEnabled: true,
    reportFeedbackEnabled: true,
    policyEvaluationEnabled: true,
    outboundDetectionEnabled: true,
    rowVersion: true,
    updatedAt: true,
    purgeApprovalRaisedBy: true,
    purgeApprovalBeforeRaise: true,
  } satisfies Prisma.ApiModeOrgSettingSelect;

  /** The organization's settings row (replica unless a client is given), null = defaults. */
  orgSettings(scope: TenantScope, client?: Tx): Promise<OrgSettingsRow | null> {
    const db = client ?? this.reader.client;
    return db.apiModeOrgSetting.findFirst({
      where: { organizationId: scope.organizationId },
      select: this.settingsSelect,
    });
  }

  /** Serializes the organization's settings and report-mailbox writes (organization row lock). */
  async lockOrganization(tx: Tx, scope: TenantScope): Promise<boolean> {
    const rows = await tx.$queryRaw<Array<{ id: bigint }>>`
      SELECT id FROM organizations WHERE id = ${scope.organizationId} FOR UPDATE`;
    return rows.length === 1;
  }

  /** The settings row, locked (`FOR UPDATE`), or null. */
  async lockOrgSettings(tx: Tx, scope: TenantScope): Promise<OrgSettingsRow | null> {
    const rows = await tx.$queryRaw<Array<{ organizationId: bigint }>>`
      SELECT organization_id AS organizationId FROM api_mode_org_settings
      WHERE organization_id = ${scope.organizationId} FOR UPDATE`;
    if (rows.length === 0) return null;
    return this.orgSettings(scope, tx);
  }

  async createOrgSettings(tx: Tx, scope: TenantScope, write: OrgSettingsWrite): Promise<void> {
    await tx.apiModeOrgSetting.create({
      data: { organizationId: scope.organizationId, ...write },
      select: { organizationId: true },
    });
  }

  /** CAS on `row_version` (+1); false when the version moved. */
  async updateOrgSettings(
    tx: Tx,
    scope: TenantScope,
    rowVersion: number,
    write: OrgSettingsWrite,
  ): Promise<boolean> {
    const { count } = await tx.apiModeOrgSetting.updateMany({
      where: { organizationId: scope.organizationId, rowVersion },
      data: { ...write, rowVersion: { increment: 1 } },
    });
    return count === 1;
  }

  // ---- seed detection (C2.4) -----------------------------------------------------------------

  /** The scope's copy with its registry message's keys (attachment and URL hashes ≤ 20 each). */
  async seedCopy(tx: Tx, scope: TenantScope, publicId: string): Promise<SeedCopyRow | null> {
    const rows = await tx.$queryRaw<Array<Record<string, unknown>>>`
      SELECT c.id, c.public_id AS publicId, c.received_at AS receivedAt, c.message_id AS messageId,
             c.message_id_hash AS messageIdHash, m.header_from AS headerFrom,
             m.envelope_from AS envelopeFrom, m.subject_key AS subjectKey
      FROM api_message_copies c
      LEFT JOIN email_messages m
        ON m.id = c.message_id AND m.received_at = c.received_at
       AND m.organization_id = c.organization_id
      WHERE c.organization_id = ${scope.organizationId} AND c.public_id = ${publicId}
      LIMIT 1`;
    const r = rows[0];
    if (r === undefined) return null;
    const messageId = big(r.messageId);
    const receivedAt = r.receivedAt as Date;
    const [attachments, urls] = await Promise.all([
      tx.$queryRaw<Array<{ sha256: string }>>`
        SELECT DISTINCT sha256 FROM email_attachments
        WHERE organization_id = ${scope.organizationId} AND message_id = ${messageId}
          AND received_at = ${receivedAt} AND sha256 IS NOT NULL
        LIMIT 20`,
      tx.$queryRaw<Array<{ sha256: string }>>`
        SELECT DISTINCT url_sha256 AS sha256 FROM message_urls
        WHERE organization_id = ${scope.organizationId} AND message_id = ${messageId}
          AND received_at = ${receivedAt}
        LIMIT 20`,
    ]);
    const lower = (v: unknown): string | null =>
      typeof v === 'string' && v.includes('@') ? v.trim().toLowerCase() : null;
    return {
      id: big(r.id),
      publicId: r.publicId as string,
      receivedAt,
      messageId,
      messageIdHash: (r.messageIdHash as string | null) ?? null,
      sender: lower(r.headerFrom) ?? lower(r.envelopeFrom),
      subjectKey: (r.subjectKey as string | null) ?? null,
      attachmentSha256: attachments.map((a) => a.sha256.toLowerCase()),
      urlSha256: urls.map((u) => u.sha256.toLowerCase()),
    };
  }

  // ---- clawbacks (C14 #1-#10) ----------------------------------------------------------------

  async createClawback(
    tx: Tx,
    scope: TenantScope,
    row: CreateClawbackRow,
  ): Promise<{ id: bigint; publicId: string; rowVersion: number }> {
    return tx.apiClawback.create({
      data: {
        publicId: row.publicId,
        organizationId: scope.organizationId,
        trigger: row.trigger,
        signalKey: null,
        signal: row.signal,
        criteria: row.criteria,
        criteriaSha256: row.criteriaSha256,
        status: 'searching',
        requestedByType: row.requestedByType,
        requestedByUserId: row.requestedByUserId,
        requestReason: row.requestReason,
        reportId: row.reportId,
        seedCopyId: row.seedCopyId,
        seedCopyReceivedAt: row.seedCopyReceivedAt,
        signalAt: row.now,
        nextStepAt: row.now,
        createdAt: row.now,
      },
      select: { id: true, publicId: true, rowVersion: true },
    });
  }

  private clawbackSql(scope: TenantScope, where: Prisma.Sql, limit: number): Prisma.Sql {
    return Prisma.sql`
      SELECT k.id, k.public_id AS publicId, k.\`trigger\` AS triggerKind, k.status, k.signal,
             k.criteria, k.decision_mode AS decisionMode, k.action,
             k.signal_verdict AS signalVerdict, k.signal_level AS signalLevel,
             k.signal_hard_blocks AS signalHardBlocks, k.cancel_requested_at AS cancelRequestedAt,
             k.restore_status AS restoreStatus, k.targets_total AS targetsTotal,
             k.mailboxes_total AS mailboxesTotal, k.targets_eligible AS targetsEligible,
             k.mailboxes_eligible AS mailboxesEligible, k.targets_skipped AS targetsSkipped,
             k.targets_simulated AS targetsSimulated, k.targets_queued AS targetsQueued,
             k.targets_succeeded AS targetsSucceeded, k.targets_failed AS targetsFailed,
             k.targets_cancelled AS targetsCancelled, k.restores_queued AS restoresQueued,
             k.restores_succeeded AS restoresSucceeded, k.restores_failed AS restoresFailed,
             k.restores_skipped AS restoresSkipped, k.requires_approval AS requiresApproval,
             k.approval_reasons AS approvalReasons, k.approval_status AS approvalStatus,
             k.approval_requested_at AS approvalRequestedAt,
             k.approval_expires_at AS approvalExpiresAt,
             k.approval_decided_at AS approvalDecidedAt,
             k.approved_by_user_id AS approvedByUserId,
             k.approval_decision_reason AS approvalDecisionReason,
             k.requested_by_type AS requestedByType, k.requested_by_user_id AS requestedByUserId,
             k.submitted_by_user_id AS submittedByUserId, k.request_reason AS requestReason,
             k.submitted_at AS submittedAt, k.report_id AS reportId,
             k.seed_copy_id AS seedCopyId, k.seed_copy_received_at AS seedCopyReceivedAt,
             k.signal_at AS signalAt, k.last_error_code AS lastErrorCode,
             k.row_version AS rowVersion, k.started_at AS startedAt,
             k.completed_at AS completedAt, k.created_at AS createdAt, k.updated_at AS updatedAt,
             r.public_id AS reportPublicId, ru.public_id AS requestedByUserPublicId,
             su.public_id AS submittedByUserPublicId, au.public_id AS approvedByUserPublicId,
             sc.public_id AS seedCopyPublicId
      FROM api_clawbacks k
      LEFT JOIN api_user_reports r ON r.id = k.report_id AND r.organization_id = k.organization_id
      LEFT JOIN users ru ON ru.id = k.requested_by_user_id
      LEFT JOIN users su ON su.id = k.submitted_by_user_id
      LEFT JOIN users au ON au.id = k.approved_by_user_id
      LEFT JOIN api_message_copies sc
        ON sc.id = k.seed_copy_id AND sc.received_at = k.seed_copy_received_at
       AND sc.organization_id = k.organization_id
      WHERE k.organization_id = ${scope.organizationId} AND ${where}
      ORDER BY k.created_at DESC, k.id DESC
      LIMIT ${limit}`;
  }

  private toClawback(r: Record<string, unknown>): ClawbackRow {
    return {
      id: big(r.id),
      publicId: r.publicId as string,
      trigger: r.triggerKind as ApiClawbackTrigger,
      status: r.status as ApiClawbackStatus,
      signal: jsonOf(r.signal),
      criteria: jsonOf(r.criteria),
      decisionMode: (r.decisionMode as ApiClawbackDecisionMode | null) ?? null,
      action: (r.action as ApiClawbackAction | null) ?? null,
      signalVerdict: (r.signalVerdict as MessageVerdict | null) ?? null,
      signalLevel: (r.signalLevel as ApiClawbackSignalLevel | null) ?? null,
      signalHardBlocks: jsonOf(r.signalHardBlocks),
      cancelRequestedAt: date(r.cancelRequestedAt),
      restoreStatus: r.restoreStatus as ApiClawbackRestoreStatus,
      targetsTotal: num(r.targetsTotal),
      mailboxesTotal: num(r.mailboxesTotal),
      targetsEligible: num(r.targetsEligible),
      mailboxesEligible: num(r.mailboxesEligible),
      targetsSkipped: num(r.targetsSkipped),
      targetsSimulated: num(r.targetsSimulated),
      targetsQueued: num(r.targetsQueued),
      targetsSucceeded: num(r.targetsSucceeded),
      targetsFailed: num(r.targetsFailed),
      targetsCancelled: num(r.targetsCancelled),
      restoresQueued: num(r.restoresQueued),
      restoresSucceeded: num(r.restoresSucceeded),
      restoresFailed: num(r.restoresFailed),
      restoresSkipped: num(r.restoresSkipped),
      requiresApproval: Boolean(r.requiresApproval),
      approvalReasons: jsonOf(r.approvalReasons),
      approvalStatus: (r.approvalStatus as ApiClawbackApprovalStatus | null) ?? null,
      approvalRequestedAt: date(r.approvalRequestedAt),
      approvalExpiresAt: date(r.approvalExpiresAt),
      approvalDecidedAt: date(r.approvalDecidedAt),
      approvedByUserId: nullableBig(r.approvedByUserId),
      approvalDecisionReason: (r.approvalDecisionReason as string | null) ?? null,
      requestedByType: r.requestedByType as ActorType,
      requestedByUserId: nullableBig(r.requestedByUserId),
      submittedByUserId: nullableBig(r.submittedByUserId),
      requestReason: (r.requestReason as string | null) ?? null,
      submittedAt: date(r.submittedAt),
      reportId: nullableBig(r.reportId),
      seedCopyId: nullableBig(r.seedCopyId),
      seedCopyReceivedAt: date(r.seedCopyReceivedAt),
      signalAt: r.signalAt as Date,
      lastErrorCode: (r.lastErrorCode as string | null) ?? null,
      rowVersion: num(r.rowVersion),
      startedAt: date(r.startedAt),
      completedAt: date(r.completedAt),
      createdAt: r.createdAt as Date,
      updatedAt: r.updatedAt as Date,
      reportPublicId: (r.reportPublicId as string | null) ?? null,
      requestedByUserPublicId: (r.requestedByUserPublicId as string | null) ?? null,
      submittedByUserPublicId: (r.submittedByUserPublicId as string | null) ?? null,
      approvedByUserPublicId: (r.approvedByUserPublicId as string | null) ?? null,
      seedCopyPublicId: (r.seedCopyPublicId as string | null) ?? null,
    };
  }

  /** A page in `[from, to)` of `created_at`, newest first (replica; keyset `(created_at, id)`). */
  async clawbacks(
    scope: TenantScope,
    filter: ClawbackFilter,
    range: { from: Date; to: Date },
    page: { take: number; before?: { at: Date; id: bigint } },
  ): Promise<ClawbackRow[]> {
    const terms: Prisma.Sql[] = [
      Prisma.sql`k.created_at >= ${range.from}`,
      Prisma.sql`k.created_at < ${range.to}`,
    ];
    if (filter.status) terms.push(Prisma.sql`k.status IN (${Prisma.join(filter.status)})`);
    if (filter.trigger) terms.push(Prisma.sql`k.\`trigger\` IN (${Prisma.join(filter.trigger)})`);
    if (filter.approvalStatus) {
      terms.push(Prisma.sql`k.approval_status IN (${Prisma.join(filter.approvalStatus)})`);
    }
    if (page.before !== undefined) {
      terms.push(
        Prisma.sql`(k.created_at < ${page.before.at} OR (k.created_at = ${page.before.at} AND k.id < ${page.before.id}))`,
      );
    }
    const rows = await this.reader.client.$queryRaw<Array<Record<string, unknown>>>(
      this.clawbackSql(scope, Prisma.join(terms, ' AND '), page.take),
    );
    return rows.map((r) => this.toClawback(r));
  }

  /** One clawback by public id (replica unless a client is given). */
  async clawback(scope: TenantScope, publicId: string, client?: Tx): Promise<ClawbackRow | null> {
    const db = client ?? this.reader.client;
    const rows = await db.$queryRaw<Array<Record<string, unknown>>>(
      this.clawbackSql(scope, Prisma.sql`k.public_id = ${publicId}`, 1),
    );
    return rows[0] === undefined ? null : this.toClawback(rows[0]);
  }

  /** The scope's clawback by public id, locked (`FOR UPDATE`). */
  async lockClawback(tx: Tx, scope: TenantScope, publicId: string): Promise<ClawbackRow | null> {
    const ids = await tx.$queryRaw<Array<{ id: bigint }>>`
      SELECT id FROM api_clawbacks
      WHERE organization_id = ${scope.organizationId} AND public_id = ${publicId}
      FOR UPDATE`;
    if (ids.length === 0) return null;
    return this.clawback(scope, publicId, tx);
  }

  /** CAS on `row_version` (+1); false when the version moved. */
  async updateClawback(
    tx: Tx,
    scope: TenantScope,
    id: bigint,
    rowVersion: number,
    update: ClawbackUpdate,
  ): Promise<boolean> {
    const { count } = await tx.apiClawback.updateMany({
      where: tenantWhere(scope, { id, rowVersion }),
      data: { ...update, rowVersion: { increment: 1 } },
    });
    return count === 1;
  }

  /** A page of the clawback's targets in materialization order (replica; keyset `id`). */
  async targets(
    scope: TenantScope,
    clawbackId: bigint,
    filter: TargetFilter,
    page: { take: number; afterId?: bigint },
  ): Promise<TargetRow[]> {
    const terms: Prisma.Sql[] = [Prisma.sql`t.clawback_id = ${clawbackId}`];
    if (filter.status) terms.push(Prisma.sql`t.status IN (${Prisma.join(filter.status)})`);
    if (filter.restoreStatus) {
      terms.push(Prisma.sql`t.restore_status IN (${Prisma.join(filter.restoreStatus)})`);
    }
    if (filter.mailboxPublicId !== undefined) {
      terms.push(Prisma.sql`mb.public_id = ${filter.mailboxPublicId}`);
    }
    if (page.afterId !== undefined) terms.push(Prisma.sql`t.id > ${page.afterId}`);
    const rows = await this.reader.client.$queryRaw<Array<Record<string, unknown>>>`
      SELECT t.id, mb.public_id AS mailboxPublicId, mb.primary_address AS mailboxAddress,
             pc.public_id AS connectionPublicId, c.public_id AS detectionPublicId,
             t.copy_received_at AS receivedAt, m.header_from AS headerFrom, m.subject,
             t.match_keys AS matchKeys, c.remediation_state AS copyRemediationState,
             t.status, t.planned_action AS plannedAction, t.reason_code AS reasonCode,
             a.public_id AS remediationPublicId, t.restore_status AS restoreStatus,
             t.restore_reason_code AS restoreReasonCode
      FROM api_clawback_targets t
      JOIN api_mailboxes mb ON mb.id = t.mailbox_id AND mb.organization_id = t.organization_id
      JOIN api_mode_connections ac
        ON ac.id = t.api_connection_id AND ac.organization_id = t.organization_id
      JOIN provider_connections pc
        ON pc.id = ac.provider_connection_id AND pc.organization_id = t.organization_id
      LEFT JOIN api_message_copies c
        ON c.id = t.copy_id AND c.received_at = t.copy_received_at
       AND c.organization_id = t.organization_id
      LEFT JOIN email_messages m
        ON m.id = t.message_id AND m.received_at = t.copy_received_at
       AND m.organization_id = t.organization_id
      LEFT JOIN api_remediation_actions a
        ON a.id = t.action_id AND a.organization_id = t.organization_id
      WHERE t.organization_id = ${scope.organizationId} AND ${Prisma.join(terms, ' AND ')}
      ORDER BY t.id ASC
      LIMIT ${page.take}`;
    return rows.map((r) => ({
      id: big(r.id),
      mailboxPublicId: r.mailboxPublicId as string,
      mailboxAddress: r.mailboxAddress as string,
      connectionPublicId: r.connectionPublicId as string,
      detectionPublicId: (r.detectionPublicId as string | null) ?? null,
      receivedAt: r.receivedAt as Date,
      headerFrom: (r.headerFrom as string | null) ?? null,
      subject: (r.subject as string | null) ?? null,
      matchKeys: jsonOf(r.matchKeys),
      copyRemediationState: (r.copyRemediationState as ApiCopyRemediationState | null) ?? null,
      status: r.status as ApiClawbackTargetStatus,
      plannedAction: (r.plannedAction as ApiCopyRemediationAction | null) ?? null,
      reasonCode: (r.reasonCode as string | null) ?? null,
      remediationPublicId: (r.remediationPublicId as string | null) ?? null,
      restoreStatus: r.restoreStatus as ApiClawbackTargetRestoreStatus,
      restoreReasonCode: (r.restoreReasonCode as string | null) ?? null,
    }));
  }

  /**
   * The public ids of the clawbacks that targeted each copy (newest first, ≤ `max` per copy;
   * index `(organization_id, copy_id, copy_received_at)`; replica).
   */
  async clawbacksOfCopies(
    scope: TenantScope,
    copies: ReadonlyArray<{ id: bigint; receivedAt: Date }>,
    max: number,
  ): Promise<Map<string, string[]>> {
    const out = new Map<string, string[]>();
    if (copies.length === 0) return out;
    const pairs = copies.map((c) => Prisma.sql`(${c.id}, ${c.receivedAt})`);
    const rows = await this.reader.client.$queryRaw<
      Array<{ copyId: bigint; receivedAt: Date; publicId: string }>
    >`
      SELECT t.copy_id AS copyId, t.copy_received_at AS receivedAt, k.public_id AS publicId
      FROM api_clawback_targets t
      JOIN api_clawbacks k ON k.id = t.clawback_id AND k.organization_id = t.organization_id
      WHERE t.organization_id = ${scope.organizationId}
        AND (t.copy_id, t.copy_received_at) IN (${Prisma.join(pairs)})
      ORDER BY k.id DESC
      LIMIT ${copies.length * max}`;
    for (const r of rows) {
      const key = copyKey(big(r.copyId), r.receivedAt);
      const list = out.get(key) ?? [];
      if (list.length < max && !list.includes(r.publicId)) list.push(r.publicId);
      out.set(key, list);
    }
    return out;
  }

  // ---- outbox and the purge-approval alert (C6) ----------------------------------------------

  async insertOutbox(tx: Tx, row: OutboxRow): Promise<void> {
    await tx.messageOutbox.create({ data: row, select: { id: true } });
  }

  /**
   * The throttle window (`notification_alert_windows`, kind `api_mode_purge_approval`, scope =
   * the clawback public id, size `windowMinutes`) and, for its first event only, the alert's
   * outbox row (built by `payload` from the window and the suppressed count of the previous
   * window). True when the alert was requested.
   */
  async requestAlert(
    tx: Tx,
    input: {
      organizationId: bigint;
      kind: string;
      scopeKey: string;
      window: { from: Date; to: Date };
      windowMinutes: number;
      sourceEventId: string;
      outbox: (suppressedBefore: number) => OutboxRow;
    },
  ): Promise<boolean> {
    const affected = await tx.$executeRaw`
      INSERT INTO notification_alert_windows
        (organization_id, kind, scope_key, window_start, event_count, first_source_event_id,
         created_at, updated_at)
      VALUES (${input.organizationId}, ${input.kind}, ${input.scopeKey}, ${input.window.from}, 1,
              ${input.sourceEventId}, NOW(3), NOW(3))
      ON DUPLICATE KEY UPDATE event_count = event_count + 1, updated_at = NOW(3)`;
    // MySQL: 1 = inserted (first event of the window), 2 = an existing window was counted.
    if (affected !== 1) return false;
    const previous = await tx.$queryRaw<Array<{ eventCount: number | bigint }>>`
      SELECT event_count AS eventCount FROM notification_alert_windows
      WHERE organization_id = ${input.organizationId} AND kind = ${input.kind}
        AND scope_key = ${input.scopeKey}
        AND window_start = ${new Date(input.window.from.getTime() - input.windowMinutes * 60_000)}`;
    const row = input.outbox(Math.max(0, num(previous[0]?.eventCount) - 1));
    await this.insertOutbox(tx, row);
    await tx.$executeRaw`
      UPDATE notification_alert_windows SET alert_event_id = ${row.eventId}
      WHERE organization_id = ${input.organizationId} AND kind = ${input.kind}
        AND scope_key = ${input.scopeKey} AND window_start = ${input.window.from}`;
    return true;
  }

  // ---- reports (C14 #11-#14) -----------------------------------------------------------------

  private reportSql(scope: TenantScope, where: Prisma.Sql, limit: number): Prisma.Sql {
    return Prisma.sql`
      SELECT r.id, r.public_id AS publicId, r.api_connection_id AS apiConnectionId, r.status,
             r.reporter_address AS reporterAddress, r.reported_at AS reportedAt,
             r.identification, r.original, r.group_key AS groupKey,
             r.original_ingested AS originalIngested, r.scan_verdict AS scanVerdict,
             r.scan_risk_score AS scanRiskScore, r.scan_level AS scanLevel, r.assessment,
             r.analyst_verdict AS analystVerdict, r.analyst_note AS analystNote,
             r.triaged_at AS triagedAt, r.clawback_id AS clawbackId,
             r.ack_feedback AS ackFeedback, r.result_feedback AS resultFeedback,
             r.reject_reason AS rejectReason, r.row_version AS rowVersion,
             r.updated_at AS updatedAt, k.public_id AS clawbackPublicId,
             rm.public_id AS reportMailboxPublicId, rm.primary_address AS reportMailboxAddress,
             pm.public_id AS reporterMailboxPublicId, ru.public_id AS reporterUserPublicId,
             tu.public_id AS triagedByUserPublicId, oc.public_id AS originalCopyPublicId
      FROM api_user_reports r
      JOIN api_mailboxes rm ON rm.id = r.report_mailbox_id AND rm.organization_id = r.organization_id
      LEFT JOIN api_clawbacks k ON k.id = r.clawback_id AND k.organization_id = r.organization_id
      LEFT JOIN api_mailboxes pm
        ON pm.id = r.reporter_mailbox_id AND pm.organization_id = r.organization_id
      LEFT JOIN users ru ON ru.id = r.reporter_user_id
      LEFT JOIN users tu ON tu.id = r.triaged_by_user_id
      LEFT JOIN api_message_copies oc
        ON oc.id = r.original_copy_id AND oc.received_at = r.original_copy_received_at
       AND oc.organization_id = r.organization_id
      WHERE r.organization_id = ${scope.organizationId} AND ${where}
      ORDER BY r.reported_at DESC, r.id DESC
      LIMIT ${limit}`;
  }

  private toReport(r: Record<string, unknown>): ReportRow {
    return {
      id: big(r.id),
      publicId: r.publicId as string,
      apiConnectionId: big(r.apiConnectionId),
      status: r.status as ApiUserReportStatus,
      reporterAddress: r.reporterAddress as string,
      reportedAt: r.reportedAt as Date,
      identification: (r.identification as ApiUserReportIdentification | null) ?? null,
      original: jsonOf(r.original),
      groupKey: (r.groupKey as string | null) ?? null,
      originalIngested: Boolean(r.originalIngested),
      scanVerdict: (r.scanVerdict as MessageVerdict | null) ?? null,
      scanRiskScore: nullableNum(r.scanRiskScore),
      scanLevel: (r.scanLevel as RiskLevel | null) ?? null,
      assessment: (r.assessment as ApiUserReportAssessment | null) ?? null,
      analystVerdict: (r.analystVerdict as ApiUserReportVerdict | null) ?? null,
      analystNote: (r.analystNote as string | null) ?? null,
      triagedAt: date(r.triagedAt),
      clawbackId: nullableBig(r.clawbackId),
      ackFeedback: r.ackFeedback as ApiUserReportFeedback,
      resultFeedback: r.resultFeedback as ApiUserReportFeedback,
      rejectReason: (r.rejectReason as string | null) ?? null,
      rowVersion: num(r.rowVersion),
      updatedAt: r.updatedAt as Date,
      clawbackPublicId: (r.clawbackPublicId as string | null) ?? null,
      reportMailboxPublicId: r.reportMailboxPublicId as string,
      reportMailboxAddress: r.reportMailboxAddress as string,
      reporterMailboxPublicId: (r.reporterMailboxPublicId as string | null) ?? null,
      reporterUserPublicId: (r.reporterUserPublicId as string | null) ?? null,
      triagedByUserPublicId: (r.triagedByUserPublicId as string | null) ?? null,
      originalCopyPublicId: (r.originalCopyPublicId as string | null) ?? null,
    };
  }

  /** A page in `[from, to)` of `reported_at`, newest first (replica; keyset `(reported_at, id)`). */
  async reports(
    scope: TenantScope,
    filter: ReportFilter,
    range: { from: Date; to: Date },
    page: { take: number; before?: { at: Date; id: bigint } },
  ): Promise<ReportRow[]> {
    const terms: Prisma.Sql[] = [
      Prisma.sql`r.reported_at >= ${range.from}`,
      Prisma.sql`r.reported_at < ${range.to}`,
    ];
    if (filter.status) terms.push(Prisma.sql`r.status IN (${Prisma.join(filter.status)})`);
    if (filter.assessment) {
      terms.push(Prisma.sql`r.assessment IN (${Prisma.join(filter.assessment)})`);
    }
    if (filter.analystVerdict) {
      terms.push(Prisma.sql`r.analyst_verdict IN (${Prisma.join(filter.analystVerdict)})`);
    }
    if (filter.reporter !== undefined) {
      terms.push(Prisma.sql`r.reporter_address = ${filter.reporter}`);
    }
    if (page.before !== undefined) {
      terms.push(
        Prisma.sql`(r.reported_at < ${page.before.at} OR (r.reported_at = ${page.before.at} AND r.id < ${page.before.id}))`,
      );
    }
    const rows = await this.reader.client.$queryRaw<Array<Record<string, unknown>>>(
      this.reportSql(scope, Prisma.join(terms, ' AND '), page.take),
    );
    return rows.map((r) => this.toReport(r));
  }

  /** One report by public id (replica unless a client is given). */
  async report(scope: TenantScope, publicId: string, client?: Tx): Promise<ReportRow | null> {
    const db = client ?? this.reader.client;
    const rows = await db.$queryRaw<Array<Record<string, unknown>>>(
      this.reportSql(scope, Prisma.sql`r.public_id = ${publicId}`, 1),
    );
    return rows[0] === undefined ? null : this.toReport(rows[0]);
  }

  /** The scope's report by public id, locked (`FOR UPDATE`). */
  async lockReport(tx: Tx, scope: TenantScope, publicId: string): Promise<ReportRow | null> {
    const ids = await tx.$queryRaw<Array<{ id: bigint }>>`
      SELECT id FROM api_user_reports
      WHERE organization_id = ${scope.organizationId} AND public_id = ${publicId}
      FOR UPDATE`;
    if (ids.length === 0) return null;
    return this.report(scope, publicId, tx);
  }

  /** Reports per group key (index `(organization_id, group_key, status)`; replica unless tx). */
  async groupSizes(
    scope: TenantScope,
    keys: readonly string[],
    client?: Tx,
  ): Promise<Map<string, number>> {
    const out = new Map<string, number>();
    const unique = [...new Set(keys)];
    if (unique.length === 0) return out;
    const db = client ?? this.reader.client;
    const rows = await db.apiUserReport.groupBy({
      by: ['groupKey'],
      where: tenantWhere(scope, { groupKey: { in: unique } }),
      _count: { _all: true },
    });
    for (const r of rows) if (r.groupKey !== null) out.set(r.groupKey, r._count._all);
    return out;
  }

  /** The other reports of a group, newest first (≤ `limit`). */
  async groupMembers(
    scope: TenantScope,
    groupKey: string,
    exceptId: bigint,
    limit: number,
  ): Promise<
    Array<{
      publicId: string;
      status: ApiUserReportStatus;
      reporterAddress: string;
      reportedAt: Date;
    }>
  > {
    return this.reader.client.apiUserReport.findMany({
      where: tenantWhere(scope, { groupKey, id: { not: exceptId } }),
      select: { publicId: true, status: true, reporterAddress: true, reportedAt: true },
      orderBy: [{ reportedAt: 'desc' }, { id: 'desc' }],
      take: limit,
    });
  }

  /** The open reports (`pending_triage`, `in_review`) of a group other than `exceptId`, locked. */
  async lockOpenGroupReports(
    tx: Tx,
    scope: TenantScope,
    groupKey: string,
    exceptId: bigint,
  ): Promise<
    Array<{
      id: bigint;
      publicId: string;
      status: ApiUserReportStatus;
      apiConnectionId: bigint;
      rowVersion: number;
    }>
  > {
    const rows = await tx.$queryRaw<Array<Record<string, unknown>>>`
      SELECT id, public_id AS publicId, status, api_connection_id AS apiConnectionId,
             row_version AS rowVersion
      FROM api_user_reports
      WHERE organization_id = ${scope.organizationId} AND group_key = ${groupKey}
        AND status IN ('pending_triage', 'in_review') AND id <> ${exceptId}
      ORDER BY id
      LIMIT 1000
      FOR UPDATE`;
    return rows.map((r) => ({
      id: big(r.id),
      publicId: r.publicId as string,
      status: r.status as ApiUserReportStatus,
      apiConnectionId: big(r.apiConnectionId),
      rowVersion: num(r.rowVersion),
    }));
  }

  /** CAS on `row_version` (+1); false when the version moved. */
  async updateReport(
    tx: Tx,
    scope: TenantScope,
    id: bigint,
    rowVersion: number,
    update: ReportUpdate,
  ): Promise<boolean> {
    const { count } = await tx.apiUserReport.updateMany({
      where: tenantWhere(scope, { id, rowVersion }),
      data: { ...update, rowVersion: { increment: 1 } },
    });
    return count === 1;
  }

  /** The report's triage history (its `api_mode.report_triaged` audit rows, newest first). */
  async reportHistory(
    scope: TenantScope,
    reportPublicId: string,
    limit: number,
    client?: Tx,
  ): Promise<HistoryRow[]> {
    const db = client ?? this.reader.client;
    const rows = await db.auditLog.findMany({
      where: {
        organizationId: scope.organizationId,
        resourceType: API_MODE_RESOURCES.report,
        resourceId: reportPublicId,
        action: API_MODE_AUDIT.reportTriaged,
      },
      select: { createdAt: true, actorType: true, actorId: true, metadata: true },
      orderBy: [{ createdAt: 'desc' }, { id: 'desc' }],
      take: limit,
    });
    return rows.map((r) => ({
      at: r.createdAt,
      actorType: r.actorType,
      actorId: r.actorId,
      metadata: r.metadata,
    }));
  }

  /** Adds `n` resolved reports to the connection's hourly counter row (additive upsert, C13). */
  async addReportsResolved(
    tx: Tx,
    scope: TenantScope,
    apiConnectionId: bigint,
    n: number,
    now: Date,
  ): Promise<void> {
    if (n <= 0) return;
    const hour = new Date(Math.floor(now.getTime() / 3_600_000) * 3_600_000);
    await tx.$executeRaw`
      INSERT INTO api_mode_counters (organization_id, api_connection_id, hour, reports_resolved,
                                     updated_at)
      VALUES (${scope.organizationId}, ${apiConnectionId}, ${hour}, ${n}, NOW(3))
      ON DUPLICATE KEY UPDATE reports_resolved = reports_resolved + VALUES(reports_resolved),
                              updated_at = NOW(3)`;
  }

  // ---- report mailboxes (C9.1, C14 #15-#17) --------------------------------------------------

  private async apiSideDomainIds(
    db: Tx | PrismaReadService['client'],
    scope: TenantScope,
    domainIds: readonly bigint[],
  ): Promise<Set<bigint>> {
    if (domainIds.length === 0) return new Set();
    const [org, domains] = await Promise.all([
      db.organization.findUnique({
        where: { id: scope.organizationId },
        select: { protectionMode: true },
      }),
      db.domain.findMany({
        where: tenantWhere(scope, {
          id: { in: [...new Set(domainIds)] },
          status: { not: 'deleted' as const },
        }),
        select: { id: true, protectionMode: true },
      }),
    ]);
    const orgMode = org?.protectionMode ?? 'inline';
    return new Set(
      domains.filter((d) => (d.protectionMode ?? orgMode) !== 'inline').map((d) => d.id),
    );
  }

  private readonly mailboxSelect = {
    id: true,
    publicId: true,
    primaryAddress: true,
    apiConnectionId: true,
    status: true,
    coverageState: true,
    domainId: true,
    reportMailbox: true,
    reportMailboxAt: true,
    apiConnection: {
      select: { provider: true, providerConnection: { select: { publicId: true } } },
    },
  } satisfies Prisma.ApiMailboxSelect;

  private async toMailboxRows(
    db: Tx | PrismaReadService['client'],
    scope: TenantScope,
    rows: Array<Prisma.ApiMailboxGetPayload<{ select: ApiClawbackRepository['mailboxSelect'] }>>,
  ): Promise<ReportMailboxRow[]> {
    const domainIds = rows.flatMap((r) => (r.domainId === null ? [] : [r.domainId]));
    const [apiSide, domains, last] = await Promise.all([
      this.apiSideDomainIds(db, scope, domainIds),
      domainIds.length === 0
        ? Promise.resolve([])
        : db.domain.findMany({
            where: tenantWhere(scope, { id: { in: [...new Set(domainIds)] } }),
            select: { id: true, publicId: true, name: true },
          }),
      rows.length === 0
        ? Promise.resolve([])
        : db.apiUserReport.groupBy({
            by: ['reportMailboxId'],
            where: tenantWhere(scope, { reportMailboxId: { in: rows.map((r) => r.id) } }),
            _max: { reportedAt: true },
          }),
    ]);
    const domainById = new Map(domains.map((d) => [d.id, d]));
    const lastById = new Map(last.map((l) => [l.reportMailboxId, l._max.reportedAt]));
    return rows.map((r) => {
      const d = r.domainId === null ? undefined : domainById.get(r.domainId);
      return {
        id: r.id,
        publicId: r.publicId,
        primaryAddress: r.primaryAddress,
        apiConnectionId: r.apiConnectionId,
        connectionPublicId: r.apiConnection.providerConnection.publicId,
        provider: r.apiConnection.provider,
        status: r.status,
        coverageState: r.coverageState,
        domain:
          d === undefined
            ? null
            : { id: d.id, publicId: d.publicId, name: d.name, apiSide: apiSide.has(d.id) },
        reportMailbox: r.reportMailbox,
        reportMailboxAt: r.reportMailboxAt,
        lastReportAt: lastById.get(r.id) ?? null,
      };
    });
  }

  /** The designated report mailboxes (replica unless a client is given), by address. */
  async reportMailboxes(scope: TenantScope, client?: Tx): Promise<ReportMailboxRow[]> {
    const db = client ?? this.reader.client;
    const rows = await db.apiMailbox.findMany({
      where: tenantWhere(scope, { reportMailbox: true }),
      select: this.mailboxSelect,
      orderBy: [{ primaryAddress: 'asc' }, { id: 'asc' }],
      take: 100,
    });
    return this.toMailboxRows(db, scope, rows);
  }

  /** How many report mailboxes the organization has (writer, inside the organization lock). */
  countReportMailboxes(tx: Tx, scope: TenantScope): Promise<number> {
    return tx.apiMailbox.count({ where: tenantWhere(scope, { reportMailbox: true }) });
  }

  /** The scope's mailbox by public id, locked (`FOR UPDATE`). */
  async lockMailbox(
    tx: Tx,
    scope: TenantScope,
    publicId: string,
  ): Promise<ReportMailboxRow | null> {
    const ids = await tx.$queryRaw<Array<{ id: bigint }>>`
      SELECT id FROM api_mailboxes
      WHERE organization_id = ${scope.organizationId} AND public_id = ${publicId}
      FOR UPDATE`;
    const id = ids[0]?.id;
    if (id === undefined) return null;
    const rows = await tx.apiMailbox.findMany({
      where: tenantWhere(scope, { id: big(id) }),
      select: this.mailboxSelect,
    });
    return (await this.toMailboxRows(tx, scope, rows))[0] ?? null;
  }

  /** The scope's mailbox by address (primary or alias, lower case), locked. */
  async lockMailboxByAddress(
    tx: Tx,
    scope: TenantScope,
    address: string,
  ): Promise<ReportMailboxRow | null> {
    const ids = await tx.$queryRaw<Array<{ id: bigint }>>`
      SELECT mb.id FROM api_mailboxes mb
      WHERE mb.organization_id = ${scope.organizationId} AND mb.primary_address = ${address}
      UNION
      SELECT a.mailbox_id AS id FROM api_mailbox_addresses a
      WHERE a.organization_id = ${scope.organizationId} AND a.address = ${address}
      ORDER BY id
      LIMIT 1`;
    const id = ids[0]?.id;
    if (id === undefined) return null;
    const locked = await tx.$queryRaw<Array<{ publicId: string }>>`
      SELECT public_id AS publicId FROM api_mailboxes
      WHERE id = ${big(id)} AND organization_id = ${scope.organizationId} FOR UPDATE`;
    const publicId = locked[0]?.publicId;
    return publicId === undefined ? null : this.lockMailbox(tx, scope, publicId);
  }

  /**
   * The organization's non-deleted domain of `name` with its effective mode and the API-mode
   * connection of the provider connection it is linked to (null when none).
   */
  async domainForReportAddress(
    tx: Tx,
    scope: TenantScope,
    name: string,
  ): Promise<{ id: bigint; apiSide: boolean; apiConnectionId: bigint | null } | null> {
    const domain = await tx.domain.findFirst({
      where: tenantWhere(scope, { name, status: { not: 'deleted' as const } }),
      select: { id: true, providerConnectionDomain: { select: { connectionId: true } } },
    });
    if (domain === null) return null;
    const apiSide = (await this.apiSideDomainIds(tx, scope, [domain.id])).has(domain.id);
    const connectionId = domain.providerConnectionDomain?.connectionId ?? null;
    const api =
      connectionId === null
        ? null
        : await tx.apiModeConnection.findFirst({
            where: tenantWhere(scope, { providerConnectionId: connectionId }),
            select: { id: true },
          });
    return { id: domain.id, apiSide, apiConnectionId: api?.id ?? null };
  }

  /** A mailbox known only by address (`discovered`, no provider id; the worker resolves it). */
  async createDiscoveredMailbox(
    tx: Tx,
    scope: TenantScope,
    input: { apiConnectionId: bigint; address: string; domainId: bigint; now: Date },
  ): Promise<string> {
    const publicId = uuidv7(input.now.getTime());
    const mailbox = await tx.apiMailbox.create({
      data: {
        publicId,
        organizationId: scope.organizationId,
        apiConnectionId: input.apiConnectionId,
        providerUserId: null,
        primaryAddress: input.address,
        domainId: input.domainId,
        status: 'discovered',
        syncRequestedAt: input.now,
      },
      select: { id: true },
    });
    await tx.apiMailboxAddress.createMany({
      data: [
        {
          organizationId: scope.organizationId,
          mailboxId: mailbox.id,
          address: input.address,
          kind: 'primary',
        },
      ],
      skipDuplicates: true,
    });
    return publicId;
  }

  async setReportMailbox(
    tx: Tx,
    scope: TenantScope,
    id: bigint,
    enabled: boolean,
    now: Date,
  ): Promise<void> {
    await tx.apiMailbox.updateMany({
      where: tenantWhere(scope, { id }),
      data: { reportMailbox: enabled, reportMailboxAt: enabled ? now : null },
    });
  }

  // ---- overview (C13) ------------------------------------------------------------------------

  /** Live clawback counts of the organization (each capped at `cap`; replica). */
  async clawbackOverview(
    scope: TenantScope,
    now: Date,
    cap: number,
  ): Promise<ClawbackOverviewCounts> {
    const db = this.reader.client;
    const since = new Date(now.getTime() - 86_400_000);
    const [byStatus, completed, oldest] = await Promise.all([
      db.$queryRaw<Array<{ status: string; n: bigint | number }>>`
        SELECT status, COUNT(*) AS n FROM (
          SELECT status FROM api_clawbacks
          WHERE organization_id = ${scope.organizationId}
            AND status IN (${Prisma.join(ACTIVE_STATUSES)})
          LIMIT ${cap + 1}) t
        GROUP BY status`,
      db.$queryRaw<Array<{ n: bigint | number }>>`
        SELECT COUNT(*) AS n FROM (
          SELECT 1 FROM api_clawbacks
          WHERE organization_id = ${scope.organizationId}
            AND status IN ('completed', 'completed_with_errors') AND completed_at >= ${since}
          LIMIT ${cap + 1}) t`,
      db.$queryRaw<Array<{ createdAt: Date }>>`
        SELECT created_at AS createdAt FROM api_clawbacks
        WHERE organization_id = ${scope.organizationId}
          AND status IN (${Prisma.join(ACTIVE_STATUSES)})
        ORDER BY created_at ASC LIMIT 1`,
    ]);
    const of = (s: string) => num(byStatus.find((r) => r.status === s)?.n);
    const active = byStatus.reduce((n, r) => n + num(r.n), 0);
    return {
      active: Math.min(active, cap),
      reviewRequired: Math.min(of('review_required'), cap),
      pendingApproval: Math.min(of('pending_approval'), cap),
      completed24h: Math.min(num(completed[0]?.n), cap),
      oldestActiveCreatedAt: oldest[0]?.createdAt ?? null,
    };
  }

  /** Live report counts per API-mode connection (open reports and report mailboxes; replica). */
  async reportOverview(
    scope: TenantScope,
    apiConnectionIds: readonly bigint[],
  ): Promise<Map<bigint, ReportOverviewCounts>> {
    const out = new Map<bigint, ReportOverviewCounts>();
    if (apiConnectionIds.length === 0) return out;
    const db = this.reader.client;
    const ids = [...apiConnectionIds];
    const [open, oldest, mailboxes] = await Promise.all([
      db.apiUserReport.groupBy({
        by: ['apiConnectionId', 'status'],
        where: tenantWhere(scope, {
          apiConnectionId: { in: ids },
          status: { in: ['pending_triage', 'in_review'] as ApiUserReportStatus[] },
        }),
        _count: { _all: true },
      }),
      db.apiUserReport.groupBy({
        by: ['apiConnectionId'],
        where: tenantWhere(scope, {
          apiConnectionId: { in: ids },
          status: 'pending_triage' as const,
        }),
        _min: { reportedAt: true },
      }),
      db.apiMailbox.groupBy({
        by: ['apiConnectionId'],
        where: tenantWhere(scope, { apiConnectionId: { in: ids }, reportMailbox: true }),
        _count: { _all: true },
      }),
    ]);
    for (const id of ids) {
      const count = (status: string) =>
        open.find((r) => r.apiConnectionId === id && r.status === status)?._count._all ?? 0;
      out.set(id, {
        pendingTriage: count('pending_triage'),
        inReview: count('in_review'),
        oldestPendingReportedAt:
          oldest.find((r) => r.apiConnectionId === id)?._min.reportedAt ?? null,
        reportMailboxes: mailboxes.find((r) => r.apiConnectionId === id)?._count._all ?? 0,
      });
    }
    return out;
  }

  /** The API-3 fields of the hourly counters from `from` (replica). */
  async clawbackCounters(
    scope: TenantScope,
    apiConnectionIds: readonly bigint[],
    from: Date,
  ): Promise<ClawbackCounterRow[]> {
    if (apiConnectionIds.length === 0) return [];
    return this.reader.client.apiModeCounter.findMany({
      where: tenantWhere(scope, {
        apiConnectionId: { in: [...apiConnectionIds] },
        hour: { gte: new Date(Math.floor(from.getTime() / 3_600_000) * 3_600_000) },
      }),
      select: {
        apiConnectionId: true,
        hour: true,
        internalCopies: true,
        clawbackTargetsQueued: true,
        clawbackTargetsSucceeded: true,
        clawbackTargetsFailed: true,
        reportsReceived: true,
        reportsResolved: true,
        policyEvaluations: true,
        policyErrors: true,
        outboundDetections: true,
      },
      orderBy: [{ hour: 'asc' }, { apiConnectionId: 'asc' }],
    });
  }
}

/** Map key of a partitioned copy. */
export const copyKey = (id: bigint, receivedAt: Date): string =>
  `${id.toString()}@${receivedAt.getTime()}`;
