import { uuidv7 } from '@email-gateway/common';
import { EventTypes, quarantineNotificationRequestedV1 } from '@email-gateway/event-contracts';
import { Prisma, type PrismaClient } from '@email-gateway/database';
import {
  hardBlockToPrimaryEngine,
  mailboxEntryExplanation,
  verdictToQuarantineReason,
  type MessageVerdict,
  type RemediationMailboxContainer,
} from '@email-gateway/mailbox-api';
import {
  computeExpiry,
  decideMailboxRestore,
  resolveQuarantineSettings,
  type ApiCopyStatus,
  type ApprovalReason,
  type QuarantinePlatformBounds,
  type QuarantineSettings,
  type ReleaseDecision,
} from '@email-gateway/quarantine';
import { big, bigOrNull, type Db } from '../shared/db';
import { InconsistentReadError } from '../shared/errors';
import { hardBlockIds } from './decide';

const HOUR_MS = 3_600_000;
/** Entry column bounds (as the policy-engine writer, step 5.3 Q6). */
const MAX_HARD_BLOCKS = 9;
const MAX_REASON_CODES = 32;
/** States an entry can leave (Q3); everything else is terminal. */
export const NON_TERMINAL_ENTRY_STATES = ['held', 'pending_approval', 'releasing'] as const;

/**
 * The effective quarantine settings of an organization (step 5.3 Q24, read like the
 * policy-engine's `QuarantineSettingsRepository`): `quarantine_settings.settings` merged with
 * `organization_settings` and clamped to the platform bounds; an invalid document → defaults.
 */
export async function resolveOrganizationQuarantineSettings(
  db: Db,
  organizationId: bigint,
  bounds: QuarantinePlatformBounds,
): Promise<QuarantineSettings> {
  const stored = await db.quarantineSettings.findFirst({
    where: { organizationId },
    select: { organizationId: true, settings: true },
  });
  if (stored !== null && stored.organizationId !== organizationId) {
    throw new InconsistentReadError('quarantine_settings');
  }
  const org = await db.organizationSetting.findFirst({
    where: { organizationId },
    select: {
      organizationId: true,
      quarantineRetentionDays: true,
      digestEnabled: true,
      digestSchedule: true,
      timezone: true,
    },
  });
  if (org !== null && org.organizationId !== organizationId) {
    throw new InconsistentReadError('organization_settings');
  }
  return resolveQuarantineSettings(
    stored?.settings ?? null,
    bounds,
    org === null
      ? null
      : {
          quarantineRetentionDays: org.quarantineRetentionDays,
          digestEnabled: org.digestEnabled,
          digestSchedule: org.digestSchedule,
          timezone: org.timezone,
        },
  ).settings;
}

/** Step API-3 C5.5: the clawback of an entry-creating action (public id, trigger, signal). */
export interface MailboxEntryClawback {
  publicId: string;
  trigger: string;
  /** `api_clawbacks.signal_verdict` (policy mode); null for an explicit admin purge. */
  signalVerdict: MessageVerdict | null;
}

/** Copy verdicts that name a threat (an explicit purge keeps their reason; else `manual`). */
const THREAT_ENTRY_VERDICTS: readonly MessageVerdict[] = [
  'malware',
  'phishing',
  'bec',
  'suspicious',
  'spam',
  'bulk',
  'dlp_violation',
];

/**
 * C5.5: the entry `reason` of a clawback action — the quarantine reason of the signal verdict;
 * an explicit purge (no signal verdict) of a copy without a threat verdict → `manual`, otherwise
 * the copy verdict's reason.
 */
export function clawbackEntryReason(
  clawback: MailboxEntryClawback,
  copyVerdict: MessageVerdict | null,
): string {
  if (clawback.signalVerdict !== null) return verdictToQuarantineReason(clawback.signalVerdict);
  return copyVerdict !== null && THREAT_ENTRY_VERDICTS.includes(copyVerdict)
    ? verdictToQuarantineReason(copyVerdict)
    : 'manual';
}

/** C5.5 explanation template (content-free). */
export const clawbackEntryExplanation = (clawback: MailboxEntryClawback): string =>
  `Removed from the mailbox by clawback ${clawback.publicId} (${clawback.trigger})`;

/** What the entry writer needs about the remediation (ids and codes only). */
export interface MailboxEntryInput {
  organizationId: bigint;
  actionId: bigint;
  actionPublicId: string;
  container: RemediationMailboxContainer;
  /** The policy rule of the decision (R2.4), null for an admin action. */
  ruleId: string | null;
  /** Step API-3: the clawback that queued the action (reason and explanation, C5.5). */
  clawback?: MailboxEntryClawback | null;
  copy: {
    id: bigint;
    receivedAt: Date;
    messageId: bigint;
    mailboxId: bigint;
    verdict: MessageVerdict | null;
    remediationGeneration: number;
  };
  now: Date;
  bounds: QuarantinePlatformBounds;
}

export interface MailboxEntryResult {
  entryId: bigint;
  entryPublicId: string;
  /** False when the entry already existed (crash replay) and was adopted. */
  created: boolean;
}

/** `quarantine_messages` columns read back for the adoption echo. */
interface StoredEntry {
  id: bigint;
  publicId: string;
  organizationId: bigint;
  location: string;
  apiCopyId: bigint | null;
}

/**
 * R9.1 (ADR-0102): the mailbox-located quarantine entry of a successful `move_quarantine`,
 * `move_junk` or `soft_delete`, in the outcome's writer transaction. Everything comes from stored
 * rows: the copy's registry message (sender, size, attachments, EML key), its latest risk row
 * (level, action, verdict, hard blocks, reason codes), the recipient row whose address is one of
 * the mailbox's addresses (lowest `rcpt_seq`), the organization's active user with that e-mail,
 * the resolved quarantine settings (`computeExpiry`, kind `quarantine`) and the fixed,
 * content-free explanation. `lifecycle_round` = the copy's remediation generation (R9.2). A
 * duplicate of `(message_id, lifecycle_round, rcpt_seq)` is a crash replay: the existing entry is
 * adopted. One `quarantine_actions` row `mailbox_remediated` per created entry. Null when the
 * message has no recipient row for the mailbox (nothing to attach the entry to; logged by the
 * caller).
 */
export async function createMailboxEntry(
  tx: Prisma.TransactionClient,
  input: MailboxEntryInput,
): Promise<MailboxEntryResult | null> {
  const { organizationId, copy, now } = input;
  const message = await tx.emailMessage.findUnique({
    where: { id_receivedAt: { id: copy.messageId, receivedAt: copy.receivedAt } },
    select: {
      organizationId: true,
      direction: true,
      envelopeFrom: true,
      headerFrom: true,
      sizeBytes: true,
      attachmentCount: true,
      emlObjectKey: true,
    },
  });
  if (!message) return null;
  if (message.organizationId !== organizationId) throw new InconsistentReadError('email_messages');
  const addresses = await tx.apiMailboxAddress.findMany({
    where: { mailboxId: copy.mailboxId, organizationId },
    select: { address: true, organizationId: true },
  });
  const mailbox = await tx.apiMailbox.findUnique({
    where: { id: copy.mailboxId },
    select: { organizationId: true, primaryAddress: true },
  });
  if (!mailbox || mailbox.organizationId !== organizationId) {
    throw new InconsistentReadError('api_mailboxes');
  }
  const wanted = new Set(
    [mailbox.primaryAddress, ...addresses.map((a) => a.address)].map((a) => a.toLowerCase()),
  );
  const recipients = await tx.emailRecipient.findMany({
    where: { messageId: copy.messageId, receivedAt: copy.receivedAt, organizationId },
    select: { id: true, rcptSeq: true, address: true, organizationId: true },
    orderBy: { rcptSeq: 'asc' },
  });
  const recipient = recipients.find((r) => wanted.has(r.address.trim().toLowerCase()));
  if (!recipient) return null;
  if (recipient.organizationId !== organizationId) {
    throw new InconsistentReadError('email_recipients');
  }
  const address = recipient.address.trim().toLowerCase();
  const risk = await tx.$queryRaw<
    Array<{
      organization_id: bigint | number;
      scan_id: bigint | number;
      score: number;
      level: string;
      verdict: string;
      recommended_action: string;
      hard_blocks: unknown;
      reason_codes: unknown;
    }>
  >`
    SELECT organization_id, scan_id, score, level, verdict, recommended_action, hard_blocks,
           reason_codes
    FROM message_risk_scores
    WHERE message_id = ${copy.messageId} AND received_at = ${copy.receivedAt}
    ORDER BY scan_id DESC, revision DESC
    LIMIT 1`;
  const r = risk[0];
  if (r && big(r.organization_id) !== organizationId) {
    throw new InconsistentReadError('message_risk_scores');
  }
  const hardBlocks = r ? hardBlockIds(parseJson(r.hard_blocks)).slice(0, MAX_HARD_BLOCKS) : [];
  const reasonCodes = r ? stringList(parseJson(r.reason_codes)).slice(0, MAX_REASON_CODES) : [];
  const user = await tx.user.findFirst({
    where: { organizationId, email: address, status: 'active', deletedAt: null },
    select: { id: true, organizationId: true },
    orderBy: { id: 'asc' },
  });
  if (user && user.organizationId !== organizationId) throw new InconsistentReadError('users');
  const settings = await resolveOrganizationQuarantineSettings(tx, organizationId, input.bounds);
  const expiresAt = computeExpiry({
    kind: 'quarantine',
    quarantinedAt: now,
    holdDays: settings.hold.days,
    reviewDays: settings.review.days,
    maxHoldDays: input.bounds.maxHoldDays,
    maxReviewDays: input.bounds.maxReviewDays,
  });
  const created = await tx.quarantineMessage.createMany({
    data: [
      {
        publicId: uuidv7(now.getTime()),
        organizationId,
        messageId: copy.messageId,
        messageReceivedAt: copy.receivedAt,
        lifecycleRound: copy.remediationGeneration,
        scanId: r ? big(r.scan_id) : null,
        evaluationSeq: null,
        recipientId: recipient.id,
        rcptSeq: recipient.rcptSeq,
        recipientAddress: address.slice(0, 320),
        userId: user?.id ?? null,
        direction: message.direction,
        kind: 'quarantine',
        origin: 'api_remediation',
        reason: (input.clawback
          ? clawbackEntryReason(input.clawback, copy.verdict)
          : verdictToQuarantineReason(copy.verdict)) as never,
        status: 'held',
        envelopeFrom: message.envelopeFrom,
        headerFrom: message.headerFrom,
        hasAttachments: message.attachmentCount > 0,
        attachmentCount: Math.min(message.attachmentCount, 65_535),
        sizeBytes: Math.min(message.sizeBytes, 4_294_967_295),
        riskScore: r ? Number(r.score) : null,
        riskLevel: (r?.level ?? null) as never,
        recommendedAction: (r?.recommended_action ?? null) as never,
        riskVerdict: (r?.verdict ?? null) as never,
        hasHardBlock: hardBlocks.length > 0,
        hardBlocks,
        reasonCodes,
        primaryEngine: hardBlockToPrimaryEngine(hardBlocks),
        decisionSource: null,
        explanationText: input.clawback
          ? clawbackEntryExplanation(input.clawback)
          : mailboxEntryExplanation(input.ruleId),
        emlObjectKey: message.emlObjectKey,
        quarantinedAt: now,
        expiresAt,
        stateChangedAt: now,
        rowVersion: 1,
        location: 'mailbox',
        mailboxContainer: input.container,
        apiCopyId: copy.id,
        apiCopyReceivedAt: copy.receivedAt,
        apiMailboxId: copy.mailboxId,
        apiRemediationActionId: input.actionId,
      },
    ],
    skipDuplicates: true,
  });
  const stored: StoredEntry | null = await tx.quarantineMessage.findUnique({
    where: {
      messageId_lifecycleRound_rcptSeq: {
        messageId: copy.messageId,
        lifecycleRound: copy.remediationGeneration,
        rcptSeq: recipient.rcptSeq,
      },
    },
    select: { id: true, publicId: true, organizationId: true, location: true, apiCopyId: true },
  });
  if (
    !stored ||
    stored.organizationId !== organizationId ||
    stored.location !== 'mailbox' ||
    stored.apiCopyId !== copy.id
  ) {
    throw new InconsistentReadError('quarantine_messages');
  }
  if (created.count === 1) {
    await tx.quarantineAction.create({
      data: {
        organizationId,
        quarantineMessageId: stored.id,
        action: 'mailbox_remediated',
        actorType: 'system',
        result: 'held',
        details: { actionId: input.actionPublicId, container: input.container },
      },
      select: { id: true },
    });
  }
  return { entryId: stored.id, entryPublicId: stored.publicId, created: created.count === 1 };
}

function parseJson(value: unknown): unknown {
  if (typeof value !== 'string') return value;
  try {
    return JSON.parse(value) as unknown;
  } catch {
    return null;
  }
}

function stringList(value: unknown): string[] {
  if (!Array.isArray(value)) return [];
  return value.filter((v): v is string => typeof v === 'string' && v.length <= 128);
}

// -------------------------------------------------------------------------------------------
// Release (restore) completion, R10.3
// -------------------------------------------------------------------------------------------

/** A mailbox entry locked for a restore decision or completion. */
export interface LockedEntry {
  id: bigint;
  publicId: string;
  organizationId: bigint;
  status: string;
  kind: 'quarantine' | 'review';
  reason: string;
  riskLevel: string | null;
  hasHardBlock: boolean;
  location: string;
  apiCopyId: bigint | null;
  rowVersion: number;
}

/** `SELECT … FOR UPDATE` of an entry (organization echo-checked); null when gone. */
export async function lockEntry(
  tx: Prisma.TransactionClient,
  entryId: bigint,
  organizationId: bigint,
): Promise<LockedEntry | null> {
  const rows = await tx.$queryRaw<
    Array<{
      id: bigint | number;
      public_id: string;
      organization_id: bigint | number;
      status: string;
      kind: 'quarantine' | 'review';
      reason: string;
      risk_level: string | null;
      has_hard_block: unknown;
      location: string;
      api_copy_id: bigint | number | null;
      row_version: number;
    }>
  >`
    SELECT id, public_id, organization_id, status, kind, reason, risk_level, has_hard_block,
           location, api_copy_id, row_version
    FROM quarantine_messages WHERE id = ${entryId} FOR UPDATE`;
  const row = rows[0];
  if (!row) return null;
  if (big(row.organization_id) !== organizationId) {
    throw new InconsistentReadError('quarantine_messages');
  }
  return {
    id: big(row.id),
    publicId: row.public_id,
    organizationId,
    status: row.status,
    kind: row.kind,
    reason: row.reason,
    riskLevel: row.risk_level,
    hasHardBlock: row.has_hard_block === true || Number(row.has_hard_block) === 1,
    location: row.location,
    apiCopyId: bigOrNull(row.api_copy_id),
    rowVersion: Number(row.row_version),
  };
}

/** CAS on `row_version` and the expected status; throws when the entry moved meanwhile. */
async function casEntry(
  tx: Prisma.TransactionClient,
  entry: LockedEntry,
  set: Prisma.Sql,
): Promise<void> {
  const n = await tx.$executeRaw`
    UPDATE quarantine_messages SET ${set}, row_version = row_version + 1
    WHERE id = ${entry.id} AND row_version = ${entry.rowVersion} AND status = ${entry.status}`;
  if (n !== 1) throw new InconsistentReadError('quarantine_messages CAS');
}

/** The release log of a restore (organization and entry echo-checked). */
export interface ReleaseLogRow {
  id: bigint;
  quarantineMessageId: bigint;
  status: string;
  mode: 'operator' | 'self' | 'approved';
  approvalRequestId: bigint | null;
  requestedByType: string;
  requestedById: string | null;
}

export async function loadReleaseLog(
  db: Db,
  logId: bigint,
  organizationId: bigint,
): Promise<ReleaseLogRow | null> {
  const log = await db.quarantineReleaseLog.findUnique({
    where: { id: logId },
    select: {
      id: true,
      organizationId: true,
      quarantineMessageId: true,
      status: true,
      mode: true,
      approvalRequestId: true,
      requestedByType: true,
      requestedById: true,
    },
  });
  if (!log) return null;
  if (log.organizationId !== organizationId) {
    throw new InconsistentReadError('quarantine_release_logs');
  }
  return log;
}

async function completeLog(
  tx: Prisma.TransactionClient,
  logId: bigint,
  now: Date,
  data: {
    status: 'restored' | 'restore_failed' | 'approval_required' | 'refused' | 'stale';
    blockedReason?: string | null;
    approvalRequestId?: bigint;
  },
): Promise<boolean> {
  const updated = await tx.quarantineReleaseLog.updateMany({
    where: { id: logId, status: 'pending' },
    data: {
      status: data.status,
      completedAt: now,
      blockedReason: data.blockedReason ?? null,
      ...(data.approvalRequestId !== undefined
        ? { approvalRequestId: data.approvalRequestId }
        : {}),
    },
  });
  return updated.count === 1;
}

async function entryAction(
  tx: Prisma.TransactionClient,
  entry: LockedEntry,
  action: 'mailbox_restored' | 'mailbox_restore_failed' | 'release_blocked' | 'expire',
  result: string,
  details: Record<string, string | number | boolean | null>,
  refs: { releaseLogId?: bigint | null; approvalRequestId?: bigint | null } = {},
): Promise<void> {
  await tx.quarantineAction.create({
    data: {
      organizationId: entry.organizationId,
      quarantineMessageId: entry.id,
      action,
      actorType: 'system',
      result: result.slice(0, 64),
      details,
      releaseLogId: refs.releaseLogId ?? null,
      approvalRequestId: refs.approvalRequestId ?? null,
    },
    select: { id: true },
  });
}

/**
 * R10.3 success: entry `releasing → released` (`released_at`; the request's `decided_at` kept),
 * release log `restored`, `quarantine_actions` `mailbox_restored`. An entry no longer
 * `releasing` (rejected or deleted while the provider call ran) is left as it is and the log
 * becomes `stale`: the mailbox state is what happened, the entry state what the operator decided.
 */
export async function completeRestore(
  tx: Prisma.TransactionClient,
  input: {
    entryId: bigint;
    organizationId: bigint;
    releaseLogId: bigint | null;
    actionPublicId: string;
    now: Date;
  },
): Promise<'released' | 'stale' | 'missing'> {
  const entry = await lockEntry(tx, input.entryId, input.organizationId);
  if (!entry) return 'missing';
  const log =
    input.releaseLogId === null
      ? null
      : await loadReleaseLog(tx, input.releaseLogId, input.organizationId);
  if (entry.status !== 'releasing' || entry.location !== 'mailbox') {
    if (log) await completeLog(tx, log.id, input.now, { status: 'stale', blockedReason: 'stale' });
    return 'stale';
  }
  await casEntry(
    tx,
    entry,
    Prisma.sql`status = 'released', state_changed_at = ${input.now}, released_at = ${input.now},
      terminal_reason = 'released', decided_at = COALESCE(decided_at, ${input.now}),
      decided_by_type = COALESCE(decided_by_type, ${log?.requestedByType ?? 'system'})`,
  );
  if (log) await completeLog(tx, log.id, input.now, { status: 'restored' });
  await entryAction(
    tx,
    entry,
    'mailbox_restored',
    'restored',
    { actionId: input.actionPublicId },
    { releaseLogId: log?.id ?? null },
  );
  return 'released';
}

/**
 * R10.3 permanent failure: entry `releasing → held`, release log `restore_failed` with the code,
 * `quarantine_actions` `mailbox_restore_failed`. The copy stays `remediated`.
 */
export async function failRestore(
  tx: Prisma.TransactionClient,
  input: {
    entryId: bigint;
    organizationId: bigint;
    releaseLogId: bigint | null;
    actionPublicId: string;
    code: string;
    now: Date;
  },
): Promise<'held' | 'stale' | 'missing'> {
  const entry = await lockEntry(tx, input.entryId, input.organizationId);
  if (!entry) return 'missing';
  const log =
    input.releaseLogId === null
      ? null
      : await loadReleaseLog(tx, input.releaseLogId, input.organizationId);
  if (entry.status !== 'releasing') {
    if (log) await completeLog(tx, log.id, input.now, { status: 'stale', blockedReason: 'stale' });
    return 'stale';
  }
  await casEntry(tx, entry, Prisma.sql`status = 'held', state_changed_at = ${input.now}`);
  if (log) {
    await completeLog(tx, log.id, input.now, {
      status: 'restore_failed',
      blockedReason: input.code.slice(0, 64),
    });
  }
  await entryAction(
    tx,
    entry,
    'mailbox_restore_failed',
    input.code,
    { actionId: input.actionPublicId, code: input.code.slice(0, 64) },
    { releaseLogId: log?.id ?? null },
  );
  return 'held';
}

/** The release log of a restore whose entry left `releasing` before the claim: `stale`. */
export async function staleRestore(
  tx: Prisma.TransactionClient,
  input: { organizationId: bigint; releaseLogId: bigint | null; now: Date },
): Promise<void> {
  if (input.releaseLogId === null) return;
  const log = await loadReleaseLog(tx, input.releaseLogId, input.organizationId);
  if (log) await completeLog(tx, log.id, input.now, { status: 'stale', blockedReason: 'stale' });
}

/** The re-check of an approved restore before the provider call (R10.3). */
export interface ApprovedRecheck {
  decision: ReleaseDecision;
  approval: {
    id: bigint;
    requestedByType: string;
    requestedByUserId: bigint | null;
    requestedByApiKeyId: bigint | null;
  } | null;
}

/**
 * R10.3 approved mode: re-runs `decideMailboxRestore` with the approval's `approved_reasons` over
 * the stored facts (they can only have changed through the copy status). Null when the restore is
 * not an approved release.
 */
export async function recheckApprovedRestore(
  db: Db,
  input: {
    entry: LockedEntry;
    log: ReleaseLogRow;
    copyStatus: ApiCopyStatus;
    settings: QuarantineSettings;
  },
): Promise<ApprovedRecheck | null> {
  if (input.log.mode !== 'approved') return null;
  const approval =
    input.log.approvalRequestId === null
      ? null
      : await db.quarantineApprovalRequest.findUnique({
          where: { id: input.log.approvalRequestId },
          select: {
            id: true,
            organizationId: true,
            quarantineMessageId: true,
            status: true,
            approvedReasons: true,
            requestedByType: true,
            requestedByUserId: true,
            requestedByApiKeyId: true,
          },
        });
  if (
    approval &&
    (approval.organizationId !== input.entry.organizationId ||
      approval.quarantineMessageId !== input.entry.id)
  ) {
    throw new InconsistentReadError('quarantine_approval_requests');
  }
  const approvedReasons =
    approval && approval.status === 'approved'
      ? (stringList(parseJson(approval.approvedReasons)) as ApprovalReason[])
      : [];
  const decision = decideMailboxRestore({
    entry: {
      kind: input.entry.kind,
      reason: input.entry.reason as never,
      state: input.entry.status as never,
      riskLevel: (input.entry.riskLevel ?? null) as never,
      hasHardBlock: input.entry.hasHardBlock,
    },
    copyStatus: input.copyStatus,
    mode: 'approved',
    approvedReasons,
    settings: input.settings,
  });
  return {
    decision,
    approval: approval
      ? {
          id: approval.id,
          requestedByType: approval.requestedByType,
          requestedByUserId: approval.requestedByUserId,
          requestedByApiKeyId: approval.requestedByApiKeyId,
        }
      : null,
  };
}

/**
 * R10.3: the approved restore no longer covers the entry's reasons. `approval_required` → a new
 * `release_approval` request (the approved request's requester; TTL
 * `settings.approvals.requestTtlHours`, as the api), entry `pending_approval`, log
 * `approval_required`, `release_blocked` action and (setting on) the `approval_requested`
 * notification. `refused` → entry back to `held`, log `refused` with the refusal code.
 */
export async function blockApprovedRestore(
  tx: Prisma.TransactionClient,
  input: {
    entry: LockedEntry;
    log: ReleaseLogRow;
    recheck: ApprovedRecheck;
    settings: QuarantineSettings;
    correlationId: string;
    now: Date;
  },
): Promise<'approval_required' | 'refused'> {
  const { entry, log, recheck, now } = input;
  if (recheck.decision.outcome === 'approval_required') {
    const requester = recheck.approval;
    const request = await tx.quarantineApprovalRequest.create({
      data: {
        organizationId: entry.organizationId,
        quarantineMessageId: entry.id,
        kind: 'release_approval',
        status: 'pending',
        approvalReasons: recheck.decision.approvalReasons,
        requestedByType: (requester?.requestedByType ?? 'system') as never,
        requestedByUserId: requester?.requestedByUserId ?? null,
        requestedByApiKeyId: requester?.requestedByApiKeyId ?? null,
        expiresAt: new Date(now.getTime() + input.settings.approvals.requestTtlHours * HOUR_MS),
      },
      select: { id: true, publicId: true },
    });
    await casEntry(
      tx,
      entry,
      Prisma.sql`status = 'pending_approval', state_changed_at = ${now},
        approval_request_id = ${request.id}`,
    );
    await completeLog(tx, log.id, now, {
      status: 'approval_required',
      blockedReason: 'approval_required',
      approvalRequestId: request.id,
    });
    await entryAction(
      tx,
      entry,
      'release_blocked',
      'approval_required',
      { approvalReasons: recheck.decision.approvalReasons.join(',') },
      { releaseLogId: log.id, approvalRequestId: request.id },
    );
    if (input.settings.alerts.approvalRequests) {
      const payload = quarantineNotificationRequestedV1.parse({
        kind: 'approval_requested',
        refs: { approvalRequestIds: [request.publicId], entryId: entry.publicId },
        requestedAt: now.toISOString(),
      });
      await tx.messageOutbox.create({
        data: {
          eventId: uuidv7(now.getTime()),
          organizationId: entry.organizationId,
          eventType: EventTypes.QuarantineNotificationRequested,
          aggregateType: 'quarantine',
          aggregateId: entry.organizationId.toString(),
          correlationId: input.correlationId.slice(0, 128),
          payload,
        },
        select: { id: true },
      });
    }
    return 'approval_required';
  }
  const cause = recheck.decision.refusal?.code ?? 'refused';
  await casEntry(tx, entry, Prisma.sql`status = 'held', state_changed_at = ${now}`);
  await completeLog(tx, log.id, now, { status: 'refused', blockedReason: cause.slice(0, 64) });
  await entryAction(
    tx,
    entry,
    'release_blocked',
    'refused',
    { cause: cause.slice(0, 64) },
    { releaseLogId: log.id },
  );
  return 'refused';
}

// -------------------------------------------------------------------------------------------
// Expiry of mailbox entries (R11.4), health leader
// -------------------------------------------------------------------------------------------

/**
 * R11.4 (API2-12): due `held` / `pending_approval` entries with `location = mailbox` → `expired`
 * (their pending approval requests `expired`, `quarantine_actions` `expire`, actor system). No
 * mailbox change (the message stays in its container), no lifecycle edge, no recipient change and
 * no object purge (the EML follows message retention). One short writer transaction per entry
 * (CAS on `row_version`); returns the entries expired.
 */
export async function expireMailboxEntries(
  prisma: PrismaClient,
  input: { now: Date; batch: number; organizationIds?: readonly bigint[] },
): Promise<number> {
  const due = await prisma.quarantineMessage.findMany({
    where: {
      location: 'mailbox',
      status: { in: ['held', 'pending_approval'] },
      expiresAt: { lte: input.now },
      ...(input.organizationIds ? { organizationId: { in: [...input.organizationIds] } } : {}),
    },
    select: { id: true, organizationId: true },
    orderBy: { expiresAt: 'asc' },
    take: input.batch,
  });
  let expired = 0;
  for (const { id, organizationId } of due) {
    const done = await prisma.$transaction(async (tx) => {
      const entry = await lockEntry(tx, id, organizationId);
      if (
        !entry ||
        entry.location !== 'mailbox' ||
        (entry.status !== 'held' && entry.status !== 'pending_approval')
      ) {
        return false;
      }
      const requests = await tx.quarantineApprovalRequest.findMany({
        where: { quarantineMessageId: entry.id, status: 'pending' },
        select: { id: true, organizationId: true, rowVersion: true },
      });
      for (const r of requests) {
        if (r.organizationId !== organizationId) {
          throw new InconsistentReadError('quarantine_approval_requests');
        }
        await tx.quarantineApprovalRequest.updateMany({
          where: { id: r.id, rowVersion: r.rowVersion, status: 'pending' },
          data: { status: 'expired', decidedAt: input.now, rowVersion: { increment: 1 } },
        });
      }
      await casEntry(
        tx,
        entry,
        Prisma.sql`status = 'expired', state_changed_at = ${input.now}, terminal_reason = 'expired',
          decided_at = ${input.now}, decided_by_type = 'system'`,
      );
      await entryAction(tx, entry, 'expire', 'expired', {
        kind: entry.kind,
        location: 'mailbox',
        approvalRequests: requests.length,
      });
      return true;
    });
    if (done) expired += 1;
  }
  return expired;
}
