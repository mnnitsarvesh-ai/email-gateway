import { explanationLineSchema } from '@email-gateway/policy-dsl';
import {
  type QuarantineApprovalView,
  type QuarantineEntryDetail,
  type QuarantineEntrySummary,
  type QuarantineReleaseView,
  releaseRevalidationSummarySchema,
  sanitizeSubject,
  type QuarantineDirection,
  type QuarantineEntryKind,
  type QuarantineOrigin,
  type QuarantinePrimaryEngine,
  type QuarantineReason,
  type QuarantineRiskLevel,
  type QuarantineState,
  type QuarantineApprovalKind,
  type QuarantineApprovalStatus,
  type QuarantineReleaseMode,
  type QuarantineReleaseStatus,
  type ApprovalReason,
  APPROVAL_REASONS,
  type EntryAction,
} from '@email-gateway/quarantine';
import { z } from 'zod';

/**
 * One `quarantine_messages` row as the quarantine services read it (step 5.3 §3; the SQL column
 * `status` is the API's `state`). JSON columns are parsed into string lists; `subject` (retired,
 * never written) is never selected.
 */
export interface EntryRow {
  id: bigint;
  publicId: string;
  organizationId: bigint;
  messageId: bigint;
  messageReceivedAt: Date;
  lifecycleRound: number;
  scanId: bigint | null;
  recipientId: bigint;
  rcptSeq: number;
  recipientAddress: string;
  userId: bigint | null;
  direction: QuarantineDirection;
  kind: QuarantineEntryKind;
  origin: QuarantineOrigin;
  reason: QuarantineReason;
  state: QuarantineState;
  envelopeFrom: string;
  headerFrom: string | null;
  hasAttachments: boolean;
  attachmentCount: number;
  sizeBytes: number;
  riskScore: number | null;
  riskLevel: QuarantineRiskLevel | null;
  recommendedAction: string | null;
  riskVerdict: string | null;
  hasHardBlock: boolean;
  hardBlocks: string[];
  reasonCodes: string[];
  floorReasons: string[];
  primaryEngine: QuarantinePrimaryEngine;
  decisionSource: 'tenant_rule' | 'platform_default' | 'floor' | null;
  decisivePolicyPublicId: string | null;
  decisivePolicyVersionNo: number | null;
  decisiveRuleId: string | null;
  explanation: unknown;
  explanationText: string | null;
  emlObjectKey: string;
  quarantinedAt: Date;
  expiresAt: Date;
  stateChangedAt: Date;
  releasedAt: Date | null;
  approvalRequestId: bigint | null;
  objectPurgedAt: Date | null;
  rowVersion: number;
}

/** A `quarantine_approval_requests` row with the public ids of its references. */
export interface ApprovalRow {
  id: bigint;
  publicId: string;
  organizationId: bigint;
  quarantineMessageId: bigint;
  entryPublicId: string;
  kind: QuarantineApprovalKind;
  status: QuarantineApprovalStatus;
  approvalReasons: ApprovalReason[];
  approvedReasons: ApprovalReason[] | null;
  requestedByType: 'system' | 'user' | 'api_key';
  requestedByUserId: bigint | null;
  requestedByApiKeyId: bigint | null;
  requestedByPublicId: string | null;
  requestReason: string | null;
  decidedByUserId: bigint | null;
  decidedByPublicId: string | null;
  decisionReason: string | null;
  expiresAt: Date;
  decidedAt: Date | null;
  rowVersion: number;
  createdAt: Date;
}

/** A `quarantine_release_logs` row with the public id of its approval request. */
export interface ReleaseRow {
  id: bigint;
  quarantineMessageId: bigint;
  entryPublicId: string;
  releasePublicId: string;
  mode: QuarantineReleaseMode;
  status: QuarantineReleaseStatus;
  requestedByType: 'system' | 'user' | 'api_key';
  requestedById: string | null;
  revalidation: unknown;
  deliveredObject: 'original' | 'rewritten' | 'policy_copy' | 'none' | null;
  approvalRequestPublicId: string | null;
  createdAt: Date;
  completedAt: Date | null;
}

/** `quarantine_actions` + the actor's public id, newest last. */
export interface ActionRow {
  id: bigint;
  action: string;
  actorType: 'system' | 'user' | 'api_key';
  actorId: string | null;
  reason: string | null;
  result: string | null;
  details: unknown;
  createdAt: Date;
}

/** A JSON column of string codes (null, non-arrays and non-strings are dropped). */
export function stringList(value: unknown, max = 64): string[] {
  if (!Array.isArray(value)) return [];
  return value.filter((v): v is string => typeof v === 'string').slice(0, max);
}

/**
 * Hard-block ids of a `message_risk_scores.hard_blocks` column (step 5.1 stores objects
 * `{ id, action, verdict }`; plain id strings are accepted too). Unknown shapes are dropped.
 */
export function hardBlockIds(value: unknown, max = 64): string[] {
  if (!Array.isArray(value)) return [];
  const ids: string[] = [];
  for (const v of value) {
    if (typeof v === 'string') ids.push(v);
    else if (
      v !== null &&
      typeof v === 'object' &&
      typeof (v as { id?: unknown }).id === 'string'
    ) {
      ids.push((v as { id: string }).id);
    }
  }
  return ids.slice(0, max);
}

const APPROVAL_REASON_SET: ReadonlySet<string> = new Set(APPROVAL_REASONS);

export function approvalReasonList(value: unknown): ApprovalReason[] {
  return stringList(value, APPROVAL_REASONS.length).filter((r): r is ApprovalReason =>
    APPROVAL_REASON_SET.has(r),
  );
}

const iso = (d: Date): string => d.toISOString();

/** Q26 `QuarantineEntrySummary` (subject only when the caller may see it, already looked up). */
export function entrySummary(
  row: EntryRow,
  refs: { messagePublicId: string; approvalPublicId: string | null; subject: string | null },
): QuarantineEntrySummary {
  return {
    id: row.publicId,
    messageId: refs.messagePublicId,
    lifecycleRound: row.lifecycleRound,
    state: row.state,
    kind: row.kind,
    origin: row.origin,
    reason: row.reason,
    direction: row.direction,
    recipient: row.recipientAddress,
    sender: {
      envelope: row.envelopeFrom === '' ? null : row.envelopeFrom,
      headerFrom: row.headerFrom,
    },
    subject: refs.subject === null ? null : sanitizeSubject(refs.subject, 256),
    receivedAt: iso(row.messageReceivedAt),
    quarantinedAt: iso(row.quarantinedAt),
    expiresAt: iso(row.expiresAt),
    riskLevel: row.riskLevel,
    riskScore: row.riskScore === null ? null : Math.min(row.riskScore, 1000),
    hardBlocks: row.hardBlocks.slice(0, 9),
    primaryEngine: row.primaryEngine,
    decisive: {
      source: row.decisionSource,
      policyId: row.decisivePolicyPublicId,
      versionNo: row.decisivePolicyVersionNo,
      ruleId: row.decisiveRuleId,
    },
    hasAttachments: row.hasAttachments,
    attachmentCount: row.attachmentCount,
    sizeBytes: row.sizeBytes,
    approvalRequestId: refs.approvalPublicId,
    rowVersion: row.rowVersion,
  };
}

const linesSchema = z.array(explanationLineSchema).max(24);

/** Q10 `QuarantineEntryDetail`. */
export function entryDetail(
  row: EntryRow,
  refs: { messagePublicId: string; approvalPublicId: string | null; subject: string | null },
  releases: readonly ReleaseRow[],
  allowedActions: EntryAction[],
): QuarantineEntryDetail {
  const lines = linesSchema.safeParse(row.explanation);
  return {
    ...entrySummary(row, refs),
    explanation: {
      lines: lines.success ? lines.data : [],
      text: (row.explanationText ?? '').slice(0, 2048),
    },
    floorReasons: row.floorReasons.slice(0, 16),
    reasonCodes: row.reasonCodes.slice(0, 32),
    releases: releases.slice(0, 100).map(releaseView),
    allowedActions,
    contentAvailable: contentAvailable(row),
  };
}

/** The message content still exists (`object_purged_at` is null). */
export const contentAvailable = (row: Pick<EntryRow, 'objectPurgedAt'>): boolean =>
  row.objectPurgedAt === null;

/** The 13.3 summary of a stored precheck/revalidation document, or null. */
export function revalidationSummary(value: unknown): QuarantineReleaseView['revalidation'] {
  const doc = value as { summary?: unknown } | null;
  const candidate = doc !== null && typeof doc === 'object' && 'summary' in doc ? doc.summary : doc;
  const parsed = releaseRevalidationSummarySchema.safeParse(candidate);
  return parsed.success ? parsed.data : null;
}

/** Q26 `QuarantineReleaseView` (the executor's re-validation, else the api's pre-check). */
export function releaseView(row: ReleaseRow): QuarantineReleaseView {
  return {
    id: row.releasePublicId,
    status: row.status,
    mode: row.mode,
    requestedBy: { type: row.requestedByType, id: uuidOrNull(row.requestedById) },
    requestedAt: iso(row.createdAt),
    completedAt: row.completedAt === null ? null : iso(row.completedAt),
    revalidation: revalidationSummary(row.revalidation),
    deliveredObject: row.deliveredObject,
    approvalRequestId: row.approvalRequestPublicId,
  };
}

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
export const uuidOrNull = (value: string | null): string | null =>
  value !== null && UUID.test(value) ? value : null;

/** Q26 `QuarantineApprovalView`. */
export function approvalView(row: ApprovalRow): QuarantineApprovalView {
  return {
    id: row.publicId,
    kind: row.kind,
    status: row.status,
    entryId: row.entryPublicId,
    approvalReasons: row.approvalReasons,
    requestedBy: { type: row.requestedByType, id: uuidOrNull(row.requestedByPublicId) },
    requestedAt: iso(row.createdAt),
    expiresAt: iso(row.expiresAt),
    decidedBy: uuidOrNull(row.decidedByPublicId),
    decidedAt: row.decidedAt === null ? null : iso(row.decidedAt),
    decisionReason: row.decisionReason,
  };
}
