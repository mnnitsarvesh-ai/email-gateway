import type { Prisma } from '@email-gateway/database';
import type { ApprovalRow, EntryRow, ReleaseRow } from '../domain/entry';
import { approvalReasonList, stringList } from '../domain/entry';

/** The `quarantine_messages` columns the services read (never the retired `subject`). */
export const entrySelect = {
  id: true,
  publicId: true,
  organizationId: true,
  messageId: true,
  messageReceivedAt: true,
  lifecycleRound: true,
  scanId: true,
  recipientId: true,
  rcptSeq: true,
  recipientAddress: true,
  userId: true,
  direction: true,
  kind: true,
  origin: true,
  reason: true,
  status: true,
  envelopeFrom: true,
  headerFrom: true,
  hasAttachments: true,
  attachmentCount: true,
  sizeBytes: true,
  riskScore: true,
  riskLevel: true,
  recommendedAction: true,
  riskVerdict: true,
  hasHardBlock: true,
  hardBlocks: true,
  reasonCodes: true,
  floorReasons: true,
  primaryEngine: true,
  decisionSource: true,
  decisivePolicyPublicId: true,
  decisivePolicyVersionNo: true,
  decisiveRuleId: true,
  explanation: true,
  explanationText: true,
  emlObjectKey: true,
  quarantinedAt: true,
  expiresAt: true,
  stateChangedAt: true,
  releasedAt: true,
  approvalRequestId: true,
  objectPurgedAt: true,
  rowVersion: true,
} satisfies Prisma.QuarantineMessageSelect;

export type EntrySelected = Prisma.QuarantineMessageGetPayload<{ select: typeof entrySelect }>;

export function toEntryRow(row: EntrySelected): EntryRow {
  const { status, hardBlocks, reasonCodes, floorReasons, ...rest } = row;
  return {
    ...rest,
    state: status,
    hardBlocks: stringList(hardBlocks, 9),
    reasonCodes: stringList(reasonCodes, 32),
    floorReasons: stringList(floorReasons, 16),
    decisionSource: row.decisionSource,
    recommendedAction: row.recommendedAction,
    riskVerdict: row.riskVerdict,
  };
}

export const approvalSelect = {
  id: true,
  publicId: true,
  organizationId: true,
  quarantineMessageId: true,
  kind: true,
  status: true,
  approvalReasons: true,
  approvedReasons: true,
  requestedByType: true,
  requestedByUserId: true,
  requestedByApiKeyId: true,
  requestReason: true,
  decidedByUserId: true,
  decisionReason: true,
  expiresAt: true,
  decidedAt: true,
  rowVersion: true,
  createdAt: true,
  quarantineMessage: { select: { publicId: true } },
  requestedByUser: { select: { publicId: true } },
  decidedByUser: { select: { publicId: true } },
} satisfies Prisma.QuarantineApprovalRequestSelect;

export type ApprovalSelected = Prisma.QuarantineApprovalRequestGetPayload<{
  select: typeof approvalSelect;
}>;

/** `apiKeyPublicIds`: public ids of the API-key requesters (no foreign key on that column). */
export function toApprovalRow(
  row: ApprovalSelected,
  apiKeyPublicIds: ReadonlyMap<bigint, string> = new Map(),
): ApprovalRow {
  return {
    id: row.id,
    publicId: row.publicId,
    organizationId: row.organizationId,
    quarantineMessageId: row.quarantineMessageId,
    entryPublicId: row.quarantineMessage.publicId,
    kind: row.kind,
    status: row.status,
    approvalReasons: approvalReasonList(row.approvalReasons),
    approvedReasons: row.approvedReasons === null ? null : approvalReasonList(row.approvedReasons),
    requestedByType: row.requestedByType,
    requestedByUserId: row.requestedByUserId,
    requestedByApiKeyId: row.requestedByApiKeyId,
    requestedByPublicId:
      row.requestedByUser?.publicId ??
      (row.requestedByApiKeyId === null
        ? null
        : (apiKeyPublicIds.get(row.requestedByApiKeyId) ?? null)),
    requestReason: row.requestReason,
    decidedByUserId: row.decidedByUserId,
    decidedByPublicId: row.decidedByUser?.publicId ?? null,
    decisionReason: row.decisionReason,
    expiresAt: row.expiresAt,
    decidedAt: row.decidedAt,
    rowVersion: row.rowVersion,
    createdAt: row.createdAt,
  };
}

export const releaseSelect = {
  id: true,
  quarantineMessageId: true,
  releasePublicId: true,
  mode: true,
  status: true,
  requestedByType: true,
  requestedById: true,
  precheck: true,
  revalidation: true,
  deliveredObject: true,
  approvalRequestId: true,
  createdAt: true,
  completedAt: true,
  quarantineMessage: { select: { publicId: true } },
} satisfies Prisma.QuarantineReleaseLogSelect;

export type ReleaseSelected = Prisma.QuarantineReleaseLogGetPayload<{
  select: typeof releaseSelect;
}>;

export function toReleaseRow(
  row: ReleaseSelected,
  approvalPublicIds: ReadonlyMap<bigint, string>,
): ReleaseRow {
  return {
    id: row.id,
    quarantineMessageId: row.quarantineMessageId,
    entryPublicId: row.quarantineMessage.publicId,
    releasePublicId: row.releasePublicId,
    mode: row.mode,
    status: row.status,
    requestedByType: row.requestedByType,
    requestedById: row.requestedById,
    // The executor's re-validation once it ran, the api's pre-check before.
    revalidation: row.revalidation ?? row.precheck,
    deliveredObject: row.deliveredObject,
    approvalRequestPublicId:
      row.approvalRequestId === null
        ? null
        : (approvalPublicIds.get(row.approvalRequestId) ?? null),
    createdAt: row.createdAt,
    completedAt: row.completedAt,
  };
}
