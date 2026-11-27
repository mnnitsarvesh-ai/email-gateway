import { createHash, randomUUID } from 'node:crypto';
import { uuidv7 } from '@email-gateway/common';
import type { ApiMessageCopy, ApiRemediationAction } from '@email-gateway/database';
import type { RunningSimulators } from '@email-gateway/idp-adapters/testing';
import {
  canonicalPolicySha256,
  remediationActionKey,
  type RemediationPolicyDocument,
} from '@email-gateway/mailbox-api';
import type { MailboxComponents } from '../../src/components';
import type { WorkerConfig } from '../../src/config';
import type { Fixtures } from './harness';

/**
 * Step API-2 helpers of the remediation suites (synthetic `it-apirem-*` organizations only):
 * stored risk rows, policies, the api's release writes (R10.2, owned by WP4 and mimicked here as
 * the rows the api commits), and loop drivers.
 */

/** Worker configuration with every role incl. `remediate`, over the in-process simulators. */
export function remediationConfig(
  fx: Fixtures,
  sims: RunningSimulators,
  overrides: Record<string, string> = {},
): Readonly<WorkerConfig> {
  return fx.config(sims, {
    MAILBOX_WORKER_ROLES: 'copies,feeds,inventory,health,remediate',
    API_MODE_REMEDIATION_CONCURRENCY: '8',
    API_MODE_REMEDIATION_CONCURRENCY_PER_CONNECTION: '2',
    ...overrides,
  });
}

/** A `message_risk_scores` row (revision 0) of a scan round: codes and enums only. */
export async function riskRow(
  fx: Fixtures,
  organizationId: bigint,
  message: { id: bigint; receivedAt: Date },
  input: {
    scanId: bigint;
    level: 'none' | 'low' | 'medium' | 'high' | 'critical';
    verdict: 'clean' | 'spam' | 'phishing' | 'malware' | 'suspicious' | 'bec';
    score: number;
    hardBlocks?: string[];
    revision?: number;
  },
): Promise<void> {
  const blocks = (input.hardBlocks ?? []).map((id) => ({
    id,
    verdict: input.verdict,
    action: 'block',
  }));
  await fx.prisma.messageRiskScore.create({
    data: {
      receivedAt: message.receivedAt,
      messageId: message.id,
      organizationId,
      scanId: input.scanId,
      lifecycleRound: 0,
      revision: input.revision ?? 0,
      direction: 'inbound',
      status: 'scored',
      score: input.score,
      level: input.level,
      verdict: input.verdict,
      recommendedAction: blocks.length > 0 ? 'block' : 'tag',
      hardBlocks: blocks,
      reasonCodes: blocks.length > 0 ? ['attachment.malware_signature'] : [],
      contributions: [],
      groups: {},
      engines: {},
      failures: [],
      floors: [],
      trust: {},
      evidence: {},
      explanation: {},
      explanationText: '',
      profileSource: 'platform',
      profileIdText: 'platform/default',
      profileSha256: 'a'.repeat(64),
      inputSha256: 'b'.repeat(64),
      scorerVersion: 'risk/1',
      signalMapVersion: 'signals/1',
      inputVersion: 'input/1',
      durationUs: 10,
    },
  });
}

/** An organization (or domain) remediation policy row as the api writes it (R2.1, §3.1). */
export async function policy(
  fx: Fixtures,
  organizationId: bigint,
  mode: 'detect_only' | 'enforce',
  document: RemediationPolicyDocument,
  domainId: bigint | null = null,
): Promise<void> {
  const existing = await fx.prisma.apiRemediationPolicy.findFirst({
    where: { organizationId, domainId },
  });
  const data = {
    mode,
    document: document as never,
    documentSha256: canonicalPolicySha256(document),
  };
  if (existing) {
    await fx.prisma.apiRemediationPolicy.update({
      where: { id: existing.id },
      data: { ...data, rowVersion: { increment: 1 } },
    });
  } else {
    await fx.prisma.apiRemediationPolicy.create({
      data: { organizationId, domainId, ...data },
    });
  }
}

export const copiesOf = (fx: Fixtures, messageId: bigint): Promise<ApiMessageCopy[]> =>
  fx.prisma.apiMessageCopy.findMany({ where: { messageId }, orderBy: { id: 'asc' } });

export const actionsOfCopy = (fx: Fixtures, copyId: bigint): Promise<ApiRemediationAction[]> =>
  fx.prisma.apiRemediationAction.findMany({ where: { copyId }, orderBy: { id: 'asc' } });

/** Leftovers of an earlier test (pending / in progress) are cancelled so later ticks skip them. */
export async function cancelOpenActions(
  fx: Fixtures,
  organizationIds: readonly bigint[],
): Promise<void> {
  await fx.prisma.apiRemediationAction.updateMany({
    where: {
      organizationId: { in: [...organizationIds] },
      status: { in: ['pending', 'in_progress'] },
    },
    data: { status: 'cancelled', leaseUntil: null, nextAttemptAt: null },
  });
}

/** Runs the remediate loop until no due action is left (at most `max` passes). */
export async function drain(comps: MailboxComponents, max = 10): Promise<void> {
  for (let i = 0; i < max; i++) {
    if (!(await comps.remediation!.tick())) return;
  }
}

/**
 * The api's writes of a mailbox-entry release (R10.2, WP4) in one transaction: the release
 * request action, a `pending` release log, the entry → `releasing`, and the `restore_inbox`
 * action (trigger `release`, or `end_user` for self mode) reversing the entry's remediation.
 * Returns the release log and the restore action ids.
 */
export async function queueRestore(
  fx: Fixtures,
  input: {
    entryId: bigint;
    mode: 'operator' | 'self' | 'approved';
    now: Date;
    approval?: { reasons: string[]; approved: string[] };
    requesterUserId?: bigint | null;
  },
): Promise<{ releaseLogId: bigint; actionId: bigint; approvalRequestId: bigint | null }> {
  return fx.prisma.$transaction(async (tx) => {
    const entry = await tx.quarantineMessage.findUniqueOrThrow({ where: { id: input.entryId } });
    const copy = await tx.apiMessageCopy.findFirstOrThrow({
      where: { id: entry.apiCopyId!, receivedAt: entry.apiCopyReceivedAt! },
    });
    let approvalRequestId: bigint | null = null;
    if (input.approval) {
      const request = await tx.quarantineApprovalRequest.create({
        data: {
          organizationId: entry.organizationId,
          quarantineMessageId: entry.id,
          kind: 'release_approval',
          status: 'approved',
          approvalReasons: input.approval.reasons,
          approvedReasons: input.approval.approved,
          requestedByType: 'user',
          requestedByUserId: input.requesterUserId ?? null,
          expiresAt: new Date(input.now.getTime() + 72 * 3_600_000),
          decidedAt: input.now,
        },
      });
      approvalRequestId = request.id;
    }
    const requestAction = await tx.quarantineAction.create({
      data: {
        organizationId: entry.organizationId,
        quarantineMessageId: entry.id,
        action: input.mode === 'self' ? 'self_release' : 'release',
        actorType: 'user',
        actorUserId: input.requesterUserId ?? null,
        result: 'queued',
      },
    });
    const log = await tx.quarantineReleaseLog.create({
      data: {
        organizationId: entry.organizationId,
        quarantineMessageId: entry.id,
        actionId: requestAction.id,
        releasePublicId: uuidv7(),
        mode: input.mode,
        approvalRequestId,
        requestedByType: 'user',
        requestedById: randomUUID(),
        releasedTo: entry.recipientAddress,
        precheck: { outcome: 'release' },
        status: 'pending',
      },
    });
    await tx.quarantineMessage.update({
      where: { id: entry.id },
      data: { status: 'releasing', stateChangedAt: input.now, rowVersion: { increment: 1 } },
    });
    const action = await tx.apiRemediationAction.create({
      data: {
        organizationId: entry.organizationId,
        apiConnectionId: copy.apiConnectionId,
        mailboxId: copy.mailboxId,
        copyId: copy.id,
        copyReceivedAt: copy.receivedAt,
        messageId: copy.messageId,
        action: 'restore_inbox',
        generation: copy.remediationGeneration,
        actionKey: remediationActionKey(copy.publicId, 'restore_inbox', copy.remediationGeneration),
        trigger: input.mode === 'self' ? 'end_user' : 'release',
        status: 'pending',
        decision: { requestedAction: 'restore_inbox', reason: 'release' },
        reversesActionId: entry.apiRemediationActionId,
        quarantineEntryId: entry.id,
        releaseLogId: log.id,
        requestedByType: 'user',
        requestedByUserId: input.requesterUserId ?? null,
        nextAttemptAt: input.now,
      },
    });
    return { releaseLogId: log.id, actionId: action.id, approvalRequestId };
  });
}

/** An admin request row (R12 manual remediation / tag reversal), as the api writes it. */
export async function queueAdminAction(
  fx: Fixtures,
  copyId: bigint,
  action: 'move_quarantine' | 'move_junk' | 'tag' | 'soft_delete' | 'remove_tag',
  now: Date,
  reversesActionId: bigint | null = null,
): Promise<bigint> {
  const copy = await fx.prisma.apiMessageCopy.findFirstOrThrow({ where: { id: copyId } });
  const row = await fx.prisma.apiRemediationAction.create({
    data: {
      organizationId: copy.organizationId,
      apiConnectionId: copy.apiConnectionId,
      mailboxId: copy.mailboxId,
      copyId: copy.id,
      copyReceivedAt: copy.receivedAt,
      messageId: copy.messageId,
      action,
      generation: copy.remediationGeneration,
      actionKey: remediationActionKey(copy.publicId, action, copy.remediationGeneration),
      trigger: 'admin',
      status: 'pending',
      decision: { requestedAction: action, reason: 'it' },
      reversesActionId,
      requestedByType: 'user',
      nextAttemptAt: now,
    },
  });
  // As the api's `markCopyPending`: the copy is `pending` on this action (a reversal keeps the
  // remediation action in effect).
  await fx.prisma.apiMessageCopy.updateMany({
    where: { id: copy.id, receivedAt: copy.receivedAt },
    data: {
      lastActionId: row.id,
      remediationState: 'pending',
      ...(action !== 'remove_tag' && { remediationAction: action }),
    },
  });
  return row.id;
}

export const sha = (value: string): string => createHash('sha256').update(value).digest('hex');
