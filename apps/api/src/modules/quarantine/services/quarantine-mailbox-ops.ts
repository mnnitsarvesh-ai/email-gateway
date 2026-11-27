import { Injectable } from '@nestjs/common';
import type { Prisma } from '@email-gateway/database';
import {
  type ApprovalReason,
  decideMailboxRestore,
  type QuarantineReleaseMode,
  type QuarantineSettings,
  type ReleaseDecision,
} from '@email-gateway/quarantine';
import type { Principal } from '../../../auth-contracts/principal';
import type { TenantScope } from '../../../auth-contracts/tenant-scope';
import {
  type QueuedAction,
  RemediationActionWriter,
} from '../../api-mode/repositories/remediation-action-writer';
import type { EntryRow } from '../domain/entry';
import { stateConflict } from '../quarantine.errors';
import {
  type EntryCopyFacts,
  QuarantineMailboxRepository,
} from '../repositories/quarantine-mailbox.repository';
import type { Precheck } from './quarantine-precheck.service';

type Tx = Prisma.TransactionClient;

/** True for an entry the mailbox-worker holds inside the recipient's mailbox (ADR-0102). */
export const isMailboxEntry = (entry: Pick<EntryRow, 'location'>): boolean =>
  entry.location === 'mailbox';

/** The stored pre-check of a mailbox restore (content-free; no policy re-validation, R10.1). */
export function mailboxPrecheckDocument(
  decision: ReleaseDecision,
  copyStatus: string,
  now: Date,
): Prisma.InputJsonValue {
  return {
    source: 'api_mailbox_precheck',
    at: now.toISOString(),
    outcome: decision.outcome,
    approvalReasons: decision.approvalReasons,
    refusal: decision.refusal ?? null,
    copyStatus,
    summary: null,
  };
}

/**
 * The mailbox-located branch of the quarantine writes (step API-2 R10.1, R10.2, R10.4;
 * ADR-0102): the release pre-check from stored facts (`decideMailboxRestore`: hard block →
 * approval or refusal by tenant setting, scan failure → approval, the end-user bounds in self
 * mode; never a policy re-validation, never `rescan_required`), the `restore_inbox` action row of
 * a queued release (instead of `mail.quarantine.release_requested.v1`) and the `soft_delete`
 * action row of a delete. Rows follow the mailbox-worker's contract (RemediationActionWriter):
 * `pending`, due now, keyed by the copy's public id, action and current generation.
 */
@Injectable()
export class QuarantineMailboxOps {
  constructor(
    private readonly repository: QuarantineMailboxRepository,
    private readonly actions: RemediationActionWriter,
  ) {}

  /** The entry's copy on the writer; a copy past its retention cannot be acted on (`409`). */
  async copy(tx: Tx, scope: TenantScope, entry: EntryRow): Promise<EntryCopyFacts> {
    const copy = await this.repository.copyOfEntry(tx, scope, entry);
    if (copy === null) throw stateConflict(entry.state, 'copy_missing');
    return copy;
  }

  /** R10.1 on the writer's facts (the entry locked, the copy read in the same transaction). */
  async precheck(
    tx: Tx,
    scope: TenantScope,
    entry: EntryRow,
    mode: QuarantineReleaseMode,
    settings: QuarantineSettings,
    now: Date,
    approvedReasons?: readonly ApprovalReason[],
  ): Promise<Precheck> {
    const copy = await this.copy(tx, scope, entry);
    const decision = decideMailboxRestore({
      entry: {
        kind: entry.kind,
        reason: entry.reason,
        state: entry.state,
        riskLevel: entry.riskLevel,
        hasHardBlock: entry.hasHardBlock,
      },
      copyStatus: copy.status,
      mode,
      ...(approvedReasons !== undefined && { approvedReasons }),
      settings,
    });
    return { decision, document: mailboxPrecheckDocument(decision, copy.status, now) };
  }

  private requester(principal: Principal) {
    return {
      requestedByType: principal.kind,
      requestedByUserId: principal.kind === 'user' ? principal.userId : null,
    } as const;
  }

  /**
   * R10.2: the `restore_inbox` row of a queued release (`trigger = release`, or `end_user` for a
   * self-release), reversing the entry's remediation, linked to the entry and its release log.
   */
  async queueRestore(
    tx: Tx,
    r: {
      scope: TenantScope;
      principal: Principal;
      entry: EntryRow;
      mode: QuarantineReleaseMode;
      releaseLogId: bigint;
      reason: string;
      now: Date;
    },
  ): Promise<QueuedAction> {
    const copy = await this.copy(tx, r.scope, r.entry);
    const queued = await this.actions.queue(tx, {
      organizationId: r.scope.organizationId,
      apiConnectionId: copy.apiConnectionId,
      mailboxId: copy.mailboxId,
      copyId: copy.copyId,
      copyReceivedAt: copy.copyReceivedAt,
      copyPublicId: copy.copyPublicId,
      messageId: copy.messageId,
      action: 'restore_inbox',
      generation: copy.remediationGeneration,
      trigger: r.mode === 'self' ? 'end_user' : 'release',
      decision: { requestedAction: 'restore_inbox', reason: r.reason },
      reversesActionId: r.entry.apiRemediationActionId,
      quarantineEntryId: r.entry.id,
      releaseLogId: r.releaseLogId,
      ...this.requester(r.principal),
      requestReason: r.reason.slice(0, 512),
      now: r.now,
    });
    if (queued.outcome === 'busy') throw stateConflict(r.entry.state, 'restore_in_progress');
    if (queued.outcome === 'succeeded') throw stateConflict(r.entry.state, 'already_restored');
    return queued;
  }

  /**
   * R10.4: a deleted mailbox entry's message is soft-deleted in the mailbox unless it already
   * sits in the deleted items (`trigger = admin`, current generation, linked to the entry).
   */
  async queueSoftDelete(
    tx: Tx,
    r: { scope: TenantScope; principal: Principal; entry: EntryRow; reason: string; now: Date },
  ): Promise<'queued' | 'not_needed' | 'busy' | 'copy_missing'> {
    if (r.entry.mailboxContainer === 'deleted_items') return 'not_needed';
    const copy = await this.repository.copyOfEntry(tx, r.scope, r.entry);
    if (copy === null) return 'copy_missing';
    const queued = await this.actions.queue(tx, {
      organizationId: r.scope.organizationId,
      apiConnectionId: copy.apiConnectionId,
      mailboxId: copy.mailboxId,
      copyId: copy.copyId,
      copyReceivedAt: copy.copyReceivedAt,
      copyPublicId: copy.copyPublicId,
      messageId: copy.messageId,
      action: 'soft_delete',
      generation: copy.remediationGeneration,
      trigger: 'admin',
      decision: { requestedAction: 'soft_delete', reason: r.reason },
      reversesActionId: null,
      quarantineEntryId: r.entry.id,
      releaseLogId: null,
      ...this.requester(r.principal),
      requestReason: r.reason.slice(0, 512),
      now: r.now,
    });
    if (queued.outcome === 'busy' || queued.outcome === 'succeeded') return 'busy';
    await this.actions.markCopyPending(
      tx,
      {
        organizationId: r.scope.organizationId,
        copyId: copy.copyId,
        copyReceivedAt: copy.copyReceivedAt,
      },
      { remediationAction: 'soft_delete', lastActionId: queued.id, now: r.now },
    );
    return 'queued';
  }
}
