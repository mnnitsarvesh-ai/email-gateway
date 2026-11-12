import { createHash } from 'node:crypto';
import { ForbiddenException, HttpStatus, Injectable } from '@nestjs/common';
import type { Prisma } from '@email-gateway/database';
import {
  APPROVAL_REASONS,
  type ApprovalReason,
  checkApprover,
  QUARANTINE_PERMISSIONS,
} from '@email-gateway/quarantine';
import type { Principal, UserPrincipal } from '../../../auth-contracts/principal';
import type { TenantScope } from '../../../auth-contracts/tenant-scope';
import { idempotencyKeyHash } from '../../../http/idempotency/idempotency-key';
import type { IdempotentResult } from '../../../http/idempotency/idempotency.service';
import type { ClientContext } from '../../auth/services/session.service';
import type { ApprovalRow } from '../domain/entry';
import type { ApprovalDecisionResponse, ReasonBody } from '../dto/quarantine.schemas';
import {
  QUARANTINE_AUDIT,
  QUARANTINE_OPERATIONS,
  QUARANTINE_RESOURCE,
} from '../quarantine.constants';
import {
  approvalForbidden,
  approvalNotFound,
  approvalNotPending,
  AuditedRefusal,
  hardBlockReleaseDisabled,
  rescanRequired,
  stateConflict,
} from '../quarantine.errors';
import { QuarantineReadRepository } from '../repositories/quarantine-read.repository';
import { QuarantineWriteRepository } from '../repositories/quarantine-write.repository';
import { QuarantineContext } from './quarantine-context';
import { QuarantineDispositionService } from './quarantine-disposition.service';
import { type LockedEntry, QuarantineEntryOps } from './quarantine-entry-ops';
import { QuarantineMetrics } from './quarantine-metrics';
import { QuarantinePrecheckService } from './quarantine-precheck.service';
import { QuarantineWriter } from './quarantine-writer';

type Tx = Prisma.TransactionClient;

export interface ApprovalInput {
  principal: Principal;
  scope: TenantScope;
  approvalId: string;
  key: string;
  body: ReasonBody;
  client: ClientContext;
}

/** SHA-256 of the decider's sorted permission keys at decision time (Q14). */
export function permissionsHash(principal: Principal): string {
  return createHash('sha256')
    .update([...principal.permissions].sort().join('\n'))
    .digest('hex');
}

const union = (a: readonly ApprovalReason[], b: readonly ApprovalReason[]): ApprovalReason[] => {
  const set = new Set([...a, ...b]);
  return APPROVAL_REASONS.filter((r) => set.has(r));
};

/**
 * Approval decisions (step 5.3 Q14; ADR-0047): approve, deny and cancel, each in one writer
 * transaction (lock order message → entry → request), separation of duties checked here with
 * `checkApprover` (never the requester — the requesting user or the creator of the requesting
 * API key —, never the entry's recipient by user id or own verified address, never an API key or
 * an end user) and re-checked by the executor against the stored
 * decision. Approve re-runs the pre-check in `approved` mode and queues the release with
 * `approved_reasons` = the request's reasons ∪ the pre-check's; deny of a `policy_review`
 * rejects the entry (as Q16), other kinds return it to `held`.
 */
@Injectable()
export class QuarantineApprovalsService {
  constructor(
    private readonly writer: QuarantineWriter,
    private readonly ops: QuarantineEntryOps,
    private readonly writes: QuarantineWriteRepository,
    private readonly reads: QuarantineReadRepository,
    private readonly context: QuarantineContext,
    private readonly precheck: QuarantinePrecheckService,
    private readonly disposition: QuarantineDispositionService,
    private readonly metrics: QuarantineMetrics,
  ) {}

  approve(input: ApprovalInput): Promise<IdempotentResult<ApprovalDecisionResponse>> {
    return this.decide('approve', input);
  }

  deny(input: ApprovalInput): Promise<IdempotentResult<ApprovalDecisionResponse>> {
    return this.decide('deny', input);
  }

  cancel(input: ApprovalInput): Promise<IdempotentResult<ApprovalDecisionResponse>> {
    return this.decide('cancel', input);
  }

  private async decide(
    decision: 'approve' | 'deny' | 'cancel',
    input: ApprovalInput,
  ): Promise<IdempotentResult<ApprovalDecisionResponse>> {
    const operation = {
      approve: QUARANTINE_OPERATIONS.approve,
      deny: QUARANTINE_OPERATIONS.deny,
      cancel: QUARANTINE_OPERATIONS.cancel,
    }[decision];
    const verifiedEmail =
      input.principal.kind === 'user'
        ? await this.context.verifiedEmail(input.principal.userId)
        : null;
    try {
      const result = await this.writer.idempotent<ApprovalDecisionResponse>(
        {
          principal: input.principal,
          scope: input.scope,
          operation,
          key: input.key,
          resourceId: input.approvalId,
          body: input.body,
        },
        input.client,
        async (tx) => ({
          statusCode: decision === 'approve' ? HttpStatus.ACCEPTED : HttpStatus.OK,
          body: await this.apply(tx, decision, input, verifiedEmail),
        }),
      );
      this.metrics.request(decision, result.replayed ? 'replayed' : 'done');
      if (!result.replayed) {
        this.metrics.approvalDecisions.inc({
          decision: { approve: 'approved', deny: 'denied', cancel: 'cancelled' }[decision],
        });
      }
      return result;
    } catch (error) {
      const code = (error as { code?: unknown }).code;
      this.metrics.request(decision, typeof code === 'string' ? code : 'error');
      throw error;
    }
  }

  private async apply(
    tx: Tx,
    decision: 'approve' | 'deny' | 'cancel',
    input: ApprovalInput,
    verifiedEmail: string | null,
  ): Promise<ApprovalDecisionResponse> {
    const { scope, principal } = input;
    const now = new Date();
    const keyHash = idempotencyKeyHash(input.key);
    const ref = await this.writes.findApprovalRef(tx, scope, input.approvalId);
    if (ref === null) throw approvalNotFound();
    const entryRef = await this.writes.entryRefById(tx, scope, ref.quarantineMessageId);
    if (entryRef === null) throw approvalNotFound();
    const locked = await this.ops.lockRef(tx, scope, entryRef);
    const approval = await this.writes.lockApproval(tx, scope, ref.id, locked.entry.id);
    if (decision === 'cancel') {
      this.checkCanceller(principal, approval);
      if (approval.status !== 'pending') throw approvalNotPending(approval.status);
      if (approval.kind === 'policy_review')
        throw stateConflict(locked.entry.state, 'policy_review');
    } else {
      const keyCreator =
        approval.requestedByType === 'api_key' && approval.requestedByApiKeyId !== null
          ? await this.writes.apiKeyCreator(tx, scope, approval.requestedByApiKeyId)
          : null;
      const check = checkApprover({
        approver: {
          type: principal.kind,
          userId: principal.kind === 'user' ? principal.userId.toString() : null,
          verifiedEmail,
          permissions: [...principal.permissions],
        },
        request: {
          status: approval.status,
          kind: approval.kind,
          expiresAt: approval.expiresAt,
          requestedByType: approval.requestedByType,
          requestedByUserId: approval.requestedByUserId?.toString() ?? null,
          requestedByApiKeyCreatorUserId: keyCreator?.toString() ?? null,
        },
        entry: {
          userId: locked.entry.userId?.toString() ?? null,
          recipientAddress: locked.entry.recipientAddress,
        },
        now,
      });
      if (!check.allowed) {
        throw check.code === 'quarantine_approval_not_pending'
          ? approvalNotPending(check.reason === 'expired' ? 'expired' : approval.status)
          : approvalForbidden(check.reason);
      }
    }
    if (
      locked.entry.state !== 'pending_approval' ||
      locked.entry.approvalRequestId !== approval.id
    ) {
      throw stateConflict(locked.entry.state, 'request_not_current');
    }
    const correlationId = this.ops.correlationId();
    const out =
      decision === 'approve'
        ? await this.applyApprove(tx, input, locked, approval, keyHash, now, correlationId)
        : decision === 'deny'
          ? await this.applyDeny(tx, input, locked, approval, keyHash, now, correlationId)
          : await this.applyCancel(tx, input, locked, approval, keyHash, now);
    if (approval.requestedByType === 'user' && approval.requestedByUserId !== null) {
      await this.ops.notify(
        tx,
        scope,
        {
          kind: 'approval_decided',
          refs: { approvalRequestIds: [approval.publicId] },
          decision:
            out.status === 'approved'
              ? 'approved'
              : out.status === 'denied'
                ? 'denied'
                : 'cancelled',
        },
        now,
        correlationId,
      );
    }
    await this.writer.record(tx, {
      principal,
      scope,
      client: input.client,
      action: {
        approve: QUARANTINE_AUDIT.approvalApproved,
        deny: QUARANTINE_AUDIT.approvalDenied,
        cancel: QUARANTINE_AUDIT.approvalCancelled,
      }[decision],
      resourceType: QUARANTINE_RESOURCE.approval,
      resourceId: approval.publicId,
      metadata: {
        approvalRequestId: approval.publicId,
        kind: approval.kind,
        entryId: locked.entry.publicId,
        entryState: out.entryState,
        releaseId: out.releaseId,
        messageTransition: out.messageTransition,
        idempotencyKeyHash: keyHash,
      },
    });
    return out;
  }

  /** Cancel: the requester (user or API key) or a holder of `quarantine:approve` (Q14). */
  private checkCanceller(principal: Principal, approval: ApprovalRow): void {
    const requester =
      (principal.kind === 'user' && approval.requestedByUserId === principal.userId) ||
      (principal.kind === 'api_key' && approval.requestedByApiKeyId === principal.apiKeyId);
    if (!requester && !principal.permissions.has(QUARANTINE_PERMISSIONS.approve)) {
      throw new ForbiddenException('Only the requester or an approver may cancel the request');
    }
  }

  private async applyApprove(
    tx: Tx,
    input: ApprovalInput,
    locked: LockedEntry,
    approval: ApprovalRow,
    keyHash: string,
    now: Date,
    correlationId: string,
  ): Promise<ApprovalDecisionResponse> {
    const { scope } = input;
    const principal = input.principal as UserPrincipal;
    const settings = await this.context.settingsTx(tx, scope);
    const ids = await this.reads.messagePublicIds(scope, [locked.entry.messageId]);
    const base = {
      scope,
      entry: locked.entry,
      messagePublicId: ids.get(locked.entry.messageId) ?? '',
      messageState: locked.snapshot.state,
      settings,
      now,
    };
    // The reasons the approver approves: the request's ∪ the current pre-check's (Q14). With
    // that set, `decideRelease` in `approved` mode releases unless the round is stale (rescan)
    // or the tenant refuses hard-block releases; one operator-mode evaluation decides both.
    const pre = await this.precheck.run({
      ...base,
      mode: 'operator',
      entry: { ...locked.entry, state: 'held' },
    });
    const approvedReasons = union(approval.approvalReasons, pre.decision.approvalReasons);
    if (pre.decision.outcome === 'rescan_required' || pre.decision.outcome === 'refused') {
      const error =
        pre.decision.outcome === 'rescan_required'
          ? rescanRequired(pre.decision.staleness.causes)
          : pre.decision.refusal?.code === 'quarantine_hard_block_release_disabled'
            ? hardBlockReleaseDisabled()
            : stateConflict(locked.entry.state, pre.decision.refusal?.cause ?? 'refused');
      throw new AuditedRefusal(error, {
        action: QUARANTINE_AUDIT.releaseRefused,
        resourceId: locked.entry.publicId,
        metadata: {
          entryId: locked.entry.publicId,
          mode: 'approved',
          approvalRequestId: approval.publicId,
          outcome: pre.decision.outcome,
          refusal: pre.decision.refusal?.cause ?? null,
        },
      });
    }
    const ok = await this.writes.updateApproval(tx, scope, approval, {
      status: 'approved',
      decidedByUserId: principal.userId,
      decisionReason: input.body.reason,
      approvedReasons,
      deciderPermissionsHash: permissionsHash(principal),
      decidedAt: now,
    });
    if (!ok) throw approvalNotPending(approval.status);
    const queued = await this.ops.queueRelease(tx, {
      scope,
      principal,
      locked,
      entry: locked.entry,
      mode: 'approved',
      cause: 'approval_granted',
      approval: { id: approval.id, publicId: approval.publicId },
      precheck: pre.document,
      reason: input.body.reason,
      keyHash,
      now,
      correlationId,
    });
    return {
      approvalRequestId: approval.publicId,
      status: 'approved',
      entryId: locked.entry.publicId,
      entryState: 'releasing',
      releaseId: queued.releaseId,
      messageTransition: null,
    };
  }

  private async applyDeny(
    tx: Tx,
    input: ApprovalInput,
    locked: LockedEntry,
    approval: ApprovalRow,
    keyHash: string,
    now: Date,
    correlationId: string,
  ): Promise<ApprovalDecisionResponse> {
    const { scope } = input;
    const principal = input.principal as UserPrincipal;
    const ok = await this.writes.updateApproval(tx, scope, approval, {
      status: 'denied',
      decidedByUserId: principal.userId,
      decisionReason: input.body.reason,
      deciderPermissionsHash: permissionsHash(principal),
      decidedAt: now,
    });
    if (!ok) throw approvalNotPending(approval.status);
    if (approval.kind === 'policy_review') {
      const done = await this.disposition.rejectLocked(tx, {
        scope,
        principal,
        locked,
        cause: 'review_denied',
        reason: input.body.reason,
        keyHash,
        now,
        correlationId,
        operation: 'deny',
        skipApprovalCancel: true,
      });
      return {
        approvalRequestId: approval.publicId,
        status: 'denied',
        entryId: locked.entry.publicId,
        entryState: 'rejected',
        releaseId: null,
        messageTransition:
          done.messageTransition === 'E17' || done.messageTransition === 'E18'
            ? done.messageTransition
            : null,
      };
    }
    const moved = await this.ops.move(tx, scope, locked.entry, 'held', 'request_denied', now, {
      approvalRequestId: null,
    });
    await this.ops.action(tx, scope, principal, moved, 'deny_release', {
      reason: input.body.reason,
      result: 'held',
      approvalRequestId: approval.id,
      keyHash,
    });
    return {
      approvalRequestId: approval.publicId,
      status: 'denied',
      entryId: moved.publicId,
      entryState: 'held',
      releaseId: null,
      messageTransition: null,
    };
  }

  private async applyCancel(
    tx: Tx,
    input: ApprovalInput,
    locked: LockedEntry,
    approval: ApprovalRow,
    keyHash: string,
    now: Date,
  ): Promise<ApprovalDecisionResponse> {
    const { scope, principal } = input;
    const ok = await this.writes.updateApproval(tx, scope, approval, {
      status: 'cancelled',
      decisionReason: input.body.reason,
      decidedAt: now,
      ...(principal.kind === 'user' && { decidedByUserId: principal.userId }),
    });
    if (!ok) throw approvalNotPending(approval.status);
    const moved = await this.ops.move(tx, scope, locked.entry, 'held', 'request_cancelled', now, {
      approvalRequestId: null,
    });
    await this.ops.action(tx, scope, principal, moved, 'approval_cancelled', {
      reason: input.body.reason,
      result: 'held',
      approvalRequestId: approval.id,
      keyHash,
    });
    return {
      approvalRequestId: approval.publicId,
      status: 'cancelled',
      entryId: moved.publicId,
      entryState: 'held',
      releaseId: null,
      messageTransition: null,
    };
  }
}
