import { HttpStatus, Injectable } from '@nestjs/common';
import type { Prisma } from '@email-gateway/database';
import {
  checkSelfService,
  type QuarantineSettings,
  type ReleaseDecision,
} from '@email-gateway/quarantine';
import type { Principal } from '../../../auth-contracts/principal';
import type { TenantScope } from '../../../auth-contracts/tenant-scope';
import { idempotencyKeyHash } from '../../../http/idempotency/idempotency-key';
import type { IdempotentResult } from '../../../http/idempotency/idempotency.service';
import type { ClientContext } from '../../auth/services/session.service';
import type { ReasonBody, ReleaseBody, ReleaseOutcome } from '../dto/quarantine.schemas';
import {
  QUARANTINE_AUDIT,
  QUARANTINE_OPERATIONS,
  QUARANTINE_RESOURCE,
} from '../quarantine.constants';
import {
  AuditedRefusal,
  hardBlockReleaseDisabled,
  rescanRequired,
  selfReleaseNotAllowed,
  stateConflict,
} from '../quarantine.errors';
import { QuarantineReadRepository } from '../repositories/quarantine-read.repository';
import { QuarantineWriteRepository } from '../repositories/quarantine-write.repository';
import { type SelfCaller, QuarantineContext, permissionsOf } from './quarantine-context';
import { type LockedEntry, QuarantineEntryOps, actorOf } from './quarantine-entry-ops';
import { QuarantineMetrics } from './quarantine-metrics';
import { QuarantinePrecheckService } from './quarantine-precheck.service';
import { QuarantineWriter } from './quarantine-writer';

type Tx = Prisma.TransactionClient;

export interface MutationInput<B> {
  principal: Principal;
  scope: TenantScope;
  entryId: string;
  key: string;
  body: B;
  client: ClientContext;
}

const ACCEPTED = HttpStatus.ACCEPTED;

/** A refused pre-check → its coded error (and the audited refusal row). */
function refusalError(decision: ReleaseDecision) {
  if (decision.outcome === 'rescan_required') return rescanRequired(decision.staleness.causes);
  if (decision.refusal?.code === 'quarantine_hard_block_release_disabled') {
    return hardBlockReleaseDisabled();
  }
  if (decision.refusal?.code === 'quarantine_self_release_not_allowed') {
    return selfReleaseNotAllowed(decision.refusal.cause);
  }
  return stateConflict('held', decision.refusal?.cause);
}

/**
 * Release and release requests (step 5.3 Q13.1, Q14, Q15): `POST …/entries/{id}/release`
 * (operator), `POST …/me/entries/{id}/release` (self-release), `POST …/entries/{id}/request-release`
 * and its self route. One writer transaction each (Idempotency-Key lookup → message lock → entry
 * lock (CAS) → state `held` → replica pre-check → outcome): `rescan_required` and refusals are
 * `409`/`403` with only the audit row `quarantine.release_refused` written; `approval_required`
 * creates a `release_approval` request (entry `pending_approval`); `release` queues the release
 * for the executor (release log `pending`, entry `releasing`, outbox event). The executor decides.
 */
@Injectable()
export class QuarantineReleaseService {
  constructor(
    private readonly writer: QuarantineWriter,
    private readonly ops: QuarantineEntryOps,
    private readonly writes: QuarantineWriteRepository,
    private readonly reads: QuarantineReadRepository,
    private readonly context: QuarantineContext,
    private readonly precheck: QuarantinePrecheckService,
    private readonly metrics: QuarantineMetrics,
  ) {}

  release(input: MutationInput<ReleaseBody>): Promise<IdempotentResult<ReleaseOutcome>> {
    return this.counted('release', () =>
      this.writer.idempotent<ReleaseOutcome>(
        this.mutation(input, QUARANTINE_OPERATIONS.release),
        input.client,
        (tx) => this.applyRelease(tx, input, null),
      ),
    );
  }

  async selfRelease(input: MutationInput<ReleaseBody>): Promise<IdempotentResult<ReleaseOutcome>> {
    const caller = await this.context.selfCaller(input.principal, input.scope);
    return this.counted('self_release', () =>
      this.writer.idempotent<ReleaseOutcome>(
        this.mutation(input, QUARANTINE_OPERATIONS.selfRelease),
        input.client,
        (tx) => this.applyRelease(tx, input, caller),
      ),
    );
  }

  requestRelease(input: MutationInput<ReasonBody>): Promise<IdempotentResult<ReleaseOutcome>> {
    return this.counted('request_release', () =>
      this.writer.idempotent<ReleaseOutcome>(
        this.mutation(input, QUARANTINE_OPERATIONS.requestRelease),
        input.client,
        (tx) => this.applyRequest(tx, input, null),
      ),
    );
  }

  async selfRequestRelease(
    input: MutationInput<ReasonBody>,
  ): Promise<IdempotentResult<ReleaseOutcome>> {
    const caller = await this.context.selfCaller(input.principal, input.scope);
    return this.counted('request_release', () =>
      this.writer.idempotent<ReleaseOutcome>(
        this.mutation(input, QUARANTINE_OPERATIONS.selfRequestRelease),
        input.client,
        (tx) => this.applyRequest(tx, input, caller),
      ),
    );
  }

  private mutation<B>(input: MutationInput<B>, operation: string) {
    return {
      principal: input.principal,
      scope: input.scope,
      operation,
      key: input.key,
      resourceId: input.entryId,
      body: input.body,
    };
  }

  private async counted<T>(
    operation: 'release' | 'self_release' | 'request_release',
    fn: () => Promise<IdempotentResult<T & { outcome?: string }>>,
  ): Promise<IdempotentResult<T>> {
    try {
      const result = await fn();
      this.metrics.request(operation, result.replayed ? 'replayed' : (result.body.outcome ?? 'ok'));
      return result;
    } catch (error) {
      const code = (error as { code?: unknown }).code;
      this.metrics.request(operation, typeof code === 'string' ? code : 'error');
      throw error;
    }
  }

  private async applyRelease(
    tx: Tx,
    input: MutationInput<ReleaseBody>,
    self: SelfCaller | null,
  ): Promise<{ statusCode: number; body: ReleaseOutcome }> {
    const { scope, principal, body } = input;
    const now = new Date();
    const keyHash = idempotencyKeyHash(input.key);
    const locked = await this.ops.lock(tx, scope, input.entryId, self?.address ?? null);
    const { entry } = locked;
    this.ops.checkVersion(entry, body.expectedRowVersion);
    const settings = await this.context.settingsTx(tx, scope);
    if (self !== null) {
      const check = checkSelfService({
        action: 'release',
        settings,
        caller: {
          type: 'user',
          verifiedEmail: self.address,
          permissions: permissionsOf(principal),
        },
        entry: {
          recipientAddress: entry.recipientAddress,
          state: entry.state,
          reason: entry.reason,
          riskLevel: entry.riskLevel,
          hasHardBlock: entry.hasHardBlock,
        },
      });
      if (!check.allowed) throw this.selfRefusal(check.code, check.cause, entry.state);
    } else if (entry.state !== 'held') {
      throw stateConflict(entry.state);
    }
    const pre = await this.runPrecheck(
      locked,
      scope,
      self === null ? 'operator' : 'self',
      settings,
      now,
    );
    const refused =
      pre.decision.outcome === 'rescan_required' || pre.decision.outcome === 'refused';
    if (refused) {
      throw new AuditedRefusal(refusalError(pre.decision), {
        action: QUARANTINE_AUDIT.releaseRefused,
        resourceId: entry.publicId,
        metadata: {
          entryId: entry.publicId,
          mode: self === null ? 'operator' : 'self',
          outcome: pre.decision.outcome,
          refusal: pre.decision.refusal?.cause ?? null,
          approvalReasons: pre.decision.approvalReasons,
          staleness: pre.decision.staleness.causes,
        },
      });
    }
    const correlationId = this.ops.correlationId();
    if (pre.decision.outcome === 'approval_required') {
      const out = await this.requestApproval(tx, {
        input,
        locked,
        settings,
        kind: 'release_approval',
        cause: 'approval_required',
        reasons: pre.decision.approvalReasons,
        now,
        keyHash,
        correlationId,
      });
      await this.writer.record(tx, {
        principal,
        scope,
        client: input.client,
        action: QUARANTINE_AUDIT.releaseRequested,
        resourceType: QUARANTINE_RESOURCE.entry,
        resourceId: entry.publicId,
        metadata: {
          entryId: entry.publicId,
          outcome: 'approval_requested',
          approvalRequestId: out.approvalRequestId,
          approvalReasons: out.approvalReasons,
          idempotencyKeyHash: keyHash,
        },
      });
      return { statusCode: ACCEPTED, body: out };
    }
    const queued = await this.ops.queueRelease(tx, {
      scope,
      principal,
      locked,
      entry,
      mode: self === null ? 'operator' : 'self',
      cause: 'release_queued',
      approval: null,
      precheck: pre.document,
      reason: body.reason,
      keyHash,
      now,
      correlationId,
    });
    await this.writer.record(tx, {
      principal,
      scope,
      client: input.client,
      action: self === null ? QUARANTINE_AUDIT.releaseRequested : QUARANTINE_AUDIT.selfReleased,
      resourceType: QUARANTINE_RESOURCE.entry,
      resourceId: entry.publicId,
      metadata: {
        entryId: entry.publicId,
        outcome: 'queued',
        releaseId: queued.releaseId,
        idempotencyKeyHash: keyHash,
      },
    });
    return {
      statusCode: ACCEPTED,
      body: {
        outcome: 'queued',
        entryId: entry.publicId,
        state: 'releasing',
        releaseId: queued.releaseId,
        rowVersion: queued.entry.rowVersion,
      },
    };
  }

  private async applyRequest(
    tx: Tx,
    input: MutationInput<ReasonBody>,
    self: SelfCaller | null,
  ): Promise<{ statusCode: number; body: ReleaseOutcome }> {
    const { scope, principal } = input;
    const now = new Date();
    const keyHash = idempotencyKeyHash(input.key);
    const locked = await this.ops.lock(tx, scope, input.entryId, self?.address ?? null);
    const { entry } = locked;
    const settings = await this.context.settingsTx(tx, scope);
    if (self !== null) {
      const check = checkSelfService({
        action: 'request_release',
        settings,
        caller: {
          type: 'user',
          verifiedEmail: self.address,
          permissions: permissionsOf(principal),
        },
        entry: {
          recipientAddress: entry.recipientAddress,
          state: entry.state,
          reason: entry.reason,
          riskLevel: entry.riskLevel,
          hasHardBlock: entry.hasHardBlock,
        },
      });
      if (!check.allowed) throw this.selfRefusal(check.code, check.cause, entry.state);
    } else if (entry.state !== 'held') {
      throw stateConflict(entry.state);
    }
    // The pre-check computes the reasons the approver sees (operator mode: no self bounds).
    const pre = await this.runPrecheck(locked, scope, 'operator', settings, now);
    if (pre.decision.outcome === 'refused') {
      throw new AuditedRefusal(refusalError(pre.decision), {
        action: QUARANTINE_AUDIT.releaseRefused,
        resourceId: entry.publicId,
        metadata: {
          entryId: entry.publicId,
          mode: 'request',
          outcome: 'refused',
          refusal: pre.decision.refusal?.cause ?? null,
        },
      });
    }
    const out = await this.requestApproval(tx, {
      input,
      locked,
      settings,
      kind: 'release_request',
      cause: 'release_request',
      reasons: pre.decision.approvalReasons,
      now,
      keyHash,
      correlationId: this.ops.correlationId(),
    });
    await this.writer.record(tx, {
      principal,
      scope,
      client: input.client,
      action: QUARANTINE_AUDIT.approvalRequested,
      resourceType: QUARANTINE_RESOURCE.approval,
      resourceId: out.approvalRequestId,
      metadata: {
        entryId: entry.publicId,
        approvalRequestId: out.approvalRequestId,
        kind: 'release_request',
        self: self !== null,
        approvalReasons: out.approvalReasons,
        idempotencyKeyHash: keyHash,
      },
    });
    return { statusCode: ACCEPTED, body: out };
  }

  private selfRefusal(code: string, cause: string, state: string) {
    if (code === 'quarantine_state_conflict') return stateConflict(state, cause);
    return selfReleaseNotAllowed(cause);
  }

  private async runPrecheck(
    locked: LockedEntry,
    scope: TenantScope,
    mode: 'operator' | 'self',
    settings: QuarantineSettings,
    now: Date,
  ) {
    const ids = await this.reads.messagePublicIds(scope, [locked.entry.messageId]);
    return this.precheck.run({
      scope,
      entry: locked.entry,
      messagePublicId: ids.get(locked.entry.messageId) ?? '',
      mode,
      messageState: locked.snapshot.state,
      settings,
      now,
    });
  }

  /** A pending request (Q14): one per entry, under the entry lock; notification when enabled. */
  async requestApproval(
    tx: Tx,
    a: {
      input: { principal: Principal; scope: TenantScope; body: { reason: string } };
      locked: LockedEntry;
      settings: QuarantineSettings;
      kind: 'release_approval' | 'release_request';
      cause: 'approval_required' | 'release_request';
      reasons: ReleaseDecision['approvalReasons'];
      now: Date;
      keyHash: string;
      correlationId: string;
    },
  ): Promise<Extract<ReleaseOutcome, { outcome: 'approval_requested' }>> {
    const { principal, scope } = a.input;
    const actor = actorOf(principal);
    const approval = await this.writes.createApproval(tx, {
      organizationId: scope.organizationId,
      quarantineMessageId: a.locked.entry.id,
      kind: a.kind,
      approvalReasons: [...a.reasons],
      requestedByType: actor.actorType,
      requestedByUserId: actor.actorUserId,
      requestedByApiKeyId: principal.kind === 'api_key' ? principal.apiKeyId : null,
      requestReason: a.input.body.reason,
      expiresAt: new Date(a.now.getTime() + a.settings.approvals.requestTtlHours * 3_600_000),
    });
    const moved = await this.ops.move(
      tx,
      scope,
      a.locked.entry,
      'pending_approval',
      a.cause,
      a.now,
      {
        approvalRequestId: approval.id,
      },
    );
    await this.ops.action(
      tx,
      scope,
      principal,
      moved,
      a.cause === 'release_request' ? 'request_release' : 'release_blocked',
      {
        reason: a.input.body.reason,
        result: 'approval_requested',
        details: { kind: a.kind, approvalReasons: [...a.reasons] },
        approvalRequestId: approval.id,
        keyHash: a.keyHash,
      },
    );
    if (a.settings.alerts.approvalRequests) {
      await this.ops.notify(
        tx,
        scope,
        { kind: 'approval_requested', refs: { approvalRequestIds: [approval.publicId] } },
        a.now,
        a.correlationId,
      );
    }
    return {
      outcome: 'approval_requested',
      entryId: moved.publicId,
      state: 'pending_approval',
      approvalRequestId: approval.publicId,
      approvalReasons: [...a.reasons],
      rowVersion: moved.rowVersion,
    };
  }
}
