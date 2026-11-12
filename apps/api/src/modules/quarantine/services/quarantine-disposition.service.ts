import { HttpStatus, Inject, Injectable } from '@nestjs/common';
import type { Prisma } from '@email-gateway/database';
import type { MessageRef, TransitionActor } from '@email-gateway/message-lifecycle';
import {
  computeExpiry,
  decideObjectDisposal,
  HARD_BLOCK_ENGINE,
  isTerminalState,
  type ObjectDisposal,
  type QuarantinePrimaryEngine,
  type QuarantineRiskLevel,
  QUARANTINE_RISK_LEVELS,
} from '@email-gateway/quarantine';
import { API_CONFIG } from '../../../api-config.token';
import type { Principal } from '../../../auth-contracts/principal';
import type { TenantScope } from '../../../auth-contracts/tenant-scope';
import { idempotencyKeyHash } from '../../../http/idempotency/idempotency-key';
import type { IdempotentResult } from '../../../http/idempotency/idempotency.service';
import type { ClientContext } from '../../auth/services/session.service';
import { LifecycleGateway } from '../../messages/services/lifecycle-gateway';
import { MessageLifecycleRepository } from '../../messages/repositories/message-lifecycle.repository';
import { hardBlockIds, stringList } from '../domain/entry';
import type {
  DeleteBody,
  EntryStateResponse,
  ManualQuarantineBody,
  ManualQuarantineResponse,
  RejectBody,
} from '../dto/quarantine.schemas';
import {
  type QuarantineConfig,
  QUARANTINE_AUDIT,
  QUARANTINE_OPERATIONS,
  QUARANTINE_RESOURCE,
  QUARANTINE_SERVICE,
} from '../quarantine.constants';
import {
  AuditedRefusal,
  legalHold,
  manualNotAllowed,
  retentionActive,
  stateConflict,
  entryNotFound,
} from '../quarantine.errors';
import { QuarantineWriteRepository } from '../repositories/quarantine-write.repository';
import { QuarantineObjectStore } from './quarantine-object-store';
import { QuarantineContext } from './quarantine-context';
import { type LockedEntry, QuarantineEntryOps, actorOf } from './quarantine-entry-ops';
import { QuarantineMetrics } from './quarantine-metrics';
import type { MutationInput } from './quarantine-release.service';
import { QuarantineWriter } from './quarantine-writer';

type Tx = Prisma.TransactionClient;

const OK = HttpStatus.OK;
const DAY_MS = 86_400_000;
/** A retained purge without a known date is re-evaluated by the sweeper after one day. */
const RETAINED_RECHECK_MS = DAY_MS;

/** Q17 rule 3: an evaluation of the message requested ARCHIVE. */
export function archiveRequested(actions: readonly unknown[]): boolean {
  return actions.some(
    (a) =>
      a !== null &&
      typeof a === 'object' &&
      (a as { type?: unknown }).type === 'ARCHIVE' &&
      (a as { status?: unknown }).status === 'requested',
  );
}

const levelOf = (levels: readonly string[]): QuarantineRiskLevel | null => {
  let best: QuarantineRiskLevel | null = null;
  for (const l of levels) {
    if (!(QUARANTINE_RISK_LEVELS as readonly string[]).includes(l)) continue;
    const level = l as QuarantineRiskLevel;
    if (
      best === null ||
      QUARANTINE_RISK_LEVELS.indexOf(level) > QUARANTINE_RISK_LEVELS.indexOf(best)
    ) {
      best = level;
    }
  }
  return best;
};

/**
 * Reject, delete and manual quarantine (step 5.3 Q7, Q16, Q17), each in one writer transaction
 * under the message lock with CAS on the entry. Reject and delete discard the recipient and
 * apply E17/E18 when the message has no other live entry and no recipient still pending,
 * deferred or delivered; delete is refused under an active legal hold or archive retention
 * (`409`, audited `quarantine.delete_refused`) and schedules the object purge per Q17.
 */
@Injectable()
export class QuarantineDispositionService {
  constructor(
    @Inject(API_CONFIG)
    private readonly config: Pick<QuarantineConfig, 'QUARANTINE_MANUAL_FROM_REJECT_MAX_DAYS'>,
    private readonly writer: QuarantineWriter,
    private readonly ops: QuarantineEntryOps,
    private readonly writes: QuarantineWriteRepository,
    private readonly context: QuarantineContext,
    private readonly objects: QuarantineObjectStore,
    private readonly lifecycle: LifecycleGateway,
    private readonly messages: MessageLifecycleRepository,
    private readonly metrics: QuarantineMetrics,
  ) {}

  async reject(input: MutationInput<RejectBody>): Promise<IdempotentResult<EntryStateResponse>> {
    return this.counted('reject', () =>
      this.writer.idempotent<EntryStateResponse>(
        {
          principal: input.principal,
          scope: input.scope,
          operation: QUARANTINE_OPERATIONS.reject,
          key: input.key,
          resourceId: input.entryId,
          body: input.body,
        },
        input.client,
        async (tx) => ({ statusCode: OK, body: await this.applyReject(tx, input) }),
      ),
    );
  }

  async delete(input: MutationInput<DeleteBody>): Promise<IdempotentResult<EntryStateResponse>> {
    return this.counted('delete', () =>
      this.writer.idempotent<EntryStateResponse>(
        {
          principal: input.principal,
          scope: input.scope,
          operation: QUARANTINE_OPERATIONS.delete,
          key: input.key,
          resourceId: input.entryId,
          body: input.body,
        },
        input.client,
        async (tx) => ({ statusCode: OK, body: await this.applyDelete(tx, input) }),
      ),
    );
  }

  async manual(input: {
    principal: Principal;
    scope: TenantScope;
    key: string;
    body: ManualQuarantineBody;
    client: ClientContext;
  }): Promise<IdempotentResult<ManualQuarantineResponse>> {
    return this.counted('manual', () =>
      this.writer.idempotent<ManualQuarantineResponse>(
        {
          principal: input.principal,
          scope: input.scope,
          operation: QUARANTINE_OPERATIONS.manual,
          key: input.key,
          resourceId: input.body.messageId,
          body: input.body,
        },
        input.client,
        async (tx) => ({ statusCode: HttpStatus.CREATED, body: await this.applyManual(tx, input) }),
      ),
    );
  }

  private async counted<T>(
    operation: 'reject' | 'delete' | 'manual',
    fn: () => Promise<IdempotentResult<T>>,
  ): Promise<IdempotentResult<T>> {
    try {
      const result = await fn();
      this.metrics.request(operation, result.replayed ? 'replayed' : 'done');
      return result;
    } catch (error) {
      const code = (error as { code?: unknown }).code;
      this.metrics.request(operation, typeof code === 'string' ? code : 'error');
      throw error;
    }
  }

  /** Q16, also used by the deny of a `policy_review` request (Q14) through `rejectLocked`. */
  private async applyReject(tx: Tx, input: MutationInput<RejectBody>): Promise<EntryStateResponse> {
    const { scope, principal, body } = input;
    const now = new Date();
    const keyHash = idempotencyKeyHash(input.key);
    const locked = await this.ops.lock(tx, scope, input.entryId);
    this.ops.checkVersion(locked.entry, body.expectedRowVersion);
    const settings = await this.context.settingsTx(tx, scope);
    const correlationId = this.ops.correlationId();
    const done = await this.rejectLocked(tx, {
      scope,
      principal,
      locked,
      cause: 'reject',
      reason: body.reason,
      keyHash,
      now,
      correlationId,
      operation: 'reject',
    });
    const notify =
      locked.entry.direction !== 'inbound' &&
      (body.notifySender ?? settings.notices.senderOnReject);
    if (notify) {
      await this.ops.notify(
        tx,
        scope,
        {
          kind: 'sender_rejected',
          refs: {
            entryId: locked.entry.publicId,
            messageId: locked.ref.id.toString(),
            receivedAt: locked.ref.receivedAt.toISOString(),
          },
        },
        now,
        correlationId,
      );
    }
    await this.writer.record(tx, {
      principal,
      scope,
      client: input.client,
      action: QUARANTINE_AUDIT.rejected,
      resourceType: QUARANTINE_RESOURCE.entry,
      resourceId: locked.entry.publicId,
      metadata: {
        entryId: locked.entry.publicId,
        fromState: locked.entry.state,
        senderNotified: notify,
        messageTransition: done.messageTransition,
        purge: done.purge,
        idempotencyKeyHash: keyHash,
      },
    });
    return done;
  }

  /**
   * The entry (`held`/`pending_approval`) → `rejected` (cause `reject` or `review_denied`), its
   * pending requests cancelled, the recipient discarded, E17/E18 when it was the last live entry,
   * and the object disposal scheduled by Q17's rules (no explicit delete needed; Q16).
   */
  async rejectLocked(
    tx: Tx,
    r: {
      scope: TenantScope;
      principal: Principal;
      locked: LockedEntry;
      cause: 'reject' | 'review_denied';
      reason: string;
      keyHash: string | null;
      now: Date;
      correlationId: string;
      operation: string;
      skipApprovalCancel?: boolean;
    },
  ): Promise<EntryStateResponse> {
    const { scope, principal, locked, now } = r;
    const actor = actorOf(principal);
    if (r.skipApprovalCancel !== true) {
      await this.writes.cancelPendingApprovals(tx, scope, locked.entry.id, now);
    }
    const moved = await this.ops.move(tx, scope, locked.entry, 'rejected', r.cause, now, {
      decidedAt: now,
      decidedByUserId: actor.actorUserId,
      decidedByType: actor.actorType,
      terminalReason: r.cause,
    });
    await this.ops.action(
      tx,
      scope,
      principal,
      moved,
      r.cause === 'reject' ? 'reject' : 'deny_release',
      {
        reason: r.reason,
        result: 'rejected',
        keyHash: r.keyHash,
      },
    );
    await this.ops.discardRecipient(tx, scope, locked);
    const edge = await this.ops.finishMessage(
      tx,
      scope,
      locked,
      principal,
      r.operation,
      r.correlationId,
    );
    const disposal = await this.disposal(tx, scope, locked, now);
    const purge = await this.schedulePurge(tx, scope, locked.ref, disposal, now);
    return {
      entryId: moved.publicId,
      state: 'rejected',
      rowVersion: moved.rowVersion,
      messageTransition: edge,
      purge,
    };
  }

  private async applyDelete(tx: Tx, input: MutationInput<DeleteBody>): Promise<EntryStateResponse> {
    const { scope, principal, body } = input;
    const now = new Date();
    const keyHash = idempotencyKeyHash(input.key);
    const locked = await this.ops.lock(tx, scope, input.entryId);
    const { entry } = locked;
    this.ops.checkVersion(entry, body.expectedRowVersion);
    if (!['held', 'pending_approval', 'rejected', 'expired'].includes(entry.state)) {
      throw stateConflict(entry.state);
    }
    const wasLive = !isTerminalState(entry.state);
    // The recipient as it will be after the delete (Q17: facts "after the action").
    const disposal = await this.disposal(tx, scope, locked, now, { discardsRecipient: wasLive });
    if (!disposal.deleteAllowed && disposal.refusal !== null) {
      const error =
        disposal.refusal.code === 'quarantine_legal_hold'
          ? legalHold(disposal.refusal.legalHoldId)
          : retentionActive(disposal.refusal.retainUntil);
      throw new AuditedRefusal(error, {
        action: QUARANTINE_AUDIT.deleteRefused,
        resourceId: entry.publicId,
        metadata: {
          entryId: entry.publicId,
          refusal: disposal.refusal.code,
          legalHoldId: disposal.refusal.legalHoldId,
          retainUntil: disposal.refusal.retainUntil,
        },
      });
    }
    const actor = actorOf(principal);
    if (wasLive) await this.writes.cancelPendingApprovals(tx, scope, entry.id, now);
    const moved = await this.ops.move(tx, scope, entry, 'deleted', 'delete', now, {
      decidedAt: now,
      decidedByUserId: actor.actorUserId,
      decidedByType: actor.actorType,
      terminalReason: 'delete',
    });
    await this.ops.action(tx, scope, principal, moved, 'delete', {
      reason: body.reason,
      result:
        disposal.purge === 'now'
          ? 'purge_pending'
          : `retained_${disposal.retainedReason ?? 'unknown'}`,
      keyHash,
    });
    const correlationId = this.ops.correlationId();
    let edge: 'E17' | 'E18' | null = null;
    if (wasLive) {
      await this.ops.discardRecipient(tx, scope, locked);
      edge = await this.ops.finishMessage(tx, scope, locked, principal, 'delete', correlationId);
    }
    const purge = await this.schedulePurge(tx, scope, locked.ref, disposal, now);
    await this.writer.record(tx, {
      principal,
      scope,
      client: input.client,
      action: QUARANTINE_AUDIT.deleted,
      resourceType: QUARANTINE_RESOURCE.entry,
      resourceId: entry.publicId,
      metadata: {
        entryId: entry.publicId,
        fromState: entry.state,
        messageTransition: edge,
        purge,
        retainedReason: disposal.retainedReason,
        idempotencyKeyHash: keyHash,
      },
    });
    return {
      entryId: moved.publicId,
      state: 'deleted',
      rowVersion: moved.rowVersion,
      messageTransition: edge,
      purge,
    };
  }

  /**
   * Q17 on writer facts. `entries` and `recipientStatuses` describe the state after the action:
   * the acting entry as terminal and its recipient discarded when it was live.
   */
  private async disposal(
    tx: Tx,
    scope: TenantScope,
    locked: LockedEntry,
    now: Date,
    /** Delete decides before writing: the acting entry as `deleted`, its recipient discarded. */
    pending: { discardsRecipient: boolean } | null = null,
  ): Promise<ObjectDisposal> {
    const discardsRecipient = pending?.discardsRecipient ?? false;
    const message = await this.writes.messageById(tx, scope, locked.ref);
    if (message === null) throw entryNotFound();
    const [facts, entries, recipients] = await Promise.all([
      this.writes.disposalFacts(tx, scope, locked.ref),
      this.writes.entriesOfMessage(tx, scope, locked.ref),
      this.writes.recipients(tx, scope, locked.ref),
    ]);
    return decideObjectDisposal({
      now,
      message: {
        receivedAt: locked.ref.receivedAt,
        direction: message.direction,
        senderAddresses: [message.envelopeFrom, message.headerFrom ?? ''].filter((a) => a !== ''),
        recipientAddresses: recipients.map((r) => r.address),
        state: locked.snapshot.state,
      },
      legalHolds: facts.legalHolds.map((h) => ({ id: h.id.toString(), criteria: h.criteria })),
      archive: facts.archive,
      retentionPolicyDays: facts.retentionPolicyDays,
      emailArchives: facts.emailArchives,
      archiveRequested: archiveRequested(facts.evaluationActions),
      entries: entries.map((e) => ({
        state: pending !== null && e.id === locked.entry.id ? 'deleted' : e.state,
      })),
      recipientStatuses: recipients.map((r) =>
        discardsRecipient && r.rcptSeq === locked.entry.rcptSeq && r.status === 'quarantined'
          ? 'discarded'
          : r.status,
      ),
    });
  }

  private async schedulePurge(
    tx: Tx,
    scope: TenantScope,
    message: MessageRef,
    disposal: ObjectDisposal,
    now: Date,
  ): Promise<'pending' | 'retained'> {
    const status = disposal.purge === 'now' ? 'pending' : 'retained';
    await this.writes.upsertPurge(tx, scope, message, {
      status,
      reason: status === 'retained' ? (disposal.retainedReason ?? 'retained') : null,
      purgeAfter:
        status === 'pending'
          ? now
          : (disposal.purgeAfter ?? new Date(now.getTime() + RETAINED_RECHECK_MS)),
    });
    return status;
  }

  // ------------------------------------------------------------------ manual quarantine (Q7)

  private async applyManual(
    tx: Tx,
    input: {
      principal: Principal;
      scope: TenantScope;
      key: string;
      body: ManualQuarantineBody;
      client: ClientContext;
    },
  ): Promise<ManualQuarantineResponse> {
    const { scope, principal, body } = input;
    const now = new Date();
    const keyHash = idempotencyKeyHash(input.key);
    const message = await this.writes.message(tx, scope, body.messageId);
    if (message === null) throw entryNotFound();
    const ref: MessageRef = {
      id: message.id,
      receivedAt: message.receivedAt,
      organizationId: scope.organizationId,
    };
    const snapshot = await this.lifecycle.lock(tx, ref);
    if (snapshot === null) throw entryNotFound();
    const correlationId = this.ops.correlationId();
    const actor: TransitionActor = {
      role: 'quarantine',
      service: QUARANTINE_SERVICE,
      type: principal.kind,
      id: actorOf(principal).actorId,
    };
    const selected = (seq: number) => body.rcptSeqs === undefined || body.rcptSeqs.includes(seq);
    let response: ManualQuarantineResponse;
    if (snapshot.state === 'held_for_review') {
      const reviews = (await this.writes.lockReviewEntries(tx, scope, ref, snapshot.round)).filter(
        (e) => selected(e.rcptSeq),
      );
      if (reviews.length === 0) throw manualNotAllowed('no_review_entry');
      const out: ManualQuarantineResponse['entries'] = [];
      for (const entry of reviews) {
        await this.writes.cancelPendingApprovals(tx, scope, entry.id, now);
        const moved = await this.ops.move(tx, scope, entry, 'held', 'manual_quarantine', now, {
          kind: 'quarantine',
          approvalRequestId: null,
        });
        await this.ops.action(tx, scope, principal, moved, 'quarantine', {
          reason: body.reason,
          result: 'held',
          details: { origin: entry.origin, from: 'review' },
          keyHash,
        });
        out.push({ id: moved.publicId, rcptSeq: moved.rcptSeq, state: 'held' });
      }
      const remaining = (await this.writes.entriesOfMessage(tx, scope, ref)).filter(
        (e) =>
          e.kind === 'review' && !isTerminalState(e.state) && e.lifecycleRound === snapshot.round,
      );
      let edge: 'E16' | null = null;
      if (remaining.length === 0) {
        const outcome = await this.lifecycle.transition(tx, {
          message: ref,
          to: 'quarantined',
          reason: 'review_quarantined',
          actor,
          transitionKey: `api:quarantine:${scope.organizationId.toString()}:manual:${keyHash}`,
          correlationId,
          expectedFrom: ['held_for_review'],
          expectedVersion: snapshot.version,
          recordIgnored: false,
        });
        if (outcome.result !== 'applied')
          throw stateConflict(snapshot.state, `message_${outcome.result}`);
        edge = 'E16';
      }
      response = { messageId: message.publicId, entries: out, messageTransition: edge };
    } else if (snapshot.state === 'rejected') {
      response = await this.manualFromReject(tx, {
        scope,
        principal,
        message,
        ref,
        snapshot,
        selected,
        reason: body.reason,
        keyHash,
        now,
        actor,
        correlationId,
      });
    } else {
      throw stateConflict(snapshot.state, 'message_state');
    }
    await this.messages.insertEmailEvent(tx, {
      message: ref,
      eventType: 'quarantine.created',
      occurredAt: now,
      sourceService: QUARANTINE_SERVICE,
      eventId: null,
      actorType: principal.kind,
      actorId: actorOf(principal).actorId,
      details: { entries: response.entries.length, kind: 'quarantine', origin: 'manual' },
    });
    await this.writer.record(tx, {
      principal,
      scope,
      client: input.client,
      action: QUARANTINE_AUDIT.manualQuarantined,
      resourceType: QUARANTINE_RESOURCE.message,
      resourceId: message.publicId,
      metadata: {
        messageId: message.publicId,
        fromState: snapshot.state,
        entryIds: response.entries.map((e) => e.id),
        messageTransition: response.messageTransition,
        idempotencyKeyHash: keyHash,
      },
    });
    return response;
  }

  /** Q7 from a policy rejection: E29 (same round), new manual entries, recipients quarantined. */
  private async manualFromReject(
    tx: Tx,
    m: {
      scope: TenantScope;
      principal: Principal;
      message: NonNullable<Awaited<ReturnType<QuarantineWriteRepository['message']>>>;
      ref: MessageRef;
      snapshot: { state: string; version: number; round: number; statusReason: string | null };
      selected: (seq: number) => boolean;
      reason: string;
      keyHash: string;
      now: Date;
      actor: TransitionActor;
      correlationId: string;
    },
  ): Promise<ManualQuarantineResponse> {
    const { scope, principal, message, ref, snapshot, now } = m;
    if (snapshot.statusReason !== 'policy_reject' && snapshot.statusReason !== 'policy_discard') {
      throw manualNotAllowed('not_policy_rejected');
    }
    const maxAge = this.config.QUARANTINE_MANUAL_FROM_REJECT_MAX_DAYS * DAY_MS;
    if (now.getTime() - message.receivedAt.getTime() > maxAge) throw manualNotAllowed('too_old');
    if (!(await this.objects.exists(scope.organizationId, message.emlObjectKey))) {
      throw manualNotAllowed('content_missing');
    }
    const existing = new Set(
      (await this.writes.entriesOfMessage(tx, scope, ref))
        .filter((e) => e.lifecycleRound === snapshot.round)
        .map((e) => e.rcptSeq),
    );
    const recipients = (await this.writes.recipients(tx, scope, ref)).filter(
      (r) =>
        m.selected(r.rcptSeq) &&
        !existing.has(r.rcptSeq) &&
        (r.status === 'discarded' || r.status === 'pending'),
    );
    if (recipients.length === 0) throw manualNotAllowed('no_eligible_recipient');
    const outcome = await this.lifecycle.transition(tx, {
      message: ref,
      to: 'quarantined',
      reason: 'manual_quarantine',
      actor: m.actor,
      transitionKey: `api:quarantine:${scope.organizationId.toString()}:manual:${m.keyHash}`,
      correlationId: m.correlationId,
      expectedFrom: ['rejected'],
      expectedVersion: snapshot.version,
      recordIgnored: false,
    });
    if (outcome.result !== 'applied')
      throw stateConflict(snapshot.state, `message_${outcome.result}`);
    const facts = await this.writes.roundFacts(tx, scope, ref, snapshot.round);
    const settings = await this.context.settingsTx(tx, scope);
    const hardBlocks = [...new Set(facts.risk.flatMap((r) => hardBlockIds(r.hardBlocks, 16)))]
      .sort()
      .slice(0, 9);
    const level = levelOf(facts.risk.map((r) => r.level));
    const action =
      facts.risk.length === 0 ? null : facts.risk[facts.risk.length - 1]!.recommendedAction;
    const ev = facts.evaluation;
    const versionNo =
      ev?.decisivePolicyPublicId === null || ev === null
        ? null
        : decisiveVersionNo(ev.policyVersions, ev.decisivePolicyPublicId);
    const engine: QuarantinePrimaryEngine =
      (hardBlocks.length > 0 ? HARD_BLOCK_ENGINE[hardBlocks[0]!] : undefined) ??
      (ev?.decisionSource === 'tenant_rule' ? 'policy' : 'none');
    const expiresAt = computeExpiry({
      kind: 'quarantine',
      quarantinedAt: now,
      holdDays: settings.hold.days,
      reviewDays: settings.review.days,
      maxHoldDays: this.context.bounds.maxHoldDays,
      maxReviewDays: this.context.bounds.maxReviewDays,
    });
    const rows: Prisma.QuarantineMessageCreateManyInput[] = [];
    for (const r of recipients) {
      rows.push({
        organizationId: scope.organizationId,
        messageId: ref.id,
        messageReceivedAt: ref.receivedAt,
        lifecycleRound: snapshot.round,
        scanId: facts.scanId,
        evaluationSeq: ev?.evaluationSeq ?? null,
        recipientId: r.id,
        rcptSeq: r.rcptSeq,
        recipientAddress: r.address.trim().toLowerCase(),
        userId: await this.writes.userIdByEmail(tx, scope, r.address.trim().toLowerCase()),
        direction: message.direction,
        kind: 'quarantine',
        origin: 'manual',
        reason: 'manual',
        policyVersionId: ev?.decisivePolicyVersionId ?? null,
        status: 'held',
        envelopeFrom: message.envelopeFrom,
        headerFrom: message.headerFrom,
        hasAttachments: message.attachmentCount > 0,
        attachmentCount: message.attachmentCount,
        sizeBytes: message.sizeBytes,
        riskScore: ev?.riskScore ?? message.riskScore,
        riskLevel: level,
        recommendedAction: action as Prisma.QuarantineMessageCreateManyInput['recommendedAction'],
        riskVerdict: (ev?.finalVerdict ??
          message.finalVerdict) as Prisma.QuarantineMessageCreateManyInput['riskVerdict'],
        hasHardBlock: hardBlocks.length > 0,
        hardBlocks,
        reasonCodes: stringList(ev?.reasonCodes, 32),
        floorReasons: stringList((ev?.floor as { reasons?: unknown } | null)?.reasons, 16),
        primaryEngine: engine,
        decisionSource: ev?.decisionSource ?? null,
        decisivePolicyPublicId: ev?.decisivePolicyPublicId ?? null,
        decisivePolicyVersionNo: versionNo,
        decisiveRuleId: ev?.decisiveRuleId ?? null,
        explanation: ev?.explanation ?? undefined,
        explanationText: ev?.explanationText.slice(0, 2048) ?? null,
        emlObjectKey: message.emlObjectKey,
        quarantinedAt: now,
        expiresAt,
        stateChangedAt: now,
      });
    }
    const created = await this.writes.createEntries(tx, rows, scope, ref, snapshot.round);
    for (const entry of created) {
      await this.writes.setRecipientStatus(
        tx,
        scope,
        ref,
        entry.rcptSeq,
        ['discarded', 'pending'],
        'quarantined',
        'quarantine',
      );
      await this.ops.action(tx, scope, principal, entry, 'quarantine', {
        reason: m.reason,
        result: 'held',
        details: { origin: 'manual', evaluationSeq: ev?.evaluationSeq ?? null },
        keyHash: m.keyHash,
      });
    }
    return {
      messageId: message.publicId,
      entries: created.map((e) => ({ id: e.publicId, rcptSeq: e.rcptSeq, state: e.state })),
      messageTransition: 'E29',
    };
  }
}

/** The decisive policy's version number from the stored `policy_versions` JSON, if present. */
function decisiveVersionNo(policyVersions: unknown, publicId: string): number | null {
  if (!Array.isArray(policyVersions)) return null;
  for (const v of policyVersions) {
    const rec = v as { policyId?: unknown; publicId?: unknown; versionNo?: unknown };
    if (
      (rec.policyId === publicId || rec.publicId === publicId) &&
      typeof rec.versionNo === 'number'
    ) {
      return rec.versionNo;
    }
  }
  return null;
}
