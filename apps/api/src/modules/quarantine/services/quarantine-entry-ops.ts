import { createHash } from 'node:crypto';
import { Injectable, Logger } from '@nestjs/common';
import { uuidv7 } from '@email-gateway/common';
import type { ActorType, Prisma, QuarantineActionType } from '@email-gateway/database';
import {
  EventTypes,
  quarantineNotificationRequestedV1,
  quarantineReleaseRequestedV1,
  type QuarantineNotificationRequestedV1,
} from '@email-gateway/event-contracts';
import { getCorrelationId } from '@email-gateway/logger';
import type {
  LifecycleSnapshot,
  MessageRef,
  TransitionActor,
} from '@email-gateway/message-lifecycle';
import {
  actionTypeFor,
  decideEntryTransition,
  type EntryTransitionCause,
  isTerminalState,
  type QuarantineReleaseMode,
  type QuarantineState,
} from '@email-gateway/quarantine';
import type { Principal } from '../../../auth-contracts/principal';
import type { TenantScope } from '../../../auth-contracts/tenant-scope';
import { LifecycleGateway } from '../../messages/services/lifecycle-gateway';
import type { EntryRow } from '../domain/entry';
import { QUARANTINE_SERVICE } from '../quarantine.constants';
import { entryNotFound, stateConflict, versionConflict } from '../quarantine.errors';
import {
  type EntryRefRow,
  type EntryUpdate,
  QuarantineWriteRepository,
} from '../repositories/quarantine-write.repository';

type Tx = Prisma.TransactionClient;

/** An entry locked for a mutation: message lock first, then the entry row (Q3 lock order). */
export interface LockedEntry {
  ref: MessageRef;
  snapshot: LifecycleSnapshot;
  entry: EntryRow;
}

export interface ActorColumns {
  actorType: ActorType;
  actorUserId: bigint | null;
  actorId: string;
}

export function actorOf(principal: Principal): ActorColumns {
  return principal.kind === 'user'
    ? { actorType: 'user', actorUserId: principal.userId, actorId: principal.userPublicId }
    : { actorType: 'api_key', actorUserId: null, actorId: principal.apiKeyPublicId };
}

/** Per-row backstop key of `quarantine_actions.idempotency_key` (unique per organization). */
export function actionKey(
  keyHash: string | null,
  entryPublicId: string,
  action: string,
): string | null {
  if (keyHash === null) return null;
  return createHash('sha256').update(`${keyHash}:${entryPublicId}:${action}`).digest('hex');
}

const RECIPIENT_BLOCKS_FINAL = new Set(['pending', 'deferred', 'delivered']);

/**
 * The building blocks every quarantine writer path shares (step 5.3 Q3, Q5, Q13–Q17): the lock
 * order, the state machine check and CAS update, the `quarantine_actions` row, the E17/E18 rule,
 * the release queue (release log + outbox) and the notification outbox rows. Used inside one
 * writer transaction of the calling service.
 */
@Injectable()
export class QuarantineEntryOps {
  private readonly logger = new Logger(QuarantineEntryOps.name);

  constructor(
    private readonly writes: QuarantineWriteRepository,
    private readonly lifecycle: LifecycleGateway,
  ) {}

  correlationId(): string {
    return `api:${getCorrelationId() ?? uuidv7()}`.slice(0, 128);
  }

  /** Message lock, then the entry row `FOR UPDATE` (another tenant/address → `404`). */
  async lock(
    tx: Tx,
    scope: TenantScope,
    entryPublicId: string,
    selfAddress: string | null = null,
  ): Promise<LockedEntry> {
    const ref = await this.writes.findEntryRef(tx, scope, entryPublicId, selfAddress);
    if (ref === null) throw entryNotFound();
    return this.lockRef(tx, scope, ref);
  }

  async lockRef(tx: Tx, scope: TenantScope, ref: EntryRefRow): Promise<LockedEntry> {
    const message: MessageRef = {
      id: ref.messageId,
      receivedAt: ref.messageReceivedAt,
      organizationId: scope.organizationId,
    };
    const snapshot = await this.lifecycle.lock(tx, message);
    if (snapshot === null) throw entryNotFound();
    const entry = await this.writes.lockEntry(tx, scope, ref);
    return { ref: message, snapshot, entry };
  }

  checkVersion(entry: EntryRow, expected: number | undefined): void {
    if (expected !== undefined && expected !== entry.rowVersion) {
      throw versionConflict(entry.rowVersion);
    }
  }

  /** Q3 transition (refused → `409 quarantine_state_conflict`) and the CAS update. */
  async move(
    tx: Tx,
    scope: TenantScope,
    entry: EntryRow,
    to: QuarantineState,
    cause: EntryTransitionCause,
    now: Date,
    extra: Omit<EntryUpdate, 'state' | 'stateChangedAt'> = {},
  ): Promise<EntryRow> {
    const decision = decideEntryTransition(entry.state, to, cause);
    if (!decision.ok) throw stateConflict(entry.state, decision.reason);
    const ok = await this.writes.updateEntry(tx, scope, entry, {
      state: to,
      stateChangedAt: now,
      ...extra,
    });
    if (!ok) throw versionConflict(entry.rowVersion);
    return {
      ...entry,
      state: to,
      stateChangedAt: now,
      rowVersion: entry.rowVersion + 1,
      ...(extra.kind !== undefined && { kind: extra.kind }),
      ...(extra.approvalRequestId !== undefined && { approvalRequestId: extra.approvalRequestId }),
    };
  }

  action(
    tx: Tx,
    scope: TenantScope,
    principal: Principal,
    entry: Pick<EntryRow, 'id' | 'publicId'>,
    action: QuarantineActionType,
    fields: {
      reason?: string | null;
      result?: string | null;
      details?: Prisma.InputJsonValue | null;
      approvalRequestId?: bigint | null;
      keyHash?: string | null;
    } = {},
  ): Promise<bigint> {
    const actor = actorOf(principal);
    return this.writes.insertAction(tx, {
      organizationId: scope.organizationId,
      quarantineMessageId: entry.id,
      action,
      ...actor,
      reason: fields.reason ?? null,
      result: fields.result ?? null,
      details: fields.details ?? null,
      approvalRequestId: fields.approvalRequestId ?? null,
      idempotencyKey: actionKey(fields.keyHash ?? null, entry.publicId, action),
    });
  }

  /**
   * After an entry ended `rejected`/`deleted` (Q5, Q16, Q17): when no entry of the message is
   * non-terminal any more and no recipient is `pending`, `deferred` or `delivered`, the message
   * leaves `quarantined` (E17 `quarantine_deleted`) or `held_for_review` (E18 `review_rejected`).
   */
  async finishMessage(
    tx: Tx,
    scope: TenantScope,
    locked: LockedEntry,
    principal: Principal,
    operation: string,
    correlationId: string,
  ): Promise<'E17' | 'E18' | null> {
    const { snapshot, ref } = locked;
    if (snapshot.state !== 'quarantined' && snapshot.state !== 'held_for_review') return null;
    const entries = await this.writes.entriesOfMessage(tx, scope, ref);
    if (entries.some((e) => !isTerminalState(e.state))) return null;
    const recipients = await this.writes.recipients(tx, scope, ref);
    if (recipients.some((r) => RECIPIENT_BLOCKS_FINAL.has(r.status))) return null;
    const edge = snapshot.state === 'quarantined' ? 'E17' : 'E18';
    const actor: TransitionActor = {
      role: 'quarantine',
      service: QUARANTINE_SERVICE,
      type: principal.kind,
      id: actorOf(principal).actorId,
    };
    const outcome = await this.lifecycle.transition(tx, {
      message: ref,
      to: 'rejected',
      reason: edge === 'E17' ? 'quarantine_deleted' : 'review_rejected',
      actor,
      transitionKey: `api:quarantine:${scope.organizationId.toString()}:${operation}:${locked.entry.publicId}:${locked.entry.rowVersion}`,
      correlationId,
      expectedFrom: [snapshot.state],
      expectedVersion: snapshot.version,
      recordIgnored: false,
    });
    if (outcome.result !== 'applied') {
      this.logger.warn({
        message: 'quarantine finishing transition not applied',
        result: outcome.result,
        edge,
      });
      throw stateConflict(locked.entry.state, `message_${outcome.result}`);
    }
    return edge;
  }

  /**
   * Queues a release for the executor (Q13.1, Q14): the entry → `releasing`, its action row
   * (`release_queued`, `self_release` or `approve_release`), a `pending` release log with the
   * pre-check, and `mail.quarantine.release_requested.v1` in the outbox.
   */
  async queueRelease(
    tx: Tx,
    input: {
      scope: TenantScope;
      principal: Principal;
      locked: LockedEntry;
      entry: EntryRow;
      mode: QuarantineReleaseMode;
      cause: 'release_queued' | 'approval_granted';
      approval: { id: bigint; publicId: string } | null;
      precheck: Prisma.InputJsonValue;
      reason: string;
      keyHash: string | null;
      now: Date;
      correlationId: string;
    },
  ): Promise<{ releaseId: string; entry: EntryRow }> {
    const { scope, principal, now } = input;
    const moved = await this.move(tx, scope, input.entry, 'releasing', input.cause, now, {
      approvalRequestId: input.approval?.id ?? input.entry.approvalRequestId,
    });
    const action = actionTypeFor(input.cause, { selfRelease: input.mode === 'self' });
    const actionId = await this.action(tx, scope, principal, moved, action, {
      reason: input.reason,
      result: 'queued',
      details: { mode: input.mode },
      approvalRequestId: input.approval?.id ?? null,
      keyHash: input.keyHash,
    });
    const releaseId = uuidv7(now.getTime());
    const actor = actorOf(principal);
    await this.writes.insertReleaseLog(tx, {
      organizationId: scope.organizationId,
      quarantineMessageId: moved.id,
      actionId,
      releasePublicId: releaseId,
      mode: input.mode,
      approvalRequestId: input.approval?.id ?? null,
      requestedByType: actor.actorType,
      requestedById: actor.actorId,
      releasedTo: moved.recipientAddress,
      precheck: input.precheck,
    });
    const payload = quarantineReleaseRequestedV1.parse({
      releaseId,
      messageId: input.locked.ref.id.toString(),
      receivedAt: input.locked.ref.receivedAt.toISOString(),
      entryIds: [moved.publicId],
      mode: input.mode,
      approvalRequestId: input.approval?.publicId ?? null,
      requestedBy: { type: actor.actorType, id: actor.actorId },
      requestedAt: now.toISOString(),
    });
    await this.writes.insertOutbox(tx, {
      eventId: uuidv7(now.getTime()),
      organizationId: scope.organizationId,
      eventType: EventTypes.QuarantineReleaseRequested,
      aggregateType: 'message',
      aggregateId: input.locked.ref.id.toString(),
      correlationId: input.correlationId,
      payload,
    });
    return { releaseId, entry: moved };
  }

  /** One `mail.quarantine.notification_requested.v1` (aggregate `quarantine`, the organization). */
  async notify(
    tx: Tx,
    scope: TenantScope,
    notification: Omit<QuarantineNotificationRequestedV1, 'requestedAt'>,
    now: Date,
    correlationId: string,
  ): Promise<void> {
    const payload = quarantineNotificationRequestedV1.parse({
      ...notification,
      requestedAt: now.toISOString(),
    });
    await this.writes.insertOutbox(tx, {
      eventId: uuidv7(now.getTime()),
      organizationId: scope.organizationId,
      eventType: EventTypes.QuarantineNotificationRequested,
      aggregateType: 'quarantine',
      aggregateId: scope.organizationId.toString(),
      correlationId,
      payload: payload,
    });
  }

  /** The recipient of a rejected/deleted entry is discarded (Q5, Q16, Q17). */
  discardRecipient(tx: Tx, scope: TenantScope, locked: LockedEntry): Promise<number> {
    return this.writes.setRecipientStatus(
      tx,
      scope,
      locked.ref,
      locked.entry.rcptSeq,
      ['quarantined'],
      'discarded',
    );
  }
}
