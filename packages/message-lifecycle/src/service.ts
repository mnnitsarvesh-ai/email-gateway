import { uuidv7 } from '@email-gateway/common';
import type {
  MessageDirection,
  Prisma,
  PrismaClient,
  RecipientStatus,
} from '@email-gateway/database';
import { EventTypes, messageStateChangedV1 } from '@email-gateway/event-contracts';
import { decideTransition, type InvalidReason, type StaleReason } from './decide';
import {
  deriveDeliveryState,
  type DerivedDeliveryState,
  type RecipientStatusCounts,
} from './derive';
import {
  isRetryableLifecycleError,
  LifecycleContractError,
  LifecycleVersionConflictError,
} from './errors';
import { toStateChangedPayload } from './events';
import { transitionKeyHash } from './keys';
import { noopLifecycleMetrics, type LifecycleMetrics } from './metrics';
import { isActorRole, isMessageState, type ActorRole, type MessageState } from './states';
import { isLifecycleReasonCode, type LifecycleReasonCode } from './transitions';

/**
 * The transition service (step 3.3 L5): the only writer of `email_messages.status`,
 * `status_changed_at`, `version`, `lifecycle_round`, `status_reason` and of
 * `email_message_status_history` after creation (one-door rule, L5.9). Writer only (ADR-0014).
 *
 * Lock order (L5.4, the step 2.3 order): `delivery_reinjections` row (queue-id binding only) →
 * `email_messages` row → `email_deliveries` rows → recipients. Re-locking the message row in the
 * same transaction is free.
 */

export interface TransitionActor {
  role: ActorRole;
  /** Deployable, e.g. 'smtp-adapter', 'delivery-worker', 'api', 'event-relay'. */
  service: string;
  type: 'system' | 'user' | 'api_key';
  /** Public id of the user or API key (operator); null for system actors. */
  id?: string | null;
}

/** The message a request addresses: partition key and the tenant from trusted context. */
export interface MessageRef {
  id: bigint;
  receivedAt: Date;
  organizationId: bigint;
}

export interface TransitionRequest {
  message: MessageRef;
  to: MessageState;
  reason: LifecycleReasonCode;
  actor: TransitionActor;
  /** Idempotency key (L5.3); hashed with SHA-256 into history.transition_key. */
  transitionKey: string;
  /** history.event_id (UUID of the causing event). */
  causationEventId?: string | null;
  /** history.correlation_id, outbox correlation_id (default `message:<id>`). */
  correlationId?: string | null;
  /** history.occurred_at (default: now). Recorded, never compared. */
  occurredAt?: Date;
  expectedRound?: number;
  expectedVersion?: number;
  expectedFrom?: readonly MessageState[];
  /** Record stale/invalid outcomes as email_events `lifecycle.ignored` (default true; the api passes false). */
  recordIgnored?: boolean;
}

export interface LifecycleSnapshot {
  state: MessageState;
  version: number;
  round: number;
  statusChangedAt: Date;
  statusReason: string | null;
  direction: MessageDirection;
  emlObjectKey: string;
}

export type TransitionOutcome =
  | {
      result: 'applied';
      from: MessageState;
      to: MessageState;
      version: number;
      round: number;
      historyId: bigint;
      stateEventId: string;
      snapshot: LifecycleSnapshot;
    }
  | { result: 'duplicate'; why: 'transition_key' | 'same_state'; snapshot: LifecycleSnapshot }
  | { result: 'stale'; why: StaleReason; snapshot: LifecycleSnapshot }
  | { result: 'invalid'; why: InvalidReason; snapshot: LifecycleSnapshot }
  | { result: 'not_found' };

/** pino's `Logger` satisfies it. Details carry ids and codes only. */
export interface LifecycleLogger {
  warn(details: Record<string, unknown>, message: string): void;
  debug?(details: Record<string, unknown>, message: string): void;
}

export interface TransitionDeps {
  metrics?: LifecycleMetrics;
  logger?: LifecycleLogger;
  now?: () => Date;
}

export interface RetryDeps extends TransitionDeps {
  /** Backoff sleep (tests inject a fake). */
  sleep?: (ms: number) => Promise<void>;
  random?: () => number;
}

const ACTOR_TYPES: ReadonlySet<string> = new Set(['system', 'user', 'api_key']);
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const SERVICE = /^[a-z0-9][a-z0-9._-]{0,63}$/i;
const MAX_ROUND = 65_535;
const MAX_ACTOR_ID = 64;
const MAX_CORRELATION_ID = 128;
const BACKOFF_BASE_MS = 20;
const BACKOFF_MAX_MS = 500;
const DEFAULT_MAX_ATTEMPTS = 5;

interface LifecycleRow {
  id: bigint;
  received_at: Date;
  organization_id: bigint;
  status: string;
  version: number | bigint;
  lifecycle_round: number | bigint;
  status_changed_at: Date;
  status_reason: string | null;
  direction: MessageDirection;
  eml_object_key: string;
}

function validateRequest(request: TransitionRequest): string {
  const { message, actor } = request;
  if (typeof message?.id !== 'bigint' || typeof message.organizationId !== 'bigint') {
    throw new LifecycleContractError('message', 'id and organizationId must be bigint');
  }
  if (!(message.receivedAt instanceof Date) || Number.isNaN(message.receivedAt.getTime())) {
    throw new LifecycleContractError('message.receivedAt', 'must be a valid Date');
  }
  if (!isMessageState(request.to)) throw new LifecycleContractError('to', 'unknown state');
  if (!isLifecycleReasonCode(request.reason)) {
    throw new LifecycleContractError('reason', 'unknown reason code');
  }
  if (!isActorRole(actor?.role)) throw new LifecycleContractError('actor.role', 'unknown role');
  if (!ACTOR_TYPES.has(actor.type)) throw new LifecycleContractError('actor.type', 'unknown type');
  if (typeof actor.service !== 'string' || !SERVICE.test(actor.service)) {
    throw new LifecycleContractError('actor.service', 'must be a service name of 1-64 characters');
  }
  if (
    actor.id !== undefined &&
    actor.id !== null &&
    (typeof actor.id !== 'string' || actor.id.length === 0 || actor.id.length > MAX_ACTOR_ID)
  ) {
    throw new LifecycleContractError('actor.id', `must be 1-${MAX_ACTOR_ID} characters or null`);
  }
  if (
    request.causationEventId !== undefined &&
    request.causationEventId !== null &&
    !UUID.test(request.causationEventId)
  ) {
    throw new LifecycleContractError('causationEventId', 'must be a UUID or null');
  }
  if (
    request.correlationId !== undefined &&
    request.correlationId !== null &&
    (typeof request.correlationId !== 'string' ||
      request.correlationId.length === 0 ||
      request.correlationId.length > MAX_CORRELATION_ID)
  ) {
    throw new LifecycleContractError(
      'correlationId',
      `must be 1-${MAX_CORRELATION_ID} characters or null`,
    );
  }
  if (
    request.occurredAt !== undefined &&
    (!(request.occurredAt instanceof Date) || Number.isNaN(request.occurredAt.getTime()))
  ) {
    throw new LifecycleContractError('occurredAt', 'must be a valid Date');
  }
  if (
    request.expectedRound !== undefined &&
    (!Number.isInteger(request.expectedRound) ||
      request.expectedRound < 0 ||
      request.expectedRound > MAX_ROUND)
  ) {
    throw new LifecycleContractError('expectedRound', `must be an integer 0-${MAX_ROUND}`);
  }
  if (
    request.expectedVersion !== undefined &&
    (!Number.isSafeInteger(request.expectedVersion) || request.expectedVersion < 0)
  ) {
    throw new LifecycleContractError('expectedVersion', 'must be a non-negative integer');
  }
  if (request.expectedFrom !== undefined && !request.expectedFrom.every(isMessageState)) {
    throw new LifecycleContractError('expectedFrom', 'contains an unknown state');
  }
  return transitionKeyHash(request.transitionKey);
}

const toSnapshot = (row: LifecycleRow): LifecycleSnapshot => {
  if (!isMessageState(row.status)) {
    throw new LifecycleContractError('email_messages.status', 'unknown stored state');
  }
  return {
    state: row.status,
    version: Number(row.version),
    round: Number(row.lifecycle_round),
    statusChangedAt: row.status_changed_at,
    statusReason: row.status_reason,
    direction: row.direction,
    emlObjectKey: row.eml_object_key,
  };
};

/**
 * Locks the message row (`SELECT … FOR UPDATE` on `(id, received_at)`) and returns its
 * lifecycle, or `null` when there is no row or it belongs to another organization (a tenant
 * mismatch is never "found"). The planner and the lifecycle check take the message lock with it
 * before their own work (L8.4, L14).
 */
export async function lockLifecycle(
  tx: Prisma.TransactionClient,
  message: MessageRef,
): Promise<LifecycleSnapshot | null> {
  const rows = await tx.$queryRaw<LifecycleRow[]>`
    SELECT id, received_at, organization_id, status, version, lifecycle_round, status_changed_at,
           status_reason, direction, eml_object_key
    FROM email_messages
    WHERE id = ${message.id} AND received_at = ${message.receivedAt}
    FOR UPDATE`;
  const row = rows[0];
  if (!row || BigInt(row.organization_id) !== message.organizationId) return null;
  return toSnapshot(row);
}

/**
 * Applies one transition request in the caller's writer transaction (step 3.3 L5.1):
 *
 * 1. lock the message row (`not_found` for no row or another organization: nothing written);
 * 2. the transition key: a history row with its SHA-256 → `duplicate/transition_key`;
 * 3. `decideTransition` (L4): not `apply` → a stale/invalid outcome writes one email_events
 *    `lifecycle.ignored` row unless `recordIgnored === false`, invalid is logged at warn;
 * 4. compare-and-set `UPDATE … WHERE version = ?` (no row → LifecycleVersionConflictError);
 * 5. the history row (every column; a P2002 on the transition key propagates, the retry answers
 *    `duplicate`);
 * 6. the email_events row `lifecycle.<to>`;
 * 7. the `mail.message.state_changed.v1` outbox row (validated with the schema, UUIDv7 id).
 *
 * Never retries inside the caller's transaction: errors propagate and the caller re-runs
 * everything. Throws LifecycleContractError for a malformed request (never retried).
 */
export async function transitionMessage(
  tx: Prisma.TransactionClient,
  request: TransitionRequest,
  deps: TransitionDeps = {},
): Promise<TransitionOutcome> {
  const keyHash = validateRequest(request);
  const metrics = deps.metrics ?? noopLifecycleMetrics;
  const { message } = request;

  // 1.
  const snapshot = await lockLifecycle(tx, message);
  if (!snapshot) return { result: 'not_found' };

  // 2.
  const known = await tx.$queryRaw<{ id: bigint }[]>`
    SELECT id FROM email_message_status_history
    WHERE message_id = ${message.id} AND received_at = ${message.receivedAt}
      AND transition_key = ${keyHash}
    LIMIT 1`;
  if (known.length > 0) {
    metrics.transition(snapshot.state, request.to, 'duplicate');
    return { result: 'duplicate', why: 'transition_key', snapshot };
  }

  // 3.
  const decision = decideTransition(
    { state: snapshot.state, version: snapshot.version, round: snapshot.round },
    request,
  );
  const ids = {
    messageId: message.id.toString(),
    organizationId: message.organizationId.toString(),
    from: snapshot.state,
    to: request.to,
    version: snapshot.version,
    round: snapshot.round,
    actorRole: request.actor.role,
    actorService: request.actor.service,
    causationEventId: request.causationEventId ?? null,
  };
  if (decision.result === 'duplicate') {
    metrics.transition(snapshot.state, request.to, 'duplicate');
    return { result: 'duplicate', why: decision.why, snapshot };
  }
  if (decision.result === 'stale' || decision.result === 'invalid') {
    metrics.transition(snapshot.state, request.to, decision.result);
    metrics.ignored(decision.why);
    if (request.recordIgnored !== false) {
      await tx.emailEvent.create({
        data: {
          receivedAt: message.receivedAt,
          messageId: message.id,
          organizationId: message.organizationId,
          eventType: 'lifecycle.ignored',
          occurredAt: (deps.now ?? (() => new Date()))(),
          sourceService: request.actor.service,
          eventId: request.causationEventId ?? null,
          actorType: request.actor.type,
          actorId: request.actor.id ?? null,
          details: {
            requested: request.to,
            current: snapshot.state,
            result: decision.result,
            why: decision.why,
            version: snapshot.version,
            round: snapshot.round,
            expectedRound: request.expectedRound ?? null,
            expectedVersion: request.expectedVersion ?? null,
            reason: request.reason,
            actorRole: request.actor.role,
          },
        },
        select: { id: true },
      });
    }
    if (decision.result === 'invalid') {
      deps.logger?.warn(
        { ...ids, result: decision.result, why: decision.why },
        'invalid lifecycle transition ignored',
      );
    } else {
      deps.logger?.debug?.(
        { ...ids, result: decision.result, why: decision.why },
        'stale lifecycle transition ignored',
      );
    }
    return decision.result === 'stale'
      ? { result: 'stale', why: decision.why, snapshot }
      : { result: 'invalid', why: decision.why, snapshot };
  }

  // 4.
  const changedAt = (deps.now ?? (() => new Date()))();
  const occurredAt = request.occurredAt ?? changedAt;
  const version = snapshot.version + 1;
  const round = decision.nextRound;
  const affected = await tx.$executeRaw`
    UPDATE email_messages
    SET status = ${request.to}, version = version + 1, lifecycle_round = ${round},
        status_reason = ${request.reason}, status_changed_at = ${changedAt},
        updated_at = ${changedAt}
    WHERE id = ${message.id} AND received_at = ${message.receivedAt}
      AND version = ${snapshot.version}`;
  if (affected !== 1) throw new LifecycleVersionConflictError(message.id);

  // 5.
  const stateEventId = uuidv7(changedAt.getTime());
  const history = await tx.emailMessageStatusHistory.create({
    data: {
      receivedAt: message.receivedAt,
      messageId: message.id,
      organizationId: message.organizationId,
      version,
      fromStatus: snapshot.state,
      toStatus: request.to,
      reasonCode: request.reason,
      lifecycleRound: round,
      actorRole: request.actor.role,
      actorService: request.actor.service,
      actorType: request.actor.type,
      actorId: request.actor.id ?? null,
      eventId: request.causationEventId ?? null,
      correlationId: request.correlationId ?? null,
      transitionKey: keyHash,
      stateEventId,
      occurredAt,
      changedAt,
    },
    select: { id: true },
  });

  // 6.
  await tx.emailEvent.create({
    data: {
      receivedAt: message.receivedAt,
      messageId: message.id,
      organizationId: message.organizationId,
      eventType: `lifecycle.${request.to}`,
      occurredAt: changedAt,
      sourceService: request.actor.service,
      eventId: request.causationEventId ?? null,
      actorType: request.actor.type,
      actorId: request.actor.id ?? null,
      details: {
        from: snapshot.state,
        to: request.to,
        version,
        round,
        reason: request.reason,
        actorRole: request.actor.role,
      },
    },
    select: { id: true },
  });

  // 7.
  const parsed = messageStateChangedV1.safeParse(
    toStateChangedPayload({
      messageId: message.id,
      receivedAt: message.receivedAt,
      direction: snapshot.direction,
      previousState: snapshot.state,
      state: request.to,
      version,
      round,
      reasonCode: request.reason,
      actor: request.actor,
      causationEventId: request.causationEventId ?? null,
      changedAt,
    }),
  );
  if (!parsed.success) {
    throw new LifecycleContractError('state_changed', 'payload does not match the event schema');
  }
  await tx.messageOutbox.create({
    data: {
      eventId: stateEventId,
      organizationId: message.organizationId,
      eventType: EventTypes.MessageStateChanged,
      aggregateType: 'message',
      aggregateId: message.id.toString(),
      correlationId: request.correlationId ?? `message:${message.id.toString()}`,
      payload: parsed.data,
    },
    select: { id: true },
  });

  // 8.
  metrics.transition(snapshot.state, request.to, 'applied');
  deps.logger?.debug?.(
    { ...ids, result: 'applied', version, round },
    'lifecycle transition applied',
  );
  return {
    result: 'applied',
    from: snapshot.state,
    to: request.to,
    version,
    round,
    historyId: history.id,
    stateEventId,
    snapshot: {
      ...snapshot,
      state: request.to,
      version,
      round,
      statusChangedAt: changedAt,
      statusReason: request.reason,
    },
  };
}

/** Equal-jitter backoff (base 20 ms, max 500 ms) before retry `attempt` (1-based). */
export function retryDelayMs(attempt: number, random: () => number = Math.random): number {
  const exponent = Math.min(Math.max(attempt, 1) - 1, 16);
  const d = Math.min(BACKOFF_MAX_MS, BACKOFF_BASE_MS * 2 ** exponent);
  const r = Math.min(Math.max(random(), 0), 1);
  return Math.floor(d / 2 + (r * d) / 2);
}

const defaultSleep = (ms: number) => new Promise<void>((resolve) => setTimeout(resolve, ms));

/**
 * `transitionMessage` in its own writer transaction (`timeoutMs` = timeout and maxWait), retried
 * on deadlock (1213), lock wait timeout (1205), P2034, LifecycleVersionConflictError and a P2002
 * on the transition key (the re-run answers `duplicate`), with equal-jitter backoff, at most
 * `maxAttempts` (default 5); then rethrows. Every retry counts
 * `lifecycle_version_conflicts_total`.
 */
export async function transitionMessageWithRetry(
  prisma: PrismaClient,
  request: TransitionRequest,
  options: { timeoutMs: number; maxAttempts?: number },
  deps: RetryDeps = {},
): Promise<TransitionOutcome> {
  validateRequest(request);
  const maxAttempts = options.maxAttempts ?? DEFAULT_MAX_ATTEMPTS;
  if (!Number.isInteger(maxAttempts) || maxAttempts < 1) {
    throw new LifecycleContractError('maxAttempts', 'must be a positive integer');
  }
  const metrics = deps.metrics ?? noopLifecycleMetrics;
  const sleep = deps.sleep ?? defaultSleep;
  for (let attempt = 1; ; attempt += 1) {
    try {
      return await prisma.$transaction((tx) => transitionMessage(tx, request, deps), {
        timeout: options.timeoutMs,
        maxWait: options.timeoutMs,
      });
    } catch (error) {
      if (attempt >= maxAttempts || !isRetryableLifecycleError(error)) throw error;
      metrics.versionConflict();
      await sleep(retryDelayMs(attempt, deps.random));
    }
  }
}

export interface DerivedStateContext {
  /** `delivery` (recorder) or `recovery` (lifecycle check). */
  actor: TransitionActor;
  /**
   * The transition key for the derived target, e.g. `signal:<deliveryId>:<signalKey>:<state>`
   * (recorder) or `recover:<id>:<version>:<state>` (lifecycle check, L5.3).
   */
  transitionKey: (derived: DerivedDeliveryState, current: LifecycleSnapshot) => string;
  causationEventId?: string | null;
  correlationId?: string | null;
  occurredAt?: Date;
  /** Default true (asynchronous producers). */
  recordIgnored?: boolean;
}

export type DerivedStateOutcome =
  | { result: 'not_found' }
  /** Not in the delivery phase: nothing written, `lifecycle_derived_skipped_total{state}`. */
  | { result: 'skipped'; state: MessageState; snapshot: LifecycleSnapshot }
  /** The derived state is the current one (or there are no recipients). */
  | {
      result: 'unchanged';
      derived: DerivedDeliveryState | null;
      snapshot: LifecycleSnapshot;
    }
  | { result: 'transition'; derived: DerivedDeliveryState; outcome: TransitionOutcome };

const DELIVERY_PHASE: readonly MessageState[] = ['delivery_pending', 'delivery_retry'];

/**
 * The derived message state in the delivery phase (step 3.3 L9), in the caller's transaction:
 * locks the message (free when the caller holds it), counts `email_recipients.status`
 * (`GROUP BY`), derives, and transitions when the derived state differs from the current one and
 * the message is `delivery_pending` or `delivery_retry`. From any other state nothing happens
 * (a late per-recipient signal after expiry or a manual state is normal; counted as
 * `lifecycle_derived_skipped_total{state}`).
 */
export async function applyDerivedDeliveryState(
  tx: Prisma.TransactionClient,
  message: MessageRef,
  ctx: DerivedStateContext,
  deps: TransitionDeps = {},
): Promise<DerivedStateOutcome> {
  const snapshot = await lockLifecycle(tx, message);
  if (!snapshot) return { result: 'not_found' };
  if (!DELIVERY_PHASE.includes(snapshot.state)) {
    (deps.metrics ?? noopLifecycleMetrics).derivedSkipped(snapshot.state);
    return { result: 'skipped', state: snapshot.state, snapshot };
  }
  const rows = await tx.$queryRaw<{ status: RecipientStatus; n: bigint | number }[]>`
    SELECT status, COUNT(*) AS n FROM email_recipients
    WHERE message_id = ${message.id} AND received_at = ${message.receivedAt}
    GROUP BY status`;
  const counts: RecipientStatusCounts = {};
  for (const row of rows) counts[row.status] = Number(row.n);
  const derived = deriveDeliveryState(counts);
  if (derived === null || derived.state === snapshot.state) {
    return { result: 'unchanged', derived, snapshot };
  }
  const outcome = await transitionMessage(
    tx,
    {
      message,
      to: derived.state,
      reason: derived.reason,
      actor: ctx.actor,
      transitionKey: ctx.transitionKey(derived, snapshot),
      ...(ctx.causationEventId !== undefined ? { causationEventId: ctx.causationEventId } : {}),
      ...(ctx.correlationId !== undefined ? { correlationId: ctx.correlationId } : {}),
      ...(ctx.occurredAt !== undefined ? { occurredAt: ctx.occurredAt } : {}),
      ...(ctx.recordIgnored !== undefined ? { recordIgnored: ctx.recordIgnored } : {}),
    },
    deps,
  );
  return { result: 'transition', derived, outcome };
}
