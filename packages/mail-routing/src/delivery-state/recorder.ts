import { randomUUID } from 'node:crypto';
import { Prisma, type PrismaClient } from '@email-gateway/database';
import { deliveryStatusChangedV1, EventTypes } from '@email-gateway/event-contracts';
import {
  applyDerivedDeliveryState,
  isRetryableLifecycleError,
  type LifecycleMetrics,
  type MessageState,
} from '@email-gateway/message-lifecycle';
import { parseReinjectionToken } from '../reinjection-key';
import type { DeliverySignal } from './signals';
import {
  mapRecipientStatus,
  nextDeliveryState,
  type DeliveryStatus,
  type TransitionResult,
} from './transitions';

/**
 * The shared delivery status recorder (step 2.3 R9.1), used by the delivery-worker (planner,
 * reinjection, Postfix log tailer, reconciler) and the smtp-adapter (bounce notices). Writer
 * only (ADR-0014).
 *
 * Lock order, identical in every writer of delivery state so concurrent signals never deadlock:
 * `delivery_reinjections` row (queue-id binding only) → `email_messages` row → `email_deliveries`
 * row(s). Locking the message first serializes the signals of one message, so the derived
 * message state (step 3.3 L9) always sees the latest committed status of every recipient. The
 * message lifecycle columns are written only through @email-gateway/message-lifecycle
 * (`applyDerivedDeliveryState`, one-door rule, ADR-0025).
 */

type Db = PrismaClient | Prisma.TransactionClient;

export interface RecorderLogger {
  warn(details: Record<string, unknown>, message: string): void;
}

export interface RecorderContext {
  /** `email_events.source_service`, e.g. `delivery-worker`, `smtp-adapter`. */
  sourceService: string;
  /** Interactive transaction timeout (and maxWait) when the recorder opens its own transaction. */
  timeoutMs: number;
  /** Envelope event id (UUID) that caused the signal (`email_events.event_id`, status history). */
  eventId?: string | null;
  /** Receives conflicts (ids and statuses only, never addresses). */
  logger?: RecorderLogger;
  /** The deployable's lifecycle series (`lifecycle_transitions_total`, …); none when absent. */
  lifecycleMetrics?: LifecycleMetrics;
}

export type RecordResult = TransitionResult | 'unmatched';

export interface RecordDeliverySignalResult {
  result: RecordResult;
  deliveryId?: bigint;
  receivedAt?: Date;
  messageId?: bigint;
  organizationId?: bigint;
  /** Status after the signal (unchanged unless applied). */
  status?: DeliveryStatus;
  previousStatus?: DeliveryStatus | null;
  /** Set when the signal moved the message to a new derived lifecycle state (step 3.3 L9). */
  messageState?: MessageState;
}

const MAX_TX_ATTEMPTS = 3;
const MAX_DETAIL = 1024;
const MAX_RESPONSE = 512;
const MAX_SMALLINT = 65_535;
const QUEUE_ID = /^[A-Za-z0-9]{1,32}$/;
const ENHANCED_STATUS = /^[245]\.\d{1,3}\.\d{1,3}$/;
const ERROR_CLASS = /^[a-z0-9_]{1,32}$/;
const HEX64 = /^[0-9a-f]{64}$/;

/** A full client (it can open transactions); an interactive transaction client cannot. */
const isPrismaClient = (client: Db): client is PrismaClient =>
  typeof (client as Partial<PrismaClient>).$transaction === 'function';

function isRetryable(error: unknown): boolean {
  // The lifecycle's compare-and-set conflict, deadlocks, lock waits, P2034 and a concurrent
  // duplicate transition key (the re-run answers `duplicate`).
  if (isRetryableLifecycleError(error)) return true;
  if (error instanceof Prisma.PrismaClientKnownRequestError) {
    if (error.code === 'P2034') return true;
    // Raw query failures carry the MySQL code: 1213 deadlock, 1205 lock wait timeout.
    if (error.code === 'P2010' && /\b(?:1213|1205)\b|deadlock/i.test(error.message)) return true;
  }
  return false;
}

/**
 * Runs `fn` in the caller's transaction, or in an own writer transaction retried up to 3 times
 * on a lifecycle version conflict, a deadlock or a write conflict.
 */
async function inTransaction<T>(
  client: Db,
  timeoutMs: number,
  fn: (tx: Prisma.TransactionClient) => Promise<T>,
): Promise<T> {
  if (!isPrismaClient(client)) return fn(client);
  for (let attempt = 1; ; attempt += 1) {
    try {
      return await client.$transaction(fn, { timeout: timeoutMs, maxWait: timeoutMs });
    } catch (error) {
      if (attempt >= MAX_TX_ATTEMPTS || !isRetryable(error)) throw error;
    }
  }
}

interface MessageRow {
  id: bigint;
  received_at: Date;
  organization_id: bigint;
  direction: 'inbound' | 'outbound' | 'internal';
}

interface DeliveryRow {
  id: bigint;
  received_at: Date;
  message_id: bigint;
  recipient_id: bigint;
  organization_id: bigint;
  delivery_seq: number;
  status: DeliveryStatus;
  attempt_count: number;
  last_signal_at: Date | null;
  outbound_queue_id: string | null;
  dsn_queue_id: string | null;
  direction: 'inbound' | 'outbound' | 'internal' | null;
}

async function lockMessage(
  tx: Prisma.TransactionClient,
  id: bigint,
  receivedAt: Date,
): Promise<MessageRow | null> {
  const rows = await tx.$queryRaw<MessageRow[]>`
    SELECT id, received_at, organization_id, direction
    FROM email_messages WHERE id = ${id} AND received_at = ${receivedAt} FOR UPDATE`;
  return rows[0] ?? null;
}

async function lockDelivery(
  tx: Prisma.TransactionClient,
  id: bigint,
  receivedAt: Date,
): Promise<DeliveryRow | null> {
  const rows = await tx.$queryRaw<DeliveryRow[]>`
    SELECT id, received_at, message_id, recipient_id, organization_id, delivery_seq, status,
           attempt_count, last_signal_at, outbound_queue_id, dsn_queue_id, direction
    FROM email_deliveries WHERE id = ${id} AND received_at = ${receivedAt} FOR UPDATE`;
  const row = rows[0];
  return row
    ? { ...row, delivery_seq: Number(row.delivery_seq), attempt_count: Number(row.attempt_count) }
    : null;
}

interface DeliveryRef {
  id: bigint;
  receivedAt: Date;
  messageId: bigint;
}

/** The delivery among `candidates` whose recipient address equals `address` (case-insensitive). */
async function pickByAddress(
  tx: Prisma.TransactionClient,
  candidates: readonly (DeliveryRef & { recipientId: bigint; deliverySeq: number })[],
  address: string,
): Promise<DeliveryRef | null> {
  if (candidates.length === 0) return null;
  const recipients = await tx.emailRecipient.findMany({
    where: { OR: candidates.map((c) => ({ id: c.recipientId, receivedAt: c.receivedAt })) },
    select: { id: true, receivedAt: true, address: true },
  });
  const wanted = address.toLowerCase();
  const matching = new Set(
    recipients
      .filter((r) => r.address.toLowerCase() === wanted)
      .map((r) => `${r.id.toString()}|${r.receivedAt.getTime()}`),
  );
  const hits = candidates
    .filter((c) => matching.has(`${c.recipientId.toString()}|${c.receivedAt.getTime()}`))
    .sort((a, b) => b.deliverySeq - a.deliverySeq || (a.id < b.id ? 1 : -1));
  return hits[0] ?? null;
}

const DELIVERY_REF_SELECT = {
  id: true,
  receivedAt: true,
  messageId: true,
  recipientId: true,
  deliverySeq: true,
} as const;

/** R9.1 step 1: by (deliveryId, receivedAt), (queueId, address) or (token, address). */
async function resolveDelivery(
  tx: Prisma.TransactionClient,
  match: DeliverySignal['match'],
): Promise<DeliveryRef | null> {
  if ('deliveryId' in match) {
    return tx.emailDelivery.findUnique({
      where: { id_receivedAt: { id: match.deliveryId, receivedAt: match.receivedAt } },
      select: { id: true, receivedAt: true, messageId: true },
    });
  }
  if ('queueId' in match) {
    if (!QUEUE_ID.test(match.queueId)) return null;
    const candidates = await tx.emailDelivery.findMany({
      where: { outboundQueueId: match.queueId },
      select: DELIVERY_REF_SELECT,
      take: 1000,
    });
    const direct = await pickByAddress(tx, candidates, match.address);
    if (direct) return direct;
    // A recipient of the reinjection bound to this queue id that no signal has tied to the
    // queue file yet: a delivery-log line naming its address proves postfix-outbound accepted
    // it under this queue id (the binding itself proves nothing per recipient: RCPT may have
    // been refused, and a session can end before the file is committed).
    const reinjection = await tx.deliveryReinjection.findFirst({
      where: { queueId: match.queueId },
      select: { id: true, receivedAt: true },
    });
    if (!reinjection) return null;
    const unbound = await tx.emailDelivery.findMany({
      where: {
        reinjectionId: reinjection.id,
        receivedAt: reinjection.receivedAt,
        outboundQueueId: null,
      },
      select: DELIVERY_REF_SELECT,
      take: 1000,
    });
    return pickByAddress(tx, unbound, match.address);
  }
  const publicId = parseReinjectionToken(match.token);
  if (publicId === null) return null;
  const reinjection = await tx.deliveryReinjection.findFirst({
    where: { publicId },
    select: { id: true, receivedAt: true },
  });
  if (!reinjection) return null;
  const candidates = await tx.emailDelivery.findMany({
    where: { reinjectionId: reinjection.id, receivedAt: reinjection.receivedAt },
    select: DELIVERY_REF_SELECT,
    take: 1000,
  });
  return pickByAddress(tx, candidates, match.address);
}

/**
 * Whether an applied signal sets `final_smtp_code` / `final_smtp_response` / `enhanced_status`
 * (review fix of step 2.3): the delivery log and DSNs (remote results and Postfix's own final
 * outcomes) always; the worker's own hop only when it explains the recipient's state (a 4xx
 * deferral, a refusal, an expiry), never for `queued`: the hop's `250 … queued as` is not the
 * remote server's acceptance and stays in the audit row only. Never the planner or the
 * reconciler. A `queued` recipient therefore never shows a `250` as if it had been delivered.
 */
function reportsFinalResult(source: DeliverySignal['source'], status: DeliveryStatus): boolean {
  if (source === 'postfix_log' || source === 'bounce_notice') return true;
  return source === 'reinjection' && status !== 'queued';
}

const truncate = (text: string | null | undefined, max: number): string | null =>
  text === null || text === undefined ? null : text.slice(0, max);

const validOr = (value: string | null | undefined, pattern: RegExp): string | undefined =>
  value !== null && value !== undefined && pattern.test(value) ? value : undefined;

const smallint = (value: number | null | undefined): number | undefined =>
  value !== null && value !== undefined && Number.isInteger(value) && value >= 0
    ? Math.min(value, MAX_SMALLINT)
    : undefined;

function validateSignal(signal: DeliverySignal): void {
  if (!HEX64.test(signal.signalKey)) throw new Error('signalKey must be a hex SHA-256');
  if (!(signal.occurredAt instanceof Date) || Number.isNaN(signal.occurredAt.getTime())) {
    throw new Error('occurredAt must be a valid Date');
  }
}

/**
 * Records one delivery status signal (R9.1 steps 1–6) in one writer transaction (or inside the
 * caller's, for the planner):
 *
 * 1. resolve the delivery (`unmatched` when none: nothing is written);
 * 2. lock the message row, then the delivery row (`SELECT … FOR UPDATE`);
 * 3. `delivery_status_events` insert-if-new on `(delivery_id, signal_key)`; a known key →
 *    `duplicate`, nothing else happens;
 * 4. decide with nextDeliveryState; the audit row records the decision (`applied`);
 * 5. if applied: `email_deliveries`, a `delivery_attempts` row for a remote attempt
 *    (`attempt_no` = the new attempt count), `email_recipients.status`, an `email_events` row
 *    (`delivery.<status>`, ids only) and the `mail.delivery.status_changed.v1` outbox row (not
 *    for the planner's initial `pending`);
 * 6. when the delivery has the highest `delivery_seq` of the message: the derived message
 *    state (step 3.3 L9, `applyDerivedDeliveryState`): from `delivery_pending` /
 *    `delivery_retry`, the state the recipients imply (`delivery_retry` while one is deferred,
 *    `delivery_pending`, `delivered` with `delivery_complete` / `delivery_partial`, `rejected`
 *    with `delivery_failed`) through the transition service, transition key
 *    `signal:<deliveryId>:<signalKey>:<state>`. A signal of an older `delivery_seq` (a delivery
 *    before a release) or a message outside the delivery phase (expired, quarantined, …)
 *    leaves the message state alone; the per-recipient state is recorded either way.
 *
 * Not-applied signals keep their audit row (`stale`, `conflict`, same-state `duplicate`); a
 * same-state signal still fills a missing `dsn_queue_id` / `outbound_queue_id` (annotation, no
 * transition). Inside a caller's transaction a lifecycle version conflict or deadlock
 * propagates for the caller to retry; in an own transaction it is retried up to 3 times.
 */
export async function recordDeliverySignal(
  client: Db,
  signal: DeliverySignal,
  ctx: RecorderContext,
): Promise<RecordDeliverySignalResult> {
  validateSignal(signal);
  return inTransaction(client, ctx.timeoutMs, async (tx) => {
    const ref = await resolveDelivery(tx, signal.match);
    if (!ref) return { result: 'unmatched' };
    const message = await lockMessage(tx, ref.messageId, ref.receivedAt);
    const delivery = message ? await lockDelivery(tx, ref.id, ref.receivedAt) : null;
    if (!message || !delivery) return { result: 'unmatched' };
    const ids = {
      deliveryId: delivery.id,
      receivedAt: delivery.received_at,
      messageId: delivery.message_id,
      organizationId: delivery.organization_id,
    };

    const known = await tx.deliveryStatusEvent.findUnique({
      where: {
        deliveryId_signalKey_receivedAt: {
          deliveryId: delivery.id,
          signalKey: signal.signalKey,
          receivedAt: delivery.received_at,
        },
      },
      select: { id: true },
    });
    if (known) return { ...ids, result: 'duplicate', status: delivery.status };

    const attempt = signal.attempt;
    const enhancedStatus = signal.enhancedStatus ?? attempt?.enhancedStatus ?? null;
    const smtpCode = signal.smtpCode ?? attempt?.smtpCode ?? null;
    const decision = nextDeliveryState(
      {
        status: delivery.status,
        lastSignalAt: delivery.last_signal_at,
        attemptCount: delivery.attempt_count,
      },
      {
        status: signal.status,
        occurredAt: signal.occurredAt,
        source: signal.source,
        enhancedStatus,
        remoteAttempt: attempt !== undefined,
      },
    );
    const initial =
      signal.source === 'planner' &&
      delivery.status === 'pending' &&
      delivery.last_signal_at === null;
    const previousStatus: DeliveryStatus | null = initial ? null : delivery.status;
    const queueId = validOr(signal.queueId, QUEUE_ID) ?? delivery.outbound_queue_id ?? null;
    const errorClass = validOr(signal.errorClass, ERROR_CLASS) ?? null;

    await tx.deliveryStatusEvent.create({
      data: {
        receivedAt: delivery.received_at,
        deliveryId: delivery.id,
        messageId: delivery.message_id,
        recipientId: delivery.recipient_id,
        organizationId: delivery.organization_id,
        source: signal.source,
        signalKey: signal.signalKey,
        occurredAt: signal.occurredAt,
        fromStatus: previousStatus,
        toStatus: signal.status,
        applied: decision.applied,
        queueId,
        smtpCode: smallint(smtpCode) ?? null,
        enhancedStatus: truncate(enhancedStatus, 16),
        remoteHost: truncate(attempt?.remoteHost, 255),
        errorClass,
        detail: truncate(signal.detail ?? attempt?.response ?? decision.note, MAX_DETAIL),
      },
      select: { id: true },
    });

    const where = { id_receivedAt: { id: delivery.id, receivedAt: delivery.received_at } };
    if (!decision.applied || !decision.next) {
      if (decision.result === 'conflict') {
        ctx.logger?.warn(
          {
            deliveryId: delivery.id.toString(),
            messageId: delivery.message_id.toString(),
            source: signal.source,
            status: delivery.status,
            signalStatus: signal.status,
          },
          'conflicting delivery status signal ignored',
        );
      } else {
        // Annotation: evidence of the same state (e.g. the DSN queue id of a bounced delivery).
        const annotation: Prisma.EmailDeliveryUpdateInput = {};
        const dsnQueueId = validOr(signal.dsnQueueId, QUEUE_ID);
        if (dsnQueueId && delivery.dsn_queue_id === null) annotation.dsnQueueId = dsnQueueId;
        const boundQueueId = validOr(signal.queueId, QUEUE_ID);
        if (boundQueueId && delivery.outbound_queue_id === null) {
          annotation.outboundQueueId = boundQueueId;
        }
        if (Object.keys(annotation).length > 0) {
          await tx.emailDelivery.update({ where, data: annotation, select: { id: true } });
        }
      }
      return { ...ids, result: decision.result, status: delivery.status, previousStatus };
    }

    // R9.1 step 5.
    const next = decision.next;
    const statusChanged = next.status !== delivery.status || initial;
    const data: Prisma.EmailDeliveryUpdateInput = {
      status: next.status,
      lastSignalAt: next.lastSignalAt,
      attemptCount: Math.min(next.attemptCount, MAX_SMALLINT),
    };
    if (statusChanged) data.statusChangedAt = signal.occurredAt;
    if (attempt) {
      data.lastAttemptAt = signal.occurredAt;
      if (attempt.remoteHost) data.remoteHost = truncate(attempt.remoteHost, 255);
    }
    if (next.status === 'delivered') data.deliveredAt = signal.occurredAt;
    if (reportsFinalResult(signal.source, next.status)) {
      // The result fields describe the last remote (or final) SMTP result. A reinjection hop
      // reply (`250 … queued as` of postfix-outbound) is never one: it stays in the audit row.
      // A later result without a code clears an earlier attempt's code instead of keeping it.
      data.finalSmtpCode = smallint(smtpCode) ?? null;
      const response = attempt?.response ?? signal.detail;
      data.finalSmtpResponse = response ? truncate(response, MAX_RESPONSE) : null;
      data.enhancedStatus = enhancedStatus ? truncate(enhancedStatus, 16) : null;
    }
    if (errorClass) data.lastErrorClass = errorClass;
    // Delivered: the earlier deferrals' error class no longer describes the delivery.
    if (next.status === 'delivered') data.lastErrorClass = null;
    if (signal.failureReason) data.failureReason = truncate(signal.failureReason, 64);
    const dsnQueueId = validOr(signal.dsnQueueId, QUEUE_ID);
    if (dsnQueueId) data.dsnQueueId = dsnQueueId;
    const boundQueueId = validOr(signal.queueId, QUEUE_ID);
    if (boundQueueId && delivery.outbound_queue_id === null) data.outboundQueueId = boundQueueId;
    await tx.emailDelivery.update({ where, data, select: { id: true } });

    if (attempt) {
      await tx.deliveryAttempt.create({
        data: {
          receivedAt: delivery.received_at,
          deliveryId: delivery.id,
          messageId: delivery.message_id,
          organizationId: delivery.organization_id,
          attemptNo: Math.min(next.attemptCount, MAX_SMALLINT),
          startedAt: signal.occurredAt,
          completedAt: signal.occurredAt,
          remoteHost: truncate(attempt.remoteHost, 255),
          remoteIp: truncate(attempt.remoteIp, 45),
          smtpCode: smallint(attempt.smtpCode) ?? null,
          enhancedStatus: truncate(attempt.enhancedStatus, 16),
          smtpResponse: truncate(attempt.response, MAX_RESPONSE),
          outcome: attempt.outcome,
          tlsProtocol: truncate(attempt.tlsProtocol, 16),
        },
        select: { id: true },
      });
    }

    const recipient = await tx.emailRecipient.findUnique({
      where: { id_receivedAt: { id: delivery.recipient_id, receivedAt: delivery.received_at } },
      select: { rcptSeq: true, status: true, direction: true },
    });
    const recipientStatus = mapRecipientStatus(next.status);
    if (recipient && recipient.status !== recipientStatus) {
      await tx.emailRecipient.update({
        where: { id_receivedAt: { id: delivery.recipient_id, receivedAt: delivery.received_at } },
        data: { status: recipientStatus },
        select: { id: true },
      });
    }

    const details = {
      deliveryId: delivery.id.toString(),
      rcptSeq: recipient?.rcptSeq ?? null,
      deliverySeq: delivery.delivery_seq,
      source: signal.source,
      queueId,
      smtpCode: smallint(smtpCode) ?? null,
      enhancedStatus: validOr(enhancedStatus, ENHANCED_STATUS) ?? null,
      errorClass,
      failureReason: truncate(signal.failureReason, 64),
    };
    await tx.emailEvent.create({
      data: {
        receivedAt: delivery.received_at,
        messageId: delivery.message_id,
        organizationId: delivery.organization_id,
        eventType: `delivery.${next.status}`,
        occurredAt: signal.occurredAt,
        sourceService: ctx.sourceService,
        eventId: ctx.eventId ?? null,
        details,
      },
      select: { id: true },
    });

    if (next.status !== 'pending') {
      const code = smallint(smtpCode);
      const payload = deliveryStatusChangedV1.parse({
        messageId: delivery.message_id.toString(),
        receivedAt: delivery.received_at.toISOString(),
        deliveryId: delivery.id.toString(),
        recipientId: delivery.recipient_id.toString(),
        rcptSeq: recipient?.rcptSeq ?? 0,
        deliverySeq: delivery.delivery_seq,
        direction: delivery.direction ?? recipient?.direction ?? message.direction,
        previousStatus,
        status: next.status,
        occurredAt: signal.occurredAt.toISOString(),
        attemptCount: next.attemptCount,
        ...(code !== undefined && code >= 200 && code <= 599 ? { smtpCode: code } : {}),
        ...(validOr(enhancedStatus, ENHANCED_STATUS)
          ? { enhancedStatus: validOr(enhancedStatus, ENHANCED_STATUS) }
          : {}),
        ...(errorClass ? { errorClass } : {}),
        ...(queueId ? { queueId } : {}),
      });
      await tx.messageOutbox.create({
        data: {
          eventId: randomUUID(),
          organizationId: delivery.organization_id,
          eventType: EventTypes.DeliveryStatusChanged,
          aggregateType: 'message',
          aggregateId: delivery.message_id.toString(),
          correlationId: `delivery:${delivery.id.toString()}`,
          payload,
        },
        select: { id: true },
      });
    }

    // Step 6 (step 3.3 L9): the derived message state, only for the newest delivery_seq.
    let messageState: MessageState | undefined;
    const newest = await tx.$queryRaw<{ seq: number | bigint | null }[]>`
      SELECT MAX(delivery_seq) AS seq FROM email_deliveries
      WHERE message_id = ${delivery.message_id} AND received_at = ${delivery.received_at}`;
    const newestSeq = newest[0]?.seq;
    if (
      newestSeq === null ||
      newestSeq === undefined ||
      delivery.delivery_seq >= Number(newestSeq)
    ) {
      const derived = await applyDerivedDeliveryState(
        tx,
        {
          id: delivery.message_id,
          receivedAt: delivery.received_at,
          organizationId: delivery.organization_id,
        },
        {
          actor: { role: 'delivery', service: ctx.sourceService, type: 'system' },
          transitionKey: (state) =>
            `signal:${delivery.id.toString()}:${signal.signalKey}:${state.state}`,
          causationEventId: ctx.eventId ?? null,
          correlationId: `delivery:${delivery.id.toString()}`,
          occurredAt: signal.occurredAt,
        },
        {
          ...(ctx.lifecycleMetrics ? { metrics: ctx.lifecycleMetrics } : {}),
          ...(ctx.logger ? { logger: ctx.logger } : {}),
        },
      );
      if (derived.result === 'transition' && derived.outcome.result === 'applied') {
        messageState = derived.outcome.to;
      }
    }

    return {
      ...ids,
      result: 'applied',
      status: next.status,
      previousStatus,
      ...(messageState ? { messageState } : {}),
    };
  });
}

export type BindQueueIdResult =
  | {
      /** `rebound`: an earlier binding of a session Postfix never committed was replaced. */
      result: 'bound' | 'rebound' | 'duplicate';
      reinjectionId: bigint;
      receivedAt: Date;
      messageId: bigint;
      organizationId: bigint;
    }
  | { result: 'conflict'; reinjectionId: bigint; receivedAt: Date; messageId: bigint }
  | { result: 'unmatched' };

/** Reinjection statuses whose binding may still be replaced by a later session's queue id. */
const REBINDABLE = new Set(['pending', 'in_progress']);

/**
 * Binds a postfix-outbound queue id to the reinjection of `token` (the `client=… orig_queue_id=`
 * log line, or the `250 … queued as` reply): sets `delivery_reinjections.queue_id`. Idempotent
 * (`duplicate` for the same queue id).
 *
 * The binding is a **correlation only**, never proof of queueing (review fix of step 2.3):
 * smtpd logs `client=` when it opens the queue file at the first accepted RCPT, before DATA, and
 * Postfix discards that file if the session ends before the final dot is accepted. Therefore:
 *
 * - no delivery is marked here; a recipient is tied to the queue file (`outbound_queue_id`) by
 *   the worker's `queued` signal, by qmgr `queue active` when its recipient count covers the
 *   group, or by a delivery-log line naming the address (the recorder's queue-id match);
 * - a row still `pending` / `in_progress` (its earlier session was never committed: retried, or
 *   released by the reconciler) is **rebound** to the new queue id (`rebound`), and deliveries
 *   still tied to the old queue id lose it; a `queued` or `failed` row bound to another queue id
 *   → `conflict`, nothing changes (the caller logs ids only).
 */
export async function bindReinjectionQueueId(
  client: Db,
  token: string,
  queueId: string,
  options: { timeoutMs?: number } = {},
): Promise<BindQueueIdResult> {
  if (!QUEUE_ID.test(queueId)) throw new Error('queueId must be 1-32 alphanumeric characters');
  const publicId = parseReinjectionToken(token);
  if (publicId === null) return { result: 'unmatched' };
  return inTransaction(client, options.timeoutMs ?? 15_000, async (tx) => {
    const rows = await tx.$queryRaw<
      {
        id: bigint;
        received_at: Date;
        message_id: bigint;
        organization_id: bigint;
        queue_id: string | null;
        status: string;
      }[]
    >`
      SELECT id, received_at, message_id, organization_id, queue_id, status
      FROM delivery_reinjections WHERE public_id = ${publicId} FOR UPDATE`;
    const row = rows[0];
    if (!row) return { result: 'unmatched' };
    const ids = { reinjectionId: row.id, receivedAt: row.received_at, messageId: row.message_id };
    const bound = { ...ids, organizationId: row.organization_id };
    if (row.queue_id === queueId) return { result: 'duplicate', ...bound };
    const previous = row.queue_id;
    if (previous !== null && !REBINDABLE.has(row.status)) return { result: 'conflict', ...ids };
    // Lock order: reinjection → message → deliveries (as the recorder).
    await lockMessage(tx, row.message_id, row.received_at);
    await tx.deliveryReinjection.update({
      where: { id_receivedAt: { id: row.id, receivedAt: row.received_at } },
      data: { queueId },
      select: { id: true },
    });
    if (previous !== null) {
      await tx.emailDelivery.updateMany({
        where: {
          reinjectionId: row.id,
          receivedAt: row.received_at,
          outboundQueueId: previous,
          status: { in: ['pending', 'in_progress', 'deferred'] },
        },
        data: { outboundQueueId: null },
      });
    }
    return { result: previous === null ? 'bound' : 'rebound', ...bound };
  });
}
