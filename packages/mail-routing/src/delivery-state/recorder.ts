import { randomUUID } from 'node:crypto';
import { Prisma, type MessageStatus, type PrismaClient } from '@email-gateway/database';
import { deliveryStatusChangedV1, EventTypes } from '@email-gateway/event-contracts';
import { parseReinjectionToken } from '../reinjection-key';
import type { DeliverySignal } from './signals';
import {
  aggregateMessageStatus,
  isTerminalDeliveryStatus,
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
 * row(s). Locking the message first serializes the signals of one message, so the aggregate
 * (R9.1 step 6) always sees the latest committed status of every sibling delivery.
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
  /** Envelope event id that caused the signal (`email_events.event_id`, status history). */
  eventId?: string | null;
  /** Receives conflicts (ids and statuses only, never addresses). */
  logger?: RecorderLogger;
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
  /** Set when the signal completed the message aggregate. */
  messageStatus?: MessageStatus;
}

/** The message row changed between read and write (optimistic `version` check). */
export class MessageVersionConflictError extends Error {
  override readonly name = 'MessageVersionConflictError';
  constructor(readonly messageId: bigint) {
    super(`email_messages ${messageId.toString()} changed concurrently`);
  }
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
  if (error instanceof MessageVersionConflictError) return true;
  if (error instanceof Prisma.PrismaClientKnownRequestError) {
    if (error.code === 'P2034') return true;
    // Raw query failures carry the MySQL code: 1213 deadlock, 1205 lock wait timeout.
    if (error.code === 'P2010' && /\b(?:1213|1205)\b|deadlock/i.test(error.message)) return true;
  }
  return false;
}

/**
 * Runs `fn` in the caller's transaction, or in an own writer transaction retried up to 3 times
 * on an optimistic-version conflict, a deadlock or a write conflict.
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
  status: MessageStatus;
  version: number;
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
    SELECT id, received_at, organization_id, status, version, direction
    FROM email_messages WHERE id = ${id} AND received_at = ${receivedAt} FOR UPDATE`;
  const row = rows[0];
  return row ? { ...row, version: Number(row.version) } : null;
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

/**
 * Sets the message status with an optimistic `version` check and appends the status history
 * row (version = the new version). Throws MessageVersionConflictError when the row changed.
 */
async function setMessageStatus(
  tx: Prisma.TransactionClient,
  message: MessageRow,
  status: MessageStatus,
  reasonCode: string,
  eventId: string | null,
  changedAt: Date,
): Promise<void> {
  const { count } = await tx.emailMessage.updateMany({
    where: { id: message.id, receivedAt: message.received_at, version: message.version },
    data: { status, version: { increment: 1 }, statusChangedAt: changedAt },
  });
  if (count !== 1) throw new MessageVersionConflictError(message.id);
  await tx.emailMessageStatusHistory.create({
    data: {
      receivedAt: message.received_at,
      messageId: message.id,
      organizationId: message.organization_id,
      version: message.version + 1,
      fromStatus: message.status,
      toStatus: status,
      reasonCode,
      eventId,
      changedAt,
    },
    select: { id: true },
  });
}

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
 * 6. when every delivery of the signal's `delivery_seq` is terminal: the message aggregate
 *    (`delivered` / `partially_delivered` / `failed`, `version + 1`, status history).
 *
 * Not-applied signals keep their audit row (`stale`, `conflict`, same-state `duplicate`); a
 * same-state signal still fills a missing `dsn_queue_id` / `outbound_queue_id` (annotation, no
 * transition). Inside a caller's transaction a version conflict throws
 * MessageVersionConflictError for the caller to retry; in an own transaction it is retried up
 * to 3 times.
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

    // R9.1 step 6: the message aggregate over this delivery_seq.
    let messageStatus: MessageStatus | undefined;
    if (isTerminalDeliveryStatus(next.status)) {
      const siblings = await tx.$queryRaw<{ status: DeliveryStatus }[]>`
        SELECT status FROM email_deliveries
        WHERE message_id = ${delivery.message_id} AND received_at = ${delivery.received_at}
          AND delivery_seq = ${delivery.delivery_seq}
        FOR SHARE`;
      const aggregate = aggregateMessageStatus(siblings.map((row) => row.status));
      if (aggregate !== null && aggregate !== message.status) {
        await setMessageStatus(
          tx,
          message,
          aggregate,
          'delivery_complete',
          ctx.eventId ?? null,
          new Date(),
        );
        messageStatus = aggregate;
      }
    }

    return {
      ...ids,
      result: 'applied',
      status: next.status,
      previousStatus,
      ...(messageStatus ? { messageStatus } : {}),
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

/** Message statuses from which planning moves a message to `delivery_queued`. */
const QUEUEABLE: readonly MessageStatus[] = ['received', 'policy_evaluated'];

/**
 * The planner's message transition (R7 step 4): `received` / `policy_evaluated` →
 * `delivery_queued` with `version + 1` and a status history row; any other status is left
 * alone (`changed: false`). Locks the message row first (the recorder's lock order). Run it in
 * the planner's transaction before recording the planner signals.
 */
export async function markMessageDeliveryQueued(
  tx: Prisma.TransactionClient,
  message: { id: bigint; receivedAt: Date },
  options: { eventId?: string | null; changedAt?: Date } = {},
): Promise<{ changed: boolean; status: MessageStatus | null }> {
  const row = await lockMessage(tx, message.id, message.receivedAt);
  if (!row) return { changed: false, status: null };
  if (!QUEUEABLE.includes(row.status)) return { changed: false, status: row.status };
  await setMessageStatus(
    tx,
    row,
    'delivery_queued',
    'delivery_planned',
    options.eventId ?? null,
    options.changedAt ?? new Date(),
  );
  return { changed: true, status: 'delivery_queued' };
}
