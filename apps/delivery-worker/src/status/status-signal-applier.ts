import type { MessageDirection, PrismaClient } from '@email-gateway/database';
import type { Logger } from '@email-gateway/logger';
import {
  bindReinjectionQueueId,
  classifyDeliveryError,
  type DeliverySignal,
  type DeliveryStatus,
  logSignalKey,
  reconcileSignalKey,
  recordDeliverySignal,
  type RecordResult,
} from '@email-gateway/mail-routing';
import type { DeliveryMetrics } from '../metrics/delivery-metrics';
import { SOURCE_SERVICE } from '../planning/delivery-planner';
import type {
  BindLine,
  MessageExpiredLine,
  NotificationLine,
  PostfixLogEvent,
  QueueActiveLine,
  RecipientResultLine,
  RemovedLine,
} from './postfix-log-parser';

export interface ApplierOptions {
  prisma: PrismaClient;
  metrics: DeliveryMetrics;
  logger: Logger;
  /** DELIVERY_STATUS_LOG_SOURCE_ID (part of every log signal key). */
  sourceId: string;
  /** DELIVERY_STATUS_UNMATCHED_RETRY_SECONDS × 1000. */
  unmatchedRetryMs: number;
  recorderTimeoutMs: number;
  clock?: () => number;
}

interface BoundReinjection {
  id: bigint;
  receivedAt: Date;
  direction: MessageDirection;
  status: string;
}

type Outcome = 'done' | 'unmatched';

const NON_TERMINAL: DeliveryStatus[] = ['pending', 'in_progress', 'queued', 'deferred', 'unknown'];
const AWAITING_REMOTE: DeliveryStatus[] = ['pending', 'in_progress', 'deferred'];
const MAX_RETRY_ENTRIES = 20_000;
const CACHE_SIZE = 10_000;
/** Queue ids seen on reinjection-listener binding lines of this stream (bounded). */
const BIND_SEEN_SIZE = 50_000;
/** Unmatched events are retried at most this often. */
const RETRY_INTERVAL_MS = 2000;

const STATUS_OF: Readonly<Record<RecipientResultLine['status'], DeliveryStatus>> = {
  sent: 'delivered',
  deferred: 'deferred',
  bounced: 'bounced',
  expired: 'expired',
};

const OUTCOME_OF: Readonly<
  Record<RecipientResultLine['status'], 'success' | 'deferred' | 'bounced'>
> = {
  sent: 'success',
  deferred: 'deferred',
  bounced: 'bounced',
  expired: 'deferred',
};

/**
 * Turns parsed delivery-log events into delivery status signals (step 2.3 R9) through the
 * shared recorder: `client=… orig_queue_id=` binds the queue id; qmgr `queue active` makes the
 * bound reinjection's accepted recipients `queued` (covers a crash after the 250); smtp / error /
 * retry results become `delivered` / `deferred` / `bounced` with attempts and error classes; the
 * message-level `expired` line expires every non-final recipient; `sender non-delivery
 * notification` records `dsn_queue_id`; `removed` turns non-final deliveries into `unknown`
 * (source reconciler).
 *
 * Unmatched events: only a binding line, or an event whose queue id appeared on a binding line
 * of this stream, is retried in memory for `unmatchedRetryMs` (a binding or a delivery may
 * commit later), then dropped and counted
 * (`delivery_status_signals_total{source="postfix_log",result="unmatched"}`). Every other queue
 * id (submissions and connector mail that postfix-outbound hands to the adapter, DSNs, bounce
 * notices) is never a reinjection: one indexed lookup, then the event is ignored at once (review
 * fix of step 2.3: no retry storm of writer queries for unrelated log lines). Postfix logs the
 * binding before any other line of the same queue id, in the same file.
 */
export class StatusSignalApplier {
  private readonly logger: Logger;
  private readonly clock: () => number;
  private readonly retries = new Map<
    string,
    { event: PostfixLogEvent; firstSeen: number; lastTry: number }
  >();
  private readonly bound = new Map<string, BoundReinjection>();
  private readonly bindSeen = new Set<string>();

  constructor(private readonly options: ApplierOptions) {
    this.logger = options.logger.child({ component: 'status-signal-applier' });
    this.clock = options.clock ?? Date.now;
  }

  get pendingRetries(): number {
    return this.retries.size;
  }

  /**
   * Applies `events` in log order, then retries earlier unmatched events. Throws on database
   * errors (the caller re-reads the batch: every signal is idempotent).
   */
  async apply(events: readonly PostfixLogEvent[]): Promise<void> {
    for (const event of events) {
      if (event.kind === 'bind') this.sawBinding(event.queueId);
      const key = eventKey(event);
      if (this.retries.has(key)) continue;
      if ((await this.handle(event)) !== 'unmatched') continue;
      if (event.kind === 'bind' || this.bindSeen.has(event.queueId)) {
        this.remember(key, event);
      }
    }
    await this.retryPending();
  }

  /** Retries unmatched events; drops (and counts) those older than the retry window. */
  async retryPending(): Promise<void> {
    const now = this.clock();
    for (const [key, entry] of [...this.retries]) {
      if (
        now - entry.lastTry < RETRY_INTERVAL_MS &&
        now - entry.firstSeen < this.options.unmatchedRetryMs
      ) {
        continue;
      }
      entry.lastTry = now;
      if ((await this.handle(entry.event)) === 'done') {
        this.retries.delete(key);
      } else if (now - entry.firstSeen >= this.options.unmatchedRetryMs) {
        this.retries.delete(key);
        this.options.metrics.signal('postfix_log', 'unmatched');
      }
    }
  }

  /** Remembers a bound queue id (oldest forgotten first beyond BIND_SEEN_SIZE). */
  private sawBinding(queueId: string): void {
    this.bindSeen.delete(queueId);
    this.bindSeen.add(queueId);
    if (this.bindSeen.size > BIND_SEEN_SIZE) {
      const oldest = this.bindSeen.values().next().value;
      if (oldest !== undefined) this.bindSeen.delete(oldest);
    }
  }

  private remember(key: string, event: PostfixLogEvent): void {
    if (this.retries.size >= MAX_RETRY_ENTRIES) {
      const oldest = this.retries.keys().next().value;
      if (oldest !== undefined) {
        this.retries.delete(oldest);
        this.options.metrics.signal('postfix_log', 'unmatched');
      }
    }
    const now = this.clock();
    this.retries.set(key, { event, firstSeen: now, lastTry: now });
  }

  private async handle(event: PostfixLogEvent): Promise<Outcome> {
    switch (event.kind) {
      case 'bind':
        return this.onBind(event);
      case 'queue_active':
        return this.onQueueActive(event);
      case 'recipient_result':
        return this.onResult(event);
      case 'message_expired':
        return this.onExpired(event);
      case 'notification':
        return this.onNotification(event);
      case 'removed':
        return this.onRemoved(event);
    }
  }

  private async reinjectionOf(queueId: string): Promise<BoundReinjection | null> {
    const cached = this.bound.get(queueId);
    if (cached) return cached;
    const row = await this.options.prisma.deliveryReinjection.findFirst({
      where: { queueId },
      select: { id: true, receivedAt: true, direction: true, status: true },
    });
    if (!row) return null;
    if (this.bound.size >= CACHE_SIZE) this.bound.clear();
    this.bound.set(queueId, row);
    return row;
  }

  private async deliveriesOf(
    reinjection: BoundReinjection,
    queueId: string,
    statuses: DeliveryStatus[],
  ): Promise<{ id: bigint; receivedAt: Date; address: string; status: DeliveryStatus }[]> {
    const deliveries = await this.options.prisma.emailDelivery.findMany({
      where: {
        receivedAt: reinjection.receivedAt,
        outboundQueueId: queueId,
        status: { in: statuses },
      },
      select: { id: true, receivedAt: true, recipientId: true, status: true },
      take: 1000,
    });
    if (deliveries.length === 0) return [];
    const recipients = await this.options.prisma.emailRecipient.findMany({
      where: {
        id: { in: deliveries.map((d) => d.recipientId) },
        receivedAt: reinjection.receivedAt,
      },
      select: { id: true, address: true },
    });
    const address = new Map(recipients.map((r) => [r.id, r.address]));
    return deliveries.flatMap((d) => {
      const a = address.get(d.recipientId);
      return a === undefined
        ? []
        : [{ id: d.id, receivedAt: d.receivedAt, address: a, status: d.status }];
    });
  }

  private async record(
    signal: DeliverySignal,
    direction: MessageDirection | null,
  ): Promise<RecordResult> {
    const result = await recordDeliverySignal(this.options.prisma, signal, {
      sourceService: SOURCE_SERVICE,
      timeoutMs: this.options.recorderTimeoutMs,
      logger: this.logger,
    });
    if (result.result !== 'unmatched') {
      this.options.metrics.signal(signal.source, result.result, {
        direction,
        status: result.status,
      });
    }
    return result.result;
  }

  private async onBind(event: BindLine): Promise<Outcome> {
    const result = await bindReinjectionQueueId(this.options.prisma, event.token, event.queueId, {
      timeoutMs: this.options.recorderTimeoutMs,
    });
    if (result.result === 'unmatched') return 'unmatched';
    this.bound.delete(event.queueId);
    if (result.result === 'conflict') {
      this.logger.warn(
        { reinjectionId: result.reinjectionId.toString() },
        'reinjection already bound to another queue id; log binding ignored',
      );
    }
    return 'done';
  }

  /**
   * qmgr `queue active`: the queue file of a bound reinjection exists, so the row is `queued`
   * (never re-sent; covers a crash after the 250). Its recipients become `queued` only when the
   * accepted set is known: `nrcpt` equals the recipients not yet tied to another outcome (every
   * recipient still waiting for the hop was accepted). Otherwise some were refused or deferred
   * at RCPT and the accepted ones are tied to the file by their own delivery-log lines; the
   * worker's commit (or, after a crash, the reconciler's unconfirmed scan) decides the rest.
   * A later `queue active` of the same file (after a deferral) finds nothing to do.
   */
  private async onQueueActive(event: QueueActiveLine): Promise<Outcome> {
    const reinjection = await this.reinjectionOf(event.queueId);
    if (!reinjection) return 'unmatched';
    await this.options.prisma.deliveryReinjection.updateMany({
      where: {
        id: reinjection.id,
        receivedAt: reinjection.receivedAt,
        status: 'in_progress',
        queueId: event.queueId,
      },
      data: { status: 'queued', queuedAt: event.timestamp, leaseExpiresAt: null },
    });
    const members = await this.options.prisma.emailDelivery.findMany({
      where: { reinjectionId: reinjection.id, receivedAt: reinjection.receivedAt },
      select: {
        id: true,
        receivedAt: true,
        recipientId: true,
        status: true,
        outboundQueueId: true,
      },
      take: 1000,
    });
    const inFile = members.filter((d) => d.outboundQueueId === event.queueId).length;
    const waiting = members.filter(
      (d) => d.outboundQueueId === null && AWAITING_REMOTE.includes(d.status),
    );
    if (waiting.length === 0) return 'done';
    if (waiting.length + inFile !== event.nrcpt) {
      this.logger.debug(
        {
          reinjectionId: reinjection.id.toString(),
          nrcpt: event.nrcpt,
          waiting: waiting.length,
          inFile,
        },
        'queue file recipient count differs from the group; recipients left to their own lines',
      );
      return 'done';
    }
    const recipients = await this.options.prisma.emailRecipient.findMany({
      where: { id: { in: waiting.map((d) => d.recipientId) }, receivedAt: reinjection.receivedAt },
      select: { id: true, address: true },
    });
    const address = new Map(recipients.map((r) => [r.id, r.address]));
    for (const delivery of waiting) {
      const rcpt = address.get(delivery.recipientId);
      if (rcpt === undefined) continue;
      await this.record(
        {
          match: { deliveryId: delivery.id, receivedAt: delivery.receivedAt },
          status: 'queued',
          occurredAt: occurred(event),
          source: 'postfix_log',
          signalKey: this.key(event, rcpt, 'queue_active', null),
          queueId: event.queueId,
          detail: 'queue file accepted by postfix-outbound (qmgr queue active)',
        },
        reinjection.direction,
      );
    }
    return 'done';
  }

  private async onResult(event: RecipientResultLine): Promise<Outcome> {
    const reinjection = await this.reinjectionOf(event.queueId);
    if (!reinjection) return 'unmatched';
    const status = STATUS_OF[event.status];
    const errorClass =
      event.status === 'sent' ? null : classifyDeliveryError(event.text, event.dsn);
    const result = await this.record(
      {
        match: { queueId: event.queueId, address: event.address },
        status,
        occurredAt: occurred(event),
        source: 'postfix_log',
        signalKey: this.key(event, event.address, event.status, event.dsn),
        enhancedStatus: event.dsn,
        smtpCode: event.smtpCode,
        errorClass,
        detail: event.text,
        queueId: event.queueId,
        ...(event.remoteAttempt
          ? {
              attempt: {
                remoteHost: event.relay?.host ?? null,
                remoteIp: event.relay?.ip ?? null,
                smtpCode: event.smtpCode,
                enhancedStatus: event.dsn,
                response: event.text,
                outcome: OUTCOME_OF[event.status],
              },
            }
          : {}),
      },
      reinjection.direction,
    );
    return result === 'unmatched' ? 'unmatched' : 'done';
  }

  private async onExpired(event: MessageExpiredLine): Promise<Outcome> {
    const reinjection = await this.reinjectionOf(event.queueId);
    if (!reinjection) return 'unmatched';
    for (const delivery of await this.deliveriesOf(reinjection, event.queueId, NON_TERMINAL)) {
      await this.record(
        {
          match: { deliveryId: delivery.id, receivedAt: delivery.receivedAt },
          status: 'expired',
          occurredAt: occurred(event),
          source: 'postfix_log',
          signalKey: this.key(event, delivery.address, 'expired', null),
          queueId: event.queueId,
          detail: 'postfix-outbound queue lifetime exceeded; returned to sender',
        },
        reinjection.direction,
      );
    }
    return 'done';
  }

  private async onNotification(event: NotificationLine): Promise<Outcome> {
    // Only the sender non-delivery notice proves a DSN to the original sender (R9 table).
    if (event.recipient !== 'sender' || event.type !== 'non_delivery') return 'done';
    const reinjection = await this.reinjectionOf(event.queueId);
    if (!reinjection) return 'unmatched';
    const finals = await this.deliveriesOf(reinjection, event.queueId, ['bounced', 'expired']);
    if (finals.length === 0) {
      // The result line may still be in the retry queue.
      const open = await this.deliveriesOf(reinjection, event.queueId, NON_TERMINAL);
      return open.length > 0 ? 'unmatched' : 'done';
    }
    for (const delivery of finals) {
      await this.record(
        {
          match: { deliveryId: delivery.id, receivedAt: delivery.receivedAt },
          status: delivery.status,
          occurredAt: occurred(event),
          source: 'postfix_log',
          signalKey: this.key(event, delivery.address, 'sender_non_delivery_notification', null),
          queueId: event.queueId,
          dsnQueueId: event.dsnQueueId,
          detail: 'delivery status notification generated to the original sender',
        },
        reinjection.direction,
      );
    }
    return 'done';
  }

  private async onRemoved(event: RemovedLine): Promise<Outcome> {
    const reinjection = await this.reinjectionOf(event.queueId);
    if (!reinjection) return 'unmatched';
    for (const delivery of await this.deliveriesOf(reinjection, event.queueId, [
      'queued',
      'deferred',
      'pending',
      'in_progress',
    ])) {
      const result = await this.record(
        {
          match: { deliveryId: delivery.id, receivedAt: delivery.receivedAt },
          status: 'unknown',
          occurredAt: occurred(event),
          source: 'reconciler',
          signalKey: reconcileSignalKey({
            deliveryId: delivery.id,
            toStatus: 'unknown',
            reason: 'queue_file_removed',
          }),
          queueId: event.queueId,
          failureReason: 'status_signal_missing',
          detail: 'queue file removed without a final delivery record',
        },
        reinjection.direction,
      );
      if (result === 'applied') {
        this.options.metrics.reconcilerActions.inc({ action: 'removed_unknown' });
        this.logger.warn(
          { deliveryId: delivery.id.toString(), reinjectionId: reinjection.id.toString() },
          'queue file removed without a final delivery record; delivery unknown',
        );
      }
    }
    return 'done';
  }

  private key(event: PostfixLogEvent, address: string, status: string, dsn: string | null): string {
    return logSignalKey({
      sourceId: this.options.sourceId,
      queueId: event.queueId,
      address,
      status,
      logTimestamp: event.rawTimestamp,
      dsn,
    });
  }
}

/**
 * When a log event happened for the state machine: the end of the logged second. Postfix logs
 * whole seconds, while the worker's own signals carry milliseconds; a line of the same second
 * as the worker's `queued` commit (e.g. an immediate `deferred`) must not look older than it.
 */
const occurred = (event: PostfixLogEvent): Date =>
  new Date(event.timestamp.getTime() + event.precisionMs - 1);

/** Identity of an event for the retry queue (re-read lines collapse onto one entry). */
function eventKey(event: PostfixLogEvent): string {
  const subject =
    event.kind === 'recipient_result'
      ? `${event.address.toLowerCase()}|${event.status}|${event.dsn}`
      : event.kind === 'bind'
        ? event.token
        : event.kind === 'notification'
          ? `${event.recipient}|${event.type}|${event.dsnQueueId}`
          : '';
  return `${event.kind}|${event.queueId}|${event.rawTimestamp}|${subject}`;
}
