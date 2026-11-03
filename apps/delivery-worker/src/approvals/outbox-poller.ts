import { Prisma, processOnce, type PrismaClient } from '@email-gateway/database';
import { type EventEnvelope, parseEvent } from '@email-gateway/event-contracts';
import type { Logger } from '@email-gateway/logger';
import type { z } from 'zod';
import type { DeliveryMetrics } from '../metrics/delivery-metrics';
import type { AdvisoryLocks } from '../shared/advisory-locks';
import { withTransactionDefaults } from '../shared/db';
import type { ApprovalFeed, FeedHandler } from './approval-feed';

export interface OutboxPollerOptions<T> {
  prisma: PrismaClient;
  locks: AdvisoryLocks;
  logger: Logger;
  metrics: DeliveryMetrics;
  /** `message_idempotency.consumer` and the cursor/lock suffix, e.g. `delivery-worker.planner`. */
  consumer: string;
  eventType: string;
  schema: z.ZodType<T>;
  /**
   * Where a consumer without a cursor starts (R6): `oldest` = the oldest retained outbox row
   * (nothing approved is lost), `latest` = `MAX(id)` at the first start (never replays old mail).
   */
  initialPosition: 'oldest' | 'latest';
  pollIntervalMs: number;
  /** DELIVERY_OUTBOX_SAFETY_LAG_MS. */
  safetyLagMs: number;
  /** DELIVERY_OUTBOX_BATCH_SIZE: rows per query and new rows handled per poll. */
  batchSize: number;
  /** Interactive transaction timeout of one handled event. */
  txTimeoutMs: number;
  now?: () => Date;
}

export interface PollReport {
  /** False when another replica holds the consumer lock (this one idles). */
  active: boolean;
  handled: number;
  duplicates: number;
  invalid: number;
  failed: number;
  /** Durable cursor after the poll. */
  cursor: bigint;
}

interface OutboxRow {
  id: bigint;
  created_at: Date;
  event_id: string;
  organization_id: bigint;
  event_type: string;
  correlation_id: string;
  payload: unknown;
}

/** In-memory recent event ids; bounded (rows below the cursor are pruned on every advance). */
const MAX_RECENT = 100_000;

/**
 * Interim approval transport (step 2.3 R6; replaced by a RabbitMQ consumer in step 3.2 behind
 * `ApprovalFeed`). One poller per consumer name:
 *
 * - reads `message_outbox` rows with `id > cursor` of one event type in id order (writer; a PK
 *   range across the daily partitions), in pages of `batchSize`;
 * - parses each row (`parseEvent` with the payload schema); an invalid row is logged, counted
 *   and skipped (it can never become valid);
 * - handles each row with `processOnce(consumer, eventId)` (a duplicate is skipped); an
 *   in-memory set of recently handled event ids avoids the ledger round trip for rows re-read
 *   inside the safety lag;
 * - advances the durable cursor (`stream_cursors`, `outbox:<consumer>`) only through a
 *   contiguous run of handled rows whose `created_at <= now - safetyLag`: auto-increment ids are
 *   allocated at insert and committed later, so a smaller id can appear after a larger one; rows
 *   newer than the lag are handled now and re-read until they are older. A row whose handler
 *   fails stops the cursor (never skipped, fail closed) but not the rows after it;
 * - runs only while it holds `GET_LOCK('dw:outbox:<consumer>')` on the dedicated lock
 *   connection; replicas without the lock idle.
 *
 * The outbox's `published_at` is never touched (it belongs to the step 3.2 relay).
 */
export class OutboxPoller<T> implements ApprovalFeed<T> {
  readonly cursorName: string;
  readonly lockName: string;
  private readonly txPrisma: PrismaClient;
  private readonly logger: Logger;
  private readonly now: () => Date;
  private readonly recent = new Map<string, bigint>();
  private handler: FeedHandler<T> | undefined;
  private timer: NodeJS.Timeout | undefined;
  private running: Promise<void> | undefined;
  private stopped = false;

  constructor(private readonly options: OutboxPollerOptions<T>) {
    this.cursorName = `outbox:${options.consumer}`;
    this.lockName = `dw:outbox:${options.consumer}`;
    this.txPrisma = withTransactionDefaults(options.prisma, { timeoutMs: options.txTimeoutMs });
    this.logger = options.logger.child({ component: 'outbox-poller', consumer: options.consumer });
    this.now = options.now ?? (() => new Date());
  }

  start(handler: FeedHandler<T>): void {
    this.handler = handler;
    this.stopped = false;
    this.schedule(0);
  }

  async stop(): Promise<void> {
    this.stopped = true;
    if (this.timer) clearTimeout(this.timer);
    await this.running;
    await this.options.locks.release(this.lockName).catch(() => undefined);
  }

  /** One poll (public for tests). */
  async pollOnce(handler: FeedHandler<T> | undefined = this.handler): Promise<PollReport> {
    if (!handler) throw new Error('OutboxPoller.pollOnce needs a handler');
    const report: PollReport = {
      active: false,
      handled: 0,
      duplicates: 0,
      invalid: 0,
      failed: 0,
      cursor: 0n,
    };
    if (!(await this.options.locks.ensure(this.lockName))) return report;
    report.active = true;
    const cursor = await this.loadCursor();
    const horizon = this.now().getTime() - this.options.safetyLagMs;
    let after = cursor;
    let advanceTo = cursor;
    let frozen = false;
    /** Oldest row not handled yet (a failing handler or a backlog beyond this poll). */
    let oldestPending: Date | null = null;
    let newRows = 0;

    for (;;) {
      const rows = await this.options.prisma.$queryRaw<OutboxRow[]>`
        SELECT id, created_at, event_id, organization_id, event_type, correlation_id, payload
        FROM message_outbox
        WHERE id > ${after} AND event_type = ${this.options.eventType}
        ORDER BY id LIMIT ${this.options.batchSize}`;
      for (const row of rows) {
        const id = BigInt(row.id);
        after = id;
        const isNew = !this.recent.has(row.event_id);
        const outcome = isNew ? await this.handleRow(row, handler) : 'recent';
        if (outcome === 'handled') report.handled += 1;
        if (outcome === 'duplicate') report.duplicates += 1;
        if (outcome === 'invalid') report.invalid += 1;
        if (outcome === 'failed') report.failed += 1;
        if (isNew) newRows += 1;
        if (outcome === 'failed') {
          frozen = true;
          oldestPending ??= row.created_at;
          continue;
        }
        if (!frozen && row.created_at.getTime() <= horizon) {
          advanceTo = id;
        } else {
          // Handled, only re-read until older than the lag: not a backlog.
          frozen = true;
        }
      }
      if (rows.length < this.options.batchSize || this.stopped) break;
      if (newRows >= this.options.batchSize) {
        // More rows than one poll handles: the next unread row is the backlog.
        const next = rows[rows.length - 1];
        if (next) oldestPending ??= next.created_at;
        break;
      }
    }

    if (advanceTo > cursor) {
      await this.options.prisma.streamCursor.update({
        where: { name: this.cursorName },
        data: { positionId: advanceTo, lastEventAt: this.now() },
      });
      for (const [eventId, id] of this.recent) if (id <= advanceTo) this.recent.delete(eventId);
    }
    report.cursor = advanceTo;
    const lagSeconds =
      oldestPending === null
        ? 0
        : Math.max(0, (this.now().getTime() - oldestPending.getTime()) / 1000);
    this.options.metrics.outboxPollLag.set({ consumer: this.options.consumer }, lagSeconds);
    return report;
  }

  private async handleRow(
    row: OutboxRow,
    handler: FeedHandler<T>,
  ): Promise<'handled' | 'duplicate' | 'invalid' | 'failed'> {
    const id = BigInt(row.id);
    let event: EventEnvelope<T>;
    try {
      event = parseEvent(
        {
          eventId: row.event_id,
          eventType: row.event_type,
          occurredAt: row.created_at.toISOString(),
          correlationId: row.correlation_id,
          organizationId: BigInt(row.organization_id).toString(),
          payload: typeof row.payload === 'string' ? safeJson(row.payload) : row.payload,
        },
        this.options.schema,
      );
    } catch (err) {
      this.options.metrics.outboxInvalid.inc({ consumer: this.options.consumer });
      this.logger.warn(
        { outboxId: id.toString(), eventId: row.event_id, err: summarize(err) },
        'invalid outbox event skipped',
      );
      this.remember(row.event_id, id);
      return 'invalid';
    }
    try {
      const result = await processOnce(this.txPrisma, this.options.consumer, event.eventId, (tx) =>
        handler(event, tx),
      );
      this.remember(row.event_id, id);
      return result.status === 'duplicate' ? 'duplicate' : 'handled';
    } catch (err) {
      this.logger.error(
        { outboxId: id.toString(), eventId: event.eventId, err },
        'outbox event handler failed; retried on the next poll',
      );
      return 'failed';
    }
  }

  private remember(eventId: string, id: bigint): void {
    if (this.recent.size >= MAX_RECENT) {
      const oldest = this.recent.keys().next().value;
      if (oldest !== undefined) this.recent.delete(oldest);
    }
    this.recent.set(eventId, id);
  }

  /** The durable cursor, created at the consumer's initial position on first use. */
  private async loadCursor(): Promise<bigint> {
    const existing = await this.options.prisma.streamCursor.findUnique({
      where: { name: this.cursorName },
      select: { positionId: true },
    });
    if (existing?.positionId !== null && existing?.positionId !== undefined) {
      return existing.positionId;
    }
    const [row] =
      this.options.initialPosition === 'latest'
        ? await this.options.prisma.$queryRaw<{ position: bigint | null }[]>`
            SELECT MAX(id) AS position FROM message_outbox`
        : await this.options.prisma.$queryRaw<{ position: bigint | null }[]>`
            SELECT MIN(id) AS position FROM message_outbox`;
    let initial = row?.position === null || row?.position === undefined ? 0n : BigInt(row.position);
    if (this.options.initialPosition === 'oldest' && initial > 0n) initial -= 1n;
    try {
      await this.options.prisma.streamCursor.create({
        data: { name: this.cursorName, positionId: initial },
      });
    } catch (err) {
      // A cursor row without a position (or a concurrent first start) is completed, never reset.
      if (!(err instanceof Prisma.PrismaClientKnownRequestError && err.code === 'P2002')) throw err;
      await this.options.prisma.streamCursor.updateMany({
        where: { name: this.cursorName, positionId: null },
        data: { positionId: initial },
      });
    }
    this.logger.info(
      { position: initial.toString(), initialPosition: this.options.initialPosition },
      'outbox cursor initialized',
    );
    const created = await this.options.prisma.streamCursor.findUniqueOrThrow({
      where: { name: this.cursorName },
      select: { positionId: true },
    });
    return created.positionId ?? initial;
  }

  private schedule(delayMs: number): void {
    if (this.stopped) return;
    this.timer = setTimeout(() => {
      this.running = this.pollOnce()
        .then(() => undefined)
        .catch((err: unknown) => this.logger.warn({ err }, 'outbox poll failed; retrying'))
        .finally(() => {
          this.running = undefined;
          this.schedule(this.options.pollIntervalMs);
        });
    }, delayMs);
    this.timer.unref();
  }
}

function safeJson(text: string): unknown {
  try {
    return JSON.parse(text) as unknown;
  } catch {
    return null;
  }
}

/** Validation issues without values (payloads may carry addresses). */
function summarize(err: unknown): string {
  if (typeof err === 'object' && err !== null && 'issues' in err) {
    const issues = (err as { issues: { path: PropertyKey[]; message: string }[] }).issues;
    return issues.map((i) => `${i.path.map(String).join('.')}: ${i.message}`).join('; ');
  }
  return err instanceof Error ? err.name : 'invalid';
}
