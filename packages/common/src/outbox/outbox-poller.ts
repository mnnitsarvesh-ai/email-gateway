import { Prisma, type PrismaClient } from '@email-gateway/database';
import { type EventEnvelope, parseEvent } from '@email-gateway/event-contracts';
import type { Logger } from '@email-gateway/logger';
import type { AdvisoryLocks } from './advisory-locks';
import type { EventFeed, EventHandler } from './event-feed';

/** The payload schema `parseEvent` accepts (a zod schema of `T`). */
export type PayloadSchema<T> = Parameters<typeof parseEvent<T>>[1];

/** The two series a poller reports; each service maps them onto its own metric names. */
export interface OutboxPollerMetrics {
  /** Age of the oldest row this consumer has not processed yet (0 when caught up). */
  pollLag(consumer: string, seconds: number): void;
  /** One outbox row that failed envelope or payload validation and was skipped. */
  invalid(consumer: string): void;
}

/** One shard of a consumer's outbox stream: the rows with `MOD(id, count) = index`. */
export interface OutboxShard {
  index: number;
  count: number;
}

/** Delay before a failed row is retried: `min(maxMs, baseMs * 2^(failures - 1))`. */
export interface FailureBackoff {
  baseMs: number;
  maxMs: number;
}

export interface OutboxPollerOptions<T> {
  /** The writer (outbox rows are read from the primary, never from a replica). */
  prisma: PrismaClient;
  locks: AdvisoryLocks;
  logger: Logger;
  metrics: OutboxPollerMetrics;
  /** The consumer name: cursor `outbox:<consumer>`, lock `<lockPrefix>:outbox:<consumer>`. */
  consumer: string;
  eventType: string;
  schema: PayloadSchema<T>;
  /**
   * Where a consumer without a cursor starts (step 2.3 R6): `oldest` = the oldest retained
   * outbox row (nothing is lost), `latest` = `MAX(id)` at the first start (never replays).
   * Existing cursors of the same consumer with another shard count take precedence: the new
   * cursor starts at their minimum (step 3.1 M2; re-read, never skip).
   */
  initialPosition: 'oldest' | 'latest';
  pollIntervalMs: number;
  /** Rows younger than this are handled but the cursor stays below them (late commits). */
  safetyLagMs: number;
  /** Rows per query and the maximum number of new rows handled per poll. */
  batchSize: number;
  /** Lock namespace of the service, e.g. `dw` (delivery-worker) or `ew` (email-worker). */
  lockPrefix: string;
  /** Rows of one page handled at the same time (default 1 = strictly sequential). */
  concurrency?: number;
  /** Default `{ index: 0, count: 1 }` (unsharded). */
  shard?: OutboxShard;
  /** In-memory retry delay per event id after a handler failure (default: retry every poll). */
  failureBackoff?: FailureBackoff;
  /**
   * Shard locks of this consumer one process may hold through the shared `AdvisoryLocks`
   * (default unlimited): a poller that does not hold its lock yet does not try to acquire it
   * while the process already holds this many, so replicas spread the shards.
   */
  maxHeldLocks?: number;
  now?: () => Date;
}

export interface PollReport {
  /** False when the lock is held elsewhere or `maxHeldLocks` is reached (this poller idles). */
  active: boolean;
  handled: number;
  duplicates: number;
  invalid: number;
  failed: number;
  /** Rows skipped this poll because their failure backoff has not elapsed (cursor frozen). */
  backedOff: number;
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

type HandledOutcome = 'handled' | 'duplicate' | 'invalid' | 'failed';
/** `recent`: handled earlier; `backedOff`/`deferred`: not attempted this poll. */
type RowOutcome = HandledOutcome | 'recent' | 'backedOff' | 'deferred';

/** In-memory recent event ids and failure records are bounded. */
const MAX_TRACKED = 100_000;
/** MySQL GET_LOCK names are server-wide and at most 64 characters. */
const MAX_LOCK_NAME = 64;
/** How often a poller that does not hold its shard re-measures that shard's lag. */
const UNOWNED_LAG_EVERY_MS = 10_000;

/**
 * Interim event transport over `message_outbox` (step 2.3 R6, generalised in step 3.1 M2;
 * replaced by a RabbitMQ consumer in step 3.2 behind `EventFeed`). One poller per consumer
 * (and shard):
 *
 * - reads `message_outbox` rows with `id > cursor` of one event type in id order (writer; a PK
 *   range across the daily partitions), in pages of `batchSize`; with `shard.count = n > 1`
 *   only the rows with `MOD(id, n) = shard.index`;
 * - parses each row (`parseEvent` with the payload schema); an invalid row is logged without
 *   values, counted and skipped (it can never become valid);
 * - hands each new row to the handler (idempotent; `processOnceHandler` for the step 2.3
 *   shape), up to `concurrency` rows of a page at a time and never more than `batchSize` new
 *   rows per poll; an in-memory set of recently handled event ids avoids redelivering rows
 *   re-read inside the safety lag;
 * - after the page, advances the durable cursor (`stream_cursors`) in id order only through a
 *   contiguous run of handled rows whose `created_at <= now - safetyLag`: auto-increment ids are
 *   allocated at insert and committed later, so a smaller id can appear after a larger one;
 *   rows newer than the lag are handled now and re-read until they are older. A row whose
 *   handler fails (or is still in its failure backoff) stops the cursor (never skipped, fail
 *   closed) but not the rows after it. The result is the same as handling the page
 *   sequentially, whatever order concurrent handlers finish in;
 * - runs only while it holds `GET_LOCK('<lockPrefix>:outbox:<consumer>[#i/n]')` on the
 *   dedicated lock connection; replicas without the lock idle. A shard poller that does not hold
 *   its lock still reports the shard's lag from its durable cursor, so a shard no replica runs
 *   is visible on the lag gauge.
 *
 * The outbox's `published_at` is never touched (it belongs to the step 3.2 relay). Handler
 * errors are logged as `{ outboxId, eventId, errName, errCode }` only: never the error object
 * or its message, which could quote message content (step 3.1 M15).
 */
export class OutboxPoller<T> implements EventFeed<T> {
  readonly cursorName: string;
  readonly lockName: string;
  private readonly baseCursorName: string;
  /** Prefix shared by this consumer's shard locks (`maxHeldLocks`). */
  private readonly shardLockPrefix: string;
  private readonly shard: OutboxShard;
  private readonly concurrency: number;
  private readonly logger: Logger;
  private readonly now: () => Date;
  private readonly recent = new Map<string, bigint>();
  private readonly failures = new Map<string, { count: number; retryAt: number }>();
  private unownedLag: { at: number; seconds: number } | null = null;
  private handler: EventHandler<T> | undefined;
  private timer: NodeJS.Timeout | undefined;
  private running: Promise<void> | undefined;
  private stopped = false;

  constructor(private readonly options: OutboxPollerOptions<T>) {
    validateOptions(options);
    this.shard = options.shard ?? { index: 0, count: 1 };
    this.concurrency = options.concurrency ?? 1;
    const suffix = this.shard.count > 1 ? `#${this.shard.index}/${this.shard.count}` : '';
    this.baseCursorName = `outbox:${options.consumer}`;
    this.cursorName = `${this.baseCursorName}${suffix}`;
    this.shardLockPrefix = `${options.lockPrefix}:outbox:${options.consumer}#`;
    this.lockName = `${options.lockPrefix}:outbox:${options.consumer}${suffix}`;
    if (this.lockName.length > MAX_LOCK_NAME) {
      throw new Error(
        `outbox lock name must be at most ${MAX_LOCK_NAME} characters (${this.lockName.length}): ` +
          'shorten the lock prefix or the consumer name',
      );
    }
    this.logger = options.logger.child({
      component: 'outbox-poller',
      consumer: options.consumer,
      ...(this.shard.count > 1 ? { shard: `${this.shard.index}/${this.shard.count}` } : {}),
    });
    this.now = options.now ?? (() => new Date());
  }

  start(handler: EventHandler<T>): void {
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
  async pollOnce(handler: EventHandler<T> | undefined = this.handler): Promise<PollReport> {
    if (!handler) throw new Error('OutboxPoller.pollOnce needs a handler');
    const report: PollReport = {
      active: false,
      handled: 0,
      duplicates: 0,
      invalid: 0,
      failed: 0,
      backedOff: 0,
      cursor: 0n,
    };
    if (!(await this.acquire())) {
      // A shard this process does not run. Its lag still comes from its durable cursor, so a
      // shard no replica runs (replicas x maxHeldLocks < shards) shows a growing lag, never 0.
      if (this.shard.count > 1) {
        this.options.metrics.pollLag(this.options.consumer, await this.unownedLagSeconds());
      }
      return report;
    }
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
      const rows = await this.readPage(after);
      // Plan the page in id order, then run the new rows (up to `concurrency` at a time).
      const outcomes: (RowOutcome | undefined)[] = new Array<RowOutcome | undefined>(rows.length);
      const firstInPage = new Map<string, number>();
      const toRun: number[] = [];
      const nowMs = this.now().getTime();
      let deferred = false;
      rows.forEach((row, i) => {
        if (this.recent.has(row.event_id)) outcomes[i] = 'recent';
        else if (firstInPage.has(row.event_id))
          return; // resolved from the first occurrence
        else if (deferred || newRows >= this.options.batchSize) {
          deferred = true;
          outcomes[i] = 'deferred';
        } else if (this.inBackoff(row.event_id, nowMs)) outcomes[i] = 'backedOff';
        else {
          newRows += 1;
          toRun.push(i);
        }
        firstInPage.set(row.event_id, i);
      });
      await runPool(toRun, this.concurrency, async (i) => {
        outcomes[i] = await this.handleRow(rows[i]!, handler);
      });

      for (const [i, row] of rows.entries()) {
        const id = BigInt(row.id);
        after = id;
        const outcome = outcomes[i] ?? repeatOutcome(outcomes[firstInPage.get(row.event_id)!]);
        if (outcome === 'handled') report.handled += 1;
        if (outcome === 'duplicate') report.duplicates += 1;
        if (outcome === 'invalid') report.invalid += 1;
        if (outcome === 'failed') report.failed += 1;
        if (outcome === 'backedOff') report.backedOff += 1;
        if (outcome === 'failed' || outcome === 'backedOff' || outcome === 'deferred') {
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
      if (deferred || rows.length < this.options.batchSize || this.stopped) break;
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
    this.options.metrics.pollLag(this.options.consumer, lagSeconds);
    return report;
  }

  /**
   * Lag of a shard this process does not hold, from its durable cursor (at most one query per
   * `UNOWNED_LAG_EVERY_MS`): seconds by which the oldest row past the cursor is older than the
   * safety lag. A shard run elsewhere stays near 0 (its cursor moves every poll); a shard nobody
   * runs grows. No cursor yet: measured from the start of the stream (`oldest`) or 0 (`latest`).
   */
  private async unownedLagSeconds(): Promise<number> {
    const nowMs = this.now().getTime();
    if (this.unownedLag !== null && nowMs - this.unownedLag.at < UNOWNED_LAG_EVERY_MS) {
      return this.unownedLag.seconds;
    }
    const { prisma, eventType, safetyLagMs } = this.options;
    const cursor = await prisma.streamCursor.findUnique({
      where: { name: this.cursorName },
      select: { positionId: true },
    });
    let seconds = 0;
    const position = cursor?.positionId ?? null;
    if (position !== null || this.options.initialPosition === 'oldest') {
      const horizon = new Date(nowMs - safetyLagMs);
      const [row] = await prisma.$queryRaw<{ created_at: Date }[]>`
        SELECT created_at FROM message_outbox
        WHERE id > ${position ?? 0n} AND event_type = ${eventType}
          AND MOD(id, ${this.shard.count}) = ${this.shard.index}
          AND created_at <= ${horizon}
        ORDER BY id LIMIT 1`;
      if (row) seconds = Math.max(0, (horizon.getTime() - row.created_at.getTime()) / 1000);
    }
    this.unownedLag = { at: nowMs, seconds };
    return seconds;
  }

  /** `ensure()`s the lock unless `maxHeldLocks` other shard locks are already held here. */
  private async acquire(): Promise<boolean> {
    const { locks, maxHeldLocks } = this.options;
    if (
      maxHeldLocks !== undefined &&
      !locks.isHeld(this.lockName) &&
      locks.heldCount(this.shardLockPrefix) >= maxHeldLocks
    ) {
      return false;
    }
    return locks.ensure(this.lockName);
  }

  private readPage(after: bigint): Promise<OutboxRow[]> {
    const { prisma, eventType, batchSize } = this.options;
    if (this.shard.count > 1) {
      return prisma.$queryRaw<OutboxRow[]>`
        SELECT id, created_at, event_id, organization_id, event_type, correlation_id, payload
        FROM message_outbox
        WHERE id > ${after} AND event_type = ${eventType}
          AND MOD(id, ${this.shard.count}) = ${this.shard.index}
        ORDER BY id LIMIT ${batchSize}`;
    }
    return prisma.$queryRaw<OutboxRow[]>`
      SELECT id, created_at, event_id, organization_id, event_type, correlation_id, payload
      FROM message_outbox
      WHERE id > ${after} AND event_type = ${eventType}
      ORDER BY id LIMIT ${batchSize}`;
  }

  private async handleRow(row: OutboxRow, handler: EventHandler<T>): Promise<HandledOutcome> {
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
      this.options.metrics.invalid(this.options.consumer);
      this.logger.warn(
        { outboxId: id.toString(), eventId: row.event_id, err: summarize(err) },
        'invalid outbox event skipped',
      );
      this.remember(row.event_id, id);
      return 'invalid';
    }
    try {
      const outcome = await handler(event);
      this.remember(row.event_id, id);
      this.failures.delete(row.event_id);
      return outcome === 'duplicate' ? 'duplicate' : 'handled';
    } catch (err) {
      this.recordFailure(row.event_id);
      this.logger.error(
        { outboxId: id.toString(), eventId: event.eventId, ...errorFields(err) },
        'outbox event handler failed; retried on a later poll',
      );
      return 'failed';
    }
  }

  private inBackoff(eventId: string, nowMs: number): boolean {
    const failure = this.failures.get(eventId);
    return failure !== undefined && failure.retryAt > nowMs;
  }

  private recordFailure(eventId: string): void {
    const backoff = this.options.failureBackoff;
    if (!backoff) return;
    const count = (this.failures.get(eventId)?.count ?? 0) + 1;
    const delay = Math.min(backoff.maxMs, backoff.baseMs * 2 ** Math.min(count - 1, 52));
    this.failures.delete(eventId);
    if (this.failures.size >= MAX_TRACKED) {
      const oldest = this.failures.keys().next().value;
      if (oldest !== undefined) this.failures.delete(oldest);
    }
    this.failures.set(eventId, { count, retryAt: this.now().getTime() + delay });
  }

  private remember(eventId: string, id: bigint): void {
    if (this.recent.size >= MAX_TRACKED) {
      const oldest = this.recent.keys().next().value;
      if (oldest !== undefined) this.recent.delete(oldest);
    }
    this.recent.set(eventId, id);
  }

  /**
   * The durable cursor, created on first use at the minimum position of the consumer's other
   * cursors (another shard count: re-read, never skip) or else at the initial position.
   */
  private async loadCursor(): Promise<bigint> {
    const { prisma } = this.options;
    const existing = await prisma.streamCursor.findUnique({
      where: { name: this.cursorName },
      select: { positionId: true },
    });
    if (existing?.positionId !== null && existing?.positionId !== undefined) {
      return existing.positionId;
    }
    const inherited = await this.minimumExistingCursor();
    let initial: bigint;
    if (inherited !== null) {
      initial = inherited;
    } else {
      const [row] =
        this.options.initialPosition === 'latest'
          ? await prisma.$queryRaw<{ position: bigint | null }[]>`
              SELECT MAX(id) AS position FROM message_outbox`
          : await prisma.$queryRaw<{ position: bigint | null }[]>`
              SELECT MIN(id) AS position FROM message_outbox`;
      initial = row?.position === null || row?.position === undefined ? 0n : BigInt(row.position);
      if (this.options.initialPosition === 'oldest' && initial > 0n) initial -= 1n;
    }
    try {
      await prisma.streamCursor.create({ data: { name: this.cursorName, positionId: initial } });
    } catch (err) {
      // A cursor row without a position (or a concurrent first start) is completed, never reset.
      if (!(err instanceof Prisma.PrismaClientKnownRequestError && err.code === 'P2002')) throw err;
      await prisma.streamCursor.updateMany({
        where: { name: this.cursorName, positionId: null },
        data: { positionId: initial },
      });
    }
    this.logger.info(
      {
        position: initial.toString(),
        initialPosition: inherited !== null ? 'existing_cursors' : this.options.initialPosition,
      },
      'outbox cursor initialized',
    );
    const created = await prisma.streamCursor.findUniqueOrThrow({
      where: { name: this.cursorName },
      select: { positionId: true },
    });
    return created.positionId ?? initial;
  }

  /**
   * MIN(position) of the consumer's cursors of **another shard count** (`outbox:<consumer>` or
   * `outbox:<consumer>#i/m` with m != n). Every row at or below such a minimum was handled under
   * the previous layout (a cursor only passes handled rows), so starting there re-reads and never
   * skips. Sibling cursors of the same count are excluded: they cover other residues and may
   * have advanced past rows of this shard that nobody handled yet.
   */
  private async minimumExistingCursor(): Promise<bigint | null> {
    const rows = await this.options.prisma.streamCursor.findMany({
      where: { name: { startsWith: this.baseCursorName }, positionId: { not: null } },
      select: { name: true, positionId: true },
    });
    const sibling = new RegExp(`#\\d+/${this.shard.count}$`);
    let min: bigint | null = null;
    for (const row of rows) {
      if (row.positionId === null || row.name === this.cursorName) continue;
      const suffix = row.name.slice(this.baseCursorName.length);
      const otherLayout =
        (suffix === '' && this.shard.count > 1) ||
        (suffix.startsWith('#') && !sibling.test(suffix));
      if (!otherLayout) continue;
      if (min === null || row.positionId < min) min = row.positionId;
    }
    return min;
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

function validateOptions(options: OutboxPollerOptions<unknown>): void {
  const positiveInt = (value: number | undefined) =>
    value === undefined || (Number.isInteger(value) && value >= 1);
  if (options.consumer.length === 0 || options.consumer.includes('#')) {
    throw new Error('outbox consumer name must be non-empty and must not contain "#"');
  }
  if (!/^[a-z0-9]+$/i.test(options.lockPrefix)) {
    throw new Error('outbox lock prefix must be alphanumeric');
  }
  if (!positiveInt(options.batchSize)) throw new Error('outbox batchSize must be an integer >= 1');
  if (!positiveInt(options.concurrency)) {
    throw new Error('outbox concurrency must be an integer >= 1');
  }
  if (!positiveInt(options.maxHeldLocks)) {
    throw new Error('outbox maxHeldLocks must be an integer >= 1');
  }
  const shard = options.shard;
  if (
    shard &&
    (!positiveInt(shard.count) ||
      !Number.isInteger(shard.index) ||
      shard.index < 0 ||
      shard.index >= shard.count)
  ) {
    throw new Error('outbox shard must satisfy 0 <= index < count');
  }
  const backoff = options.failureBackoff;
  if (backoff && !(backoff.baseMs > 0 && backoff.maxMs >= backoff.baseMs)) {
    throw new Error('outbox failureBackoff must satisfy 0 < baseMs <= maxMs');
  }
}

/** Runs `fn` over `items` with at most `limit` calls in flight. */
async function runPool<I>(items: I[], limit: number, fn: (item: I) => Promise<void>) {
  let next = 0;
  const workers = Array.from({ length: Math.min(limit, items.length) }, async () => {
    while (next < items.length) {
      const item = items[next]!;
      next += 1;
      await fn(item);
    }
  });
  await Promise.all(workers);
}

/** A second row with an event id already in the page: done if the first was, else pending. */
function repeatOutcome(first: RowOutcome | undefined): RowOutcome {
  if (first === 'handled' || first === 'duplicate' || first === 'invalid' || first === 'recent') {
    return 'recent';
  }
  return first ?? 'deferred';
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

/** The error's class and code only: messages may quote content (step 3.1 M15). */
function errorFields(err: unknown): { errName: string; errCode?: string } {
  const errName = err instanceof Error ? err.name : typeof err;
  const code =
    typeof err === 'object' && err !== null ? (err as { code?: unknown }).code : undefined;
  return typeof code === 'string' || typeof code === 'number'
    ? { errName, errCode: String(code) }
    : { errName };
}
