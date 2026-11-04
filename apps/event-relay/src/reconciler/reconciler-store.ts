import { Prisma, type PrismaClient } from '@email-gateway/database';

/** The columns of an outbox row the reconciler reads. */
export interface SweepRow {
  id: bigint;
  createdAt: Date;
  eventId: string;
  eventType: string;
  publishedAt: Date | null;
  attempts: number;
  redriveCount: number;
  lastRedrivenAt: Date | null;
}

export interface OutboxHealth {
  /** Unpublished, non-poison rows (capped at `cap`). */
  unpublished: number;
  /** `created_at` of the oldest unpublished, non-poison row. */
  oldestUnpublished: Date | null;
  /** Rows with `attempts >= maxAttempts` still unpublished. */
  poison: number;
  oldestPoisonId: bigint | null;
}

export interface Scope {
  organizationIds?: readonly bigint[];
}

/** A consumer's `message_consumer_progress` row of an event it has not handled. */
export interface ConsumerProgress {
  state: 'retrying' | 'dead_lettered';
  /** The dead-letter reason code (`null` for `retrying`). */
  reason: string | null;
  /** Database clock (`NOW(3)` of the consumer's last hop). */
  updatedAt: Date;
}

/** The reconciler's database access (a fake implements it in unit tests). */
export interface ReconcilerStore {
  health(maxAttempts: number, cap: number, scope: Scope): Promise<OutboxHealth>;
  /** `position_id` of the cursor, `undefined` when the cursor does not exist (first start). */
  loadCursor(name: string): Promise<bigint | null | undefined>;
  /** Creates (or completes a position-less) cursor; returns the stored position. */
  initCursor(name: string, position: bigint): Promise<bigint>;
  saveCursor(name: string, position: bigint, at: Date): Promise<void>;
  /** `MIN(id) − 1` of rows created at or after `since` (else `MAX(id)`, else 0). */
  oldestPosition(since: Date, scope: Scope): Promise<bigint>;
  /** `MAX(id)` (0 when empty). */
  latestPosition(scope: Scope): Promise<bigint>;
  /** Rows `id > after` with `created_at >= since`, in id order. */
  readAfter(after: bigint, since: Date, limit: number, scope: Scope): Promise<SweepRow[]>;
  /** Event ids among `eventIds` that have a `message_idempotency (consumer, event_id)` row. */
  ledgerPresent(consumer: string, eventIds: readonly string[]): Promise<Set<string>>;
  /** `message_consumer_progress` rows of `consumer` for `eventIds`, by event id. */
  progress(consumer: string, eventIds: readonly string[]): Promise<Map<string, ConsumerProgress>>;
  /**
   * A deferral: `last_redriven_at = NOW(3)` without a re-drive (the row stays published and its
   * `redrive_count` unchanged), so the re-check looks at it again after the threshold. True when
   * changed.
   */
  watch(row: Pick<SweepRow, 'id' | 'createdAt'>): Promise<boolean>;
  /**
   * Q12 re-drive: `published_at = NULL, available_at = NOW(3), redrive_count + 1,
   * last_redriven_at = NOW(3)` while published and below `maxRedrives`. True when changed.
   */
  redrive(row: Pick<SweepRow, 'id' | 'createdAt'>, maxRedrives: number): Promise<boolean>;
  /** `last_redriven_at = NULL` (settled or exhausted; `redrive_count` kept as history). */
  clearRedrive(row: Pick<SweepRow, 'id' | 'createdAt'>): Promise<void>;
  /**
   * Re-driven rows due for their re-check: `last_redriven_at < before` and published before
   * `before` as well (the consumer had the full threshold since the republish). Index
   * `last_redriven_at`.
   */
  dueRechecks(before: Date, limit: number, scope: Scope): Promise<SweepRow[]>;
}

function scopePredicate(scope: Scope): Prisma.Sql {
  const ids = scope.organizationIds;
  if (ids === undefined) return Prisma.empty;
  if (ids.length === 0) return Prisma.sql`AND FALSE`;
  return Prisma.sql`AND organization_id IN (${Prisma.join([...ids])})`;
}

interface RawSweepRow {
  id: bigint | number;
  created_at: Date;
  event_id: string;
  event_type: string;
  published_at: Date | null;
  attempts: bigint | number;
  redrive_count: bigint | number;
  last_redriven_at: Date | null;
}

const toSweepRow = (r: RawSweepRow): SweepRow => ({
  id: BigInt(r.id),
  createdAt: r.created_at,
  eventId: r.event_id,
  eventType: r.event_type,
  publishedAt: r.published_at,
  attempts: Number(r.attempts),
  redriveCount: Number(r.redrive_count),
  lastRedrivenAt: r.last_redriven_at,
});

const optionalBigInt = (value: bigint | number | null | undefined): bigint | null =>
  value === null || value === undefined ? null : BigInt(value);

/** `ReconcilerStore` on the MySQL writer. */
export class PrismaReconcilerStore implements ReconcilerStore {
  constructor(private readonly prisma: PrismaClient) {}

  async health(maxAttempts: number, cap: number, scope: Scope): Promise<OutboxHealth> {
    const scoped = scopePredicate(scope);
    const [count] = await this.prisma.$queryRaw<{ n: bigint | number }[]>`
      SELECT COUNT(*) AS n FROM (
        SELECT 1 FROM message_outbox
        WHERE published_at IS NULL AND attempts < ${maxAttempts} ${scoped}
        LIMIT ${cap}
      ) AS capped`;
    const [oldest] = await this.prisma.$queryRaw<{ oldest: Date | null }[]>`
      SELECT MIN(created_at) AS oldest FROM message_outbox
      WHERE published_at IS NULL AND attempts < ${maxAttempts} ${scoped}`;
    const [poison] = await this.prisma.$queryRaw<
      { n: bigint | number; oldest_id: bigint | number | null }[]
    >`
      SELECT COUNT(*) AS n, MIN(id) AS oldest_id FROM message_outbox
      WHERE published_at IS NULL AND attempts >= ${maxAttempts} ${scoped}`;
    return {
      unpublished: Number(count?.n ?? 0),
      oldestUnpublished: oldest?.oldest ?? null,
      poison: Number(poison?.n ?? 0),
      oldestPoisonId: optionalBigInt(poison?.oldest_id),
    };
  }

  async loadCursor(name: string): Promise<bigint | null | undefined> {
    const cursor = await this.prisma.streamCursor.findUnique({
      where: { name },
      select: { positionId: true },
    });
    return cursor === null ? undefined : cursor.positionId;
  }

  async initCursor(name: string, position: bigint): Promise<bigint> {
    try {
      await this.prisma.streamCursor.create({ data: { name, positionId: position } });
    } catch (error) {
      // A concurrent first start or a position-less row: completed, never reset.
      if (!(error instanceof Prisma.PrismaClientKnownRequestError && error.code === 'P2002')) {
        throw error;
      }
      await this.prisma.streamCursor.updateMany({
        where: { name, positionId: null },
        data: { positionId: position },
      });
    }
    const stored = await this.prisma.streamCursor.findUniqueOrThrow({
      where: { name },
      select: { positionId: true },
    });
    return stored.positionId ?? position;
  }

  async saveCursor(name: string, position: bigint, at: Date): Promise<void> {
    await this.prisma.streamCursor.update({
      where: { name },
      data: { positionId: position, lastEventAt: at },
    });
  }

  async oldestPosition(since: Date, scope: Scope): Promise<bigint> {
    const [row] = await this.prisma.$queryRaw<{ id: bigint | number | null }[]>`
      SELECT MIN(id) AS id FROM message_outbox WHERE created_at >= ${since} ${scopePredicate(scope)}`;
    const min = optionalBigInt(row?.id);
    if (min !== null) return min - 1n;
    return this.latestPosition(scope);
  }

  async latestPosition(scope: Scope): Promise<bigint> {
    const [row] = await this.prisma.$queryRaw<{ id: bigint | number | null }[]>`
      SELECT MAX(id) AS id FROM message_outbox WHERE TRUE ${scopePredicate(scope)}`;
    return optionalBigInt(row?.id) ?? 0n;
  }

  async readAfter(after: bigint, since: Date, limit: number, scope: Scope): Promise<SweepRow[]> {
    const rows = await this.prisma.$queryRaw<RawSweepRow[]>`
      SELECT id, created_at, event_id, event_type, published_at, attempts, redrive_count,
             last_redriven_at
      FROM message_outbox
      WHERE id > ${after} AND created_at >= ${since} ${scopePredicate(scope)}
      ORDER BY id
      LIMIT ${limit}`;
    return rows.map(toSweepRow);
  }

  async ledgerPresent(consumer: string, eventIds: readonly string[]): Promise<Set<string>> {
    if (eventIds.length === 0) return new Set();
    const rows = await this.prisma.messageIdempotency.findMany({
      where: { consumer, eventId: { in: [...new Set(eventIds)] } },
      select: { eventId: true },
    });
    return new Set(rows.map((r) => r.eventId));
  }

  async progress(
    consumer: string,
    eventIds: readonly string[],
  ): Promise<Map<string, ConsumerProgress>> {
    if (eventIds.length === 0) return new Map();
    const rows = await this.prisma.messageConsumerProgress.findMany({
      where: { consumer, eventId: { in: [...new Set(eventIds)] } },
      select: { eventId: true, state: true, reason: true, updatedAt: true },
    });
    return new Map(
      rows.map((r) => [r.eventId, { state: r.state, reason: r.reason, updatedAt: r.updatedAt }]),
    );
  }

  async watch(row: Pick<SweepRow, 'id' | 'createdAt'>): Promise<boolean> {
    const changed = await this.prisma.$executeRaw`
      UPDATE message_outbox SET last_redriven_at = NOW(3)
      WHERE id = ${row.id} AND created_at = ${row.createdAt} AND published_at IS NOT NULL`;
    return changed > 0;
  }

  async redrive(row: Pick<SweepRow, 'id' | 'createdAt'>, maxRedrives: number): Promise<boolean> {
    const changed = await this.prisma.$executeRaw`
      UPDATE message_outbox
      SET published_at = NULL, available_at = NOW(3), redrive_count = redrive_count + 1,
          last_redriven_at = NOW(3)
      WHERE id = ${row.id} AND created_at = ${row.createdAt}
        AND published_at IS NOT NULL AND redrive_count < ${maxRedrives}`;
    return changed > 0;
  }

  async clearRedrive(row: Pick<SweepRow, 'id' | 'createdAt'>): Promise<void> {
    await this.prisma.$executeRaw`
      UPDATE message_outbox SET last_redriven_at = NULL
      WHERE id = ${row.id} AND created_at = ${row.createdAt}`;
  }

  async dueRechecks(before: Date, limit: number, scope: Scope): Promise<SweepRow[]> {
    const rows = await this.prisma.$queryRaw<RawSweepRow[]>`
      SELECT id, created_at, event_id, event_type, published_at, attempts, redrive_count,
             last_redriven_at
      FROM message_outbox
      WHERE last_redriven_at < ${before} AND published_at IS NOT NULL
        AND published_at < ${before} ${scopePredicate(scope)}
      ORDER BY last_redriven_at
      LIMIT ${limit}`;
    return rows.map(toSweepRow);
  }
}
