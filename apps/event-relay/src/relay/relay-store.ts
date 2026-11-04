import { Prisma, type PrismaClient } from '@email-gateway/database';

/** One shard of the relay: rows with `MOD(CRC32(CONCAT(aggregate_type, ':', aggregate_id)), count) = index`. */
export interface RelayShard {
  index: number;
  count: number;
}

/** The columns of an unpublished outbox row the relay reads (Q11 step 3). */
export interface OutboxRow {
  id: bigint;
  createdAt: Date;
  eventId: string;
  organizationId: bigint;
  eventType: string;
  aggregateType: string;
  aggregateId: string;
  correlationId: string;
  payload: unknown;
  availableAt: Date;
  attempts: number;
}

/** Primary key of a `message_outbox` row (partitioned by `created_at`). */
export interface OutboxKey {
  id: bigint;
  createdAt: Date;
}

export interface FailedRow extends OutboxKey {
  /** `available_at` of the next attempt. */
  availableAt: Date;
  /** A code (`nacked`, `unroutable`), never an error message. */
  code: string;
  /**
   * `attempts + 1` (row-specific: `unroutable`). False for a broker nack (a full or unavailable
   * queue is infrastructure): the row is only deferred and can never become poison that way.
   */
  countsAttempt: boolean;
}

export interface PoisonRow extends OutboxKey {
  code: string;
}

export interface ReadOptions {
  shard: RelayShard;
  limit: number;
  maxAttempts: number;
  /** Optional `organization_id IN (…)` scope (tests, dedicated per-tenant relays). */
  organizationIds?: readonly bigint[];
}

/** The relay's database access (a fake implements it in unit tests). */
export interface RelayStore {
  /** Q11 step 3: unpublished, non-poison rows of the shard in id order. */
  readUnpublished(options: ReadOptions): Promise<OutboxRow[]>;
  /** `created_at` of the oldest unpublished, non-poison row of the shard (unowned-shard lag). */
  oldestUnpublished(options: Omit<ReadOptions, 'limit'>): Promise<Date | null>;
  /** Q11 step 7: `published_at = NOW(3)` for rows still unpublished; returns rows changed. */
  markPublished(rows: readonly OutboxKey[]): Promise<number>;
  /**
   * Q11 step 6: `available_at`, `last_error`, and `attempts + 1` when `countsAttempt` (mandatory
   * return; a broker nack only defers the row).
   */
  markFailed(rows: readonly FailedRow[]): Promise<void>;
  /** Q11 step 5: `attempts = maxAttempts`, `last_error = code` (never published). */
  markPoison(rows: readonly PoisonRow[], maxAttempts: number): Promise<void>;
}

/** The SQL shard predicate (also computed in TypeScript by `shardOf`). */
export function shardPredicate(shard: RelayShard): Prisma.Sql {
  return Prisma.sql`MOD(CRC32(CONCAT(aggregate_type, ':', aggregate_id)), ${shard.count}) = ${shard.index}`;
}

function scopePredicate(organizationIds: readonly bigint[] | undefined): Prisma.Sql {
  if (organizationIds === undefined) return Prisma.empty;
  if (organizationIds.length === 0) return Prisma.sql`AND FALSE`;
  return Prisma.sql`AND organization_id IN (${Prisma.join([...organizationIds])})`;
}

/**
 * `(id = ? AND created_at = ?) OR …` for a set of primary keys. (A row-constructor
 * `(id, created_at) IN ((?, ?), …)` is not used: MySQL rejects the DATETIME parameters of a
 * prepared row constructor with error 1292 through Prisma's binary protocol.)
 */
function keyMatch(rows: readonly OutboxKey[]): Prisma.Sql {
  return Prisma.join(
    rows.map((r) => Prisma.sql`(id = ${r.id} AND created_at = ${r.createdAt})`),
    ' OR ',
  );
}

interface RawRow {
  id: bigint | number;
  created_at: Date;
  event_id: string;
  organization_id: bigint | number;
  event_type: string;
  aggregate_type: string;
  aggregate_id: string;
  correlation_id: string;
  payload: unknown;
  available_at: Date;
  attempts: bigint | number;
}

/** `RelayStore` on the MySQL writer (raw SQL on `message_outbox`, index `(published_at, id)`). */
export class PrismaRelayStore implements RelayStore {
  constructor(private readonly prisma: PrismaClient) {}

  async readUnpublished(options: ReadOptions): Promise<OutboxRow[]> {
    const rows = await this.prisma.$queryRaw<RawRow[]>`
      SELECT id, created_at, event_id, organization_id, event_type, aggregate_type, aggregate_id,
             correlation_id, payload, available_at, attempts
      FROM message_outbox
      WHERE published_at IS NULL AND attempts < ${options.maxAttempts}
        AND ${shardPredicate(options.shard)} ${scopePredicate(options.organizationIds)}
      ORDER BY id
      LIMIT ${options.limit}`;
    return rows.map((r) => ({
      id: BigInt(r.id),
      createdAt: r.created_at,
      eventId: r.event_id,
      organizationId: BigInt(r.organization_id),
      eventType: r.event_type,
      aggregateType: r.aggregate_type,
      aggregateId: r.aggregate_id,
      correlationId: r.correlation_id,
      payload: r.payload,
      availableAt: r.available_at,
      attempts: Number(r.attempts),
    }));
  }

  async oldestUnpublished(options: Omit<ReadOptions, 'limit'>): Promise<Date | null> {
    const [row] = await this.prisma.$queryRaw<{ oldest: Date | null }[]>`
      SELECT MIN(created_at) AS oldest
      FROM message_outbox
      WHERE published_at IS NULL AND attempts < ${options.maxAttempts}
        AND ${shardPredicate(options.shard)} ${scopePredicate(options.organizationIds)}`;
    return row?.oldest ?? null;
  }

  async markPublished(rows: readonly OutboxKey[]): Promise<number> {
    if (rows.length === 0) return 0;
    return this.prisma.$executeRaw`
      UPDATE message_outbox SET published_at = NOW(3)
      WHERE published_at IS NULL AND (${keyMatch(rows)})`;
  }

  async markFailed(rows: readonly FailedRow[]): Promise<void> {
    // One statement per (code, available_at) would need a CASE; rows per batch are few.
    for (const row of rows) {
      const increment = row.countsAttempt ? 1 : 0;
      await this.prisma.$executeRaw`
        UPDATE message_outbox
        SET attempts = attempts + ${increment}, available_at = ${row.availableAt},
            last_error = ${row.code}
        WHERE id = ${row.id} AND created_at = ${row.createdAt} AND published_at IS NULL`;
    }
  }

  async markPoison(rows: readonly PoisonRow[], maxAttempts: number): Promise<void> {
    for (const row of rows) {
      await this.prisma.$executeRaw`
        UPDATE message_outbox SET attempts = ${maxAttempts}, last_error = ${row.code}
        WHERE id = ${row.id} AND created_at = ${row.createdAt} AND published_at IS NULL`;
    }
  }
}
