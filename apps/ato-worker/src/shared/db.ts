import { createHash } from 'node:crypto';
import { withTransactionDefaults } from '@email-gateway/common';
import { Prisma, type PrismaClient, processOnce } from '@email-gateway/database';
import { ATO_TRANSACTION_ISOLATION, uuidFromDigest } from '@email-gateway/ato-detection';

/** A writer client or an interactive transaction of it. */
export type Db = PrismaClient | Prisma.TransactionClient;
export type Tx = Prisma.TransactionClient;

/** Ledger consumers of the ato-worker (`message_idempotency.consumer`, D3, D15). */
export const LEDGERS = Object.freeze({
  events: 'ato-worker.events',
  mail: 'ato-worker.mail',
  respond: 'ato-worker.respond',
  provider: 'ato-worker.provider',
});

/** A deterministic event id (UUID shape) for a sub-key of a source event (`eventId:seq`). */
export function subEventId(...parts: readonly string[]): string {
  return uuidFromDigest(createHash('sha256').update(parts.join('\0'), 'utf8').digest());
}

/**
 * Writer transactions of the worker: every interactive transaction runs with
 * `ATO_TX_TIMEOUT_MS` (≥ 120 s, the 4.2 §6 wrong-read rule) at READ COMMITTED
 * (`ATO_TRANSACTION_ISOLATION`: the store's lock-then-read patterns), and `once` runs a handler under a
 * `processOnce` ledger row (`message_idempotency`) in the same transaction.
 */
export class AtoDb {
  readonly tx: PrismaClient;

  constructor(
    readonly prisma: PrismaClient,
    readonly timeoutMs: number,
  ) {
    this.tx = withTransactionDefaults(prisma, {
      timeoutMs,
      maxWaitMs: Math.min(timeoutMs, 30_000),
      isolationLevel: ATO_TRANSACTION_ISOLATION,
    });
  }

  transaction<T>(fn: (tx: Tx) => Promise<T>): Promise<T> {
    return this.tx.$transaction(fn);
  }

  async once<T>(
    consumer: string,
    eventId: string,
    fn: (tx: Tx) => Promise<T>,
  ): Promise<{ status: 'processed'; result: T } | { status: 'duplicate' }> {
    return processOnce(this.tx, consumer, eventId, fn);
  }

  /** Whether a ledger row exists (catch-up skips keys the live consumer already processed). */
  async processed(consumer: string, eventId: string): Promise<boolean> {
    const row = await this.prisma.messageIdempotency.findUnique({
      where: { consumer_eventId: { consumer, eventId } },
      select: { eventId: true },
    });
    return row !== null;
  }
}

/** `stream_cursors` row of a forward sweep. */
export interface CursorRow {
  positionId: bigint | null;
  lastEventAt: Date | null;
}

export async function readCursor(db: Db, name: string): Promise<CursorRow | null> {
  const row = await db.streamCursor.findUnique({
    where: { name },
    select: { name: true, positionId: true, lastEventAt: true },
  });
  if (row === null || row.name !== name) return null;
  return { positionId: row.positionId, lastEventAt: row.lastEventAt };
}

export async function writeCursor(
  db: Db,
  name: string,
  positionId: bigint | null,
  lastEventAt: Date | null,
): Promise<void> {
  await db.streamCursor.upsert({
    where: { name },
    create: { name, positionId, lastEventAt },
    update: { positionId, lastEventAt },
  });
}

/**
 * A restriction of a job to some organizations (integration suites run the jobs in-process
 * against the shared writer). `undefined` = every organization; an empty list matches nothing.
 */
export function orgFilter(column: string, ids: readonly bigint[] | undefined): Prisma.Sql {
  if (ids === undefined) return Prisma.empty;
  return ids.length === 0
    ? Prisma.sql`AND 1 = 0`
    : Prisma.sql`AND ${Prisma.raw(column)} IN (${Prisma.join(ids)})`;
}

export function orgAllowed(organizationId: bigint, ids: readonly bigint[] | undefined): boolean {
  return ids === undefined || ids.includes(organizationId);
}

/** `BIGINT` from a raw row value (MySQL returns bigint, number or string). */
export const big = (value: bigint | number | string): bigint => BigInt(value);
export const num = (value: bigint | number | string | boolean | null | undefined): number =>
  Number(value ?? 0);

/** Measures a promise into a histogram (seconds). */
export async function timed<T>(
  observe: (seconds: number) => void,
  fn: () => Promise<T>,
): Promise<T> {
  const started = performance.now();
  try {
    return await fn();
  } finally {
    observe((performance.now() - started) / 1000);
  }
}
