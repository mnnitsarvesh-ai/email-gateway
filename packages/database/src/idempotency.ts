import { Prisma, type PrismaClient } from '@prisma/client';

export type IdempotentResult<T> = { status: 'processed'; result: T } | { status: 'duplicate' };

class DuplicateEventError extends Error {}

/**
 * Runs `handler` at most once per (consumer, eventId), atomically with its side effects
 * (ADR-0005). The ledger is the `message_idempotency` table.
 *
 * The ledger row is inserted first inside the transaction. If another delivery of the same
 * event already committed, that insert fails on the primary key and the handler never runs.
 * If the handler throws, the whole transaction (ledger row included) rolls back so a retry can
 * succeed. Unique violations raised by the handler itself propagate unchanged.
 */
export async function processOnce<T>(
  prisma: PrismaClient,
  consumer: string,
  eventId: string,
  handler: (tx: Prisma.TransactionClient) => Promise<T>,
): Promise<IdempotentResult<T>> {
  try {
    return await prisma.$transaction(async (tx) => {
      try {
        await tx.messageIdempotency.create({ data: { consumer, eventId } });
      } catch (err) {
        if (err instanceof Prisma.PrismaClientKnownRequestError && err.code === 'P2002') {
          throw new DuplicateEventError();
        }
        throw err;
      }
      return { status: 'processed', result: await handler(tx) } as const;
    });
  } catch (err) {
    if (err instanceof DuplicateEventError) return { status: 'duplicate' };
    throw err;
  }
}
