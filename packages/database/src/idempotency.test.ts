import { Prisma, type PrismaClient } from '@prisma/client';
import { describe, expect, it, vi } from 'vitest';
import { processOnce } from './idempotency';

function uniqueViolation(): Prisma.PrismaClientKnownRequestError {
  return new Prisma.PrismaClientKnownRequestError('Unique constraint failed', {
    code: 'P2002',
    clientVersion: Prisma.prismaVersion.client,
  });
}

/**
 * A fake client whose `$transaction` runs the callback against a fake transaction client.
 * `ledgerCreate` controls what the ledger insert does.
 */
function fakeClient(ledgerCreate: (args: unknown) => Promise<unknown>) {
  const create = vi.fn(ledgerCreate);
  const tx = { messageIdempotency: { create } };
  const $transaction = vi.fn((fn: (tx: unknown) => Promise<unknown>) => fn(tx));
  return { prisma: { $transaction } as unknown as PrismaClient, tx, create, $transaction };
}

describe('processOnce', () => {
  it('records the event and returns the handler result', async () => {
    const { prisma, tx, create } = fakeClient(() => Promise.resolve({}));
    const handler = vi.fn(() => Promise.resolve('done'));

    const result = await processOnce(prisma, 'email-worker', 'evt-1', handler);

    expect(result).toEqual({ status: 'processed', result: 'done' });
    expect(create).toHaveBeenCalledWith({
      data: { consumer: 'email-worker', eventId: 'evt-1' },
    });
    expect(handler).toHaveBeenCalledWith(tx);
    expect(create.mock.invocationCallOrder[0]).toBeLessThan(handler.mock.invocationCallOrder[0]!);
  });

  it('returns duplicate without calling the handler when the ledger insert hits P2002', async () => {
    const { prisma } = fakeClient(() => Promise.reject(uniqueViolation()));
    const handler = vi.fn(() => Promise.resolve('done'));

    const result = await processOnce(prisma, 'email-worker', 'evt-1', handler);

    expect(result).toEqual({ status: 'duplicate' });
    expect(handler).not.toHaveBeenCalled();
  });

  it('rejects with the handler error so the transaction rolls back', async () => {
    const { prisma, $transaction } = fakeClient(() => Promise.resolve({}));
    const failure = new Error('handler failed');

    await expect(
      processOnce(prisma, 'email-worker', 'evt-1', () => Promise.reject(failure)),
    ).rejects.toBe(failure);
    // The error escaped the $transaction callback, which is what makes Prisma roll back.
    await expect($transaction.mock.results[0]!.value).rejects.toBe(failure);
  });

  it('propagates a P2002 raised by the handler itself instead of reporting a duplicate', async () => {
    const { prisma } = fakeClient(() => Promise.resolve({}));
    const handlerViolation = uniqueViolation();

    await expect(
      processOnce(prisma, 'email-worker', 'evt-1', () => Promise.reject(handlerViolation)),
    ).rejects.toBe(handlerViolation);
  });

  it('propagates non-P2002 ledger errors without calling the handler', async () => {
    const ledgerError = new Prisma.PrismaClientKnownRequestError('Timed out fetching connection', {
      code: 'P2024',
      clientVersion: Prisma.prismaVersion.client,
    });
    const { prisma } = fakeClient(() => Promise.reject(ledgerError));
    const handler = vi.fn(() => Promise.resolve('done'));

    await expect(processOnce(prisma, 'email-worker', 'evt-1', handler)).rejects.toBe(ledgerError);
    expect(handler).not.toHaveBeenCalled();
  });
});
