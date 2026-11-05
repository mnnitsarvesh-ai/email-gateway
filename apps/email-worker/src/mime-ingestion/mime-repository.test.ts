import type { PrismaClient } from '@email-gateway/database';
import { describe, expect, it, vi } from 'vitest';
import { MimeRepository } from './mime-repository';

/**
 * Every writer transaction of the repository runs with MIME_DB_TIMEOUT_MS as timeout and maxWait,
 * never with Prisma's 5 s default: an expired interactive transaction is a wrong-read trigger on
 * Prisma 6.19.3 (docs/plan/steps/10-attachment-scanning.md §6, §13).
 */
describe('MimeRepository transaction budget', () => {
  it('runs the markParsing re-attempt transaction with the configured budget', async () => {
    const tx = {
      emailMessageParse: {
        updateMany: vi.fn().mockResolvedValue({ count: 1 }),
        findFirst: vi.fn().mockResolvedValue({ attempts: 2 }),
      },
    };
    const $transaction = vi.fn(
      (fn: (t: typeof tx) => Promise<unknown>, _options?: { timeout: number; maxWait: number }) =>
        fn(tx),
    );
    const prisma = {
      $transaction,
      emailMessageParse: {
        findFirst: vi.fn().mockResolvedValue({ status: 'parsing', attempts: 1 }),
      },
    } as unknown as PrismaClient;
    const repo = new MimeRepository(prisma, 120_000);
    const message = {
      id: 7n,
      receivedAt: new Date('2026-11-05T00:00:00.000Z'),
      organizationId: 3n,
      direction: 'inbound',
      emlObjectKey: 'org/3/eml/7.eml',
      emlSha256: 'a'.repeat(64),
      sizeBytes: 10,
    } as Parameters<MimeRepository['markParsing']>[0];

    const result = await repo.markParsing(message, {
      eventId: 'evt-1',
      parserVersion: 'p1',
      startedAt: new Date('2026-11-05T00:00:01.000Z'),
    });

    expect(result).toEqual({ kind: 'parsing', attempts: 2 });
    expect($transaction).toHaveBeenCalledTimes(1);
    expect($transaction.mock.calls[0]?.[1]).toEqual({ timeout: 120_000, maxWait: 120_000 });
  });
});
