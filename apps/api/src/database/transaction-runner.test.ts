import type { PrismaService } from '@email-gateway/common';
import { Prisma } from '@email-gateway/database';
import { describe, expect, it, vi } from 'vitest';
import { TransactionRunner } from './transaction-runner';

describe('TransactionRunner', () => {
  it('runs the callback in a writer transaction with bounded timeouts', async () => {
    const tx = { marker: 'tx' };
    const $transaction = vi.fn((fn: (t: unknown) => Promise<unknown>) => fn(tx));
    const runner = new TransactionRunner({ $transaction } as unknown as PrismaService);
    const result = await runner.run((client) =>
      Promise.resolve((client as unknown as typeof tx).marker),
    );
    expect(result).toBe('tx');
    expect($transaction).toHaveBeenCalledWith(expect.any(Function), {
      timeout: 15_000,
      maxWait: 5_000,
    });
  });

  it('passes isolation level and timeouts through', async () => {
    const $transaction = vi.fn().mockResolvedValue(1);
    const runner = new TransactionRunner({ $transaction } as unknown as PrismaService);
    await runner.run(() => Promise.resolve(1), {
      isolationLevel: Prisma.TransactionIsolationLevel.Serializable,
      timeoutMs: 1_000,
      maxWaitMs: 500,
    });
    expect($transaction).toHaveBeenCalledWith(expect.any(Function), {
      timeout: 1_000,
      maxWait: 500,
      isolationLevel: 'Serializable',
    });
  });

  it('propagates failures (the transaction rolls back)', async () => {
    const $transaction = vi.fn((fn: (t: unknown) => Promise<unknown>) => fn({}));
    const runner = new TransactionRunner({ $transaction } as unknown as PrismaService);
    await expect(runner.run(() => Promise.reject(new Error('boom')))).rejects.toThrow('boom');
  });
});
