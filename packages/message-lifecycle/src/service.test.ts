import { Prisma, type PrismaClient } from '@email-gateway/database';
import { describe, expect, it, vi } from 'vitest';
import {
  isRetryableLifecycleError,
  LifecycleContractError,
  LifecycleVersionConflictError,
} from './errors';
import { transitionKeyHash } from './keys';
import type { LifecycleMetrics } from './metrics';
import {
  retryDelayMs,
  transitionMessage,
  transitionMessageWithRetry,
  type TransitionRequest,
} from './service';

const known = (code: string, meta?: Record<string, unknown>, message = 'failed') =>
  new Prisma.PrismaClientKnownRequestError(message, { code, clientVersion: 'test', meta });

const request: TransitionRequest = {
  message: { id: 1n, receivedAt: new Date('2026-11-04T10:00:00Z'), organizationId: 2n },
  to: 'approved',
  reason: 'dev_passthrough',
  actor: { role: 'dev_passthrough', service: 'delivery-worker', type: 'system' },
  transitionKey: 'evt:0190f0a0-0000-7000-8000-000000000001:approved',
  expectedRound: 0,
  expectedFrom: ['scanned'],
};

function countingMetrics() {
  const calls: string[] = [];
  const metrics: LifecycleMetrics = {
    transition: (from, to, result) => calls.push(`transition:${from}:${to}:${result}`),
    ignored: (reason) => calls.push(`ignored:${reason}`),
    versionConflict: () => calls.push('conflict'),
    derivedSkipped: (state) => calls.push(`skipped:${state}`),
  };
  return { metrics, calls };
}

describe('transitionKeyHash', () => {
  it('is the hex SHA-256 of the key and refuses empty or > 512 character keys', () => {
    expect(transitionKeyHash('a')).toBe(
      'ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb',
    );
    expect(transitionKeyHash('x'.repeat(512))).toMatch(/^[0-9a-f]{64}$/);
    expect(() => transitionKeyHash('')).toThrow(LifecycleContractError);
    expect(() => transitionKeyHash('x'.repeat(513))).toThrow(LifecycleContractError);
  });
});

describe('isRetryableLifecycleError (L5.4)', () => {
  it('retries conflicts, deadlocks, lock waits, P2034 and P2002 on the transition key', () => {
    expect(isRetryableLifecycleError(new LifecycleVersionConflictError(1n))).toBe(true);
    expect(isRetryableLifecycleError(known('P2034'))).toBe(true);
    expect(isRetryableLifecycleError(known('P2010', { code: '1213' }))).toBe(true);
    expect(isRetryableLifecycleError(known('P2010', { code: '1205' }))).toBe(true);
    expect(
      isRetryableLifecycleError(
        known('P2010', {}, 'Raw query failed. Code: `1213`. Deadlock found'),
      ),
    ).toBe(true);
    expect(
      isRetryableLifecycleError(
        known('P2002', {
          target: 'email_message_status_history_message_id_transition_key_recei_key',
        }),
      ),
    ).toBe(true);
    expect(
      isRetryableLifecycleError(known('P2002', { target: ['messageId', 'transitionKey'] })),
    ).toBe(true);
  });

  it('does not retry other errors (connections, other unique keys, contracts)', () => {
    expect(isRetryableLifecycleError(known('P2002', { target: 'PRIMARY' }))).toBe(false);
    expect(isRetryableLifecycleError(known('P1001'))).toBe(false);
    expect(isRetryableLifecycleError(known('P2010', { code: '1062' }, 'Duplicate entry'))).toBe(
      false,
    );
    expect(isRetryableLifecycleError(new LifecycleContractError('to', 'x'))).toBe(false);
    expect(isRetryableLifecycleError(new Error('deadlock'))).toBe(false);
  });
});

describe('retryDelayMs', () => {
  it('is equal jitter over 20 ms doubling up to 500 ms', () => {
    expect(retryDelayMs(1, () => 0)).toBe(10);
    expect(retryDelayMs(1, () => 1)).toBe(20);
    expect(retryDelayMs(3, () => 0)).toBe(40);
    expect(retryDelayMs(10, () => 0)).toBe(250);
    expect(retryDelayMs(10, () => 1)).toBe(500);
  });
});

describe('transitionMessage request validation (L5.7)', () => {
  const tx = {} as Prisma.TransactionClient;
  it.each([
    ['to', { to: 'nope' }],
    ['reason', { reason: 'nope' }],
    ['actor.role', { actor: { ...request.actor, role: 'nope' } }],
    ['actor.type', { actor: { ...request.actor, type: 'robot' } }],
    ['actor.service', { actor: { ...request.actor, service: '' } }],
    ['transitionKey', { transitionKey: '' }],
    ['causationEventId', { causationEventId: 'not-a-uuid' }],
    ['correlationId', { correlationId: 'x'.repeat(129) }],
    ['expectedRound', { expectedRound: 70_000 }],
    ['expectedVersion', { expectedVersion: -1 }],
    ['expectedFrom', { expectedFrom: ['nope'] }],
  ])('refuses an invalid %s before touching the database', async (field, patch) => {
    const error = await transitionMessage(tx, { ...request, ...patch } as TransitionRequest).catch(
      (e: unknown) => e,
    );
    expect(error).toBeInstanceOf(LifecycleContractError);
    expect((error as LifecycleContractError).field).toBe(field);
  });
});

describe('transitionMessageWithRetry', () => {
  const applied = { result: 'not_found' } as const;
  const prismaFailing = (...errors: Error[]) => {
    const $transaction = vi.fn((_fn: unknown, _opts: unknown) => {
      const next = errors.shift();
      return next === undefined ? Promise.resolve(applied) : Promise.reject(next);
    });
    return { prisma: { $transaction } as unknown as PrismaClient, $transaction };
  };

  it('retries retryable errors with backoff and counts each retry', async () => {
    const { prisma, $transaction } = prismaFailing(
      known('P2034'),
      new LifecycleVersionConflictError(1n),
    );
    const { metrics, calls } = countingMetrics();
    const sleeps: number[] = [];
    const outcome = await transitionMessageWithRetry(
      prisma,
      request,
      { timeoutMs: 5000 },
      { metrics, sleep: (ms) => Promise.resolve(void sleeps.push(ms)), random: () => 0 },
    );
    expect(outcome).toEqual(applied);
    expect($transaction).toHaveBeenCalledTimes(3);
    expect($transaction.mock.calls[0]?.[1]).toEqual({ timeout: 5000, maxWait: 5000 });
    expect(sleeps).toEqual([10, 20]);
    expect(calls).toEqual(['conflict', 'conflict']);
  });

  it('rethrows after maxAttempts and never retries a non-retryable error', async () => {
    const sleep = () => Promise.resolve();
    const exhausted = prismaFailing(known('P2034'), known('P2034'), known('P2034'));
    await expect(
      transitionMessageWithRetry(
        exhausted.prisma,
        request,
        { timeoutMs: 100, maxAttempts: 3 },
        { sleep },
      ),
    ).rejects.toMatchObject({ code: 'P2034' });
    expect(exhausted.$transaction).toHaveBeenCalledTimes(3);

    const fatal = prismaFailing(known('P1001'));
    await expect(
      transitionMessageWithRetry(fatal.prisma, request, { timeoutMs: 100 }, { sleep }),
    ).rejects.toMatchObject({ code: 'P1001' });
    expect(fatal.$transaction).toHaveBeenCalledTimes(1);
  });

  it('refuses a malformed request without opening a transaction', async () => {
    const { prisma, $transaction } = prismaFailing();
    await expect(
      transitionMessageWithRetry(prisma, { ...request, transitionKey: '' }, { timeoutMs: 100 }),
    ).rejects.toBeInstanceOf(LifecycleContractError);
    expect($transaction).not.toHaveBeenCalled();
  });
});
