import { HttpStatus } from '@nestjs/common';
import { Prisma } from '@email-gateway/database';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import type { TransactionRunner } from '../../database/transaction-runner';
import { CodedHttpException } from '../coded-exception';
import {
  IDEMPOTENCY_KEY_REUSED,
  IDEMPOTENCY_REQUEST_IN_PROGRESS,
  IDEMPOTENCY_TTL_MS,
  IdempotencyInProgressException,
} from './idempotency-key';
import type {
  IdempotencyRecord,
  IdempotencyRepository,
  NewIdempotencyRecord,
} from './idempotency.repository';
import {
  isIdempotencyKeyViolation,
  isIdempotencyRace,
  isWriteConflict,
} from './idempotency.repository';
import {
  IdempotencyRaceError,
  type IdempotentRequest,
  IdempotencyService,
} from './idempotency.service';

type Tx = Prisma.TransactionClient;

/**
 * In-memory `api_idempotency_keys` with transaction semantics: a transaction's inserts and
 * deletes apply only when its function resolves (the fake runner commits or discards them).
 */
class FakeStore {
  rows = new Map<string, IdempotencyRecord & NewIdempotencyRecord>();
  nextId = 1n;
  pending: Array<() => void> = [];
  locks: string[] = [];
  /** Throw this P2002 from the next insert (a concurrent request committed the key). */
  insertConflict: (() => void) | null = null;
  /** The error code of the next insert conflict (P2034: the InnoDB gap-lock deadlock). */
  conflictCode: 'P2002' | 'P2034' = 'P2002';
  /** Every insert fails with an InnoDB deadlock (P2034). */
  alwaysDeadlock = false;

  readonly repo: IdempotencyRepository = {
    lock: (_tx: Tx, organizationId: bigint, key: string) => {
      this.locks.push(`${organizationId}:${key}`);
      return Promise.resolve(this.rows.get(`${organizationId}:${key}`) ?? null);
    },
    delete: (_tx: Tx, id: bigint) => {
      this.pending.push(() => {
        for (const [k, row] of this.rows) if (row.id === id) this.rows.delete(k);
      });
      return Promise.resolve();
    },
    insert: (_tx: Tx, record: NewIdempotencyRecord) => {
      if (this.alwaysDeadlock) return Promise.reject(deadlock());
      if (this.insertConflict) {
        const conflict = this.insertConflict;
        this.insertConflict = null;
        conflict();
        if (this.conflictCode === 'P2034') return Promise.reject(deadlock());
        return Promise.reject(
          new Prisma.PrismaClientKnownRequestError('Unique constraint failed', {
            code: 'P2002',
            clientVersion: 'test',
            meta: { target: 'api_idempotency_keys_organization_id_idempotency_key_key' },
          }),
        );
      }
      const id = this.nextId++;
      this.pending.push(() =>
        this.rows.set(`${record.organizationId}:${record.idempotencyKey}`, {
          ...record,
          id,
        }),
      );
      return Promise.resolve();
    },
  };

  readonly runner = {
    run: vi.fn(async <T>(fn: (tx: Tx) => Promise<T>) => {
      this.pending = [];
      try {
        const result = await fn({} as Tx);
        for (const apply of this.pending) apply();
        return result;
      } finally {
        this.pending = [];
      }
    }),
  } as unknown as TransactionRunner & { run: ReturnType<typeof vi.fn> };

  store(request: IdempotentRequest, overrides: Partial<IdempotencyRecord> = {}): void {
    this.rows.set(`${request.organizationId}:${request.key}`, {
      id: this.nextId++,
      organizationId: request.organizationId,
      idempotencyKey: request.key,
      operation: request.operation,
      principal: request.principal,
      requestSha256: request.fingerprint,
      resourceId: request.resourceId,
      statusCode: 202,
      response: { stored: true },
      expiresAt: new Date(NOW.getTime() + 60_000),
      ...overrides,
    } as IdempotencyRecord & NewIdempotencyRecord);
  }
}

const NOW = new Date('2026-11-04T10:00:00.000Z');

/** What Prisma raises when InnoDB picks the transaction as the deadlock victim (1213). */
function deadlock(): Prisma.PrismaClientKnownRequestError {
  return new Prisma.PrismaClientKnownRequestError(
    'Transaction failed due to a write conflict or a deadlock. Please retry your transaction',
    { code: 'P2034', clientVersion: 'test' },
  );
}

const request: IdempotentRequest = {
  organizationId: 7n,
  principal: 'user:u-1',
  operation: 'message.rescan',
  key: 'key-1',
  resourceId: 'm-1',
  fingerprint: 'f'.repeat(64),
};

function reusedCode(error: unknown): string | undefined {
  return error instanceof CodedHttpException && error.getStatus() === 422 ? error.code : undefined;
}

describe('IdempotencyService', () => {
  let store: FakeStore;
  let service: IdempotencyService;
  const now = NOW;

  beforeEach(() => {
    store = new FakeStore();
    service = new IdempotencyService(store.runner, store.repo);
    vi.spyOn(service, 'now').mockReturnValue(now);
  });

  it('runs the work once, stores its 2xx response for 24 h and replays it afterwards', async () => {
    const work = vi.fn(() => Promise.resolve({ statusCode: 202, body: { done: 1 } }));
    const first = await service.execute(request, work);
    expect(first).toEqual({ replayed: false, statusCode: 202, body: { done: 1 } });
    const row = store.rows.get('7:key-1')!;
    expect(row).toMatchObject({
      operation: 'message.rescan',
      principal: 'user:u-1',
      requestSha256: request.fingerprint,
      resourceId: 'm-1',
      statusCode: 202,
      response: { done: 1 },
    });
    expect(row.expiresAt.getTime()).toBe(now.getTime() + IDEMPOTENCY_TTL_MS);

    const second = await service.execute(request, work);
    expect(second).toEqual({ replayed: true, statusCode: 202, body: { done: 1 } });
    expect(work).toHaveBeenCalledTimes(1);
    expect(store.locks).toEqual(['7:key-1', '7:key-1']);
  });

  it.each([
    ['another body', { fingerprint: 'e'.repeat(64) }],
    ['another principal', { principal: 'api_key:k-9' }],
    ['another operation', { operation: 'message.release' }],
    ['another resource', { resourceId: 'm-2' }],
  ])('refuses the same key with %s as 422 idempotency_key_reused', async (_label, change) => {
    store.store(request);
    const work = vi.fn();
    const error = await service.execute({ ...request, ...change }, work).catch((e: unknown) => e);
    expect(reusedCode(error)).toBe(IDEMPOTENCY_KEY_REUSED);
    expect(work).not.toHaveBeenCalled();
  });

  it('answers a live pending reservation of the same request with 409 in progress + Retry-After', async () => {
    store.store(request, {
      state: 'pending',
      statusCode: 0,
      response: null,
      expiresAt: new Date(now.getTime() + 90_500),
    });
    const work = vi.fn();
    const error = await service.execute(request, work).catch((e: unknown) => e);
    expect(error).toBeInstanceOf(IdempotencyInProgressException);
    expect((error as IdempotencyInProgressException).getStatus()).toBe(HttpStatus.CONFLICT);
    expect((error as IdempotencyInProgressException).code).toBe(IDEMPOTENCY_REQUEST_IN_PROGRESS);
    expect((error as IdempotencyInProgressException).retryAfterSeconds).toBe(91);
    expect(work).not.toHaveBeenCalled();
  });

  it('answers a live pending reservation of another request with 422 reused', async () => {
    store.store(request, { state: 'pending', statusCode: 0, response: null });
    const error = await service
      .execute({ ...request, fingerprint: 'other' }, vi.fn())
      .catch((e: unknown) => e);
    expect(reusedCode(error)).toBe(IDEMPOTENCY_KEY_REUSED);
  });

  it('replaces an expired pending reservation', async () => {
    store.store(request, {
      state: 'pending',
      statusCode: 0,
      response: null,
      expiresAt: new Date(now.getTime() - 1),
    });
    const result = await service.execute(request, () =>
      Promise.resolve({ statusCode: 201, body: { fresh: true } }),
    );
    expect(result).toEqual({ replayed: false, statusCode: 201, body: { fresh: true } });
  });

  it('replaces an expired record (treated as absent)', async () => {
    store.store(request, { expiresAt: new Date(now.getTime() - 1), response: { old: true } });
    const result = await service.execute({ ...request, fingerprint: 'other' }, () =>
      Promise.resolve({ statusCode: 202, body: { fresh: true } }),
    );
    expect(result).toEqual({ replayed: false, statusCode: 202, body: { fresh: true } });
    expect(store.rows.get('7:key-1')).toMatchObject({ response: { fresh: true } });
    expect(store.rows.size).toBe(1);
  });

  it('never stores an error: the work throws, nothing is kept, the same key works later', async () => {
    const conflict = new CodedHttpException(HttpStatus.CONFLICT, 'x', 'conflict');
    await expect(service.execute(request, () => Promise.reject(conflict))).rejects.toBe(conflict);
    expect(store.rows.size).toBe(0);
    await expect(
      service.execute(request, () => Promise.resolve({ statusCode: 202, body: 1 })),
    ).resolves.toMatchObject({ replayed: false });
  });

  it('refuses to store a non-2xx response (programming error)', async () => {
    await expect(
      service.execute(request, () => Promise.resolve({ statusCode: 409, body: {} })),
    ).rejects.toThrow('2xx');
    expect(store.rows.size).toBe(0);
  });

  it('retries once after a P2002 race and replays what the winner stored', async () => {
    const work = vi.fn(() => Promise.resolve({ statusCode: 202, body: { mine: true } }));
    store.insertConflict = () => store.store(request, { response: { winner: true } });
    const result = await service.execute(request, work);
    expect(result).toEqual({ replayed: true, statusCode: 202, body: { winner: true } });
    expect(store.runner.run).toHaveBeenCalledTimes(2);
    expect(work).toHaveBeenCalledTimes(1);
  });

  it('retries once after an InnoDB deadlock (P2034) on the absent key and replays the winner', async () => {
    const work = vi.fn(() => Promise.resolve({ statusCode: 202, body: { mine: true } }));
    store.conflictCode = 'P2034';
    store.insertConflict = () => store.store(request, { response: { winner: true } });
    const result = await service.execute(request, work);
    expect(result).toEqual({ replayed: true, statusCode: 202, body: { winner: true } });
    expect(store.runner.run).toHaveBeenCalledTimes(2);
  });

  it('a second deadlock is rethrown as it is, not reported as a key reuse', async () => {
    store.alwaysDeadlock = true;
    const error = await service
      .execute(request, () => Promise.resolve({ statusCode: 202, body: {} }))
      .catch((e: unknown) => e);
    expect(error).toBeInstanceOf(Prisma.PrismaClientKnownRequestError);
    expect((error as Prisma.PrismaClientKnownRequestError).code).toBe('P2034');
    expect(store.runner.run).toHaveBeenCalledTimes(2);
  });

  it('retries once after an IdempotencyRaceError from the work', async () => {
    let calls = 0;
    const result = await service.execute(request, () => {
      calls += 1;
      store.store(request, { response: { winner: true } });
      return Promise.reject(new IdempotencyRaceError());
    });
    expect(result).toEqual({ replayed: true, statusCode: 202, body: { winner: true } });
    expect(calls).toBe(1);
  });

  it('a second race is a key reuse (422): the effect exists without a live record', async () => {
    const error = await service
      .execute(request, () => Promise.reject(new IdempotencyRaceError()))
      .catch((e: unknown) => e);
    expect(reusedCode(error)).toBe(IDEMPOTENCY_KEY_REUSED);
    expect(store.runner.run).toHaveBeenCalledTimes(2);
  });

  it('propagates other errors without a retry', async () => {
    const boom = new Error('db down');
    await expect(service.execute(request, () => Promise.reject(boom))).rejects.toBe(boom);
    expect(store.runner.run).toHaveBeenCalledTimes(1);
  });

  it('passes the transaction timeout to the runner', async () => {
    await service.execute(request, () => Promise.resolve({ statusCode: 200, body: null }), {
      timeoutMs: 1234,
    });
    expect(store.runner.run).toHaveBeenCalledWith(expect.any(Function), { timeoutMs: 1234 });
  });
});

describe('isIdempotencyKeyViolation', () => {
  const p2002 = (target: unknown) =>
    new Prisma.PrismaClientKnownRequestError('x', {
      code: 'P2002',
      clientVersion: 'test',
      meta: { target },
    });

  it('matches the unique key by index name or fields only', () => {
    expect(
      isIdempotencyKeyViolation(p2002('api_idempotency_keys_organization_id_idempotency_key_key')),
    ).toBe(true);
    expect(isIdempotencyKeyViolation(p2002(['organization_id', 'idempotency_key']))).toBe(true);
    expect(
      isIdempotencyKeyViolation(
        p2002('email_message_status_history_message_id_transition_key_recei_key'),
      ),
    ).toBe(false);
    expect(isIdempotencyKeyViolation(new Error('P2002'))).toBe(false);
  });
});

describe('isWriteConflict / isIdempotencyRace', () => {
  it('matches P2034 and a raw-query deadlock (P2010, MySQL 1213) only', () => {
    expect(isWriteConflict(deadlock())).toBe(true);
    const raw = (code: unknown) =>
      new Prisma.PrismaClientKnownRequestError('Raw query failed', {
        code: 'P2010',
        clientVersion: 'test',
        meta: { code, message: 'x' },
      });
    expect(isWriteConflict(raw('1213'))).toBe(true);
    expect(isWriteConflict(raw('1205'))).toBe(false);
    expect(isWriteConflict(new Error('P2034'))).toBe(false);
    expect(isIdempotencyRace(deadlock())).toBe(true);
    expect(
      isIdempotencyRace(
        new Prisma.PrismaClientKnownRequestError('x', {
          code: 'P2002',
          clientVersion: 'test',
          meta: { target: ['organization_id', 'idempotency_key'] },
        }),
      ),
    ).toBe(true);
    expect(
      isIdempotencyRace(
        new Prisma.PrismaClientKnownRequestError('x', { code: 'P2003', clientVersion: 'test' }),
      ),
    ).toBe(false);
  });
});
