import {
  type CallHandler,
  type ExecutionContext,
  HttpCode,
  HttpStatus,
  Logger,
  Post,
} from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { Prisma } from '@email-gateway/database';
import { lastValueFrom, of, throwError } from 'rxjs';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import type { ApiKeyPrincipal, UserPrincipal } from '../../auth-contracts/principal';
import type { TransactionRunner } from '../../database/transaction-runner';
import {
  RATE_CLASS_KEY,
  RETURNS_SECRET_KEY,
  RETURNS_SECRET_REDACTED_REPLAY_KEY,
  ReturnsSecret,
} from '../../rate-limit/rate-class.decorator';
import { CodedHttpException } from '../coded-exception';
import {
  canonicalJson,
  IdempotencyInProgressException,
  requestFingerprint,
} from './idempotency-key';
import type { IdempotencyReservationRepository } from './idempotency-reservation.repository';
import { IdempotencyReservationService } from './idempotency-reservation.service';
import {
  containsSensitiveKey,
  IDEMPOTENCY_DEPRECATION_DOC,
  IDEMPOTENT_KEY,
  Idempotent,
  IdempotencyInterceptor,
} from './idempotency.interceptor';
import type { IdempotencyRecord, IdempotencyRepository } from './idempotency.repository';
import { IdempotencyService } from './idempotency.service';

type Tx = Prisma.TransactionClient;
type Row = IdempotencyRecord & { organizationId: bigint; idempotencyKey: string };

const NOW = new Date('2026-11-12T10:00:00.000Z');

/** `api_idempotency_keys` in memory (the interceptor's two short transactions). */
class Store {
  rows = new Map<string, Row>();
  nextId = 1n;
  conflictOnce = false;
  /** The error of the conflictOnce race: P2002 (unique key) or P2034 (gap-lock deadlock). */
  conflictCode: 'P2002' | 'P2034' = 'P2002';
  key = (org: bigint, key: string) => `${org}:${key}`;

  readonly records = {
    lock: (_tx: Tx, org: bigint, key: string) =>
      Promise.resolve(this.rows.get(this.key(org, key)) ?? null),
    delete: (_tx: Tx, id: bigint) => {
      for (const [k, row] of this.rows) if (row.id === id) this.rows.delete(k);
      return Promise.resolve();
    },
    insert: () => Promise.reject(new Error('not used by the interceptor')),
  } as unknown as IdempotencyRepository;

  readonly reservations = {
    reserve: (_tx: Tx, r: Omit<Row, 'id' | 'statusCode' | 'response' | 'state'>) => {
      if (this.conflictOnce) {
        this.conflictOnce = false;
        this.rows.set(this.key(r.organizationId, r.idempotencyKey), {
          ...r,
          id: this.nextId++,
          statusCode: 0,
          response: null,
          state: 'pending',
        });
        return Promise.reject(
          this.conflictCode === 'P2034'
            ? new Prisma.PrismaClientKnownRequestError('deadlock', {
                code: 'P2034',
                clientVersion: 't',
              })
            : new Prisma.PrismaClientKnownRequestError('dup', {
                code: 'P2002',
                clientVersion: 't',
                meta: { target: 'api_idempotency_keys_organization_id_idempotency_key_key' },
              }),
        );
      }
      const id = this.nextId++;
      this.rows.set(this.key(r.organizationId, r.idempotencyKey), {
        ...r,
        id,
        statusCode: 0,
        response: null,
        state: 'pending',
      });
      return Promise.resolve(id);
    },
    complete: (
      _tx: Tx,
      res: { id: bigint },
      out: { statusCode: number; body: unknown; expiresAt: Date },
    ) => {
      for (const row of this.rows.values()) {
        if (row.id === res.id && row.state === 'pending') {
          Object.assign(row, {
            state: 'completed',
            statusCode: out.statusCode,
            response: out.body === Prisma.JsonNull ? null : out.body,
            expiresAt: out.expiresAt,
          });
          return Promise.resolve(true);
        }
      }
      return Promise.resolve(false);
    },
    release: (_tx: Tx, res: { id: bigint }) => {
      for (const [k, row] of this.rows) {
        if (row.id === res.id && row.state === 'pending') {
          this.rows.delete(k);
          return Promise.resolve(true);
        }
      }
      return Promise.resolve(false);
    },
  } as unknown as IdempotencyReservationRepository;

  readonly runner = {
    run: vi.fn(<T>(fn: (tx: Tx) => Promise<T>) => fn({} as Tx)),
  } as unknown as TransactionRunner;
}

class Controller {
  @Post(':domainId/dkim/rotate')
  @HttpCode(201)
  @Idempotent({ operation: 'domain.dkim_rotate' })
  rotate(): void {}

  @Post(':id/status')
  @Idempotent({ operation: 'organization.status_change', legacy: true })
  legacy(): void {}

  @Post()
  @Idempotent({ operation: 'platform.dead_letter_replay' })
  noParams(): void {}
}

const user: UserPrincipal = {
  kind: 'user',
  userId: 10n,
  userPublicId: 'u-1',
  organizationId: 7n,
  organizationPublicId: 'o-7',
  organizationKind: 'customer',
  sessionId: 's',
  mfaAuthenticated: true,
  mfaEnrollmentRequired: false,
  permissions: new Set(),
};

interface Call {
  handler?: () => void;
  key?: string | string[];
  body?: unknown;
  params?: Record<string, string>;
  principal?: UserPrincipal | ApiKeyPrincipal;
  status?: number;
}

function harness(mode: 'enforce' | 'warn' = 'enforce') {
  const store = new Store();
  const service = new IdempotencyService(store.runner, store.records);
  vi.spyOn(service, 'now').mockReturnValue(NOW);
  const reservations = new IdempotencyReservationService(
    store.runner,
    store.records,
    store.reservations,
    service,
    { API_IDEMPOTENCY_PENDING_TTL_SECONDS: 300 },
  );
  const outcomes: string[] = [];
  const metrics = {
    idempotency: { inc: vi.fn((l: { outcome: string }) => outcomes.push(l.outcome)) },
  };
  const interceptor = new IdempotencyInterceptor(new Reflector(), reservations, metrics as never, {
    API_IDEMPOTENCY_LEGACY_MODE: mode,
  });

  async function call(c: Call, run: () => unknown = () => ({ ok: true })) {
    const headers: Record<string, string> = {};
    const res = {
      statusCode: c.status ?? 201,
      sent: undefined as unknown,
      setHeader: (n: string, v: string) => (headers[n] = v),
      status(code: number) {
        res.statusCode = code;
        return res;
      },
      json(body: unknown) {
        res.sent = body;
        return res;
      },
      end: () => res,
    };
    const req = {
      headers: c.key === undefined ? {} : { 'idempotency-key': c.key },
      params: c.params ?? { domainId: 'd-1' },
      body: c.body ?? { selector: 's2' },
      principal: c.principal ?? user,
    };
    const context = {
      getHandler: () => c.handler ?? Controller.prototype.rotate,
      getClass: () => Controller,
      switchToHttp: () => ({ getRequest: () => req, getResponse: () => res }),
    } as unknown as ExecutionContext;
    const handled = vi.fn(() => {
      try {
        return of(run());
      } catch (error) {
        return throwError(() => error);
      }
    });
    const result = await lastValueFrom(
      interceptor.intercept(context, { handle: handled } as CallHandler),
      {
        defaultValue: undefined,
      },
    );
    return { result, headers, res, handled };
  }
  return { store, call, outcomes };
}

async function codeOf(promise: Promise<unknown>): Promise<{ status: number; code: string }> {
  try {
    await promise;
  } catch (error) {
    if (error instanceof CodedHttpException) return { status: error.getStatus(), code: error.code };
    throw error;
  }
  throw new Error('expected a coded error');
}

describe('IdempotencyInterceptor (step 6.1 D9)', () => {
  beforeEach(() => {
    vi.spyOn(Logger.prototype, 'warn').mockImplementation(() => undefined);
    vi.spyOn(Logger.prototype, 'error').mockImplementation(() => undefined);
  });
  afterEach(() => vi.restoreAllMocks());

  it('requires the header (enforce), and refuses an invalid one, before any storage', async () => {
    const { call, store } = harness();
    expect(await codeOf(call({}))).toEqual({ status: 400, code: 'idempotency_key_required' });
    expect(await codeOf(call({ key: '' }))).toEqual({
      status: 400,
      code: 'idempotency_key_required',
    });
    expect(await codeOf(call({ key: 'has space' }))).toEqual({
      status: 400,
      code: 'idempotency_key_invalid',
    });
    expect(await codeOf(call({ key: ['a', 'b'] }))).toEqual({
      status: 400,
      code: 'idempotency_key_invalid',
    });
    expect(store.rows.size).toBe(0);
    // A legacy route under enforce is refused too.
    expect(await codeOf(call({ handler: Controller.prototype.legacy }))).toEqual({
      status: 400,
      code: 'idempotency_key_required',
    });
  });

  it('warn mode: a keyless legacy request runs as before with Deprecation + Link, nothing stored', async () => {
    const { call, store, outcomes } = harness('warn');
    const { result, headers, handled } = await call({ handler: Controller.prototype.legacy });
    expect(result).toEqual({ ok: true });
    expect(handled).toHaveBeenCalledTimes(1);
    expect(headers.Deprecation).toBe('true');
    expect(headers.Link).toBe(`<${IDEMPOTENCY_DEPRECATION_DOC}>; rel="deprecation"`);
    expect(store.rows.size).toBe(0);
    expect(outcomes).toEqual(['missing_legacy']);
    // A non-legacy route still requires the key in warn mode.
    expect(await codeOf(call({}))).toEqual({ status: 400, code: 'idempotency_key_required' });
  });

  it('reserves, runs once, stores status + body (completed, 24 h) and replays afterwards', async () => {
    const { call, store, outcomes } = harness();
    const first = await call({ key: 'k-1' }, () => ({ selector: 's2', at: new Date(NOW) }));
    expect(first.result).toEqual({ selector: 's2', at: new Date(NOW) });
    const row = store.rows.get('7:k-1')!;
    expect(row).toMatchObject({
      state: 'completed',
      statusCode: 201,
      response: { selector: 's2', at: NOW.toISOString() },
      operation: 'domain.dkim_rotate',
      principal: 'user:u-1',
      resourceId: 'd-1',
      requestSha256: requestFingerprint({
        operation: 'domain.dkim_rotate',
        resourceId: canonicalJson({ domainId: 'd-1' }),
        body: { selector: 's2' },
      }),
    });
    expect(row.expiresAt.getTime()).toBe(NOW.getTime() + 24 * 3600 * 1000);

    const second = await call({ key: 'k-1' }, () => expect.fail('must not run'));
    expect(second.result).toEqual({ selector: 's2', at: NOW.toISOString() });
    expect(second.headers['Idempotency-Replayed']).toBe('true');
    expect(second.handled).not.toHaveBeenCalled();
    expect(outcomes).toEqual(['stored', 'replayed']);
  });

  it('replays the stored status even when it differs from the route status (202 vs 201)', async () => {
    const { call, store } = harness();
    await call({ key: 'k-2', status: 202 }, () => ({ accepted: true }));
    expect(store.rows.get('7:k-2')!.statusCode).toBe(202);
    const replay = await call({ key: 'k-2', status: 201 });
    expect(replay.res.statusCode).toBe(202);
    expect(replay.res.sent).toEqual({ accepted: true });
    expect(replay.result).toBeUndefined();
    // Nest's later default status does not rewrite what was sent.
    replay.res.status(201);
    expect(replay.res.statusCode).toBe(202);
  });

  it('refuses the same key for another body, path, operation or caller (422) and never runs', async () => {
    const { call, outcomes } = harness();
    await call({ key: 'k-3' });
    for (const change of [
      { body: { selector: 'other' } },
      { params: { domainId: 'd-2' } },
      { handler: Controller.prototype.noParams, params: {} },
      { principal: { ...user, userPublicId: 'u-2' } },
    ] as Call[]) {
      expect(await codeOf(call({ key: 'k-3', ...change }))).toEqual({
        status: 422,
        code: 'idempotency_key_reused',
      });
    }
    expect(outcomes.filter((o) => o === 'reused')).toHaveLength(4);
  });

  it('answers a live pending reservation of the same request with 409 + retry seconds', async () => {
    const { call, store, outcomes } = harness();
    let inner: Promise<unknown> | undefined;
    await call({ key: 'k-4' }, () => {
      inner = call({ key: 'k-4' });
      return { ok: true };
    }).catch(() => undefined);
    const error = await inner!.catch((e: unknown) => e);
    expect(error).toBeInstanceOf(IdempotencyInProgressException);
    expect((error as IdempotencyInProgressException).retryAfterSeconds).toBe(300);
    expect(outcomes).toContain('in_progress');
    expect(store.rows.get('7:k-4')!.state).toBe('completed');
  });

  it('replaces an expired pending reservation (crash window) and runs again', async () => {
    const { call, store } = harness();
    store.rows.set('7:k-5', {
      id: 99n,
      organizationId: 7n,
      idempotencyKey: 'k-5',
      operation: 'domain.dkim_rotate',
      principal: 'user:u-1',
      requestSha256: 'x',
      resourceId: 'd-1',
      statusCode: 0,
      response: null,
      state: 'pending',
      expiresAt: new Date(NOW.getTime() - 1),
    });
    const { handled } = await call({ key: 'k-5' });
    expect(handled).toHaveBeenCalledTimes(1);
    expect(store.rows.get('7:k-5')).toMatchObject({ state: 'completed', statusCode: 201 });
    expect(store.rows.get('7:k-5')!.id).not.toBe(99n);
  });

  it('releases the reservation when the handler fails, so the same key works again', async () => {
    const { call, store } = harness();
    const conflict = new CodedHttpException(HttpStatus.CONFLICT, 'domain_state_conflict', 'No');
    await expect(
      call({ key: 'k-6' }, () => {
        throw conflict;
      }),
    ).rejects.toBe(conflict);
    expect(store.rows.size).toBe(0);
    const retry = await call({ key: 'k-6' });
    expect(retry.result).toEqual({ ok: true });
  });

  it('retries a reservation race once and then answers in progress', async () => {
    const { call, store } = harness();
    store.conflictOnce = true;
    const error = await call({ key: 'k-7' }).catch((e: unknown) => e);
    expect(error).toBeInstanceOf(IdempotencyInProgressException);
  });

  it('retries a reservation deadlock (P2034, gap locks on the absent key) once: 409, not 500', async () => {
    const { call, store } = harness();
    store.conflictOnce = true;
    store.conflictCode = 'P2034';
    const error = await call({ key: 'k-7b' }).catch((e: unknown) => e);
    expect(error).toBeInstanceOf(IdempotencyInProgressException);
  });

  it('refuses to store a body with a credential-like key (500, nothing stored)', async () => {
    const { call, store } = harness();
    await expect(call({ key: 'k-8' }, () => ({ data: [{ apiKey: 'egk_…' }] }))).rejects.toThrow(
      /refuses to store/,
    );
    expect(store.rows.size).toBe(0);
    expect(containsSensitiveKey({ statusCode: 1, planCode: 'x', nested: [{ ok: 1 }] })).toBe(false);
    expect(containsSensitiveKey({ nested: { deep: [{ secret: 1 }] } })).toBe(true);
    expect(containsSensitiveKey({ refreshToken: 'x' })).toBe(true);
  });

  it('stores a null body and the organization of an API key principal; resource "-" without params', async () => {
    const { call, store } = harness();
    const key: ApiKeyPrincipal = {
      kind: 'api_key',
      apiKeyId: 3n,
      apiKeyPublicId: 'k-pub',
      organizationId: 9n,
      organizationPublicId: 'o-9',
      permissions: new Set(),
    };
    await call(
      {
        key: 'k-9',
        principal: key,
        handler: Controller.prototype.noParams,
        params: {},
        status: 204,
      },
      () => undefined,
    );
    expect(store.rows.get('9:k-9')).toMatchObject({
      principal: 'api_key:k-pub',
      resourceId: '-',
      statusCode: 204,
      response: null,
      state: 'completed',
    });
  });
});

describe('@Idempotent and @ReturnsSecret (step 6.1 D9)', () => {
  it('sets the metadata, the sensitive class and refuses invalid operations', () => {
    expect(Reflect.getMetadata(IDEMPOTENT_KEY, Controller.prototype.legacy)).toEqual({
      operation: 'organization.status_change',
      legacy: true,
    });
    expect(Reflect.getMetadata(RATE_CLASS_KEY, Controller.prototype.rotate)).toBe('sensitive');
    expect(Reflect.getMetadata('swagger/apiExtension', Controller.prototype.legacy)).toMatchObject({
      'x-eg-idempotency': 'legacy',
      'x-eg-rate-class': 'sensitive',
    });
    expect(Reflect.getMetadata('swagger/apiExtension', Controller.prototype.rotate)).toMatchObject({
      'x-eg-idempotency': 'required',
    });
    expect(() => Idempotent({ operation: 'NoDot' })).toThrow();
  });

  it('cannot be combined in either order', () => {
    expect(() => {
      class A {
        @Idempotent({ operation: 'a.b' })
        @ReturnsSecret()
        m(): void {}
      }
      return A;
    }).toThrow(/ReturnsSecret/);
    expect(() => {
      class B {
        @ReturnsSecret()
        @Idempotent({ operation: 'a.b' })
        m(): void {}
      }
      return B;
    }).toThrow(/Idempotent/);
  });

  it('redactedReplay (ADR-0057) marks the route but still refuses @Idempotent()', () => {
    class C {
      @ReturnsSecret({ redactedReplay: true })
      @Post()
      create(): void {}

      @ReturnsSecret()
      @Post()
      plain(): void {}
    }
    expect(Reflect.getMetadata(RETURNS_SECRET_KEY, C.prototype.create)).toBe(true);
    expect(Reflect.getMetadata(RETURNS_SECRET_REDACTED_REPLAY_KEY, C.prototype.create)).toBe(true);
    expect(Reflect.getMetadata(RETURNS_SECRET_REDACTED_REPLAY_KEY, C.prototype.plain)).toBe(
      undefined,
    );
    expect(Reflect.getMetadata(RATE_CLASS_KEY, C.prototype.create)).toBe('sensitive');
    expect(Reflect.getMetadata('swagger/apiExtension', C.prototype.create)).toMatchObject({
      'x-eg-returns-secret': true,
      'x-eg-secret-replay': 'redacted',
    });
    expect(Reflect.getMetadata('swagger/apiExtension', C.prototype.plain)).not.toHaveProperty(
      'x-eg-secret-replay',
    );
    expect(() => {
      class D {
        @Idempotent({ operation: 'a.b' })
        @ReturnsSecret({ redactedReplay: true })
        m(): void {}
      }
      return D;
    }).toThrow(/ReturnsSecret/);
  });
});
