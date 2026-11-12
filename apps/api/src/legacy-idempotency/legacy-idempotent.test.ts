import type { CallHandler, ExecutionContext } from '@nestjs/common';
import { INTERCEPTORS_METADATA } from '@nestjs/common/constants';
import { lastValueFrom, of } from 'rxjs';
import { describe, expect, it } from 'vitest';
import {
  IDEMPOTENT_KEY,
  IdempotencyInterceptor,
} from '../http/idempotency/idempotency.interceptor';
import { containsSensitiveKey } from '../http/idempotency/idempotency.interceptor';
import { RATE_CLASS_KEY } from '../rate-limit/rate-class.decorator';
import {
  credentialLikeKeys,
  LEGACY_RESPONSE_ENVELOPE,
  LegacyIdempotent,
  LegacyResponseUnwrapInterceptor,
  LegacyResponseWrapInterceptor,
} from './legacy-idempotent';

const context = {} as ExecutionContext;
const handlerOf = (value: unknown): CallHandler => ({ handle: () => of(value) });

const ROTATE_RESPONSE = {
  domainId: '0190c5a1-0000-7000-8000-000000000001',
  key: { selector: 'eg2026a', algorithm: 'rsa_2048', status: 'pending' },
  previous: null,
  dnsRecord: { key: 'dkim:eg2026a', value: 'v=DKIM1; k=rsa; p=MIIB' },
  overlapDays: 7,
  createdAt: new Date('2026-11-12T10:00:00.000Z'),
};

describe('LegacyIdempotent (step 6.1 §3.5, WP4)', () => {
  it('credentialLikeKeys exempts only the named fields, at any depth', () => {
    const exempt = new Set(['key']);
    expect(credentialLikeKeys(ROTATE_RESPONSE, exempt)).toEqual([]);
    expect(credentialLikeKeys({ roles: [{ key: 'admin' }], apiKey: 'x' }, exempt)).toEqual([
      'apiKey',
    ]);
    expect(credentialLikeKeys({ nested: { token: 't', statusCode: 200 } }, exempt)).toEqual([
      'nested.token',
    ]);
  });

  it('wraps the body into an envelope the IdempotencyInterceptor accepts and unwraps it unchanged', async () => {
    expect(containsSensitiveKey(JSON.parse(JSON.stringify(ROTATE_RESPONSE)))).toBe(true);
    const wrap = new LegacyResponseWrapInterceptor('domain.dkim_rotate', ['key']);
    const envelope = await lastValueFrom(wrap.intercept(context, handlerOf(ROTATE_RESPONSE)));
    expect(Object.keys(envelope as object)).toEqual([LEGACY_RESPONSE_ENVELOPE]);
    expect(containsSensitiveKey(envelope)).toBe(false);

    const unwrap = new LegacyResponseUnwrapInterceptor();
    const body = await lastValueFrom(unwrap.intercept(context, handlerOf(envelope)));
    expect(body).toEqual(JSON.parse(JSON.stringify(ROTATE_RESPONSE)));
  });

  it('fails closed (nothing to store) when another credential-like key appears', async () => {
    const wrap = new LegacyResponseWrapInterceptor('user.invite', ['key']);
    await expect(
      lastValueFrom(wrap.intercept(context, handlerOf({ roles: [{ key: 'a' }], token: 'x' }))),
    ).rejects.toThrow(/refuses to store/);
  });

  it('passes empty bodies and non-envelopes through', async () => {
    const wrap = new LegacyResponseWrapInterceptor('x.y', ['key']);
    expect(await lastValueFrom(wrap.intercept(context, handlerOf(undefined)))).toBeUndefined();
    const unwrap = new LegacyResponseUnwrapInterceptor();
    expect(await lastValueFrom(unwrap.intercept(context, handlerOf({ a: 1 })))).toEqual({ a: 1 });
    expect(await lastValueFrom(unwrap.intercept(context, handlerOf(null)))).toBeNull();
  });

  it('decorates like @Idempotent() with the unwrap → idempotency → wrap interceptor order', () => {
    class Controller {
      @LegacyIdempotent({ operation: 'domain.dkim_rotate', legacy: true, publicFields: ['key'] })
      rotate(): void {}
    }
    const handler = Object.getOwnPropertyDescriptor(Controller.prototype, 'rotate')!
      .value as object;
    expect(Reflect.getMetadata(IDEMPOTENT_KEY, handler)).toEqual({
      operation: 'domain.dkim_rotate',
      legacy: true,
    });
    expect(Reflect.getMetadata(RATE_CLASS_KEY, handler)).toBe('sensitive');
    const chain = Reflect.getMetadata(INTERCEPTORS_METADATA, handler) as unknown[];
    expect(chain).toHaveLength(3);
    expect(chain[0]).toBeInstanceOf(LegacyResponseUnwrapInterceptor);
    expect(chain[1]).toBe(IdempotencyInterceptor);
    expect(chain[2]).toBeInstanceOf(LegacyResponseWrapInterceptor);
  });

  it('refuses names that are not pattern matches or that name real credentials', () => {
    expect(() => LegacyIdempotent({ operation: 'a.b', publicFields: [] })).toThrow();
    expect(() => LegacyIdempotent({ operation: 'a.b', publicFields: ['name'] })).toThrow();
    expect(() => LegacyIdempotent({ operation: 'a.b', publicFields: ['token'] })).toThrow();
    expect(() => LegacyIdempotent({ operation: 'a.b', publicFields: ['secretKey'] })).toThrow();
  });
});
