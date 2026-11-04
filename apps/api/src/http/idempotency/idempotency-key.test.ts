import { createHash } from 'node:crypto';
import { HttpStatus } from '@nestjs/common';
import { describe, expect, it } from 'vitest';
import type { ApiKeyPrincipal, UserPrincipal } from '../../auth-contracts/principal';
import { CodedHttpException } from '../coded-exception';
import {
  canonicalJson,
  IDEMPOTENCY_KEY_INVALID,
  IDEMPOTENCY_KEY_REQUIRED,
  idempotencyKeyHash,
  IdempotencyKeyPipe,
  parseIdempotencyKey,
  principalKey,
  requestFingerprint,
} from './idempotency-key';

function codeOf(fn: () => unknown): { status: number; code: string } {
  try {
    fn();
  } catch (error) {
    if (error instanceof CodedHttpException) return { status: error.getStatus(), code: error.code };
    throw error;
  }
  throw new Error('expected a CodedHttpException');
}

describe('parseIdempotencyKey (L11 header rules)', () => {
  it.each(['a', 'K-1', 'ui:2026-11-04.release_1', 'A'.repeat(128), 'abc.DEF_123:xyz-9'])(
    'accepts %s',
    (key) => {
      expect(parseIdempotencyKey(key)).toBe(key);
      expect(new IdempotencyKeyPipe().transform(key)).toBe(key);
    },
  );

  it.each([undefined, null, ''])(
    'refuses a missing key (%s) as idempotency_key_required',
    (raw) => {
      expect(codeOf(() => parseIdempotencyKey(raw))).toEqual({
        status: HttpStatus.BAD_REQUEST,
        code: IDEMPOTENCY_KEY_REQUIRED,
      });
    },
  );

  it.each([
    ['too long', 'A'.repeat(129)],
    ['a space', 'has space'],
    ['a slash', 'a/b'],
    ['non-ASCII', 'clé'],
    ['a repeated header', ['a', 'b']],
    ['a number', 42],
  ])('refuses %s as idempotency_key_invalid', (_label, raw) => {
    expect(codeOf(() => parseIdempotencyKey(raw))).toEqual({
      status: HttpStatus.BAD_REQUEST,
      code: IDEMPOTENCY_KEY_INVALID,
    });
  });

  it('never echoes the value', () => {
    try {
      parseIdempotencyKey('secret value with spaces');
    } catch (error) {
      expect(JSON.stringify((error as CodedHttpException).getResponse())).not.toContain('secret');
    }
  });
});

describe('requestFingerprint', () => {
  it('is the SHA-256 of the canonical JSON { operation, resourceId, body }', () => {
    const expected = createHash('sha256')
      .update(
        '{"body":{"expectedVersion":3,"reason":"because it is safe"},"operation":"op","resourceId":"r"}',
      )
      .digest('hex');
    expect(
      requestFingerprint({
        operation: 'op',
        resourceId: 'r',
        body: { reason: 'because it is safe', expectedVersion: 3 },
      }),
    ).toBe(expected);
  });

  it('ignores key order but not values, operation or resource', () => {
    const base = { operation: 'message.rescan', resourceId: 'm1', body: { a: 1, b: [1, 2] } };
    const same = requestFingerprint({ ...base, body: { b: [1, 2], a: 1 } });
    expect(requestFingerprint(base)).toBe(same);
    expect(requestFingerprint({ ...base, body: { a: 2, b: [1, 2] } })).not.toBe(same);
    expect(requestFingerprint({ ...base, body: { a: 1, b: [2, 1] } })).not.toBe(same);
    expect(requestFingerprint({ ...base, operation: 'message.release' })).not.toBe(same);
    expect(requestFingerprint({ ...base, resourceId: 'm2' })).not.toBe(same);
  });

  it('canonicalJson sorts nested keys and drops undefined', () => {
    expect(canonicalJson({ b: { d: 1, c: undefined, a: [{ z: 1, y: 2 }] }, a: null })).toBe(
      '{"a":null,"b":{"a":[{"y":2,"z":1}],"d":1}}',
    );
  });
});

describe('principalKey and idempotencyKeyHash', () => {
  it('names users and API keys by public id', () => {
    expect(principalKey({ kind: 'user', userPublicId: 'u-1' } as UserPrincipal)).toBe('user:u-1');
    expect(principalKey({ kind: 'api_key', apiKeyPublicId: 'k-1' } as ApiKeyPrincipal)).toBe(
      'api_key:k-1',
    );
  });

  it('hashes the key (hex SHA-256)', () => {
    expect(idempotencyKeyHash('abc')).toBe(createHash('sha256').update('abc').digest('hex'));
  });
});
