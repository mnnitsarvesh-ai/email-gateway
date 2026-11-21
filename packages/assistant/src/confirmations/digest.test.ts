import fc from 'fast-check';
import { describe, expect, it } from 'vitest';
import { canonicalJson, sha256Hex } from './canonical';
import {
  actionDigest,
  hashConfirmationToken,
  isDigestHex,
  newConfirmationToken,
  pickState,
  stateDigest,
  tokenMatches,
  valueAtPath,
  type DigestInput,
} from './digest';

const BASE: DigestInput = {
  v: 'assistant-action/1',
  confirmationId: '0193aaaa-0000-7000-8000-000000000001',
  organizationPublicId: '0193aaaa-0000-7000-8000-00000000000a',
  userPublicId: '0193aaaa-0000-7000-8000-00000000000b',
  sessionFamilyId: '0193aaaa-0000-7000-8000-00000000000c',
  overrideId: null,
  conversationId: '0193aaaa-0000-7000-8000-00000000000d',
  executionId: '0193aaaa-0000-7000-8000-00000000000e',
  tool: 'policy_management_disable',
  operationId: 'PolicyManagementController_disable_v1',
  risk: 'medium',
  requiresReauth: false,
  request: {
    method: 'POST',
    path: '/api/v1/policies/0193aaaa-0000-7000-8000-000000000002/disable',
    body: { expectedRowVersion: 3, nested: { list: [1, 'two', { three: true }] } },
  },
  preconditions: { stateDigest: 'a'.repeat(64), rowVersion: 3, definitionSha256: null },
  expiresAt: '2026-11-21T10:05:00.000Z',
};

describe('canonicalJson', () => {
  it('sorts keys at every depth and drops undefined members', () => {
    expect(canonicalJson({ b: 1, a: { d: [3, { z: 1, y: 2 }], c: undefined } })).toBe(
      '{"a":{"d":[3,{"y":2,"z":1}]},"b":1}',
    );
    expect(canonicalJson([undefined, null])).toBe('[null,null]');
  });

  it('keeps an own __proto__ member of parsed JSON as data', () => {
    const a = JSON.parse('{"__proto__":{"x":1},"b":2}') as unknown;
    const b = JSON.parse('{"__proto__":{"x":2},"b":2}') as unknown;
    expect(canonicalJson(a)).toBe('{"__proto__":{"x":1},"b":2}');
    expect(canonicalJson(a)).not.toBe(canonicalJson(b));
  });

  it('writes bigint as a decimal string and Date as ISO; refuses non-finite numbers', () => {
    expect(canonicalJson({ n: 12345678901234567890n })).toBe('{"n":"12345678901234567890"}');
    expect(canonicalJson({ at: new Date('2026-11-21T00:00:00Z') })).toBe(
      '{"at":"2026-11-21T00:00:00.000Z"}',
    );
    expect(() => canonicalJson({ x: Number.NaN })).toThrow(/non-finite/);
    expect(() => canonicalJson({ x: Number.POSITIVE_INFINITY })).toThrow(/non-finite/);
  });

  it('agrees with the provider-integrations algorithm on a fixed vector', () => {
    expect(sha256Hex(canonicalJson({ b: [1, 2], a: 'x' }))).toBe(sha256Hex('{"a":"x","b":[1,2]}'));
    expect(sha256Hex('')).toBe('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855');
  });
});

describe('actionDigest', () => {
  it('is a lower-case SHA-256 hex of the canonical input', () => {
    const digest = actionDigest(BASE);
    expect(isDigestHex(digest)).toBe(true);
    expect(digest).toBe(sha256Hex(canonicalJson(BASE)));
    expect(actionDigest(structuredClone(BASE))).toBe(digest);
    expect(isDigestHex('A'.repeat(64))).toBe(false);
    expect(() => actionDigest({ ...BASE, v: 'other' as 'assistant-action/1' })).toThrow();
  });

  it('changes with every member (explicit)', () => {
    const digest = actionDigest(BASE);
    const variants: DigestInput[] = [
      { ...BASE, confirmationId: '0193aaaa-0000-7000-8000-0000000000ff' },
      { ...BASE, organizationPublicId: 'x' },
      { ...BASE, userPublicId: 'x' },
      { ...BASE, sessionFamilyId: 'x' },
      { ...BASE, overrideId: 'x' },
      { ...BASE, conversationId: 'x' },
      { ...BASE, executionId: 'x' },
      { ...BASE, tool: 'policy_management_enable' },
      { ...BASE, operationId: 'x' },
      { ...BASE, risk: 'high' },
      { ...BASE, requiresReauth: true },
      { ...BASE, request: { ...BASE.request, method: 'PUT' } },
      { ...BASE, request: { ...BASE.request, path: `${BASE.request.path}?x=1` } },
      { ...BASE, request: { ...BASE.request, body: null } },
      { ...BASE, preconditions: { ...BASE.preconditions, stateDigest: 'b'.repeat(64) } },
      { ...BASE, preconditions: { ...BASE.preconditions, rowVersion: 4 } },
      { ...BASE, preconditions: { ...BASE.preconditions, definitionSha256: 'c'.repeat(64) } },
      { ...BASE, preconditions: { ...BASE.preconditions, items: [] } },
      { ...BASE, expiresAt: '2026-11-21T10:05:00.001Z' },
    ];
    const digests = new Set(variants.map(actionDigest));
    expect(digests.size).toBe(variants.length);
    expect(digests.has(digest)).toBe(false);
  });
});

// ---------------------------------------------------------------------------------------------
// Property tests (design 29 §9 item 1)
// ---------------------------------------------------------------------------------------------

const key = fc.string({ minLength: 1, maxLength: 6 }).filter((k) => k !== '__proto__');
const json = fc.letrec((tie) => ({
  value: fc.oneof(
    { depthSize: 'small' },
    fc.constant(null),
    fc.boolean(),
    fc.integer({ min: -1_000_000, max: 1_000_000 }),
    fc.string({ maxLength: 12 }),
    fc.array(tie('value'), { maxLength: 4 }),
    fc.dictionary(key, tie('value'), { maxKeys: 4 }),
  ),
})).value;

const digestInput: fc.Arbitrary<DigestInput> = fc.record({
  v: fc.constant('assistant-action/1' as const),
  confirmationId: fc.uuid(),
  organizationPublicId: fc.uuid(),
  userPublicId: fc.uuid(),
  sessionFamilyId: fc.uuid(),
  overrideId: fc.option(fc.uuid(), { nil: null }),
  conversationId: fc.uuid(),
  executionId: fc.uuid(),
  tool: fc.stringMatching(/^[a-z][a-z0-9_]{0,30}$/),
  operationId: fc.stringMatching(/^[A-Z][A-Za-z]{0,20}Controller_[a-z]{1,10}_v1$/),
  risk: fc.constantFrom('low' as const, 'medium' as const, 'high' as const),
  requiresReauth: fc.boolean(),
  request: fc.record({
    method: fc.constantFrom('POST' as const, 'PUT' as const, 'PATCH' as const, 'DELETE' as const),
    path: fc.stringMatching(/^\/api\/v1\/[a-z0-9/-]{1,40}$/),
    body: fc.oneof(fc.constant(null), fc.dictionary(key, json, { maxKeys: 5 })),
  }),
  preconditions: fc.record(
    {
      stateDigest: fc.option(fc.hexaString({ minLength: 64, maxLength: 64 }), { nil: null }),
      rowVersion: fc.option(fc.integer({ min: 0, max: 1_000_000 }), { nil: null }),
      definitionSha256: fc.option(fc.hexaString({ minLength: 64, maxLength: 64 }), { nil: null }),
      items: fc.array(
        fc.record({ id: fc.uuid(), stateDigest: fc.hexaString({ minLength: 64, maxLength: 64 }) }),
        { maxLength: 3 },
      ),
    },
    { requiredKeys: ['stateDigest', 'rowVersion', 'definitionSha256'] },
  ),
  expiresAt: fc
    .date({ min: new Date('2026-01-01T00:00:00Z'), max: new Date('2030-01-01T00:00:00Z') })
    .map((d) => d.toISOString()),
});

/** Deep copy with object keys inserted in a permuted order at every depth. */
function reorder(value: unknown, seed: number): unknown {
  if (Array.isArray(value)) return value.map((item) => reorder(item, seed + 1));
  if (value !== null && typeof value === 'object') {
    const keys = Object.keys(value);
    const rotated =
      keys.length > 0
        ? [...keys.slice(seed % keys.length), ...keys.slice(0, seed % keys.length)].reverse()
        : keys;
    const out: Record<string, unknown> = {};
    for (const key of rotated)
      out[key] = reorder((value as Record<string, unknown>)[key], seed + 1);
    return out;
  }
  return value;
}

/** Every leaf path (object members and array items) of a JSON value. */
function leafPaths(
  value: unknown,
  prefix: Array<string | number> = [],
): Array<Array<string | number>> {
  if (Array.isArray(value))
    return value.length === 0
      ? [prefix]
      : value.flatMap((item, i) => leafPaths(item, [...prefix, i]));
  if (value !== null && typeof value === 'object') {
    const keys = Object.keys(value);
    return keys.length === 0
      ? [prefix]
      : keys.flatMap((key) => leafPaths((value as Record<string, unknown>)[key], [...prefix, key]));
  }
  return [prefix];
}

/** A copy with the leaf at `path` replaced by a value that differs from it. */
function mutate(input: DigestInput, path: Array<string | number>): DigestInput {
  const copy = structuredClone(input) as unknown as Record<string | number, unknown>;
  if (path.length === 0) throw new Error('root');
  let node: Record<string | number, unknown> = copy;
  for (const segment of path.slice(0, -1)) node = node[segment] as Record<string | number, unknown>;
  const last = path[path.length - 1]!;
  const current = node[last];
  node[last] =
    typeof current === 'string'
      ? `${current}x`
      : typeof current === 'number'
        ? current + 1
        : typeof current === 'boolean'
          ? !current
          : current === null
            ? 'not-null'
            : Array.isArray(current)
              ? [...current, 'extra']
              : { ...(current as object), __extra: 1 };
  return copy as unknown as DigestInput;
}

describe('actionDigest properties (fast-check)', () => {
  it('is stable under key reordering at any depth', () => {
    fc.assert(
      fc.property(digestInput, fc.nat(10), (input, seed) => {
        expect(actionDigest(reorder(input, seed) as DigestInput)).toBe(actionDigest(input));
      }),
      { numRuns: 200 },
    );
  });

  it('changes when any single member changes (identity, session, request incl. nested body leaves, preconditions, risk, expiry)', () => {
    fc.assert(
      fc.property(digestInput, fc.nat(), (input, pick) => {
        const paths = leafPaths(input).filter((path) => !(path.length === 1 && path[0] === 'v'));
        const path = paths[pick % paths.length]!;
        expect(actionDigest(mutate(input, path)), path.join('.')).not.toBe(actionDigest(input));
      }),
      { numRuns: 500 },
    );
  });
});

describe('state digest', () => {
  const body = {
    rowVersion: 3,
    status: 'active',
    sender: { envelope: 'a@example.com' },
    name: 'P',
  };

  it('picks dotted paths; a missing path is null', () => {
    expect(valueAtPath(body, 'sender.envelope')).toBe('a@example.com');
    expect(valueAtPath(body, 'sender.missing')).toBeUndefined();
    expect(valueAtPath(body, 'name.length')).toBeUndefined();
    expect(pickState(body, ['rowVersion', 'sender.envelope', 'gone'])).toEqual({
      rowVersion: 3,
      'sender.envelope': 'a@example.com',
      gone: null,
    });
  });

  it('changes only when a picked field changes', () => {
    const fields = ['rowVersion', 'status'];
    const digest = stateDigest(body, fields);
    expect(digest).toMatch(/^[0-9a-f]{64}$/);
    expect(stateDigest({ ...body, name: 'renamed' }, fields)).toBe(digest);
    expect(stateDigest({ ...body, rowVersion: 4 }, fields)).not.toBe(digest);
    expect(stateDigest({ ...body, status: 'disabled' }, fields)).not.toBe(digest);
    expect(stateDigest({ status: 'active', rowVersion: 3 }, [...fields].reverse())).toBe(digest);
  });
});

describe('confirmation token', () => {
  it('is 32 random bytes in base64url (43 characters); only the hash matches', () => {
    const token = newConfirmationToken();
    expect(token).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(Buffer.from(token, 'base64url')).toHaveLength(32);
    expect(newConfirmationToken()).not.toBe(token);
    const hash = hashConfirmationToken(token);
    expect(hash).toMatch(/^[0-9a-f]{64}$/);
    expect(tokenMatches(token, hash)).toBe(true);
  });

  it('never matches and never throws for wrong or malformed tokens and hashes', () => {
    const token = 'a'.repeat(43);
    const hash = hashConfirmationToken(token);
    for (const candidate of [
      'b'.repeat(43),
      'a'.repeat(42),
      'a'.repeat(44),
      `${'a'.repeat(42)}=`,
      `${'a'.repeat(42)}+`,
      '',
      null,
      undefined,
      43,
      { token },
    ])
      expect(tokenMatches(candidate, hash)).toBe(false);
    expect(tokenMatches(token, hash.toUpperCase())).toBe(false);
    expect(tokenMatches(token, 'zz')).toBe(false);
    expect(tokenMatches(token, null)).toBe(false);
    fc.assert(
      fc.property(fc.string({ maxLength: 60 }), (candidate) => {
        expect(tokenMatches(candidate, hash)).toBe(candidate === token);
      }),
      { numRuns: 300 },
    );
    fc.assert(
      fc.property(fc.stringMatching(/^[A-Za-z0-9_-]{43}$/), (candidate) => {
        expect(tokenMatches(candidate, hash)).toBe(candidate === token);
      }),
      { numRuns: 300 },
    );
  });
});
