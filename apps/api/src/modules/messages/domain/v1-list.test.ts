import { randomBytes, randomUUID } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import type { Principal } from '../../../auth-contracts/principal';
import { CursorCodec } from '../../../http/cursor/cursor-codec';
import {
  decimalKey,
  decodeListCursor,
  directionOf,
  encodeListCursor,
  instantKey,
  intKey,
  listBinding,
  scopeOrganizationPublicId,
  sha256Hex,
  timeIdKeyOf,
  timeIdKeys,
} from './v1-list';

const codec = new CursorCodec({
  API_CURSOR_KEY: randomBytes(32).toString('hex'),
  API_CURSOR_KEY_PREVIOUS: undefined,
  API_CURSOR_TTL_SECONDS: 86_400,
});

const org = randomUUID();
const user: Principal = {
  kind: 'user',
  userId: 1n,
  userPublicId: randomUUID(),
  organizationId: 1n,
  organizationPublicId: org,
  organizationKind: 'customer',
  sessionId: randomUUID(),
  mfaAuthenticated: false,
  mfaEnrollmentRequired: false,
  permissions: new Set(),
};

function expectInvalid(fn: () => unknown): void {
  try {
    fn();
    expect.fail('expected cursor_invalid');
  } catch (error) {
    expect((error as { code?: string }).code).toBe('cursor_invalid');
  }
}

describe('v1 list cursors of the messages data routes (step 6.1 D3)', () => {
  const filters = { verdict: { values: ['spam'] } };
  const binding = listBinding({
    resource: 'messages',
    principal: user,
    filters,
    sort: '-receivedAt',
  });

  it('binds resource, organization, filter hash and direction', () => {
    expect(binding).toMatchObject({
      resource: 'messages',
      organizationPublicId: org,
      direction: 'desc',
    });
    expect(binding.filterHash).toMatch(/^[0-9a-f]{16}$/);
    expect(directionOf('receivedAt')).toBe('asc');
    expect(directionOf('rcptSeq')).toBe('asc');
  });

  it('round-trips keys and the window', () => {
    const key = { at: new Date('2026-11-12T08:00:00.123Z'), id: 42n };
    const cursor = encodeListCursor(codec, binding, timeIdKeys(key), [1, 2]);
    const decoded = decodeListCursor(codec, binding, cursor, 2);
    expect(decoded?.window).toEqual([1, 2]);
    expect(timeIdKeyOf(decoded)).toEqual(key);
    expect(decodeListCursor(codec, binding, undefined, 2)).toBeUndefined();
  });

  it('refuses another filter set, sort, resource, organization or key count', () => {
    const cursor = encodeListCursor(codec, binding, ['2026-11-12T08:00:00.123Z', '42'], [1, 2]);
    const other = (over: Partial<Parameters<typeof listBinding>[0]>) =>
      listBinding({ resource: 'messages', principal: user, filters, sort: '-receivedAt', ...over });
    expectInvalid(() => decodeListCursor(codec, other({ filters: {} }), cursor, 2));
    expectInvalid(() => decodeListCursor(codec, other({ sort: 'receivedAt' }), cursor, 2));
    expectInvalid(() => decodeListCursor(codec, other({ resource: 'url_clicks' }), cursor, 2));
    expectInvalid(() =>
      decodeListCursor(
        codec,
        other({ principal: { ...user, organizationPublicId: randomUUID() } }),
        cursor,
        2,
      ),
    );
    expectInvalid(() => decodeListCursor(codec, binding, cursor, 1));
    expectInvalid(() => decodeListCursor(codec, binding, `${cursor}x`, 2));
  });

  it('a direction that does not match the sort is refused', () => {
    const asc = { ...binding, direction: 'asc' as const };
    const cursor = encodeListCursor(codec, asc, ['1']);
    expectInvalid(() => decodeListCursor(codec, binding, cursor, 1));
  });

  it('binds the override target under a platform override', () => {
    const target = randomUUID();
    const override: Principal = {
      ...user,
      override: {
        id: randomUUID(),
        reason: 'support',
        targetOrganizationId: 9n,
        targetOrganizationPublicId: target,
        expiresAt: new Date(),
      },
    };
    expect(scopeOrganizationPublicId(override)).toBe(target);
    expect(scopeOrganizationPublicId(user)).toBe(org);
  });

  it('parses keyset values strictly', () => {
    expect(decimalKey('0')).toBe(0n);
    expect(decimalKey('18446744073709551615')).toBe(18_446_744_073_709_551_615n);
    for (const bad of [undefined, '', '-1', '01', '1.5', '18446744073709551616', 'x']) {
      expectInvalid(() => decimalKey(bad));
    }
    expect(instantKey('2026-11-12T08:00:00.000Z')).toEqual(new Date('2026-11-12T08:00:00Z'));
    for (const bad of [undefined, '2026-11-12', '2026-11-12T08:00:00Z', 'nope']) {
      expectInvalid(() => instantKey(bad));
    }
    expect(intKey('7', 10)).toBe(7);
    expectInvalid(() => intKey('11', 10));
    expectInvalid(() => intKey('-1', 10));
  });

  it('hashes identifying values (never stored in the clear)', () => {
    expect(sha256Hex('a@b.example')).toMatch(/^[0-9a-f]{64}$/);
    expect(sha256Hex('a@b.example')).not.toContain('a@b');
  });
});
