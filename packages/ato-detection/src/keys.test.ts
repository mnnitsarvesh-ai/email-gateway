import { describe, expect, it } from 'vitest';
import {
  atoMailboxSha256,
  atoMailKey,
  atoSubjectHash,
  hmacKey,
  providerPageKey,
  restrictionSubjectHash,
  signalDedupeKey,
} from './keys';

const UUID_V8 = /^[0-9a-f]{8}-[0-9a-f]{4}-8[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;

describe('keys', () => {
  it('atoMailKey is a deterministic RFC 9562 version-8 UUID per (message, scan)', () => {
    const a = atoMailKey(123n, 456n);
    expect(a).toMatch(UUID_V8);
    expect(atoMailKey('123', '456')).toBe(a);
    expect(atoMailKey(123n, 457n)).not.toBe(a);
    expect(atoMailKey(1234n, 56n)).not.toBe(atoMailKey(123n, 456n));
  });

  it('providerPageKey separates integrations, streams and cursors', () => {
    const k = providerPageKey(1n, 'sign_ins', null);
    expect(k).toMatch(UUID_V8);
    expect(providerPageKey('1', 'sign_ins', '')).toBe(k);
    expect(providerPageKey(1n, 'sign_ins', '2')).not.toBe(k);
    expect(providerPageKey(1n, 'risk_events', null)).not.toBe(k);
  });

  it('restrictionSubjectHash covers kind, scope, connector, mailbox and CIDR', () => {
    const base = {
      kind: 'send_block' as const,
      scope: 'mailbox' as const,
      connectorId: null,
      mailboxSha256: 'a'.repeat(64),
      cidr: null,
    };
    const h = restrictionSubjectHash(base);
    expect(h).toMatch(/^[0-9a-f]{64}$/);
    expect(restrictionSubjectHash({ ...base, kind: 'auth_block' })).not.toBe(h);
    expect(
      restrictionSubjectHash({
        kind: 'auth_block',
        scope: 'connector_ip',
        connectorId: 7n,
        mailboxSha256: null,
        cidr: '192.0.2.0/24',
      }),
    ).not.toBe(
      restrictionSubjectHash({
        kind: 'auth_block',
        scope: 'connector_ip',
        connectorId: 7n,
        mailboxSha256: null,
        cidr: '192.0.2.0/25',
      }),
    );
  });

  it('hmacKey is keyed and purpose-separated', () => {
    const k = 'k'.repeat(32);
    expect(hmacKey(k, 'domain', 'example.com')).toMatch(/^[0-9a-f]{32}$/);
    expect(hmacKey(k, 'domain', 'example.com')).not.toBe(hmacKey(k, 'account', 'example.com'));
    expect(hmacKey(k, 'domain', 'example.com')).not.toBe(
      hmacKey('x'.repeat(32), 'domain', 'example.com'),
    );
  });

  it('re-exports the shared subject hashes', () => {
    expect(atoSubjectHash('mailbox', 'A@Example.TEST')).toBe(
      atoSubjectHash('mailbox', 'a@example.test'),
    );
    expect(atoMailboxSha256('a@example.test')).toMatch(/^[0-9a-f]{64}$/);
  });

  it('signalDedupeKey changes with each part', () => {
    const k = signalDedupeKey('ato.auth.bruteforce', 1n, 'account', 10);
    expect(k).not.toBe(signalDedupeKey('ato.auth.bruteforce', 1n, 'account', 11));
    expect(k).not.toBe(signalDedupeKey('ato.auth.bruteforce', 2n, 'account', 10));
    expect(k).not.toBe(signalDedupeKey('ato.auth.lockout', 1n, 'account', 10));
  });
});
