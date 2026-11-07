import { createHmac } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import {
  buildHistoryUpdates,
  canonicalPair,
  contextKeyHash,
  fingerprintHash,
  historyReadKeys,
  infrastructureFingerprint,
  ipNetwork,
  type HistoryMessageInput,
} from './keys';

const KEY = 'k'.repeat(43);

describe('contextKeyHash', () => {
  it('is HMAC-SHA256 over the prefixed, organization- and scope-bound key', () => {
    const expected = createHmac('sha256', KEY)
      .update('eg-bec-ctx/v1\u000042\u0000sender\u0000a@x.test')
      .digest('hex');
    expect(contextKeyHash(KEY, 42n, 'sender', 'a@x.test')).toBe(expected);
    expect(contextKeyHash(KEY, '42', 'sender', 'a@x.test')).toBe(expected);
  });
  it('is unlinkable across organizations, scopes and keys', () => {
    const a = contextKeyHash(KEY, 1n, 'sender', 'a@x.test');
    expect(contextKeyHash(KEY, 2n, 'sender', 'a@x.test')).not.toBe(a);
    expect(contextKeyHash(KEY, 1n, 'pair', 'a@x.test')).not.toBe(a);
    expect(
      contextKeyHash('other-key-of-sufficient-length-0000000000', 1n, 'sender', 'a@x.test'),
    ).not.toBe(a);
    expect(() => contextKeyHash('', 1n, 'sender', 'a')).toThrow(/empty/);
  });
  it('canonical pairs are direction-insensitive and case-insensitive', () => {
    expect(canonicalPair('B@y.test', 'a@x.test')).toBe('a@x.test\u0000b@y.test');
    expect(canonicalPair('a@x.test', 'B@y.test')).toBe(canonicalPair('b@y.TEST', 'A@x.test'));
  });
});

describe('infrastructure fingerprint', () => {
  it('prefers the DKIM-aligned domain, then the SPF-pass domain, then the client network', () => {
    expect(
      infrastructureFingerprint(
        { dkimAlignedDomain: 'x.test', spfPassDomain: 'esp.test' },
        '192.0.2.10',
      ),
    ).toBe('dkim:x.test');
    expect(
      infrastructureFingerprint(
        { dkimAlignedDomain: null, spfPassDomain: 'esp.test' },
        '192.0.2.10',
      ),
    ).toBe('spf:esp.test');
    expect(
      infrastructureFingerprint({ dkimAlignedDomain: null, spfPassDomain: null }, '192.0.2.10'),
    ).toBe('net:192.0.2.0/24');
    expect(infrastructureFingerprint(null, null)).toBeNull();
  });
  it('/24 and /48 networks', () => {
    expect(ipNetwork('203.0.113.77')).toBe('203.0.113.0/24');
    expect(ipNetwork('2001:db8:abcd:12::1')).toBe('2001:db8:abcd::/48');
    expect(ipNetwork('2001:db8::1')).toBe('2001:db8:0::/48');
    expect(ipNetwork('::ffff:198.51.100.9')).toBe('198.51.100.0/24');
    expect(ipNetwork('not-an-ip')).toBeNull();
  });
  it('fingerprint hash is 16 hex and organization-scoped', () => {
    const h = fingerprintHash(KEY, 1n, 'dkim:x.test');
    expect(h).toMatch(/^[0-9a-f]{16}$/);
    expect(fingerprintHash(KEY, 2n, 'dkim:x.test')).not.toBe(h);
  });
});

describe('buildHistoryUpdates', () => {
  const base: HistoryMessageInput = {
    organizationId: 7n,
    direction: 'inbound',
    headers: { From: ['Ext <Ext@Partner.test>'] },
    envelopeFrom: 'bounce@partner.test',
    recipients: ['a@acmecorp.test', 'B@acmecorp.test', 'a@acmecorp.test'],
    receivedAt: new Date('2026-11-02T09:00:00Z'),
    tenantDomains: ['acmecorp.test'],
    maxRecipients: 50,
    fingerprint: 'dkim:partner.test',
    inboundEligible: true,
  };
  it('inbound: the sender row plus one pair per distinct recipient, sorted, no plaintext', () => {
    const updates = buildHistoryUpdates(KEY, base);
    expect(updates).toHaveLength(3);
    expect(updates.map((u) => u.scope)).toEqual(['pair', 'pair', 'sender']);
    const sorted = [...updates].sort((a, b) =>
      a.scope + a.keyHash < b.scope + b.keyHash ? -1 : 1,
    );
    expect(updates).toEqual(sorted);
    const sender = updates.find((u) => u.scope === 'sender')!;
    expect(sender).toMatchObject({
      inbound: 1,
      outbound: 0,
      keyHash: contextKeyHash(KEY, 7n, 'sender', 'ext@partner.test'),
    });
    expect(sender.fingerprintHash).toBe(fingerprintHash(KEY, 7n, 'dkim:partner.test'));
    expect(
      updates.find(
        (u) =>
          u.keyHash ===
          contextKeyHash(KEY, 7n, 'pair', canonicalPair('ext@partner.test', 'b@acmecorp.test')),
      ),
    ).toBeDefined();
    expect(JSON.stringify(updates)).not.toMatch(/partner|acmecorp/);
  });
  it('inbound not eligible (unauthenticated From or a suspicious/malicious verdict): nothing counted', () => {
    expect(buildHistoryUpdates(KEY, { ...base, inboundEligible: false })).toEqual([]);
    // Outbound updates never depend on it.
    expect(
      buildHistoryUpdates(KEY, {
        ...base,
        inboundEligible: false,
        direction: 'outbound',
        headers: { From: ['me@acmecorp.test'] },
        recipients: ['ext@partner.test'],
      }),
    ).toHaveLength(1);
  });
  it('outbound / internal: pairs with external recipients only (outbound_count)', () => {
    const out = buildHistoryUpdates(KEY, {
      ...base,
      direction: 'outbound',
      headers: { From: ['me@acmecorp.test'] },
      recipients: ['ext@partner.test', 'colleague@acmecorp.test'],
    });
    expect(out).toHaveLength(1);
    expect(out[0]).toMatchObject({ scope: 'pair', inbound: 0, outbound: 1, fingerprintHash: null });
    expect(out[0]!.keyHash).toBe(
      contextKeyHash(KEY, 7n, 'pair', canonicalPair('ext@partner.test', 'me@acmecorp.test')),
    );
    expect(
      buildHistoryUpdates(KEY, {
        ...base,
        direction: 'internal',
        headers: { From: ['me@acmecorp.test'] },
        recipients: ['x@acmecorp.test'],
      }),
    ).toEqual([]);
  });
  it('an outbound pair is found again by the inbound reply (direction-insensitive)', () => {
    const out = buildHistoryUpdates(KEY, {
      ...base,
      direction: 'outbound',
      headers: { From: ['a@acmecorp.test'] },
      recipients: ['ext@partner.test'],
    });
    const reads = historyReadKeys(KEY, base);
    expect(reads.pairs).toContain(out[0]!.keyHash);
  });
  it('is bounded to 51 rows', () => {
    const recipients = Array.from({ length: 80 }, (_, i) => `r${i}@acmecorp.test`);
    expect(buildHistoryUpdates(KEY, { ...base, recipients })).toHaveLength(51);
    expect(historyReadKeys(KEY, { ...base, recipients }).pairs).toHaveLength(50);
  });
  it('no From and no envelope sender → nothing', () => {
    expect(buildHistoryUpdates(KEY, { ...base, headers: {}, envelopeFrom: null })).toEqual([]);
  });
});
