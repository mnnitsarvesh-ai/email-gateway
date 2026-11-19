import { createHash } from 'node:crypto';
import type { Prisma } from '@prisma/client';
import { describe, expect, it } from 'vitest';
import {
  PROVIDER_EGRESS_SNAPSHOT,
  compareEgressRanges,
  egressSetSha256,
  parseEgressCidr,
  seedProviderEgress,
} from './provider-egress';

describe('parseEgressCidr', () => {
  it('encodes IPv4 networks as 4-byte big-endian ranges', () => {
    const r = parseEgressCidr('40.92.0.0/15');
    expect(r).toMatchObject({ cidr: '40.92.0.0/15', ipVersion: 4, prefix: 15 });
    expect(r.rangeStart.toString('hex')).toBe('285c0000');
    expect(r.rangeEnd.toString('hex')).toBe('285dffff');
  });

  it('encodes IPv6 networks as 16-byte big-endian ranges', () => {
    const r = parseEgressCidr('2001:4860:4000::/36');
    expect(r).toMatchObject({ ipVersion: 6, prefix: 36 });
    expect(r.rangeStart.toString('hex')).toBe('20014860400000000000000000000000');
    expect(r.rangeEnd.toString('hex')).toBe('200148604fffffffffffffffffffffff');
    expect(parseEgressCidr('2a01:111:f400::/48').rangeEnd.toString('hex')).toBe(
      '2a010111f400ffffffffffffffffffff',
    );
  });

  it('refuses non-canonical, malformed and overly broad input', () => {
    for (const bad of [
      '40.92.0.0', // no prefix
      '40.92.0.1/15', // host bits set
      '40.093.0.0/16', // leading zero
      '256.0.0.0/8',
      '40.92.0.0/33',
      '0.0.0.0/0',
      '10.0.0.0/7',
      '2001:4860:4000:0::/36', // not RFC 5952
      '2001:4860:4000::/129',
      '2A00:1450:4000::/36', // upper case
      '::ffff:1.2.3.4/128', // embedded IPv4
      'fe80::1%eth0/64',
      ' 40.92.0.0/15',
      '',
    ]) {
      expect(() => parseEgressCidr(bad), bad).toThrow();
    }
  });
});

describe('PROVIDER_EGRESS_SNAPSHOT', () => {
  const byProvider = (provider: string) =>
    PROVIDER_EGRESS_SNAPSHOT.find((s) => s.provider === provider)!;

  it('holds version 1 of both providers, published 2026-06-01, imported by the seed', () => {
    expect(PROVIDER_EGRESS_SNAPSHOT.map((s) => s.provider)).toEqual([
      'microsoft_365',
      'google_workspace',
    ]);
    for (const set of PROVIDER_EGRESS_SNAPSHOT) {
      expect(set.version).toBe(1);
      expect(set.importedBy).toBe('seed');
      expect(set.publishedAt.toISOString()).toBe('2026-06-01T00:00:00.000Z');
      expect(set.source.length).toBeLessThanOrEqual(512);
      expect(set.source).toMatch(/^https:\/\//);
    }
  });

  it('copies the design note §3.2 ranges verbatim', () => {
    expect([...byProvider('microsoft_365').cidrs]).toEqual([
      '40.92.0.0/15',
      '40.107.0.0/16',
      '52.100.0.0/15',
      '52.102.0.0/16',
      '52.103.0.0/17',
      '104.47.0.0/17',
      '2a01:111:f400::/48',
      '2a01:111:f403::/48',
    ]);
    expect(byProvider('google_workspace').cidrs).toHaveLength(27);
    expect(byProvider('google_workspace').cidrs.filter((c) => c.includes(':'))).toEqual([
      '2001:4860:4000::/36',
      '2404:6800:4000::/36',
      '2607:f8b0:4000::/36',
      '2800:3f0:4000::/36',
      '2a00:1450:4000::/36',
      '2c0f:fb50:4000::/36',
    ]);
  });

  it('contains only canonical, unique, non-overlapping CIDRs', () => {
    for (const set of PROVIDER_EGRESS_SNAPSHOT) {
      const ranges = set.cidrs.map(parseEgressCidr).sort(compareEgressRanges);
      expect(new Set(ranges.map((r) => r.cidr)).size).toBe(ranges.length);
      for (let i = 1; i < ranges.length; i++) {
        const prev = ranges[i - 1]!;
        const cur = ranges[i]!;
        if (prev.ipVersion !== cur.ipVersion) continue;
        expect(
          Buffer.compare(prev.rangeEnd, cur.rangeStart),
          `${prev.cidr} / ${cur.cidr}`,
        ).toBeLessThan(0);
      }
    }
  });
});

describe('egressSetSha256', () => {
  it('hashes the canonical CIDRs in IPv4-then-IPv6 address order, independent of input order', () => {
    const ranges = ['2a01:111:f400::/48', '52.100.0.0/15', '40.92.0.0/15'].map(parseEgressCidr);
    const expected = createHash('sha256')
      .update('40.92.0.0/15\n52.100.0.0/15\n2a01:111:f400::/48', 'utf8')
      .digest('hex');
    expect(egressSetSha256(ranges)).toBe(expected);
    expect(egressSetSha256([...ranges].reverse())).toBe(expected);
  });
});

/** Minimal in-memory stand-in for the two egress tables (the seed uses findFirst and create). */
function fakeTx(existing: string[] = []) {
  const sets: { provider: string; data: Record<string, unknown> }[] = existing.map((provider) => ({
    provider,
    data: { provider },
  }));
  const tx = {
    providerEgressRangeSet: {
      findFirst: ({ where }: { where: { provider: string } }) => {
        const found = sets.find((s) => s.provider === where.provider);
        return Promise.resolve(found ? { id: BigInt(sets.indexOf(found) + 1) } : null);
      },
      create: ({ data }: { data: Record<string, unknown> & { provider: string } }) => {
        sets.push({ provider: data.provider, data });
        return Promise.resolve({ id: BigInt(sets.length) });
      },
    },
  };
  return { tx: tx as unknown as Prisma.TransactionClient, sets };
}

describe('seedProviderEgress', () => {
  it('inserts an active snapshot set with every range for each provider without a set', async () => {
    const { tx, sets } = fakeTx();
    const summary = await seedProviderEgress(tx);
    expect(summary.created).toEqual(['microsoft_365', 'google_workspace']);
    expect(sets).toHaveLength(2);
    const m365 = sets[0]!.data as {
      status: string;
      version: number;
      rangeCount: number;
      sha256: string;
      importedBy: string;
      publishedAt: Date;
      ranges: {
        createMany: {
          data: { provider: string; cidr: string; ipVersion: number; rangeStart: Uint8Array }[];
        };
      };
    };
    expect(m365).toMatchObject({ status: 'active', version: 1, rangeCount: 8, importedBy: 'seed' });
    expect(m365.publishedAt.toISOString()).toBe('2026-06-01T00:00:00.000Z');
    const rows = m365.ranges.createMany.data;
    expect(rows).toHaveLength(8);
    expect(rows.every((r) => r.provider === 'microsoft_365')).toBe(true);
    // Stored in lookup order: IPv4 first, ascending.
    expect(rows.map((r) => r.cidr)).toEqual([
      '40.92.0.0/15',
      '40.107.0.0/16',
      '52.100.0.0/15',
      '52.102.0.0/16',
      '52.103.0.0/17',
      '104.47.0.0/17',
      '2a01:111:f400::/48',
      '2a01:111:f403::/48',
    ]);
    expect(m365.sha256).toBe(egressSetSha256(rows.map((r) => parseEgressCidr(r.cidr))));
    expect((sets[1]!.data as { rangeCount: number }).rangeCount).toBe(27);
  });

  it('never touches a provider that already has a set (seeded or imported)', async () => {
    const { tx, sets } = fakeTx(['microsoft_365']);
    const summary = await seedProviderEgress(tx);
    expect(summary.created).toEqual(['google_workspace']);
    expect(sets).toHaveLength(2);
    const again = await seedProviderEgress(tx);
    expect(again.created).toEqual([]);
    expect(sets).toHaveLength(2);
  });

  it('refuses a snapshot with duplicate CIDRs', async () => {
    const { tx } = fakeTx();
    await expect(
      seedProviderEgress(tx, [
        { ...PROVIDER_EGRESS_SNAPSHOT[0]!, cidrs: ['40.92.0.0/15', '40.92.0.0/15'] },
      ]),
    ).rejects.toThrow(/duplicate/);
  });
});
