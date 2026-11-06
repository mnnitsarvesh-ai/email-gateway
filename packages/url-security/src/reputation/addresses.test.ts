import { describe, expect, it } from 'vitest';
import { mergeLookalike, type LookalikeResult } from '../lookalike';
import { fakeDns, testGuard } from '../net/net.test-support';
import { HostAddressResolver } from './addresses';
import { addressItems, chainHosts, chainItems } from './items';

/** IP reputation of resolved addresses (brief item 4, U3 step 5) and the shared chain helpers. */

const { resolver, queries } = fakeDns({
  'site.test': { v4: ['203.0.113.10', '203.0.113.11'], v6: ['::1'] },
  'listed.test': { v4: ['203.0.113.66'] },
  'private.test': { v4: ['10.0.0.5'] },
  'mixed.test': { v4: ['203.0.113.12', '10.0.0.5'] },
  'many.test': { v4: ['203.0.113.1', '203.0.113.2', '203.0.113.3', '203.0.113.4', '203.0.113.5'] },
});

describe('HostAddressResolver', () => {
  it('returns public answers only, deduplicated and capped; literals and NXDOMAIN have none', async () => {
    queries.length = 0;
    const addresses = await new HostAddressResolver(resolver, testGuard()).resolve([
      'site.test',
      'SITE.test',
      'listed.test',
      'private.test',
      'mixed.test',
      'many.test',
      'nx.test',
      '203.0.113.9',
      '[2001:db8::1]',
      '',
    ]);
    expect(Object.fromEntries(addresses)).toEqual({
      // ::1 (loopback) is dropped: internal answers are never sent to a provider.
      'site.test': ['203.0.113.10', '203.0.113.11'],
      'listed.test': ['203.0.113.66'],
      // Mixed answers are blocked for fetching; the public one is still looked up.
      'mixed.test': ['203.0.113.12'],
      'many.test': ['203.0.113.1', '203.0.113.2', '203.0.113.3', '203.0.113.4'],
    });
    // Literals are never resolved; every name once.
    expect(queries.filter((q) => q.startsWith('v4:')).map((q) => q.slice(3))).toEqual([
      'site.test',
      'listed.test',
      'private.test',
      'mixed.test',
      'many.test',
      'nx.test',
    ]);
  });

  it('a failing resolver or an aborted signal yields no address (never a throw)', async () => {
    const failing = {
      resolveValidated: () => Promise.reject(new Error('socket closed')),
    };
    expect((await new HostAddressResolver(failing, testGuard()).resolve(['a.test'])).size).toBe(0);
    const aborted = AbortSignal.abort();
    expect(
      (await new HostAddressResolver(resolver, testGuard()).resolve(['site.test'], aborted)).size,
    ).toBe(0);
  });
});

describe('chain helpers (shared by the engine and the click-service)', () => {
  const result = {
    hops: [
      { host: 'short.test', port: null, status: 301, kind: 'initial' as const, blocked: null },
      { host: 'hop.test', port: null, status: 302, kind: 'http' as const, blocked: null },
      { host: '203.0.113.10', port: null, status: 302, kind: 'http' as const, blocked: null },
      {
        host: '10.0.0.5',
        port: null,
        status: null,
        kind: 'http' as const,
        blocked: 'private' as const,
      },
    ],
    finalUrl: 'http://final.test/x',
  };

  it('chainHosts: the final domain host and later unblocked domain hops', () => {
    expect(chainHosts(result)).toEqual(['final.test', 'hop.test']);
  });

  it('chainItems: final URL + host, hop hosts, and the addresses of domain hosts', () => {
    const addresses = new Map([
      ['final.test', ['203.0.113.66']],
      ['hop.test', ['203.0.113.10', '203.0.113.77']],
    ]);
    expect(chainItems(result, addresses)).toEqual([
      { kind: 'url', value: 'http://final.test/x' },
      { kind: 'domain', value: 'final.test' },
      { kind: 'domain', value: 'hop.test' },
      { kind: 'ip', value: '203.0.113.10' },
      { kind: 'ip', value: '203.0.113.66' },
      { kind: 'ip', value: '203.0.113.77' },
    ]);
    expect(chainItems(result)).toHaveLength(4);
    expect(addressItems(['HOP.test'], addresses)).toEqual([
      { kind: 'ip', value: '203.0.113.10' },
      { kind: 'ip', value: '203.0.113.77' },
    ]);
  });

  it('mergeLookalike keeps the strongest findings and unions the flags', () => {
    const none: LookalikeResult = {
      findings: [],
      mixedScript: false,
      idn: false,
      highConfidence: false,
      codes: [],
    };
    const strong: LookalikeResult = {
      findings: [
        {
          rule: 'L2',
          targetKind: 'extra',
          targetDomain: 'examplebank.test',
          score: 0.9,
          distance: 1,
        },
      ],
      mixedScript: false,
      idn: true,
      highConfidence: true,
      codes: ['url.idn', 'url.lookalike_edit_distance'],
    };
    expect(mergeLookalike(none, null)).toBe(none);
    expect(mergeLookalike(none, strong)).toEqual(strong);
  });
});
