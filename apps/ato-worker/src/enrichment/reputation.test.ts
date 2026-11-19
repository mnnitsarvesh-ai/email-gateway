import { describe, expect, it } from 'vitest';
import {
  ReputationService,
  type ProviderAnswer,
  type ReputationItem,
  type ReputationLookup,
  type ReputationProvider,
} from '@email-gateway/url-security';
import { AtoReputation, toAtoIpReputation } from './reputation';

const signal = new AbortController().signal;

function provider(
  id: string,
  answer: (item: ReputationItem) => Partial<ProviderAnswer>,
): ReputationProvider & { seen: string[] } {
  const p = {
    id,
    version: `${id}/1`,
    kinds: ['ip'] as const,
    cacheable: false,
    seen: [] as string[],
    lookup(items: readonly ReputationItem[]): Promise<ProviderAnswer[]> {
      p.seen.push(...items.map((i) => `${i.kind}:${i.value}`));
      return Promise.resolve(
        items.map((i) => ({
          kind: i.kind,
          value: i.value,
          status: 'clear' as const,
          category: null,
          severity: null,
          detail: null,
          ...answer(i),
        })),
      );
    },
  };
  return p;
}

const service = (...providers: ReputationProvider[]) =>
  new ReputationService(providers, { timeoutMs: 500, breakerThreshold: 3, breakerResetMs: 1000 });

const lookup = (p: Partial<ReputationLookup>): ReputationLookup => ({
  kind: 'ip',
  value: '192.0.2.1',
  status: 'clear',
  category: null,
  severity: null,
  detail: null,
  provider: 'local_feed',
  version: 'v',
  cache: 'none',
  ...p,
});

describe('toAtoIpReputation (D7 normalized result)', () => {
  it('listed → the most severe listed answer; confidence is null today', () => {
    expect(
      toAtoIpReputation([
        lookup({ status: 'listed', severity: 'medium', category: 'spam' }),
        lookup({ status: 'listed', severity: 'critical', category: 'c2', provider: 'other' }),
      ]),
    ).toEqual({
      status: 'listed',
      severity: 'critical',
      category: 'c2',
      confidence: null,
      providers: ['local_feed', 'other'],
    });
  });

  it('errors are error (never clear), no answer is error, all clear is clear', () => {
    expect(toAtoIpReputation([lookup({}), lookup({ status: 'error' })]).status).toBe('error');
    expect(toAtoIpReputation([]).status).toBe('error');
    expect(toAtoIpReputation([lookup({})])).toMatchObject({ status: 'clear', severity: null });
  });
});

describe('AtoReputation.lookupIps (the single ReputationService adapter)', () => {
  it('sends ip items through ReputationService and separates the feed from DNSBL (T1 vs T2)', async () => {
    const feed = provider('local_feed', (i) =>
      i.value === '192.0.2.66' ? { status: 'listed', severity: 'high', category: 'other' } : {},
    );
    const dnsbl = provider('dnsbl', (i) =>
      i.value === '192.0.2.77' ? { status: 'listed', category: 'other' } : {},
    );
    const rep = new AtoReputation(service(feed, dnsbl), null, 1);
    const out = await rep.lookupIps(1n, ['192.0.2.66', '192.0.2.77', '192.0.2.66'], signal);
    expect(feed.seen).toEqual(['ip:192.0.2.66', 'ip:192.0.2.77']);
    expect(out.get('192.0.2.66')).toEqual({
      reputation: {
        status: 'listed',
        severity: 'high',
        category: 'other',
        confidence: null,
        providers: ['local_feed'],
      },
      dnsblListed: false,
    });
    expect(out.get('192.0.2.77')).toMatchObject({
      reputation: { status: 'clear' },
      dnsblListed: true,
    });
  });

  it('honours the tenant switches and an unconfigured DNSBL', async () => {
    const feed = provider('local_feed', () => ({ status: 'listed', severity: 'low' }));
    const dnsbl = provider('dnsbl', () => ({ status: 'listed' }));
    const rep = new AtoReputation(service(feed, dnsbl), null, 1);
    const off = await rep.lookupIps(1n, ['192.0.2.1'], signal, {
      useLocalFeed: false,
      useDnsbl: false,
    });
    expect(off.get('192.0.2.1')).toEqual({ reputation: null, dnsblListed: null });
    const noZones = new AtoReputation(service(feed), null, 0);
    expect((await noZones.lookupIps(1n, ['192.0.2.1'], signal)).get('192.0.2.1')?.dnsblListed).toBe(
      null,
    );
    expect(noZones.dnsblConfigured).toBe(false);
    expect((await rep.lookupIps(1n, [], signal)).size).toBe(0);
  });

  it('a DNSBL error is unknown (null), never clear', async () => {
    const feed = provider('local_feed', () => ({}));
    const dnsbl = provider('dnsbl', () => ({ status: 'error' }));
    const rep = new AtoReputation(service(feed, dnsbl), null, 1);
    expect((await rep.lookupIps(1n, ['192.0.2.9'], signal)).get('192.0.2.9')?.dnsblListed).toBe(
      null,
    );
  });
});
