import { createHash } from 'node:crypto';
import {
  type FeedRow,
  LocalFeedProvider,
  normalizeIndicator,
  normalizeUrl,
  type ReputationKind,
  reputationItemsFor,
} from '@email-gateway/url-security';
import { describe, expect, it } from 'vitest';
import { normalizeLookup } from './lookup-value';

const sha = (v: string) => createHash('sha256').update(v).digest('hex');

/** The hashes the URL engine's local feed asks MySQL for, per kind, for one URL in a message. */
async function engineHashes(rawUrl: string): Promise<Map<ReputationKind, string[]>> {
  const normalized = normalizeUrl(rawUrl);
  if (!normalized.ok) throw new Error('fixture URL does not normalize');
  const asked = new Map<ReputationKind, string[]>();
  const provider = new LocalFeedProvider((kind, hashes): Promise<FeedRow[]> => {
    asked.set(kind, [...(asked.get(kind) ?? []), ...hashes]);
    return Promise.resolve([]);
  });
  await provider.lookup(reputationItemsFor(normalized.url), new AbortController().signal);
  return asked;
}

function lookup(type: 'sha256' | 'url' | 'domain' | 'ip', value: string) {
  const result = normalizeLookup(type, value);
  if (!result.ok) throw new Error(`expected ${type} ${value} to normalize`);
  return result.lookup;
}

describe('threat lookup normalization (parity with the engines)', () => {
  it('url: the same value_sha256 the URL engine looks up and the platform catalog stores', async () => {
    const raw = 'HTTPS://Login.Example-Bank.COM:443/a/../Verify?x=1#frag';
    const asked = await engineHashes(raw);
    const l = lookup('url', raw);
    expect(l.matchHashes).toEqual(asked.get('url'));
    const stored = normalizeIndicator('url', raw);
    expect(stored.ok && stored.valueSha256).toBe(l.valueSha256);
    expect(l.indicatorType).toBe('url');
  });

  it('domain: the host and its parents down to the registrable domain, as the engine expands', async () => {
    const asked = await engineHashes('https://a.b.Example-Bank.co.uk./x');
    const l = lookup('domain', 'A.B.EXAMPLE-BANK.CO.UK.');
    expect([...l.matchHashes].sort()).toEqual([...(asked.get('domain') ?? [])].sort());
    expect(l.matchHashes).toContain(sha('example-bank.co.uk'));
    expect(l.valueSha256).toBe(sha('a.b.example-bank.co.uk'));
    // IDNA: a Unicode domain normalizes to the ASCII form the URL parser gives the engine.
    const idn = lookup('domain', 'bücher.example');
    expect(idn.value).toBe('xn--bcher-kva.example');
    const askedIdn = await engineHashes('https://bücher.example/');
    expect(idn.matchHashes).toEqual(askedIdn.get('domain'));
  });

  it('ip: the canonical text the engine hashes', async () => {
    const asked = await engineHashes('http://[2001:DB8:0:0::1]/');
    const l = lookup('ip', '2001:db8::0:1');
    expect(l.matchHashes).toEqual(asked.get('ip'));
    expect(l.value).toBe('2001:db8::1');
    expect(lookup('ip', '192.0.2.1').valueSha256).toBe(sha('192.0.2.1'));
  });

  it('sha256: lower-case hex; the indicator key is the SHA-256 of the hex text', () => {
    const hex = 'AB'.repeat(32);
    const l = lookup('sha256', ` ${hex} `);
    expect(l.value).toBe('ab'.repeat(32));
    expect(l.valueSha256).toBe(sha('ab'.repeat(32)));
    expect(l.indicatorType).toBe('file_sha256');
  });

  it('refuses invalid values with a reason (no value echoed)', () => {
    expect(normalizeLookup('sha256', 'xyz').ok).toBe(false);
    expect(normalizeLookup('url', 'ftp://example.com/').ok).toBe(false);
    expect(normalizeLookup('url', 'not a url').ok).toBe(false);
    expect(normalizeLookup('domain', 'co.uk').ok).toBe(false);
    expect(normalizeLookup('domain', 'localhost').ok).toBe(false);
    expect(normalizeLookup('domain', '192.0.2.1').ok).toBe(false);
    expect(normalizeLookup('ip', '300.1.1.1').ok).toBe(false);
    expect(normalizeLookup('domain', `${'a'.repeat(250)}.com`).ok).toBe(false);
    expect(normalizeLookup('url', `https://e.com/${'a'.repeat(2100)}`).ok).toBe(false);
  });
});
