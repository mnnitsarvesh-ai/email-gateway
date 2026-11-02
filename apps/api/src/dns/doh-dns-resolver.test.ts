import * as dnsPacket from 'dns-packet';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { TestDnsServer } from '../../test/support/dns/test-dns-server';
import { TestDohServer } from '../../test/support/dns/test-doh-server';
import { DohDnsResolver } from './doh-dns-resolver';

let dns: TestDnsServer;
let doh: TestDohServer;
let resolver: DohDnsResolver;

beforeAll(async () => {
  dns = await TestDnsServer.start({ defaultTtl: 120 });
  doh = await TestDohServer.start(dns);
  resolver = new DohDnsResolver({ url: doh.url, timeoutMs: 300, tries: 2 });
});
afterAll(async () => {
  await doh.close();
  await dns.close();
});
beforeEach(() => dns.reset());

function urlOf(input: string | URL | Request): string {
  if (typeof input === 'string') return input;
  return input instanceof URL ? input.href : input.url;
}

/** A resolver whose fetch returns a fixed response (for malformed upstream behaviour). */
function withResponse(make: (query: dnsPacket.Packet) => Response): DohDnsResolver {
  return new DohDnsResolver({
    url: 'https://doh.invalid/dns-query',
    timeoutMs: 300,
    tries: 1,
    fetch: (input) => {
      const param = new URL(urlOf(input)).searchParams.get('dns')!;
      return Promise.resolve(make(dnsPacket.decode(Buffer.from(param, 'base64url'))));
    },
  });
}

function wire(packet: dnsPacket.Packet): Response {
  return new Response(new Uint8Array(dnsPacket.encode(packet)), {
    status: 200,
    headers: { 'content-type': 'application/dns-message' },
  });
}

describe('DohDnsResolver against TestDohServer', () => {
  it('sends an RFC 8484 GET with message id 0 and returns answers with the minimum TTL', async () => {
    dns.setTxt('acme.test', ['v=spf1 include:_spf.mail-gateway.test ~all']);
    const result = await resolver.resolveTxt('acme.test');
    expect(result).toMatchObject({
      outcome: 'answer',
      records: ['v=spf1 include:_spf.mail-gateway.test ~all'],
      ttlSeconds: 120,
      upstream: `doh:${doh.url}`,
      fromCache: false,
      dnssecAuthenticated: false,
    });
    expect(dns.queries).toEqual([{ name: 'acme.test', type: 'TXT', transport: 'doh' }]);
  });

  it('joins long TXT strings and lower-cases MX exchanges', async () => {
    const long = `v=DKIM1; k=rsa; p=${'B'.repeat(700)}`;
    dns.setTxt('sel._domainkey.acme.test', [long]);
    dns.setMx('acme.test', [{ priority: 5, exchange: 'MX1.Mail-Gateway.test' }]);
    const txt = await resolver.resolveTxt('sel._domainkey.acme.test');
    expect(txt.outcome === 'answer' && txt.records).toEqual([long]);
    const mx = await resolver.resolveMx('acme.test');
    expect(mx.outcome === 'answer' && mx.records).toEqual([
      { priority: 5, exchange: 'mx1.mail-gateway.test' },
    ]);
  });

  it('follows CNAME chains for the asked type', async () => {
    dns.setCname('sel._domainkey.acme.test', 'keys.provider.test');
    dns.setCname('keys.provider.test', 'k2.provider.test');
    dns.setTxt('k2.provider.test', ['v=DKIM1; k=ed25519; p=abc']);
    const result = await resolver.resolveTxt('sel._domainkey.acme.test');
    expect(result).toMatchObject({ outcome: 'answer', records: ['v=DKIM1; k=ed25519; p=abc'] });
  });

  it('reports NODATA when a CNAME chain ends without the asked type', async () => {
    dns.setCname('alias.acme.test', 'target.acme.test');
    dns.setMx('target.acme.test', [{ priority: 1, exchange: 'mx.acme.test' }]);
    expect((await resolver.resolveTxt('alias.acme.test')).outcome).toBe('nodata');
  });

  it('maps NXDOMAIN and NODATA with the SOA negative TTL', async () => {
    dns.setMx('acme.test', [{ priority: 10, exchange: 'mx.acme.test' }]);
    expect(await resolver.resolveTxt('missing.test')).toMatchObject({
      outcome: 'nxdomain',
      ttlSeconds: 120,
    });
    expect(await resolver.resolveTxt('acme.test')).toMatchObject({
      outcome: 'nodata',
      ttlSeconds: 120,
    });
  });

  it.each([
    ['servfail', 'servfail'],
    ['refused', 'refused'],
  ] as const)('maps RCODE %s to indeterminate', async (failure, reason) => {
    dns.fail('acme.test', failure);
    expect(await resolver.resolveTxt('acme.test')).toMatchObject({
      outcome: 'indeterminate',
      reason,
    });
  });

  it('times out per try and retries up to the try count', async () => {
    dns.fail('acme.test', 'timeout');
    const result = await resolver.resolveTxt('acme.test');
    expect(result).toMatchObject({ outcome: 'indeterminate', reason: 'timeout' });
    expect(dns.queries).toHaveLength(2);
  });

  it('retries HTTP 5xx and succeeds within the try count', async () => {
    dns.setTxt('acme.test', ['ok']);
    doh.failNext(503, 1);
    expect(await resolver.resolveTxt('acme.test')).toMatchObject({
      outcome: 'answer',
      records: ['ok'],
    });
  });

  it('gives up after the last 5xx', async () => {
    dns.setTxt('acme.test', ['ok']);
    doh.failNext(502, 2);
    expect(await resolver.resolveTxt('acme.test')).toMatchObject({
      outcome: 'indeterminate',
      detail: 'HTTP 502',
    });
  });

  it('does not retry HTTP 4xx', async () => {
    dns.setTxt('acme.test', ['ok']);
    doh.failNext(400, 1);
    expect(await resolver.resolveTxt('acme.test')).toMatchObject({
      outcome: 'indeterminate',
      reason: 'other',
      detail: 'HTTP 400',
    });
    expect(await resolver.resolveTxt('acme.test')).toMatchObject({ outcome: 'answer' });
  });

  it('reports connection refused as a network failure', async () => {
    const closed = new DohDnsResolver({
      url: 'http://127.0.0.1:9/dns-query',
      timeoutMs: 300,
      tries: 1,
    });
    expect(await closed.resolveTxt('acme.test')).toMatchObject({
      outcome: 'indeterminate',
      reason: 'network',
    });
  });

  it('serves POST requests too (server contract)', async () => {
    dns.setTxt('acme.test', ['posted']);
    const query = dnsPacket.encode({
      type: 'query',
      id: 0,
      questions: [{ type: 'TXT', name: 'acme.test' }],
    });
    const res = await fetch(doh.url, {
      method: 'POST',
      headers: { 'content-type': 'application/dns-message' },
      body: new Uint8Array(query),
    });
    expect(res.status).toBe(200);
    const decoded = dnsPacket.decode(Buffer.from(await res.arrayBuffer()));
    expect(decoded.answers?.[0]).toMatchObject({ type: 'TXT', name: 'acme.test' });
  });
});

describe('DohDnsResolver response validation', () => {
  const answer = (query: dnsPacket.Packet, extra: Partial<dnsPacket.Packet> = {}) =>
    wire({
      type: 'response',
      id: 0,
      flags: 0,
      questions: query.questions,
      answers: [{ type: 'TXT', name: query.questions![0]!.name, ttl: 30, data: 'x' }],
      ...extra,
    });

  it('rejects a wrong content type', async () => {
    const r = withResponse(
      () => new Response('{}', { status: 200, headers: { 'content-type': 'application/json' } }),
    );
    expect(await r.resolveTxt('acme.test')).toMatchObject({
      outcome: 'indeterminate',
      reason: 'malformed',
    });
  });

  it('rejects bodies over 64 KiB', async () => {
    const r = withResponse(
      () =>
        new Response(new Uint8Array(70 * 1024), {
          status: 200,
          headers: { 'content-type': 'application/dns-message' },
        }),
    );
    expect(await r.resolveTxt('acme.test')).toMatchObject({
      outcome: 'indeterminate',
      reason: 'malformed',
      detail: 'response larger than 64 KiB',
    });
  });

  it('rejects undecodable bodies', async () => {
    const r = withResponse(
      () =>
        new Response(new Uint8Array([1, 2, 3]), {
          status: 200,
          headers: { 'content-type': 'application/dns-message' },
        }),
    );
    expect(await r.resolveTxt('acme.test')).toMatchObject({
      outcome: 'indeterminate',
      reason: 'malformed',
    });
  });

  it('rejects an answer to another question', async () => {
    const r = withResponse((query) =>
      answer(query, { questions: [{ type: 'TXT', name: 'evil.test' }] }),
    );
    expect(await r.resolveTxt('acme.test')).toMatchObject({
      outcome: 'indeterminate',
      reason: 'malformed',
    });
  });

  it('maps other RCODEs to indeterminate/other', async () => {
    const r = withResponse((query) => answer(query, { flags: 4, answers: [] })); // NOTIMP
    expect(await r.resolveTxt('acme.test')).toMatchObject({
      outcome: 'indeterminate',
      reason: 'other',
    });
  });

  it('records the AD flag as dnssecAuthenticated', async () => {
    const r = withResponse((query) => answer(query, { flags: dnsPacket.AUTHENTIC_DATA }));
    expect(await r.resolveTxt('acme.test')).toMatchObject({
      outcome: 'answer',
      records: ['x'],
      ttlSeconds: 30,
      dnssecAuthenticated: true,
    });
  });

  it('requests with id 0, RD and the accept header', async () => {
    let seen: { id?: number; flags?: number; accept: string | null } | undefined;
    const r = new DohDnsResolver({
      url: 'https://doh.invalid/dns-query?ct',
      timeoutMs: 300,
      tries: 1,
      fetch: (input, init) => {
        const url = new URL(urlOf(input));
        const query = dnsPacket.decode(Buffer.from(url.searchParams.get('dns')!, 'base64url'));
        seen = {
          id: query.id,
          flags: query.flags,
          accept: new Headers(init?.headers).get('accept'),
        };
        expect(url.searchParams.get('dns')).not.toMatch(/[=+/]/);
        return Promise.resolve(answer(query));
      },
    });
    await r.resolveTxt('acme.test');
    expect(seen?.id).toBe(0);
    expect((seen?.flags ?? 0) & dnsPacket.RECURSION_DESIRED).toBeTruthy();
    expect(seen?.accept).toBe('application/dns-message');
  });
});
