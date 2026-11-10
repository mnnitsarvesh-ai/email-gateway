import http from 'node:http';
import type { AddressInfo } from 'node:net';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { SinkholeClient, SinkholeError } from './sinkhole-client';

const TOKEN = 't'.repeat(40);
const SHA = 'a'.repeat(64);

describe('SinkholeClient (HTTP transport against a fake admin API)', () => {
  let server: http.Server;
  let url: string;
  const seen: Array<{ method?: string; url?: string; auth?: string }> = [];
  let body: unknown = { records: [], dropped: 0 };

  beforeAll(async () => {
    server = http.createServer((req, res) => {
      seen.push({ method: req.method, url: req.url, auth: req.headers.authorization });
      if (req.url === '/health') return void res.end('{"ok":true}');
      if (req.headers.authorization !== `Bearer ${TOKEN}`) {
        res.writeHead(401).end('{"error":"unauthorized"}');
        return;
      }
      if (req.url?.includes('ip=172.31.253.199')) return void res.end('x'.repeat(100_000));
      if (req.url === '/stats') return void res.end('{"total":3,"sources":1}');
      if (req.method === 'DELETE') return void res.end('{"deleted":2}');
      res.end(JSON.stringify(body));
    });
    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
    url = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  });

  afterAll(() => new Promise<void>((resolve) => server.close(() => resolve())));

  it('sends the bearer token and validates records strictly (invalid ones are counted, not kept)', async () => {
    body = {
      records: [
        { kind: 'dns', at: 1, name: 'metadata.google.internal', type: 'A', transport: 'udp' },
        {
          kind: 'http',
          at: 2,
          host: 'mysql',
          port: 80,
          method: 'GET',
          pathSha256: SHA,
          userAgentSha256: null,
        },
        { kind: 'tls', at: 3, sni: null, port: 443 },
        { kind: 'dns', at: 4, name: 'BAD NAME', type: 'A', transport: 'udp' },
        {
          kind: 'http',
          at: 5,
          host: 'x',
          port: 80,
          method: 'GET',
          pathSha256: SHA,
          userAgentSha256: null,
          extra: 1,
        },
        { kind: 'smtp', at: 6 },
      ],
      dropped: 1,
    };
    const client = new SinkholeClient({ adminUrl: url, token: TOKEN });
    const result = await client.fetchRecords('172.31.253.130', 1_700_000_000_123.7);
    expect(result.records.map((r) => r.kind)).toEqual(['dns', 'http', 'tls']);
    expect(result.dropped).toBe(4);
    expect(seen.at(-1)).toEqual({
      method: 'GET',
      url: '/records?ip=172.31.253.130&since=1700000000123',
      auth: `Bearer ${TOKEN}`,
    });
    expect(await client.clearRecords('172.31.253.130')).toBe(2);
    expect(seen.at(-1)?.method).toBe('DELETE');
    expect(await client.stats()).toEqual({ total: 3, sources: 1 });
    expect(await client.health()).toBe(true);
  });

  it('a wrong token or a malformed answer is a SinkholeError', async () => {
    const wrong = new SinkholeClient({ adminUrl: url, token: 'w'.repeat(40) });
    await expect(wrong.fetchRecords('172.31.253.130', 0)).rejects.toMatchObject({ status: 401 });
    body = { records: 'nope', dropped: 0 };
    const client = new SinkholeClient({ adminUrl: url, token: TOKEN });
    await expect(client.fetchRecords('172.31.253.130', 0)).rejects.toBeInstanceOf(SinkholeError);
    body = { records: Array.from({ length: 1_001 }, () => ({})), dropped: 0 };
    await expect(client.fetchRecords('172.31.253.130', 0)).rejects.toBeInstanceOf(SinkholeError);
  });

  it('bounds the response size and refuses bad input', async () => {
    const client = new SinkholeClient({ adminUrl: url, token: TOKEN, maxResponseBytes: 1_000 });
    await expect(client.fetchRecords('172.31.253.199', 0)).rejects.toMatchObject({
      operation: 'response_too_large',
    });
    await expect(client.fetchRecords('not-an-ip', 0)).rejects.toThrow(/invalid runner ip/);
    expect(() => new SinkholeClient({ adminUrl: url, token: 'short' })).toThrow(/too short/);
    expect(() => new SinkholeClient({ adminUrl: 'https://x', token: TOKEN })).toThrow(/http/);
  });

  it('an unreachable sinkhole is a SinkholeError; health is false', async () => {
    const client = new SinkholeClient({
      adminUrl: 'http://127.0.0.1:1',
      token: TOKEN,
      timeoutMs: 500,
    });
    await expect(client.fetchRecords('172.31.253.130', 0)).rejects.toBeInstanceOf(SinkholeError);
    expect(await client.health()).toBe(false);
  });
});
