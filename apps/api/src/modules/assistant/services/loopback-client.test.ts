import {
  createServer,
  type IncomingHttpHeaders,
  type Server,
  type ServerResponse,
} from 'node:http';
import type { AddressInfo } from 'node:net';
import { OPERATION_TOOLS } from '@email-gateway/assistant';
import { afterEach, describe, expect, it } from 'vitest';
import type { AssistantConfig } from '../assistant.constants';
import {
  buildLoopbackHeaders,
  buildLoopbackRequest,
  isSafePathSegment,
  LoopbackClient,
  loopbackBaseUrl,
  pathMatchesTemplate,
  unsafePathParams,
} from './loopback-client';
import { READ_PRIMARY_HEADER, readPrimaryToken } from './read-primary';

/** An in-process HTTP stub that records the request and answers with `respond`. */
async function stub(respond: (res: ServerResponse) => void): Promise<{
  server: Server;
  url: string;
  seen: Array<{ method: string; url: string; headers: IncomingHttpHeaders; body: string }>;
}> {
  const seen: Array<{ method: string; url: string; headers: IncomingHttpHeaders; body: string }> =
    [];
  const server = createServer((req, res) => {
    let body = '';
    req.on('data', (c: Buffer) => (body += c.toString('utf8')));
    req.on('end', () => {
      seen.push({ method: req.method!, url: req.url!, headers: req.headers, body });
      respond(res);
    });
  });
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
  const { port } = server.address() as AddressInfo;
  return { server, url: `http://127.0.0.1:${port}`, seen };
}

const servers: Server[] = [];
afterEach(async () => {
  await Promise.all(servers.splice(0).map((s) => new Promise((r) => s.close(r))));
});

const config = (overrides: Partial<AssistantConfig> = {}): AssistantConfig =>
  ({
    HTTP_PORT: 3000,
    ASSISTANT_MAX_CONCURRENT_TURNS: 2,
    ASSISTANT_TOOL_TIMEOUT_MS: 2000,
    API_TRUSTED_FORWARDER_TOKEN: undefined,
    ...overrides,
  }) as AssistantConfig;

const call = (signal = new AbortController().signal) => ({
  method: 'GET' as const,
  path: '/api/v1/policies?status=active',
  authorization: 'Bearer it-access-token',
  correlationId: 'it-corr-0001.1',
  clientIp: '198.51.100.7',
  executionId: '0193d000-0000-7000-8000-0000000000e1',
  signal,
});

describe('LoopbackClient (D2): the exact request against an in-process HTTP stub', () => {
  it('sends exactly the D2 header set; no forwarder headers without the token', async () => {
    const s = await stub((res) =>
      res.writeHead(200, { 'content-type': 'application/json' }).end('{"data":[]}'),
    );
    servers.push(s.server);
    const client = new LoopbackClient(config({ ASSISTANT_LOOPBACK_URL: s.url }));
    const result = await client.send(call());
    client.onModuleDestroy();
    expect(result).toEqual({ kind: 'response', status: 200, body: { data: [] } });
    const req = s.seen[0]!;
    expect(req.method).toBe('GET');
    expect(req.url).toBe('/api/v1/policies?status=active');
    expect(Object.keys(req.headers).sort()).toEqual(
      [
        'accept',
        'authorization',
        'connection',
        'host',
        'user-agent',
        'x-correlation-id',
        'x-eg-assistant-execution',
      ].sort(),
    );
    expect(req.headers).toMatchObject({
      authorization: 'Bearer it-access-token',
      'x-correlation-id': 'it-corr-0001.1',
      accept: 'application/json',
      'user-agent': 'eg-assistant/1',
      'x-eg-assistant-execution': '0193d000-0000-7000-8000-0000000000e1',
    });
  });

  it('adds x-eg-client-ip and x-eg-forwarder-token only when the forwarder token is set', async () => {
    const s = await stub((res) => res.writeHead(204).end());
    servers.push(s.server);
    const client = new LoopbackClient(
      config({
        ASSISTANT_LOOPBACK_URL: s.url,
        API_TRUSTED_FORWARDER_TOKEN: 'it-forwarder-value-0001',
      }),
    );
    expect(await client.send(call())).toEqual({ kind: 'response', status: 204, body: null });
    await client.send({ ...call(), clientIp: null });
    client.onModuleDestroy();
    expect(s.seen[0]!.headers).toMatchObject({
      'x-eg-client-ip': '198.51.100.7',
      'x-eg-forwarder-token': 'it-forwarder-value-0001',
    });
    expect(s.seen[1]!.headers['x-eg-client-ip']).toBeUndefined();
    expect(s.seen[1]!.headers['x-eg-forwarder-token']).toBeUndefined();
  });

  it('sends idempotency-key on the wire exactly when the call carries one', async () => {
    const s = await stub((res) => res.writeHead(200).end('{}'));
    servers.push(s.server);
    const client = new LoopbackClient(config({ ASSISTANT_LOOPBACK_URL: s.url }));
    const key = '0193d000-0000-7000-8000-0000000000c1';
    await client.send({
      ...call(),
      method: 'POST',
      path: '/api/v1/messages/x/rescan',
      body: {},
      idempotencyKey: key,
    });
    await client.send(call());
    client.onModuleDestroy();
    expect(s.seen[0]!.headers['idempotency-key']).toBe(key);
    expect(Object.keys(s.seen[0]!.headers).sort()).toEqual(
      [
        'accept',
        'authorization',
        'connection',
        'content-length',
        'content-type',
        'host',
        'idempotency-key',
        'user-agent',
        'x-correlation-id',
        'x-eg-assistant-execution',
      ].sort(),
    );
    expect(s.seen[1]!.headers['idempotency-key']).toBeUndefined();
  });

  it('sends a JSON body with content-type only when the operation takes one', async () => {
    const s = await stub((res) => res.writeHead(200).end('{}'));
    servers.push(s.server);
    const client = new LoopbackClient(config({ ASSISTANT_LOOPBACK_URL: s.url }));
    await client.send({
      ...call(),
      method: 'POST',
      path: '/api/v1/policies/validate',
      body: { a: 1 },
    });
    client.onModuleDestroy();
    expect(s.seen[0]!.headers['content-type']).toBe('application/json');
    expect(s.seen[0]!.body).toBe('{"a":1}');
  });

  it('caps the response body at 1 MiB, times out, and aborts', async () => {
    const big = await stub((res) => res.writeHead(200).end('x'.repeat(1024 * 1024 + 10)));
    servers.push(big.server);
    const c1 = new LoopbackClient(config({ ASSISTANT_LOOPBACK_URL: big.url }));
    expect(await c1.send(call())).toEqual({ kind: 'too_large', status: 200 });
    c1.onModuleDestroy();

    const slow = await stub(() => undefined); // never answers
    servers.push(slow.server);
    const c2 = new LoopbackClient(
      config({ ASSISTANT_LOOPBACK_URL: slow.url, ASSISTANT_TOOL_TIMEOUT_MS: 100 }),
    );
    expect(await c2.send(call())).toEqual({ kind: 'timeout' });
    const controller = new AbortController();
    const pending = c2.send(call(controller.signal));
    controller.abort();
    expect(await pending).toEqual({ kind: 'aborted' });
    c2.onModuleDestroy();
    slow.server.closeAllConnections();
  });

  it('resolves the base URL lazily from the listening server, else HTTP_PORT', () => {
    expect(loopbackBaseUrl('http://api.internal:3000/', undefined, 1)).toBe(
      'http://api.internal:3000',
    );
    expect(
      loopbackBaseUrl(undefined, { address: () => ({ port: 41234 }) as AddressInfo }, 3000),
    ).toBe('http://127.0.0.1:41234');
    expect(loopbackBaseUrl(undefined, { address: () => null }, 3000)).toBe('http://127.0.0.1:3000');
  });
});

describe('buildLoopbackRequest / buildLoopbackHeaders (D2)', () => {
  const tool = {
    method: 'GET' as const,
    pathTemplate: '/api/v1/things/{thingId}/parts/{part}',
    pathParams: ['thingId', 'part'],
    queryParams: ['status', 'limit', 'flag', 'ids'],
    hasBody: false,
  };

  it('encodes path parameters and builds the query from declared parameters only', () => {
    expect(
      buildLoopbackRequest(tool, {
        thingId: 'a/b c',
        part: '../x?y#z',
        status: 'active',
        limit: 5,
        flag: true,
        ids: ['1', '2'],
        injected: 'ignored',
      }),
    ).toEqual({
      method: 'GET',
      path: '/api/v1/things/a%2Fb%20c/parts/..%2Fx%3Fy%23z?status=active&limit=5&flag=true&ids=1%2C2',
    });
    expect(() => buildLoopbackRequest(tool, { part: 'x' })).toThrow(/thingId/);
  });

  it('refuses dot-segment and empty path values (URL resolution would change the route)', () => {
    // What the guard prevents: `new URL()` collapses an unescaped `..` segment.
    expect(new URL('/api/v1/things/abc/parts/..', 'http://127.0.0.1/').pathname).toBe(
      '/api/v1/things/abc/',
    );
    for (const part of ['..', '.', '']) {
      expect(() => buildLoopbackRequest(tool, { thingId: 'abc', part }), part).toThrow(
        /not a single path segment/,
      );
    }
    expect(unsafePathParams(tool, { thingId: '..', part: 'ok' })).toEqual(['thingId']);
    expect(unsafePathParams(tool, { thingId: 'a..b', part: '...' })).toEqual([]);
    expect(isSafePathSegment('.')).toBe(false);
    expect(isSafePathSegment('...')).toBe(true);
    expect(pathMatchesTemplate('/api/v1/things/a/parts/b', tool.pathTemplate)).toBe(true);
    expect(pathMatchesTemplate('/api/v1/things/a/parts', tool.pathTemplate)).toBe(false);
    expect(pathMatchesTemplate('/api/v1/things/a/parts/..', tool.pathTemplate)).toBe(false);
    expect(pathMatchesTemplate('/api/v1/other/a/parts/b', tool.pathTemplate)).toBe(false);
  });

  it('send() refuses a path that URL resolution would change (defence in depth)', async () => {
    const s = await stub((res) => res.end('{}'));
    servers.push(s.server);
    const client = new LoopbackClient(config({ ASSISTANT_LOOPBACK_URL: s.url }));
    const result = await client.send({ ...call(), path: '/api/v1/roles/../organizations' });
    expect(result).toEqual({ kind: 'unavailable' });
    expect(s.seen).toHaveLength(0);
    client.onModuleDestroy();
  });

  it('never takes a header from the arguments', () => {
    const get = OPERATION_TOOLS.find((t) => t.name === 'policy_management_get')!;
    const request = buildLoopbackRequest(get, {
      policyId: '0193c000-0000-7000-8000-000000000001',
      authorization: 'Bearer evil',
      'x-eg-forwarder-token': 'evil',
    });
    expect(request).toEqual({
      method: 'GET',
      path: '/api/v1/policies/0193c000-0000-7000-8000-000000000001',
    });
    const headers = buildLoopbackHeaders(
      {
        authorization: 'Bearer real',
        correlationId: 'c-123456',
        clientIp: '198.51.100.7',
        executionId: null,
      },
      undefined,
      null,
    );
    expect(headers).toEqual({
      authorization: 'Bearer real',
      'x-correlation-id': 'c-123456',
      accept: 'application/json',
      'user-agent': 'eg-assistant/1',
    });
  });
  it('adds idempotency-key only from the server value, validated (step AI-2 D2 step 13)', () => {
    const key = '0193d000-0000-7000-8000-0000000000c1';
    const headers = buildLoopbackHeaders(
      {
        authorization: 'Bearer real',
        correlationId: 'c-123456',
        clientIp: null,
        executionId: '0193d000-0000-7000-8000-0000000000e1',
        idempotencyKey: key,
      },
      undefined,
      2,
    );
    expect(headers).toEqual({
      authorization: 'Bearer real',
      'x-correlation-id': 'c-123456',
      accept: 'application/json',
      'user-agent': 'eg-assistant/1',
      'x-eg-assistant-execution': '0193d000-0000-7000-8000-0000000000e1',
      'idempotency-key': key,
      'content-type': 'application/json',
      'content-length': '2',
    });
    for (const bad of ['', 'a b', 'x'.repeat(129), 'k\r\nx-evil: 1']) {
      expect(() =>
        buildLoopbackHeaders(
          {
            authorization: 'Bearer real',
            correlationId: 'c-123456',
            clientIp: null,
            executionId: null,
            idempotencyKey: bad,
          },
          undefined,
          null,
        ),
      ).toThrow(/idempotency key/);
    }
  });
  it('adds x-eg-assistant-read-primary only to a read-primary GET, with the server token (AI-2 review)', () => {
    const base = {
      authorization: 'Bearer real',
      correlationId: 'c-123456',
      clientIp: null,
      executionId: null,
    };
    const token = readPrimaryToken('a'.repeat(64));
    expect(
      buildLoopbackHeaders({ ...base, method: 'GET', readPrimary: true }, undefined, null, token),
    ).toEqual({
      authorization: 'Bearer real',
      'x-correlation-id': 'c-123456',
      accept: 'application/json',
      'user-agent': 'eg-assistant/1',
      [READ_PRIMARY_HEADER]: token,
    });
    expect(
      buildLoopbackHeaders({ ...base, method: 'GET' }, undefined, null, token),
    ).not.toHaveProperty(READ_PRIMARY_HEADER);
    expect(() =>
      buildLoopbackHeaders({ ...base, method: 'POST', readPrimary: true }, undefined, 2, token),
    ).toThrow(/read-primary/);
    expect(() =>
      buildLoopbackHeaders({ ...base, method: 'GET', readPrimary: true }, undefined, null),
    ).toThrow(/read-primary/);
  });

  it('LoopbackClient sends the read-primary token derived from AUTH_TOKEN_PEPPER', async () => {
    const s = await stub((res) =>
      res.writeHead(200, { 'content-type': 'application/json' }).end('{}'),
    );
    servers.push(s.server);
    const pepper = 'b'.repeat(64);
    const client = new LoopbackClient(
      config({ ASSISTANT_LOOPBACK_URL: s.url, AUTH_TOKEN_PEPPER: pepper }),
    );
    try {
      await client.send({ ...call(), readPrimary: true });
      await client.send(call());
    } finally {
      client.onModuleDestroy();
    }
    expect(s.seen[0]!.headers[READ_PRIMARY_HEADER]).toBe(readPrimaryToken(pepper));
    expect(s.seen[0]!.headers[READ_PRIMARY_HEADER]).not.toContain(pepper);
    expect(s.seen[1]!.headers[READ_PRIMARY_HEADER]).toBeUndefined();
  });
});
