import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';
import type { AddressInfo } from 'node:net';
import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';
import { ProviderRequestError } from '../errors';
import {
  buildProviderUrl,
  classifyProviderFailure,
  isUnderOrigin,
  parseRetryAfter,
  providerRequest,
} from './provider-http';
import { withProviderRetry } from './retry';

type Handler = (req: IncomingMessage, res: ServerResponse) => void;
let handler: Handler = (_req, res) => res.end();
let server: Server;
let origin: URL;
const seen: { url: string; headers: IncomingMessage['headers']; body: string }[] = [];

beforeAll(async () => {
  server = createServer((req, res) => {
    let body = '';
    req.on('data', (c: Buffer) => (body += c.toString('utf8')));
    req.on('end', () => {
      seen.push({ url: req.url ?? '', headers: req.headers, body });
      handler(req, res);
    });
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  origin = new URL(`http://127.0.0.1:${(server.address() as AddressInfo).port}/base`);
});
afterAll(async () => {
  server.closeAllConnections();
  await new Promise<void>((resolve) => server.close(() => resolve()));
});

const json =
  (status: number, body: unknown, headers: Record<string, string> = {}): Handler =>
  (_req, res) => {
    res.writeHead(status, { 'content-type': 'application/json', ...headers });
    res.end(JSON.stringify(body));
  };

const request = (overrides: Partial<Parameters<typeof providerRequest>[0]> = {}) =>
  providerRequest({
    origin,
    method: 'GET',
    path: '/v1/thing',
    signal: AbortSignal.timeout(10_000),
    allowHttp: true,
    ...overrides,
  });

async function codeOf(promise: Promise<unknown>): Promise<string> {
  try {
    await promise;
    return 'resolved';
  } catch (error) {
    expect(error).toBeInstanceOf(ProviderRequestError);
    return (error as ProviderRequestError).code;
  }
}

describe('providerRequest', () => {
  it('sends to the configured origin and base path, with query, JSON body and form body', async () => {
    handler = json(200, { ok: true });
    const res = await request({
      query: { $select: 'id,name', skip: undefined },
      headers: { authorization: 'Bearer t' },
    });
    expect(res).toMatchObject({ status: 200, json: { ok: true } });
    expect(seen.at(-1)!.url).toBe('/base/v1/thing?%24select=id%2Cname');
    await request({ method: 'POST', body: { a: 1 } });
    expect(seen.at(-1)!.headers['content-type']).toBe('application/json');
    expect(seen.at(-1)!.body).toBe('{"a":1}');
    await request({ method: 'POST', body: new URLSearchParams({ grant_type: 'x' }) });
    expect(seen.at(-1)!.headers['content-type']).toBe('application/x-www-form-urlencoded');
    await request({ path: '' });
    expect(seen.at(-1)!.url).toBe('/base');
  });

  it('refuses paths that would leave the origin or its base path', () => {
    for (const path of [
      '//evil.example/x',
      'https://evil.example/x',
      '/../x',
      '/a/../../x',
      '/%2e%2e/x',
      '/a%2fb',
      '/a?b=1',
      '/a#b',
      'relative',
    ]) {
      expect(() => buildProviderUrl(origin, path), path).toThrow(ProviderRequestError);
    }
    expect(isUnderOrigin(origin, `${origin.href}/v1/next?$skiptoken=2`)).toBe(true);
    expect(isUnderOrigin(origin, `http://evil.example/base/v1/next`)).toBe(false);
    expect(isUnderOrigin(origin, `${origin.origin}/other/v1/next`)).toBe(false);
    expect(isUnderOrigin(origin, `http://user:pw@${origin.host}/base/v1`)).toBe(false);
    expect(isUnderOrigin(origin, 'not a url')).toBe(false);
  });

  it('refuses http: origins unless allowed, and credentials in the origin', async () => {
    expect(await codeOf(request({ allowHttp: false }))).toBe('bad_response');
    expect(await codeOf(request({ origin: new URL(`http://u:p@${origin.host}/base`) }))).toBe(
      'bad_response',
    );
  });

  it('never follows redirects', async () => {
    handler = (_req, res) => {
      res.writeHead(302, { location: 'http://127.0.0.1:1/elsewhere' });
      res.end();
    };
    expect(await codeOf(request())).toBe('bad_response');
  });

  it('caps the response size', async () => {
    handler = json(200, { filler: 'x'.repeat(5000) });
    expect(await codeOf(request({ maxResponseBytes: 1000 }))).toBe('bad_response');
    handler = (_req, res) => {
      res.writeHead(200, { 'content-type': 'application/json' }); // chunked, no content-length
      res.write(`{"a":"${'y'.repeat(3000)}`);
      res.end('"}');
    };
    expect(await codeOf(request({ maxResponseBytes: 1000 }))).toBe('bad_response');
    expect((await request({ maxResponseBytes: 10_000 })).status).toBe(200);
  });

  it('times out', async () => {
    handler = (_req, res) => setTimeout(() => json(200, {})(_req, res), 500);
    expect(await codeOf(request({ timeoutMs: 50 }))).toBe('timeout');
  });

  it('propagates the caller abort as is', async () => {
    handler = (_req, res) => setTimeout(() => json(200, {})(_req, res), 500);
    const controller = new AbortController();
    const pending = request({ signal: controller.signal });
    controller.abort(new Error('caller stopped'));
    await expect(pending).rejects.toThrow('caller stopped');
  });

  it('requires JSON responses', async () => {
    handler = (_req, res) => {
      res.writeHead(200, { 'content-type': 'text/html' });
      res.end('<html></html>');
    };
    expect(await codeOf(request())).toBe('bad_response');
    handler = (_req, res) => {
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end('{broken');
    };
    expect(await codeOf(request())).toBe('bad_response');
    handler = (_req, res) => {
      res.writeHead(204);
      res.end();
    };
    expect((await request()).json).toBeNull();
  });

  it('honours Retry-After on 429 and 503, capped', async () => {
    handler = json(429, {}, { 'retry-after': '7' });
    let error = await request().catch((e: unknown) => e as ProviderRequestError);
    expect(error).toMatchObject({
      code: 'throttled',
      retryable: true,
      retryAfterMs: 7000,
      status: 429,
    });
    handler = json(503, {}, { 'retry-after': '3600' });
    error = await request({ retryAfterCapMs: 60_000 }).catch(
      (e: unknown) => e as ProviderRequestError,
    );
    expect(error).toMatchObject({ code: 'unavailable', retryable: true, retryAfterMs: 60_000 });
    expect(parseRetryAfter(new Date(Date.now() + 5_000).toUTCString(), 60_000)).toBeGreaterThan(
      3_000,
    );
    expect(parseRetryAfter('soon', 60_000)).toBeUndefined();
    expect(parseRetryAfter(null, 60_000)).toBeUndefined();
  });

  it('returns accepted statuses instead of throwing', async () => {
    handler = json(404, { error: { code: 'Request_ResourceNotFound' } });
    expect((await request({ acceptStatuses: [404] })).status).toBe(404);
    expect(await codeOf(request())).toBe('bad_response');
  });

  it('never puts the body, a token or a secret in errors or logs', async () => {
    const secretish = 'AADSTS7000215 the secret value fakeS3cretValue and token eyJfake';
    handler = json(401, {
      error: 'invalid_client',
      error_description: secretish,
      error_codes: [7000215],
    });
    const logger = { debug: vi.fn(), warn: vi.fn() };
    const observe = vi.fn();
    const error = (await request({
      tokenEndpoint: 'microsoft',
      headers: { authorization: 'Bearer eyJfakeAccessToken' },
      body: new URLSearchParams({ client_secret: 'fakeS3cretValue' }),
      method: 'POST',
      logger,
      observe,
    }).catch((e: unknown) => e)) as ProviderRequestError;
    expect(error.code).toBe('invalid_client');
    const everything = JSON.stringify([
      error.message,
      error,
      String(error.stack),
      logger.debug.mock.calls,
      observe.mock.calls,
    ]);
    for (const needle of ['fakeS3cretValue', 'eyJfake', 'AADSTS', 'secret value']) {
      expect(everything).not.toContain(needle);
    }
    expect(observe).toHaveBeenCalledWith(
      expect.objectContaining({ result: 'invalid_client', status: 401 }),
    );
  });
});

describe('classifyProviderFailure', () => {
  it.each([
    [401, { error: 'invalid_client', error_codes: [7000215] }, 'microsoft', 'invalid_client'],
    [400, { error: 'unauthorized_client', error_codes: [700016] }, 'microsoft', 'consent_missing'],
    [400, { error: 'invalid_grant', error_codes: [65001] }, 'microsoft', 'consent_missing'],
    [400, { error: 'invalid_request', error_codes: [90002] }, 'microsoft', 'tenant_not_found'],
    [400, { error: 'unauthorized_client' }, 'microsoft', 'unauthorized_client'],
    [401, { error: 'unauthorized_client' }, 'google', 'consent_missing'],
    [400, { error: 'invalid_grant' }, 'google', 'invalid_client'],
    [400, { error: 'invalid_scope' }, 'google', 'consent_missing'],
    [400, { error: 'temporarily_unavailable' }, 'microsoft', 'unavailable'],
    [403, { error: { code: 'Authorization_RequestDenied' } }, undefined, 'forbidden'],
    [401, { error: { code: 'InvalidAuthenticationToken' } }, undefined, 'forbidden'],
    [403, { error: { code: 403, status: 'PERMISSION_DENIED' } }, undefined, 'forbidden'],
    [429, {}, undefined, 'throttled'],
    [500, {}, undefined, 'unavailable'],
    [503, {}, undefined, 'unavailable'],
    [504, {}, undefined, 'timeout'],
    [400, { error: { code: 'Request_BadRequest' } }, undefined, 'bad_response'],
    [404, null, 'microsoft', 'tenant_not_found'],
  ] as const)('%i %j (%s) → %s', (status, body, tokenEndpoint, code) => {
    expect(classifyProviderFailure(status, body, tokenEndpoint ? { tokenEndpoint } : {})).toBe(
      code,
    );
  });
});

describe('withProviderRetry', () => {
  it('retries throttled and unavailable, not other codes', async () => {
    const signal = AbortSignal.timeout(5_000);
    let calls = 0;
    const result = await withProviderRetry(
      () => {
        calls += 1;
        if (calls < 3)
          return Promise.reject(new ProviderRequestError('throttled', { retryAfterMs: 1 }));
        return Promise.resolve('done');
      },
      signal,
      { retries: 2, baseDelayMs: 1 },
    );
    expect(result).toBe('done');
    calls = 0;
    await expect(
      withProviderRetry(() => {
        calls += 1;
        return Promise.reject(new ProviderRequestError('forbidden'));
      }, signal),
    ).rejects.toMatchObject({ code: 'forbidden' });
    expect(calls).toBe(1);
    calls = 0;
    await expect(
      withProviderRetry(
        () => {
          calls += 1;
          return Promise.reject(new ProviderRequestError('unavailable'));
        },
        signal,
        { retries: 1, baseDelayMs: 1 },
      ),
    ).rejects.toMatchObject({ code: 'unavailable' });
    expect(calls).toBe(2);
  });
});
