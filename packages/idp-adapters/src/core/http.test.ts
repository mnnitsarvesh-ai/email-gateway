import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';
import type { AddressInfo } from 'node:net';
import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { z } from 'zod';
import { CapturingLogger } from '../testing/harness';
import { ProviderCallError } from './errors';
import {
  ProviderHttpClient,
  computeBackoffMs,
  parseRetryAfter,
  type IdpMetricsSink,
  type TokenSource,
} from './http';

const TOKEN = 'EXAMPLE-sim-token-901';
const SECOND_TOKEN = 'EXAMPLE-sim-token-902';
const NOW = Date.parse('2026-11-10T12:00:00.000Z');

type Handler = (req: IncomingMessage, res: ServerResponse) => void;

let server: Server;
let base: string;
let handler: Handler;
const seen: { url: string; headers: IncomingMessage['headers']; method: string }[] = [];

beforeAll(async () => {
  server = createServer((req, res) => {
    seen.push({ url: req.url ?? '', headers: req.headers, method: req.method ?? '' });
    handler(req, res);
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
});

afterAll(async () => {
  server.closeAllConnections();
  await new Promise<void>((resolve) => server.close(() => resolve()));
});

let logger: CapturingLogger;
let metrics: Required<Pick<IdpMetricsSink, 'httpRequest' | 'throttled'>>;

beforeEach(() => {
  seen.length = 0;
  logger = new CapturingLogger();
  metrics = { httpRequest: vi.fn(), throttled: vi.fn() };
  handler = (_req, res) => json(res, 200, { value: [] });
});

function json(
  res: ServerResponse,
  status: number,
  body: unknown,
  headers: Record<string, string> = {},
) {
  res.writeHead(status, { 'Content-Type': 'application/json', ...headers });
  res.end(JSON.stringify(body));
}

function client(overrides: Partial<ConstructorParameters<typeof ProviderHttpClient>[0]> = {}) {
  return new ProviderHttpClient({
    baseUrls: {
      graph: `${base}/graph`,
      o365: `${base}/o365`,
      google_admin: `${base}/google-admin`,
      gmail: `${base}/gmail`,
    },
    allowHttpEndpoints: true,
    timeoutMs: 300,
    maxResponseBytes: 2048,
    maxBackoffMs: 900_000,
    provider: 'microsoft_entra',
    logger,
    metrics,
    random: () => 0.5,
    now: () => NOW,
    env: {},
    ...overrides,
  });
}

function tokenSource(...tokens: string[]): TokenSource & { invalidate: ReturnType<typeof vi.fn> } {
  let index = 0;
  return {
    get: vi.fn(() => Promise.resolve(tokens[Math.min(index, tokens.length - 1)] as string)),
    invalidate: vi.fn(() => {
      index += 1;
    }),
  };
}

const pageSchema = z.object({ value: z.array(z.unknown()) });
const signal = () => new AbortController().signal;

async function failure(promise: Promise<unknown>): Promise<ProviderCallError> {
  try {
    await promise;
  } catch (error) {
    expect(error).toBeInstanceOf(ProviderCallError);
    return error as ProviderCallError;
  }
  throw new Error('expected a ProviderCallError');
}

function get(
  http: ProviderHttpClient,
  url = '/v1.0/auditLogs/signIns?$top=1',
  family: 'graph' | 'google_reports' = 'graph',
) {
  return http.request({
    family,
    method: 'GET',
    url,
    pathTemplate: '/v1.0/auditLogs/signIns',
    token: tokenSource(TOKEN),
    signal: signal(),
    schema: pageSchema,
  });
}

describe('ProviderHttpClient requests', () => {
  it('sends the fixed headers, a Graph client-request-id and validates the body', async () => {
    handler = (_req, res) => json(res, 200, { value: [1, 2], extra: true });
    const response = await get(client());
    expect(response.data.value).toEqual([1, 2]);
    const request = seen[0];
    expect(request?.url).toBe('/graph/v1.0/auditLogs/signIns?$top=1');
    expect(request?.headers.authorization).toBe(`Bearer ${TOKEN}`);
    expect(request?.headers['user-agent']).toBe('EmailGateway-ATO/1');
    expect(request?.headers.accept).toBe('application/json');
    expect(request?.headers['client-request-id']).toBe(response.requestId);
    expect(request?.headers.cookie).toBeUndefined();
  });

  it('sends no client-request-id outside Graph and JSON bodies with a content type', async () => {
    handler = (_req, res) => {
      res.writeHead(204);
      res.end();
    };
    await client().request({
      family: 'gmail',
      method: 'PUT',
      url: '/gmail/v1/users/me/settings/autoForwarding',
      pathTemplate: '/gmail/v1/users/me/settings/autoForwarding',
      token: tokenSource(TOKEN),
      signal: signal(),
      body: { enabled: false },
    });
    expect(seen[0]?.headers['client-request-id']).toBeUndefined();
    expect(seen[0]?.headers['content-type']).toBe('application/json');
    expect(seen[0]?.method).toBe('PUT');
  });

  it('records metrics and a debug line with the path template only', async () => {
    await get(client());
    expect(metrics.httpRequest).toHaveBeenCalledWith(
      { provider: 'microsoft_entra', family: 'graph', statusClass: '2xx' },
      expect.any(Number),
    );
    expect(logger.lines).toEqual([
      {
        level: 'debug',
        msg: 'provider request',
        obj: {
          family: 'graph',
          method: 'GET',
          path: '/v1.0/auditLogs/signIns',
          status: 200,
          durationMs: 0,
        },
      },
    ]);
  });
});

describe('host allow-list', () => {
  it('follows same-origin links under the base path only', () => {
    const http = client();
    expect(http.relativize('graph', `${base}/graph/v1.0/users?$skiptoken=abc`)).toBe(
      '/v1.0/users?$skiptoken=abc',
    );
    expect(() => http.relativize('graph', 'https://graph.example.invalid/v1.0/users')).toThrow(
      ProviderCallError,
    );
    expect(() => http.relativize('graph', `${base}/o365/api/v1.0/x`)).toThrow('blocked_host');
    expect(() => http.relativize('graph', `http://user:pw@127.0.0.1/graph/x`)).toThrow(
      'blocked_host',
    );
    expect(() => http.relativize('o365', 'not a url')).toThrow('blocked_host');
  });

  it('refuses foreign nextLink, NextPageUri and contentUri values without calling them', async () => {
    const error = await failure(get(client(), 'https://attacker.example.invalid/graph/v1.0/users'));
    expect(error.code).toBe('blocked_host');
    expect(error.retryable).toBe(false);
    expect(seen).toHaveLength(0);
  });

  it('refuses http base URLs unless allowed, credentials and queries in base URLs', () => {
    expect(() => client({ allowHttpEndpoints: false })).toThrow('provider_base_url_scheme_refused');
    expect(() =>
      client({
        baseUrls: {
          graph: 'https://a.example',
          o365: 'https://u:p@b.example',
          google_admin: 'https://c.example',
          gmail: 'https://d.example',
        },
      }),
    ).toThrow('provider_base_url_invalid');
    expect(() =>
      client({
        baseUrls: {
          graph: 'ftp://a.example',
          o365: 'https://b.example',
          google_admin: 'https://c.example',
          gmail: 'https://d.example',
        },
      }),
    ).toThrow('provider_base_url_scheme_refused');
  });

  it('refuses to run with the proxy environment enabled', () => {
    expect(() => client({ env: { NODE_USE_ENV_PROXY: '1' } })).toThrow(
      'provider_http_proxy_env_refused',
    );
    expect(() =>
      client({ env: { NODE_USE_ENV_PROXY: 'false', HTTPS_PROXY: 'http://proxy.example' } }),
    ).not.toThrow();
  });

  it('never follows redirects', async () => {
    handler = (_req, res) => {
      res.writeHead(302, { Location: 'https://attacker.example.invalid/' });
      res.end();
    };
    const error = await failure(get(client()));
    expect(error.code).toBe('redirect_refused');
    expect(error.retryable).toBe(false);
    expect(seen).toHaveLength(1);
  });
});

describe('timeouts, aborts and size caps', () => {
  it('times out a hanging provider as provider_unavailable (retryable)', async () => {
    handler = () => undefined; // never answers
    const error = await failure(get(client({ timeoutMs: 100 })));
    expect(error.code).toBe('provider_unavailable');
    expect(error.retryable).toBe(true);
  });

  it('answers aborted when the caller aborts', async () => {
    handler = () => undefined;
    const controller = new AbortController();
    const pending = client({ timeoutMs: 5_000 }).request({
      family: 'graph',
      method: 'GET',
      url: '/v1.0/users',
      pathTemplate: '/v1.0/users',
      token: tokenSource(TOKEN),
      signal: controller.signal,
      schema: pageSchema,
    });
    setTimeout(() => controller.abort(), 20);
    const error = await failure(pending);
    expect(error.code).toBe('aborted');
    expect(error.retryable).toBe(false);
  });

  it('refuses bodies over the cap by Content-Length and while streaming', async () => {
    handler = (_req, res) => json(res, 200, { value: ['x'.repeat(5000)] });
    expect((await failure(get(client()))).code).toBe('response_too_large');
    handler = (_req, res) => {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.write('{"value":["');
      res.write('y'.repeat(4000));
      res.end('"]}');
    };
    const error = await failure(get(client()));
    expect(error.code).toBe('response_too_large');
    expect(error.retryable).toBe(false);
  });
});

describe('error classification', () => {
  const cases: [number, unknown, Record<string, string>, string, boolean][] = [
    [403, { error: { code: 'Authorization_RequestDenied' } }, {}, 'missing_permission', false],
    [
      403,
      { error: { code: 'Authentication_RequestFromNonPremiumTenantOrB2CTenant' } },
      {},
      'missing_license',
      false,
    ],
    [403, { error: { code: 'AF20023' } }, {}, 'missing_license', false],
    [403, { error: { code: 'AF10002' } }, {}, 'missing_permission', false],
    [403, { error: { code: 'SomethingElse' } }, {}, 'forbidden', false],
    [
      403,
      { error: { code: 403, errors: [{ reason: 'insufficientPermissions' }] } },
      {},
      'missing_permission',
      false,
    ],
    [
      403,
      { error: { code: 403, errors: [{ reason: 'rateLimitExceeded' }] } },
      {},
      'throttled',
      true,
    ],
    [
      403,
      { error: { code: 403, errors: [{ reason: 'userRateLimitExceeded' }] } },
      {},
      'throttled',
      true,
    ],
    [
      403,
      { error: { code: 403, errors: [{ reason: 'dailyLimitExceeded' }] } },
      {},
      'quota_exhausted',
      true,
    ],
    [
      403,
      { error: { code: 403, errors: [{ reason: 'quotaExceeded' }] } },
      {},
      'quota_exhausted',
      true,
    ],
    [404, { error: { code: 'Request_ResourceNotFound' } }, {}, 'not_found', false],
    [409, {}, {}, 'conflict', false],
    [412, {}, {}, 'conflict', false],
    [400, { error: { code: 'AF20022' } }, {}, 'bad_request', false],
    [429, { error: { code: 'TooManyRequests' } }, { 'Retry-After': '7' }, 'throttled', true],
    [500, {}, {}, 'provider_unavailable', true],
    [503, {}, { 'Retry-After': '30' }, 'provider_unavailable', true],
  ];

  it.each(cases)('HTTP %i %j %j → %s', async (status, body, headers, code, retryable) => {
    handler = (_req, res) => json(res, status, body, headers);
    const error = await failure(get(client()));
    expect(error.code).toBe(code);
    expect(error.retryable).toBe(retryable);
    expect(error.status).toBe(status);
  });

  it('keeps the sanitized provider code (AF20022) for the adapter', async () => {
    handler = (_req, res) =>
      json(res, 400, { error: { code: 'AF20022', message: 'no subscription' } });
    expect((await failure(get(client()))).providerCode).toBe('AF20022');
    handler = (_req, res) => json(res, 400, { error: { code: 'free text with spaces' } });
    expect((await failure(get(client()))).providerCode).toBeUndefined();
  });

  it('reads Retry-After in seconds and as an HTTP date, else backs off with jitter', async () => {
    handler = (_req, res) => json(res, 429, {}, { 'Retry-After': '7' });
    expect((await failure(get(client()))).retryAfterMs).toBe(7_000);
    handler = (_req, res) =>
      json(res, 429, {}, { 'Retry-After': new Date(NOW + 90_000).toUTCString() });
    expect((await failure(get(client()))).retryAfterMs).toBe(90_000);
    handler = (_req, res) => json(res, 429, {});
    expect((await failure(get(client()))).retryAfterMs).toBe(500); // attempt 0: 0.5 × 1 s
    handler = (_req, res) =>
      json(res, 403, { error: { errors: [{ reason: 'dailyLimitExceeded' }] } });
    expect((await failure(get(client()))).retryAfterMs).toBe(3_600_000);
    expect(metrics.throttled).toHaveBeenCalledTimes(4);
  });

  it('caps Retry-After at the maximum back-off', async () => {
    handler = (_req, res) => json(res, 429, {}, { 'Retry-After': '86400' });
    expect((await failure(get(client({ maxBackoffMs: 900_000 })))).retryAfterMs).toBe(900_000);
  });

  it('fails unexpected_response on schema mismatch and invalid JSON (not retryable)', async () => {
    handler = (_req, res) => json(res, 200, { notValue: true });
    const schemaError = await failure(get(client()));
    expect(schemaError.code).toBe('unexpected_response');
    expect(schemaError.retryable).toBe(false);
    handler = (_req, res) => {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end('{not json');
    };
    expect((await failure(get(client()))).code).toBe('unexpected_response');
  });

  it('drops the token once on 401 and retries once', async () => {
    let calls = 0;
    handler = (req, res) => {
      calls += 1;
      if (req.headers.authorization === `Bearer ${TOKEN}`)
        json(res, 401, { error: { code: 'InvalidAuthenticationToken' } });
      else json(res, 200, { value: [] });
    };
    const token = tokenSource(TOKEN, SECOND_TOKEN);
    await client().request({
      family: 'graph',
      method: 'GET',
      url: '/v1.0/users',
      pathTemplate: '/v1.0/users',
      token,
      signal: signal(),
      schema: pageSchema,
    });
    expect(calls).toBe(2);
    expect(token.invalidate).toHaveBeenCalledTimes(1);
  });

  it('gives up after the single retry with unauthorized', async () => {
    handler = (_req, res) => json(res, 401, { error: { code: 'InvalidAuthenticationToken' } });
    const token = tokenSource(TOKEN, SECOND_TOKEN);
    const error = await failure(
      client().request({
        family: 'graph',
        method: 'GET',
        url: '/v1.0/users',
        pathTemplate: '/v1.0/users',
        token,
        signal: signal(),
        schema: pageSchema,
      }),
    );
    expect(error.code).toBe('unauthorized');
    expect(seen).toHaveLength(2);
    expect(token.invalidate).toHaveBeenCalledTimes(1);
  });
});

describe('back-off helpers', () => {
  it('grows 1 s → 64 s with full jitter and respects the cap', () => {
    expect(computeBackoffMs(0, () => 0.999, 900_000)).toBeLessThan(1_000);
    expect(computeBackoffMs(6, () => 0.999, 900_000)).toBeLessThanOrEqual(64_000);
    expect(computeBackoffMs(60, () => 0.999, 900_000)).toBeLessThanOrEqual(64_000);
    expect(computeBackoffMs(6, () => 0.999, 5_000)).toBeLessThanOrEqual(5_000);
    expect(computeBackoffMs(3, () => 0, 900_000)).toBe(1);
  });

  it('parses Retry-After seconds, dates, and rejects garbage', () => {
    expect(parseRetryAfter('3', NOW, 900_000)).toBe(3_000);
    expect(parseRetryAfter(new Date(NOW - 5_000).toUTCString(), NOW, 900_000)).toBe(0);
    expect(parseRetryAfter('soon', NOW, 900_000)).toBeUndefined();
    expect(parseRetryAfter(null, NOW, 900_000)).toBeUndefined();
  });
});

describe('redaction (invariant 2)', () => {
  it('never puts a token, header, query string or body in errors or log lines', async () => {
    const bodyMarker = 'EXAMPLE-body-marker-7731';
    const queryMarker = 'query-marker-5521';
    const statuses = [400, 401, 403, 404, 429, 500, 200];
    const errors: unknown[] = [];
    for (const status of statuses) {
      handler = (_req, res) =>
        status === 200
          ? json(res, 200, { unexpected: bodyMarker })
          : json(
              res,
              status,
              { error: { code: 'Denied', message: bodyMarker, token: TOKEN } },
              { 'X-Echo': TOKEN },
            );
      try {
        await get(client(), `/v1.0/users?$filter=${queryMarker}`);
      } catch (error) {
        errors.push(error);
      }
    }
    expect(errors).toHaveLength(statuses.length);
    const dump = [
      logger.text(),
      ...errors.map((error) => JSON.stringify(error)),
      ...errors.map((error) => String(error)),
      ...errors.map((error) =>
        error instanceof Error ? `${error.message} ${error.stack ?? ''}` : '',
      ),
      ...errors.map((error) => JSON.stringify(Object.entries(error as object))),
    ].join('\n');
    for (const secret of [
      TOKEN,
      SECOND_TOKEN,
      'Bearer',
      queryMarker,
      bodyMarker,
      'authorization',
    ]) {
      expect(dump).not.toContain(secret);
    }
  });
});

describe('requestStream (step API-1 D9)', () => {
  const stream = (
    http: ProviderHttpClient,
    overrides: Partial<Parameters<ProviderHttpClient['requestStream']>[0]> = {},
  ) =>
    http.requestStream({
      family: 'graph',
      method: 'GET',
      url: '/v1.0/users/u1/messages/m1/$value',
      pathTemplate: '/v1.0/users/{id}/messages/{mid}/$value',
      token: tokenSource(TOKEN),
      signal: signal(),
      maxBytes: 4096,
      ...overrides,
    });

  async function collect(body: AsyncIterable<Uint8Array>): Promise<Buffer> {
    const chunks: Uint8Array[] = [];
    for await (const chunk of body) chunks.push(chunk);
    return Buffer.concat(chunks);
  }

  async function streamFailure(body: AsyncIterable<Uint8Array>): Promise<ProviderCallError> {
    return failure(collect(body));
  }

  it('streams the body chunk by chunk with the fixed headers', async () => {
    handler = (_req, res) => {
      res.writeHead(200, { 'Content-Type': 'message/rfc822' });
      res.write('Subject: one\r\n');
      setTimeout(() => res.end('\r\nbody\r\n'), 10);
    };
    const response = await stream(client(), { accept: 'message/rfc822' });
    expect(response.status).toBe(200);
    expect(response.headers.contentType).toBe('message/rfc822');
    expect((await collect(response.body)).toString('utf8')).toBe('Subject: one\r\n\r\nbody\r\n');
    const request = seen[0];
    expect(request?.url).toBe('/graph/v1.0/users/u1/messages/m1/$value');
    expect(request?.headers.authorization).toBe(`Bearer ${TOKEN}`);
    expect(request?.headers.accept).toBe('message/rfc822');
    expect(request?.headers['client-request-id']).toBe(response.requestId);
    expect(metrics.httpRequest).toHaveBeenCalledWith(
      { provider: 'microsoft_entra', family: 'graph', statusClass: '2xx' },
      expect.any(Number),
    );
    expect(logger.lines[0]?.obj).toEqual({
      family: 'graph',
      method: 'GET',
      path: '/v1.0/users/{id}/messages/{mid}/$value',
      status: 200,
      durationMs: 0,
      stream: true,
    });
  });

  it('refuses a declared Content-Length over the cap before streaming', async () => {
    handler = (_req, res) => {
      res.writeHead(200, { 'Content-Type': 'message/rfc822', 'Content-Length': '5000' });
      res.end('x'.repeat(5000));
    };
    const error = await failure(stream(client()));
    expect(error.code).toBe('response_too_large');
    expect(error.retryable).toBe(false);
  });

  it('fails response_too_large once the cap is exceeded while streaming (chunked)', async () => {
    handler = (_req, res) => {
      res.writeHead(200, { 'Content-Type': 'message/rfc822' });
      res.write('a'.repeat(3000));
      setTimeout(() => res.end('b'.repeat(3000)), 10);
    };
    const response = await stream(client());
    const error = await streamFailure(response.body);
    expect(error.code).toBe('response_too_large');
    expect(error.status).toBe(200);
  });

  it('accepts a body of exactly maxBytes', async () => {
    handler = (_req, res) => {
      res.writeHead(200);
      res.end('z'.repeat(4096));
    };
    const response = await stream(client());
    expect((await collect(response.body)).length).toBe(4096);
  });

  it('cancels the transfer when the consumer stops early', async () => {
    let closed = false;
    handler = (req, res) => {
      res.writeHead(200);
      res.write('first');
      req.socket.on('close', () => {
        closed = true;
      });
      // never ends on its own
    };
    const response = await stream(client({ timeoutMs: 2_000 }));
    for await (const chunk of response.body) {
      expect(Buffer.from(chunk).toString()).toBe('first');
      break;
    }
    await new Promise((resolve) => setTimeout(resolve, 50));
    expect(closed).toBe(true);
  });

  it('applies the idle limit between chunks and the total body limit', async () => {
    handler = (_req, res) => {
      res.writeHead(200);
      res.write('start');
      // then stalls
    };
    let response = await stream(client({ timeoutMs: 100 }));
    let error = await streamFailure(response.body);
    expect(error.code).toBe('provider_unavailable');
    expect(error.retryable).toBe(true);

    let timer: NodeJS.Timeout | undefined;
    handler = (_req, res) => {
      res.writeHead(200);
      timer = setInterval(() => res.write('.'), 20);
    };
    response = await stream(client({ timeoutMs: 200 }), { bodyTimeoutMs: 150 });
    error = await streamFailure(response.body);
    clearInterval(timer);
    expect(error.code).toBe('provider_unavailable');
  });

  it('times out before the headers and answers aborted when the caller aborts', async () => {
    handler = () => undefined;
    expect((await failure(stream(client({ timeoutMs: 100 })))).code).toBe('provider_unavailable');
    handler = (_req, res) => {
      res.writeHead(200);
      res.write('start');
    };
    const controller = new AbortController();
    const response = await stream(client({ timeoutMs: 5_000 }), { signal: controller.signal });
    setTimeout(() => controller.abort(), 20);
    const error = await streamFailure(response.body);
    expect(error.code).toBe('aborted');
    expect(error.retryable).toBe(false);
  });

  it('keeps the origin allow-list and never follows redirects', async () => {
    expect(
      (await failure(stream(client(), { url: 'https://attacker.example.invalid/graph/x' }))).code,
    ).toBe('blocked_host');
    expect(seen).toHaveLength(0);
    // A provider link under the base path is followed.
    handler = (_req, res) => {
      res.writeHead(200);
      res.end('ok');
    };
    const response = await stream(client(), { url: `${base}/graph/v1.0/next?$skiptoken=a` });
    expect((await collect(response.body)).toString()).toBe('ok');
    expect(() => client().relativize('graph', `${base}/gmail/x`)).toThrow('blocked_host');
    handler = (_req, res) => {
      res.writeHead(302, { Location: 'https://attacker.example.invalid/' });
      res.end();
    };
    const error = await failure(stream(client()));
    expect(error.code).toBe('redirect_refused');
  });

  it('drops the token once on 401 and retries once', async () => {
    handler = (req, res) => {
      if (req.headers.authorization === `Bearer ${TOKEN}`) {
        json(res, 401, { error: { code: 'InvalidAuthenticationToken' } });
      } else {
        res.writeHead(200);
        res.end('second');
      }
    };
    const token = tokenSource(TOKEN, SECOND_TOKEN);
    const response = await stream(client(), { token });
    expect((await collect(response.body)).toString()).toBe('second');
    expect(token.invalidate).toHaveBeenCalledTimes(1);
    handler = (_req, res) => json(res, 401, { error: { code: 'InvalidAuthenticationToken' } });
    const again = tokenSource(TOKEN, SECOND_TOKEN);
    expect((await failure(stream(client(), { token: again }))).code).toBe('unauthorized');
    expect(again.invalidate).toHaveBeenCalledTimes(1);
  });

  it('classifies 429/503 with Retry-After (capped) and reports throttling', async () => {
    handler = (_req, res) =>
      json(res, 429, { error: { code: 'TooManyRequests' } }, { 'Retry-After': '9' });
    let error = await failure(stream(client()));
    expect(error.code).toBe('throttled');
    expect(error.retryAfterMs).toBe(9_000);
    expect(metrics.throttled).toHaveBeenCalledWith({
      provider: 'microsoft_entra',
      family: 'graph',
    });
    handler = (_req, res) => json(res, 503, {}, { 'Retry-After': '86400' });
    error = await failure(stream(client({ maxBackoffMs: 600_000 })));
    expect(error.code).toBe('provider_unavailable');
    expect(error.retryAfterMs).toBe(600_000);
    handler = (_req, res) => json(res, 404, { error: { code: 'ErrorItemNotFound' } });
    expect((await failure(stream(client()))).code).toBe('not_found');
  });

  it('never leaks a token, query string or body into errors or log lines', async () => {
    const bodyMarker = 'EXAMPLE-stream-body-4417';
    const queryMarker = 'stream-query-8812';
    const errors: unknown[] = [];
    for (const status of [400, 401, 403, 429, 500]) {
      handler = (_req, res) =>
        json(res, status, { error: { code: 'Denied', message: bodyMarker, token: TOKEN } });
      try {
        await stream(client(), { url: `/v1.0/x?$filter=${queryMarker}` });
      } catch (error) {
        errors.push(error);
      }
    }
    handler = (_req, res) => {
      res.writeHead(200);
      res.end(`${bodyMarker}${'q'.repeat(5000)}`);
    };
    const response = await stream(client(), { url: `/v1.0/x?$filter=${queryMarker}` });
    errors.push(await streamFailure(response.body));
    expect(errors).toHaveLength(6);
    const dump = [
      logger.text(),
      ...errors.map((error) => JSON.stringify(error)),
      ...errors.map((error) =>
        error instanceof Error ? `${error.message} ${error.stack ?? ''}` : '',
      ),
    ].join('\n');
    for (const secret of [TOKEN, SECOND_TOKEN, 'Bearer', queryMarker, bodyMarker]) {
      expect(dump).not.toContain(secret);
    }
  });
});
