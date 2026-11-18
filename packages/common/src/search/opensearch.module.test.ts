import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';
import type { AddressInfo } from 'node:net';
import { Test } from '@nestjs/testing';
import { afterAll, afterEach, beforeAll, describe, expect, it } from 'vitest';
import { OpenSearchError } from './opensearch.errors';
import { OpenSearchModule, OpenSearchService } from './opensearch.module';

interface Recorded {
  method: string;
  url: string;
  headers: IncomingMessage['headers'];
  body: string;
}

type Handler = (req: Recorded, res: ServerResponse) => void;

let server: Server;
let baseUrl: string;
let handler: Handler = (_req, res) => res.end('{}');
const requests: Recorded[] = [];

const json = (res: ServerResponse, status: number, body: unknown) => {
  res.writeHead(status, { 'content-type': 'application/json' });
  res.end(JSON.stringify(body));
};

beforeAll(async () => {
  server = createServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on('data', (c: Buffer) => chunks.push(c));
    req.on('end', () => {
      const rec = {
        method: req.method ?? '',
        url: req.url ?? '',
        headers: req.headers,
        body: Buffer.concat(chunks).toString('utf8'),
      };
      requests.push(rec);
      handler(rec, res);
    });
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  baseUrl = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
});

afterAll(async () => {
  server.closeAllConnections();
  await new Promise<void>((resolve) => server.close(() => resolve()));
});

afterEach(() => {
  requests.length = 0;
  handler = (_req, res) => res.end('{}');
});

const client = (options: Partial<ConstructorParameters<typeof OpenSearchService>[0]> = {}) =>
  new OpenSearchService({ url: `${baseUrl}/`, timeoutMs: 2_000, ...options });

async function failure(promise: Promise<unknown>): Promise<OpenSearchError> {
  try {
    await promise;
  } catch (error) {
    expect(error).toBeInstanceOf(OpenSearchError);
    return error as OpenSearchError;
  }
  return expect.fail('expected OpenSearchError');
}

describe('OpenSearchService', () => {
  it('sends JSON with routing and query parameters, without auth by default', async () => {
    handler = (_req, res) =>
      json(res, 200, {
        timed_out: false,
        hits: { hits: [{ _index: 'i', _id: '1', sort: [1, 'a'] }] },
      });
    const result = await client().search('eg-test-t42', { size: 1 }, { routing: '42' });
    expect(result).toEqual({ timedOut: false, hits: [{ _index: 'i', _id: '1', sort: [1, 'a'] }] });
    expect(requests[0]).toMatchObject({ method: 'POST', url: '/eg-test-t42/_search?routing=42' });
    expect(requests[0]!.headers['content-type']).toBe('application/json');
    expect(requests[0]!.headers.authorization).toBeUndefined();
    expect(JSON.parse(requests[0]!.body)).toEqual({ size: 1 });
  });

  it('adds a basic auth header when credentials are configured', async () => {
    await client({ username: 'svc', password: 'pw-for-test' }).request('GET', '/');
    expect(requests[0]!.headers.authorization).toBe(
      `Basic ${Buffer.from('svc:pw-for-test').toString('base64')}`,
    );
  });

  it('refuses invalid configuration without echoing values', () => {
    expect(() => client({ url: 'ftp://x' })).toThrow(/http\(s\)/);
    expect(() => client({ url: 'http://user:secret-pw@host:9200' })).toThrow(/without credentials/);
    expect(() => client({ url: 'http://user:secret-pw@host:9200' })).not.toThrow(/secret-pw/);
    expect(() => client({ username: 'only' })).toThrow(/set together/);
  });

  it('errors expose only the status and error type, never the bodies', async () => {
    handler = (_req, res) =>
      json(res, 404, {
        error: { type: 'index_not_found_exception', reason: 'no such index [secret-index]' },
        status: 404,
      });
    const err = await failure(
      client().search('secret-index', { query: { term: { subject: 'confidential words' } } }),
    );
    expect(err).toMatchObject({
      kind: 'http',
      status: 404,
      errorType: 'index_not_found_exception',
    });
    expect(err.message).toBe(
      'OpenSearch request failed (http, status 404, index_not_found_exception)',
    );
    expect(err.message).not.toContain('secret');
    expect(err.message).not.toContain('confidential');
    handler = (_req, res) => json(res, 500, { error: { type: 'Weird Type <script>' } });
    expect((await failure(client().request('GET', '/'))).errorType).toBeNull();
    handler = (_req, res) => {
      res.writeHead(200);
      res.end('not json');
    };
    expect((await failure(client().request('GET', '/'))).kind).toBe('invalid_response');
  });

  it('times out with AbortSignal.timeout', async () => {
    handler = () => undefined; // never answers
    const err = await failure(client({ timeoutMs: 150 }).request('GET', '/slow'));
    expect(err.kind).toBe('timeout');
    expect(err.status).toBeNull();
    // Under load the server may record the request only after the client gave up: wait for it,
    // so it never leaks into the next test's recorded requests.
    for (let i = 0; i < 100 && !requests.some((r) => r.url === '/slow'); i += 1) {
      await new Promise((resolve) => setTimeout(resolve, 20));
    }
    expect(requests.some((r) => r.url === '/slow')).toBe(true);
  });

  it('reports an unreachable cluster as unavailable', async () => {
    const err = await failure(
      new OpenSearchService({ url: 'http://127.0.0.1:1', timeoutMs: 2_000 }).request('GET', '/'),
    );
    expect(err.kind).toBe('unavailable');
  });

  it('refuses paths that are not absolute or climb', async () => {
    expect((await failure(client().request('GET', 'relative'))).errorType).toBe('invalid_path');
    expect((await failure(client().request('GET', '/a/../b'))).errorType).toBe('invalid_path');
  });

  it('bulk sends NDJSON with routing and returns per-item results', async () => {
    handler = (_req, res) =>
      json(res, 200, {
        errors: true,
        items: [
          { index: { _index: 'eg-test-v1-2026', _id: 'a', status: 201 } },
          {
            index: {
              _index: 'eg-test-v1-2026',
              _id: 'b',
              status: 400,
              error: { type: 'strict_dynamic_mapping_exception', reason: 'field [body]' },
            },
          },
          { delete: { _index: 'eg-test-v1-2026', _id: 'c', status: 404, result: 'not_found' } },
        ],
      });
    const result = await client().bulk(
      [
        {
          action: 'index',
          index: 'eg-test-v1-2026',
          id: 'a',
          routing: '42',
          document: { org_id: '42' },
        },
        {
          action: 'index',
          index: 'eg-test-v1-2026',
          id: 'b',
          routing: '42',
          document: { body: 'x' },
        },
        { action: 'delete', index: 'eg-test-v1-2026', id: 'c', routing: '42' },
      ],
      { refresh: 'wait_for' },
    );
    expect(requests[0]!.url).toBe('/_bulk?refresh=wait_for');
    expect(requests[0]!.headers['content-type']).toBe('application/x-ndjson');
    const lines = requests[0]!.body.split('\n');
    expect(lines).toHaveLength(6); // 5 lines + trailing newline
    expect(JSON.parse(lines[0]!)).toEqual({
      index: { _index: 'eg-test-v1-2026', _id: 'a', routing: '42' },
    });
    expect(JSON.parse(lines[1]!)).toEqual({ org_id: '42' });
    expect(JSON.parse(lines[4]!)).toEqual({
      delete: { _index: 'eg-test-v1-2026', _id: 'c', routing: '42' },
    });
    expect(lines[5]).toBe('');
    expect(result.errors).toBe(true);
    expect(result.items).toEqual([
      {
        action: 'index',
        index: 'eg-test-v1-2026',
        id: 'a',
        status: 201,
        errorType: null,
        ok: true,
      },
      {
        action: 'index',
        index: 'eg-test-v1-2026',
        id: 'b',
        status: 400,
        errorType: 'strict_dynamic_mapping_exception',
        ok: false,
      },
      {
        action: 'delete',
        index: 'eg-test-v1-2026',
        id: 'c',
        status: 404,
        errorType: null,
        ok: true,
      },
    ]);
    expect(JSON.stringify(result)).not.toContain('field [body]');
    expect(await client().bulk([])).toEqual({ errors: false, items: [] });
  });

  it('bulk refuses a response whose items do not match the request', async () => {
    handler = (_req, res) => json(res, 200, { errors: false, items: [] });
    expect((await failure(client().bulk([{ action: 'delete', index: 'i', id: 'x' }]))).kind).toBe(
      'invalid_response',
    );
  });

  it('createIndex ignores resource_already_exists_exception only', async () => {
    handler = (_req, res) => json(res, 200, { acknowledged: true });
    expect(await client().createIndex('eg-test-v1-2026', { aliases: {} })).toEqual({
      created: true,
    });
    expect(requests[0]).toMatchObject({ method: 'PUT', url: '/eg-test-v1-2026' });
    handler = (_req, res) =>
      json(res, 400, { error: { type: 'resource_already_exists_exception' } });
    expect(await client().createIndex('eg-test-v1-2026')).toEqual({ created: false });
    handler = (_req, res) => json(res, 400, { error: { type: 'illegal_argument_exception' } });
    expect((await failure(client().createIndex('eg-test-v1-2026'))).errorType).toBe(
      'illegal_argument_exception',
    );
  });

  it('template, aliases, count, getDoc, deleteByQuery, indexExists and cluster health', async () => {
    const c = client();
    handler = (_req, res) => json(res, 200, { acknowledged: true });
    await c.putIndexTemplate('eg-test-v1', { index_patterns: ['eg-test-v1-*'] });
    expect(requests.at(-1)).toMatchObject({ method: 'PUT', url: '/_index_template/eg-test-v1' });
    await c.updateAliases({ actions: [{ add: { index: 'a', alias: 'b' } }] });
    expect(requests.at(-1)).toMatchObject({ method: 'POST', url: '/_aliases' });
    const before = requests.length;
    await c.updateAliases({ actions: [] });
    expect(requests.length).toBe(before);

    handler = (_req, res) => json(res, 200, { count: 7 });
    expect(await c.count('eg-test-t1', { query: {} }, { routing: '1' })).toBe(7);
    handler = (_req, res) => json(res, 404, { error: { type: 'index_not_found_exception' } });
    expect(await c.count('eg-test-t1', {})).toBe(0);

    handler = (_req, res) =>
      json(res, 200, { found: true, _index: 'eg-test-v1-2026', _source: { org_id: '1' } });
    expect(await c.getDoc('eg-test-v1-2026', 'id/with/slash', { routing: '1' })).toEqual({
      index: 'eg-test-v1-2026',
      source: { org_id: '1' },
    });
    expect(requests.at(-1)!.url).toBe('/eg-test-v1-2026/_doc/id%2Fwith%2Fslash?routing=1');
    handler = (_req, res) => json(res, 404, { found: false });
    expect(await c.getDoc('eg-test-v1-2026', 'x')).toBeNull();

    handler = (_req, res) => json(res, 200, { deleted: 3 });
    expect(
      await c.deleteByQuery('eg-test-v1-*', { query: {} }, { routing: '1', refresh: true }),
    ).toEqual({ deleted: 3 });
    expect(requests.at(-1)!.url).toBe(
      '/eg-test-v1-*/_delete_by_query?refresh=true&conflicts=proceed&routing=1',
    );

    handler = (req, res) => {
      res.writeHead(req.url === '/eg-test-v1-2026' ? 200 : 404);
      res.end();
    };
    expect(await c.indexExists('eg-test-v1-2026')).toBe(true);
    expect(await c.indexExists('eg-test-v1-2027')).toBe(false);

    handler = (_req, res) => json(res, 200, { status: 'yellow', number_of_nodes: 1 });
    expect(await c.clusterHealth()).toEqual({ status: 'yellow', numberOfNodes: 1 });
    expect(await c.checkHealth()).toEqual({ clusterStatus: 'yellow' });
    expect(c.healthName).toBe('opensearch');
    handler = (_req, res) => json(res, 200, { status: 'red' });
    await expect(c.checkHealth()).rejects.toThrow(/red/);
    handler = (_req, res) => json(res, 200, { status: 'purple' });
    expect((await failure(c.clusterHealth())).kind).toBe('invalid_response');
  });

  it('is provided by OpenSearchModule.forRoot', async () => {
    const moduleRef = await Test.createTestingModule({
      imports: [OpenSearchModule.forRoot({ url: baseUrl, timeoutMs: 1000 })],
    }).compile();
    expect(moduleRef.get(OpenSearchService)).toBeInstanceOf(OpenSearchService);
    await moduleRef.close();
  });
});
