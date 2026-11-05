import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';
import { createServer as createTcpServer, type AddressInfo, type Socket } from 'node:net';
import { Readable } from 'node:stream';
import { afterAll, afterEach, beforeAll, describe, expect, it } from 'vitest';
import { parseServerVersion, RspamdClient } from './client';
import {
  RspamdHttpError,
  RspamdProtocolError,
  RspamdRequestError,
  RspamdSoftRejectError,
  RspamdTimeoutError,
  RspamdUnavailableError,
} from './errors';
import type { RspamdEnvelope } from './headers';

/**
 * A local HTTP server stands in for Rspamd's wire protocol (the real Rspamd runs in the
 * integration suite): it records what the client sent and answers per test.
 */
interface Recorded {
  method: string;
  url: string;
  headers: IncomingMessage['headers'];
  rawHeaders: string[];
  body: Buffer;
}

type Handler = (req: IncomingMessage, res: ServerResponse, body: Buffer) => void;

let server: Server;
let base: string;
let handler: Handler;
const recorded: Recorded[] = [];

const okReply = {
  is_skipped: false,
  score: 0.5,
  required_score: 15,
  action: 'no action',
  symbols: { R_SPF_ALLOW: { name: 'R_SPF_ALLOW', score: -0.2, options: ['+ip4:192.0.2.10'] } },
};

function json(
  res: ServerResponse,
  status: number,
  value: unknown,
  headers: Record<string, string> = {},
) {
  const text = JSON.stringify(value);
  res.writeHead(status, {
    'Content-Type': 'application/json',
    'Content-Length': Buffer.byteLength(text),
    ...headers,
  });
  res.end(text);
}

beforeAll(async () => {
  server = createServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on('data', (c: Buffer) => chunks.push(c));
    req.on('end', () => {
      const body = Buffer.concat(chunks);
      recorded.push({
        method: req.method ?? '',
        url: req.url ?? '',
        headers: req.headers,
        rawHeaders: req.rawHeaders,
        body,
      });
      handler(req, res, body);
    });
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
});

afterAll(async () => {
  server.closeAllConnections();
  await new Promise<void>((resolve) => server.close(() => resolve()));
});

afterEach(() => {
  recorded.length = 0;
  handler = (_req, res) => json(res, 200, okReply, { Server: 'rspamd/3.12.1' });
});

handler = (_req, res) => json(res, 200, okReply, { Server: 'rspamd/3.12.1' });

const envelope: RspamdEnvelope = {
  direction: 'inbound',
  organizationId: 5n,
  clientIp: '192.0.2.10',
  clientHelo: 'mx.clean.scan.test',
  clientName: null,
  envelopeFrom: 'alice@clean.scan.test',
  recipients: ['bob@customer.scan.test'],
  queueId: 'ABC123',
};

const READ_PASSWORD = 'read-password-0123456789';
const ENABLE_PASSWORD = 'enable-password-0123456789';

function client(overrides: Partial<ConstructorParameters<typeof RspamdClient>[0]> = {}) {
  return new RspamdClient({
    baseUrl: base,
    controllerUrl: base,
    controllerPassword: READ_PASSWORD,
    controllerEnablePassword: ENABLE_PASSWORD,
    timeoutMs: 2_000,
    ...overrides,
  });
}

/** A body that is produced lazily, chunk by chunk (proves the client streams). */
function lazyBody(parts: string[]): { stream: Readable; size: number; pulled: () => number } {
  let index = 0;
  const stream = new Readable({
    read() {
      if (index < parts.length) this.push(Buffer.from(parts[index++]!));
      else this.push(null);
    },
  });
  return { stream, size: parts.reduce((n, p) => n + Buffer.byteLength(p), 0), pulled: () => index };
}

describe('RspamdClient.check', () => {
  it('streams the body with Content-Length and the envelope headers', async () => {
    const parts = ['Subject: hello\r\n', '\r\n', 'line one\r\n', 'line two\r\n'];
    const body = lazyBody(parts);
    const result = await client().check({
      body: body.stream,
      sizeBytes: body.size,
      envelope,
      logTag: 'm1r0',
    });
    expect(body.pulled()).toBe(parts.length);
    const req = recorded[0]!;
    expect(req.method).toBe('POST');
    expect(req.url).toBe('/checkv2');
    expect(req.headers['content-length']).toBe(String(body.size));
    expect(req.headers['transfer-encoding']).toBeUndefined();
    expect(req.body.toString()).toBe(parts.join(''));
    expect(req.headers.ip).toBe('192.0.2.10');
    expect(req.headers.helo).toBe('mx.clean.scan.test');
    expect(req.headers.from).toBe('alice@clean.scan.test');
    expect(req.headers.rcpt).toBe('bob@customer.scan.test');
    expect(req.headers['queue-id']).toBe('ABC123');
    expect(req.headers['settings-id']).toBe('eg_inbound');
    expect(req.headers['log-tag']).toBe('m1r0');
    expect(req.headers.user).toBeUndefined();
    expect(req.headers.password).toBeUndefined();
    expect(result.reply.score).toBe(0.5);
    expect(result.serverVersion).toBe('3.12.1');
    expect(result.rcptTruncated).toBe(false);
    expect(result.omittedHeaders).toEqual(['Hostname']);
    expect(result.durationMs).toBeGreaterThanOrEqual(0);
  });

  it('sends every recipient (fetch joins repeated Rcpt headers with ", ", which Rspamd 3.12 splits)', async () => {
    await client().check({
      body: Buffer.from('x'),
      sizeBytes: 1,
      envelope: { ...envelope, recipients: ['a@x.scan.test', 'b@x.scan.test', 'c@x.scan.test'] },
      logTag: 't',
    });
    const raw = recorded[0]!.rawHeaders;
    const rcpts = raw
      .filter((_, i) => i % 2 === 1 && raw[i - 1]!.toLowerCase() === 'rcpt')
      .flatMap((v) => v.split(', '));
    expect(rcpts).toEqual(['a@x.scan.test', 'b@x.scan.test', 'c@x.scan.test']);
  });

  it('accepts a byte body and remembers the server version', async () => {
    const c = client();
    expect(c.lastServerVersion).toBeNull();
    await c.check({ body: Buffer.from('abc'), sizeBytes: 3, envelope, logTag: 't' });
    expect(c.lastServerVersion).toBe('3.12.1');
    expect(recorded[0]!.body.toString()).toBe('abc');
  });

  it('reports no version when Rspamd sends no Server header', async () => {
    handler = (_req, res) => json(res, 200, okReply);
    const result = await client().check({
      body: Buffer.from('a'),
      sizeBytes: 1,
      envelope,
      logTag: 't',
    });
    expect(result.serverVersion).toBeNull();
  });

  it('refuses a byte body whose length differs from sizeBytes before sending', async () => {
    await expect(
      client().check({ body: Buffer.from('abc'), sizeBytes: 4, envelope, logTag: 't' }),
    ).rejects.toBeInstanceOf(RspamdRequestError);
    expect(recorded).toHaveLength(0);
  });

  it('classifies a stream shorter than sizeBytes as a request error', async () => {
    const body = lazyBody(['short']);
    const error = await client()
      .check({ body: body.stream, sizeBytes: 100, envelope, logTag: 't' })
      .catch((e: unknown) => e);
    expect(error).toBeInstanceOf(RspamdRequestError);
    expect((error as RspamdRequestError).field).toBe('sizeBytes');
  });

  it('rethrows an error of the source stream unchanged (the caller classifies S3 failures)', async () => {
    const failure = Object.assign(new Error('s3 read failed'), { code: 'S3_TEST' });
    let sent = false;
    const stream = new Readable({
      read() {
        if (!sent) {
          sent = true;
          this.push(Buffer.from('partial'));
        } else {
          this.destroy(failure);
        }
      },
    });
    await expect(
      client().check({ body: stream, sizeBytes: 50, envelope, logTag: 't' }),
    ).rejects.toBe(failure);
  });

  it('maps HTTP errors with retryability and never echoes the reply body', async () => {
    handler = (_req, res) => json(res, 500, { error: 'secret-message-id@x' });
    const e500 = await client()
      .check({ body: Buffer.from('a'), sizeBytes: 1, envelope, logTag: 't' })
      .catch((e: unknown) => e);
    expect(e500).toBeInstanceOf(RspamdHttpError);
    expect((e500 as RspamdHttpError).status).toBe(500);
    expect((e500 as RspamdHttpError).retryable).toBe(true);
    expect((e500 as Error).message).not.toContain('secret');

    handler = (_req, res) => json(res, 400, { error: 'bad' });
    const e400 = await client()
      .check({ body: Buffer.from('a'), sizeBytes: 1, envelope, logTag: 't' })
      .catch((e: unknown) => e);
    expect((e400 as RspamdHttpError).retryable).toBe(false);
  });

  it('maps invalid JSON and schema mismatches to protocol errors', async () => {
    handler = (_req, res) => {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end('{not json');
    };
    const invalid = await client()
      .check({ body: Buffer.from('a'), sizeBytes: 1, envelope, logTag: 't' })
      .catch((e: unknown) => e);
    expect(invalid).toBeInstanceOf(RspamdProtocolError);
    expect((invalid as RspamdProtocolError).reason).toBe('invalid_json');

    handler = (_req, res) => json(res, 200, { score: 'high', action: 'reject' });
    const schema = await client()
      .check({ body: Buffer.from('a'), sizeBytes: 1, envelope, logTag: 't' })
      .catch((e: unknown) => e);
    expect((schema as RspamdProtocolError).reason).toBe('schema_mismatch');
    expect((schema as RspamdProtocolError).issuePaths).toEqual(
      expect.arrayContaining(['score', 'required_score']),
    );
    expect((schema as Error).message).not.toContain('high');
  });

  it('refuses oversized replies', async () => {
    handler = (_req, res) => json(res, 200, { ...okReply, padding: 'x'.repeat(5000) });
    const error = await client({ maxReplyBytes: 1000 })
      .check({ body: Buffer.from('a'), sizeBytes: 1, envelope, logTag: 't' })
      .catch((e: unknown) => e);
    expect((error as RspamdProtocolError).reason).toBe('reply_too_large');

    handler = (_req, res) => {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.write(JSON.stringify(okReply).slice(0, 10));
      res.end('x'.repeat(5000));
    };
    const chunked = await client({ maxReplyBytes: 1000 })
      .check({ body: Buffer.from('a'), sizeBytes: 1, envelope, logTag: 't' })
      .catch((e: unknown) => e);
    expect((chunked as RspamdProtocolError).reason).toBe('reply_too_large');
  });

  it('turns the soft reject action into RspamdSoftRejectError', async () => {
    handler = (_req, res) => json(res, 200, { ...okReply, action: 'soft reject' });
    await expect(
      client().check({ body: Buffer.from('a'), sizeBytes: 1, envelope, logTag: 't' }),
    ).rejects.toBeInstanceOf(RspamdSoftRejectError);
  });

  it('times out on a server that never answers', async () => {
    handler = () => undefined;
    const error = await client({ timeoutMs: 200 })
      .check({ body: Buffer.from('a'), sizeBytes: 1, envelope, logTag: 't' })
      .catch((e: unknown) => e);
    expect(error).toBeInstanceOf(RspamdTimeoutError);
    expect((error as RspamdTimeoutError).timeoutMs).toBe(200);
    server.closeAllConnections();
  });

  it('maps a caller timeout signal to RspamdTimeoutError and rethrows other aborts', async () => {
    handler = () => undefined;
    const timedOut = await client({ timeoutMs: 5_000 })
      .check(
        { body: Buffer.from('a'), sizeBytes: 1, envelope, logTag: 't' },
        AbortSignal.timeout(100),
      )
      .catch((e: unknown) => e);
    expect(timedOut).toBeInstanceOf(RspamdTimeoutError);

    const controller = new AbortController();
    const shutdown = new Error('shutting down');
    setTimeout(() => controller.abort(shutdown), 50);
    await expect(
      client({ timeoutMs: 5_000 }).check(
        { body: Buffer.from('a'), sizeBytes: 1, envelope, logTag: 't' },
        controller.signal,
      ),
    ).rejects.toBe(shutdown);
    server.closeAllConnections();
  });

  it('reports a refused connection as unavailable', async () => {
    const probe = createTcpServer();
    await new Promise<void>((resolve) => probe.listen(0, '127.0.0.1', resolve));
    const port = (probe.address() as AddressInfo).port;
    await new Promise<void>((resolve) => probe.close(() => resolve()));
    const error = await client({ baseUrl: `http://127.0.0.1:${port}` })
      .check({ body: Buffer.from('a'), sizeBytes: 1, envelope, logTag: 't' })
      .catch((e: unknown) => e);
    expect(error).toBeInstanceOf(RspamdUnavailableError);
    expect((error as RspamdUnavailableError).causeCode).toBe('ECONNREFUSED');
    expect((error as RspamdUnavailableError).retryable).toBe(true);
  });

  it('reports a connection reset mid-reply as unavailable', async () => {
    const sockets: Socket[] = [];
    const reset = createTcpServer((socket) => {
      sockets.push(socket);
      socket.once('data', () => {
        socket.write('HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n{"score"');
        socket.destroy();
      });
    });
    await new Promise<void>((resolve) => reset.listen(0, '127.0.0.1', resolve));
    try {
      const error = await client({
        baseUrl: `http://127.0.0.1:${(reset.address() as AddressInfo).port}`,
      })
        .check({ body: Buffer.from('a'), sizeBytes: 1, envelope, logTag: 't' })
        .catch((e: unknown) => e);
      expect(error).toBeInstanceOf(RspamdUnavailableError);
    } finally {
      for (const s of sockets) s.destroy();
      await new Promise<void>((resolve) => reset.close(() => resolve()));
    }
  });

  it('limits in-flight calls to maxInFlight', async () => {
    let active = 0;
    let peak = 0;
    handler = (_req, res) => {
      active += 1;
      peak = Math.max(peak, active);
      setTimeout(() => {
        active -= 1;
        json(res, 200, okReply);
      }, 50);
    };
    const c = client({ maxInFlight: 2 });
    await Promise.all(
      Array.from({ length: 6 }, (_, i) =>
        c.check({ body: Buffer.from('a'), sizeBytes: 1, envelope, logTag: `t${i}` }),
      ),
    );
    expect(recorded).toHaveLength(6);
    expect(peak).toBe(2);
    expect(c.inFlight).toEqual({ active: 0, waiting: 0 });
  });
});

describe('RspamdClient controller operations', () => {
  it('learns with the enable password and maps 208 and 204 to already_learned', async () => {
    handler = (_req, res) => json(res, 200, { success: true });
    await expect(client().learn('spam', Buffer.from('m'), 1)).resolves.toBe('learned');
    expect(recorded[0]!.url).toBe('/learnspam');
    expect(recorded[0]!.headers.password).toBe(ENABLE_PASSWORD);

    handler = (_req, res) =>
      json(res, 208, { error: '<mid@x> has been already learned as ham, ignore it' });
    await expect(client().learn('ham', Buffer.from('m'), 1)).resolves.toBe('already_learned');
    expect(recorded[1]!.url).toBe('/learnham');

    handler = (_req, res) => {
      res.writeHead(204);
      res.end();
    };
    await expect(client().learn('spam', Buffer.from('m'), 1)).resolves.toBe('already_learned');
  });

  it('never puts a password into an error message', async () => {
    handler = (_req, res) => json(res, 401, { error: 'Unauthorized' });
    const error = await client()
      .learn('spam', Buffer.from('m'), 1)
      .catch((e: unknown) => e);
    expect(error).toBeInstanceOf(RspamdHttpError);
    expect((error as RspamdHttpError).status).toBe(401);
    expect(
      JSON.stringify({ message: (error as Error).message, ...(error as object) }),
    ).not.toContain(ENABLE_PASSWORD);
  });

  it('adds fuzzy hashes with Flag and Weight and deletes with Flag only', async () => {
    handler = (_req, res) => json(res, 200, { success: true, hashes: ['h1', 'h2'] });
    await expect(client().fuzzy('add', 11, 10, Buffer.from('m'), 1)).resolves.toEqual({
      result: 'added',
      hashes: 2,
    });
    expect(recorded[0]!.url).toBe('/fuzzyadd');
    expect(recorded[0]!.headers.flag).toBe('11');
    expect(recorded[0]!.headers.weight).toBe('10');
    await expect(client().fuzzy('delete', 12, 10, Buffer.from('m'), 1)).resolves.toEqual({
      result: 'deleted',
      hashes: 2,
    });
    expect(recorded[1]!.url).toBe('/fuzzydel');
    expect(recorded[1]!.headers.flag).toBe('12');
    expect(recorded[1]!.headers.weight).toBeUndefined();
  });

  it('refuses invalid fuzzy flags and weights', async () => {
    await expect(client().fuzzy('add', 0, 10, Buffer.from('m'), 1)).rejects.toBeInstanceOf(
      RspamdRequestError,
    );
    await expect(client().fuzzy('add', 11, 1.5, Buffer.from('m'), 1)).rejects.toBeInstanceOf(
      RspamdRequestError,
    );
    expect(recorded).toHaveLength(0);
  });

  it('reads the version from /stat with the read password', async () => {
    handler = (_req, res) => json(res, 200, { version: '3.12.1', uptime: 5 });
    const c = client();
    await expect(c.version()).resolves.toBe('3.12.1');
    expect(recorded[0]!.method).toBe('GET');
    expect(recorded[0]!.url).toBe('/stat');
    expect(recorded[0]!.headers.password).toBe(READ_PASSWORD);
    expect(c.lastServerVersion).toBe('3.12.1');
  });

  it('refuses controller calls without a configured controller or password', async () => {
    const noController = new RspamdClient({ baseUrl: base, timeoutMs: 1000 });
    await expect(noController.version()).rejects.toMatchObject({ field: 'controllerUrl' });
    const noPassword = new RspamdClient({ baseUrl: base, controllerUrl: base, timeoutMs: 1000 });
    await expect(noPassword.learn('spam', Buffer.from('m'), 1)).rejects.toMatchObject({
      field: 'controllerEnablePassword',
    });
    await expect(noPassword.version()).rejects.toMatchObject({ field: 'controllerPassword' });
  });
});

describe('parseServerVersion', () => {
  it('parses rspamd/<version> only', () => {
    expect(parseServerVersion('rspamd/3.12.1')).toBe('3.12.1');
    expect(parseServerVersion('nginx/1.2')).toBeNull();
    expect(parseServerVersion(null)).toBeNull();
    expect(parseServerVersion('rspamd/3.12.1\r\nX: y')).toBeNull();
  });
});

describe('RspamdClient options', () => {
  it('validates the timeout', () => {
    expect(() => new RspamdClient({ baseUrl: base, timeoutMs: 0 })).toThrow(RangeError);
  });
});
