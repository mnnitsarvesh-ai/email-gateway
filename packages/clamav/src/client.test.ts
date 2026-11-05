import { createServer, type AddressInfo, type Server, type Socket } from 'node:net';
import { Readable } from 'node:stream';
import { afterEach, describe, expect, it } from 'vitest';
import { ClamdClient } from './client';
import {
  ClamdProtocolError,
  ClamdSizeLimitError,
  ClamdTimeoutError,
  ClamdUnavailableError,
} from './errors';

const VERSION = 'ClamAV 1.4.6/28173/Tue Nov  3 06:27:52 2026';

interface ScanSeen {
  bytes: Buffer;
  chunkSizes: number[];
}

interface FakeOptions {
  /** Reply text of an INSTREAM (default `stream: OK`). */
  onScan?: (seen: ScanSeen) => string;
  /** clamd's StreamMaxLength: replies the size-limit error and closes once exceeded. */
  streamMax?: number;
  /** Delay before every reply. */
  delayMs?: number;
  /** Per connection: what happens right after the commands arrive. */
  mode?: 'normal' | 'reset' | 'close' | 'garbage' | 'silent' | 'reverse' | 'unnumbered';
  versionText?: string;
}

/**
 * A fake clamd speaking the null-terminated protocol (IDSESSION, VERSION, PING, INSTREAM chunks,
 * END) closely enough to exercise the client: numbered replies in a session, the size-limit
 * reply + close of clamd 1.4, and failure modes. Records concurrency and chunk sizes.
 */
class FakeClamd {
  server: Server;
  active = 0;
  maxActive = 0;
  connections = 0;
  scans: ScanSeen[] = [];
  sockets = new Set<Socket>();

  constructor(private readonly options: FakeOptions = {}) {
    this.server = createServer((socket) => this.handle(socket));
  }

  async listen(): Promise<number> {
    await new Promise<void>((resolve) => this.server.listen(0, '127.0.0.1', resolve));
    return (this.server.address() as AddressInfo).port;
  }

  async close(): Promise<void> {
    for (const socket of this.sockets) socket.destroy();
    await new Promise<void>((resolve) => this.server.close(() => resolve()));
  }

  private handle(socket: Socket): void {
    this.connections += 1;
    this.active += 1;
    this.maxActive = Math.max(this.maxActive, this.active);
    this.sockets.add(socket);
    // In flight at clamd until the replies are flushed (the client releases its slot as soon
    // as it has them; the server-side close event may come later).
    let counted = true;
    const done = () => {
      if (!counted) return;
      counted = false;
      this.active -= 1;
    };
    socket.on('close', () => {
      done();
      this.sockets.delete(socket);
    });
    socket.on('error', () => undefined);
    const mode = this.options.mode ?? 'normal';
    let buffer = Buffer.alloc(0);
    let session = false;
    let nextId = 1;
    let inStream: { id: number; parts: Buffer[]; total: number; sizes: number[] } | null = null;
    const pending: string[] = [];
    let ended = false;

    const send = (id: number | null, text: string) => {
      const line = session && id !== null ? `${id}: ${text}\0` : `${text}\0`;
      pending.push(line);
    };
    const flush = (closeAfter: boolean) => {
      const lines = mode === 'reverse' ? pending.slice().reverse() : pending.slice();
      pending.length = 0;
      const out = () => {
        if (socket.destroyed) return;
        if (mode === 'garbage') socket.write('this is not clamd\0and more\0');
        else if (mode === 'unnumbered') socket.write('UNKNOWN COMMAND\0');
        else for (const line of lines) socket.write(line);
        if (closeAfter) {
          done();
          socket.end();
        }
      };
      if (this.options.delayMs) setTimeout(out, this.options.delayMs);
      else out();
    };

    socket.on('data', (chunk: Buffer) => {
      if (ended) return;
      buffer = Buffer.concat([buffer, chunk]);
      for (;;) {
        if (inStream) {
          if (buffer.length < 4) return;
          const length = buffer.readUInt32BE(0);
          if (length === 0) {
            buffer = buffer.subarray(4);
            const seen = { bytes: Buffer.concat(inStream.parts), chunkSizes: inStream.sizes };
            this.scans.push(seen);
            send(inStream.id, (this.options.onScan ?? (() => 'stream: OK'))(seen));
            inStream = null;
            continue;
          }
          if (buffer.length < 4 + length) return;
          inStream.parts.push(Buffer.from(buffer.subarray(4, 4 + length)));
          inStream.sizes.push(length);
          inStream.total += length;
          buffer = buffer.subarray(4 + length);
          if (this.options.streamMax !== undefined && inStream.total > this.options.streamMax) {
            send(inStream.id, 'INSTREAM size limit exceeded. ERROR');
            ended = true;
            flush(true);
            return;
          }
          continue;
        }
        const end = buffer.indexOf(0);
        if (end < 0) return;
        const command = buffer.toString('latin1', 0, end);
        buffer = buffer.subarray(end + 1);
        if (mode === 'reset') {
          socket.resetAndDestroy();
          return;
        }
        if (mode === 'close') {
          socket.end();
          return;
        }
        if (mode === 'silent') continue;
        const id = session ? nextId++ : null;
        if (command === 'zIDSESSION') {
          session = true;
          nextId = 1;
        } else if (command === 'zPING') {
          send(null, 'PONG');
          flush(true);
        } else if (command === 'zVERSION') {
          send(id, this.options.versionText ?? VERSION);
          if (!session) flush(true);
        } else if (command === 'zINSTREAM') {
          inStream = { id: id ?? 0, parts: [], total: 0, sizes: [] };
        } else if (command === 'zEND') {
          ended = true;
          flush(true);
          return;
        } else {
          send(null, 'UNKNOWN COMMAND');
          flush(true);
          return;
        }
      }
    });
  }
}

const fakes: FakeClamd[] = [];
async function start(options: FakeOptions = {}): Promise<{ fake: FakeClamd; port: number }> {
  const fake = new FakeClamd(options);
  fakes.push(fake);
  return { fake, port: await fake.listen() };
}

function client(
  port: number,
  overrides: Partial<ConstructorParameters<typeof ClamdClient>[0]> = {},
) {
  return new ClamdClient({ host: '127.0.0.1', port, timeoutMs: 2_000, ...overrides });
}

afterEach(async () => {
  await Promise.all(fakes.splice(0).map((fake) => fake.close()));
});

describe('ClamdClient options', () => {
  it('validates host, port, timeout, connections and chunk size', () => {
    const base = { host: '127.0.0.1', port: 3310, timeoutMs: 1000 };
    expect(() => new ClamdClient({ ...base, host: '' })).toThrow(RangeError);
    expect(() => new ClamdClient({ ...base, port: 0 })).toThrow(RangeError);
    expect(() => new ClamdClient({ ...base, timeoutMs: 0 })).toThrow(RangeError);
    expect(() => new ClamdClient({ ...base, maxConnections: 65 })).toThrow(RangeError);
    expect(() => new ClamdClient({ ...base, maxConnections: 0 })).toThrow(RangeError);
    expect(() => new ClamdClient({ ...base, chunkBytes: 100 })).toThrow(RangeError);
    expect(() => new ClamdClient({ ...base, maxConnections: 64 })).not.toThrow();
  });
});

describe('ClamdClient.ping and version', () => {
  it('pings', async () => {
    const { port } = await start();
    await expect(client(port).ping()).resolves.toBeUndefined();
  });

  it('parses VERSION', async () => {
    const { port } = await start();
    await expect(client(port).version()).resolves.toEqual({
      engine: '1.4.6',
      dbVersion: 28173,
      dbTime: new Date('2026-11-03T06:27:52Z'),
    });
  });

  it('refuses a VERSION reply without a database', async () => {
    const { port } = await start({ versionText: 'ClamAV 1.4.6' });
    await expect(client(port).version()).rejects.toMatchObject({
      kind: 'protocol_error',
      reason: 'invalid_version',
    });
  });

  it('reports a refused connection as unavailable', async () => {
    const { fake, port } = await start();
    await fake.close();
    fakes.splice(fakes.indexOf(fake), 1);
    const error = await client(port)
      .ping()
      .catch((e: unknown) => e);
    expect(error).toBeInstanceOf(ClamdUnavailableError);
    expect(error).toMatchObject({ causeCode: 'ECONNREFUSED', retryable: true, operation: 'ping' });
  });
});

describe('ClamdClient.scan', () => {
  it('streams a buffer in chunks inside one IDSESSION and returns clean with the version', async () => {
    const { fake, port } = await start();
    const data = Buffer.alloc(150_000, 7);
    const result = await client(port, { chunkBytes: 65_536 }).scan(data);
    expect(result).toMatchObject({
      status: 'clean',
      engine: '1.4.6',
      dbVersion: 28173,
      bytes: 150_000,
    });
    expect(result.dbTime.toISOString()).toBe('2026-11-03T06:27:52.000Z');
    expect(fake.scans).toHaveLength(1);
    expect(fake.scans[0]?.bytes.equals(data)).toBe(true);
    expect(fake.scans[0]?.chunkSizes).toEqual([65_536, 65_536, 18_928]);
    expect(fake.connections).toBe(1);
  });

  it('scans an empty input', async () => {
    const { port } = await start();
    await expect(client(port).scan(Buffer.alloc(0))).resolves.toMatchObject({
      status: 'clean',
      bytes: 0,
    });
  });

  it('returns found with the signature name', async () => {
    const { port } = await start({ onScan: () => 'stream: Win.Test.EICAR_HDB-1 FOUND' });
    await expect(client(port).scan(Buffer.from('x'))).resolves.toMatchObject({
      status: 'found',
      signature: 'Win.Test.EICAR_HDB-1',
      dbVersion: 28173,
    });
  });

  it('matches replies by id when clamd answers out of order', async () => {
    const { port } = await start({ mode: 'reverse', onScan: () => 'stream: Sig-1 FOUND' });
    await expect(client(port).scan(Buffer.from('x'))).resolves.toMatchObject({
      status: 'found',
      signature: 'Sig-1',
      engine: '1.4.6',
    });
  });

  it('re-chunks a Readable with back-pressure and never exceeds chunkBytes', async () => {
    const { fake, port } = await start();
    const parts = [Buffer.alloc(5000, 1), Buffer.alloc(1, 2), Buffer.alloc(3000, 3)];
    const result = await client(port, { chunkBytes: 2048 }).scan(Readable.from(parts));
    expect(result.bytes).toBe(8001);
    expect(Math.max(...(fake.scans[0]?.chunkSizes ?? []))).toBeLessThanOrEqual(2048);
    expect(fake.scans[0]?.bytes.equals(Buffer.concat(parts))).toBe(true);
  });

  it('streams a large input through a slow reader (drain) without losing bytes', async () => {
    const { fake, port } = await start();
    const data = Buffer.alloc(8 * 1024 * 1024);
    for (let i = 0; i < data.length; i += 4096) data[i] = i % 251;
    const result = await client(port, { timeoutMs: 20_000 }).scan(data);
    expect(result.bytes).toBe(data.length);
    expect(fake.scans[0]?.bytes.equals(data)).toBe(true);
  });

  it('rethrows an error of the input stream unchanged', async () => {
    const { port } = await start();
    const failure = new Error('s3 body failed');
    const input = new Readable({
      read() {
        this.destroy(failure);
      },
    });
    await expect(client(port).scan(input)).rejects.toBe(failure);
  });

  it('refuses a Readable that yields strings', async () => {
    const { port } = await start();
    await expect(client(port).scan(Readable.from(['text']))).rejects.toBeInstanceOf(TypeError);
  });

  it('throws ClamdSizeLimitError with the version when clamd refuses the stream', async () => {
    const { port } = await start({ streamMax: 100_000 });
    const error = await client(port, { chunkBytes: 16_384 })
      .scan(Buffer.alloc(2 * 1024 * 1024))
      .catch((e: unknown) => e);
    expect(error).toBeInstanceOf(ClamdSizeLimitError);
    const sizeError = error as ClamdSizeLimitError;
    expect(sizeError.retryable).toBe(false);
    expect(sizeError.version?.dbVersion).toBe(28173);
    expect(sizeError.bytesSent).toBeGreaterThan(100_000);
    expect(sizeError.bytesSent).toBeLessThan(2 * 1024 * 1024);
  });

  it('maps another ERROR reply to a protocol error', async () => {
    const { port } = await start({ onScan: () => "stream: Can't allocate memory ERROR" });
    await expect(client(port).scan(Buffer.from('x'))).rejects.toMatchObject({
      kind: 'protocol_error',
      reason: 'server_error',
      retryable: true,
    });
  });

  it('refuses an invalid signature name', async () => {
    const { port } = await start({ onScan: () => 'stream: two words FOUND' });
    await expect(client(port).scan(Buffer.from('x'))).rejects.toMatchObject({
      reason: 'invalid_signature',
    });
  });

  it('refuses garbage replies', async () => {
    const { port } = await start({ mode: 'garbage' });
    const error = await client(port)
      .scan(Buffer.from('x'))
      .catch((e: unknown) => e);
    expect(error).toBeInstanceOf(ClamdProtocolError);
    expect(error).toMatchObject({ reason: 'unexpected_reply' });
  });

  it('refuses an unnumbered reply followed by a close', async () => {
    const { port } = await start({ mode: 'unnumbered' });
    await expect(client(port).scan(Buffer.from('x'))).rejects.toMatchObject({
      kind: 'protocol_error',
    });
  });

  it('refuses a scan reply with an unparseable version', async () => {
    const { port } = await start({ versionText: 'ClamAV ?' });
    await expect(client(port).scan(Buffer.from('x'))).rejects.toMatchObject({
      reason: 'invalid_version',
    });
  });

  it('maps a reset connection to unavailable', async () => {
    const { port } = await start({ mode: 'reset' });
    const error = await client(port)
      .scan(Buffer.alloc(1000))
      .catch((e: unknown) => e);
    expect(error).toBeInstanceOf(ClamdUnavailableError);
    expect(['ECONNRESET', 'EPIPE', 'CLOSED']).toContain((error as ClamdUnavailableError).causeCode);
  });

  it('maps a close without a reply to unavailable', async () => {
    const { port } = await start({ mode: 'close' });
    await expect(client(port).scan(Buffer.from('x'))).rejects.toBeInstanceOf(ClamdUnavailableError);
  });

  it('times out on a silent clamd and destroys the socket', async () => {
    const { fake, port } = await start({ mode: 'silent' });
    const started = Date.now();
    const error = await client(port, { timeoutMs: 200 })
      .scan(Buffer.from('x'))
      .catch((e: unknown) => e);
    expect(error).toBeInstanceOf(ClamdTimeoutError);
    expect(error).toMatchObject({ timeoutMs: 200, operation: 'scan' });
    expect(Date.now() - started).toBeLessThan(1500);
    await expect.poll(() => fake.active).toBe(0);
  });

  it('times out on a slow clamd', async () => {
    const { port } = await start({ delayMs: 500 });
    await expect(client(port, { timeoutMs: 150 }).scan(Buffer.from('x'))).rejects.toBeInstanceOf(
      ClamdTimeoutError,
    );
    await expect(client(port, { timeoutMs: 2000 }).scan(Buffer.from('x'))).resolves.toMatchObject({
      status: 'clean',
    });
  });

  it('rethrows the abort reason and destroys the socket', async () => {
    const { fake, port } = await start({ mode: 'silent' });
    const controller = new AbortController();
    const reason = new Error('round cancelled');
    const pending = client(port).scan(Buffer.from('x'), controller.signal);
    await expect.poll(() => fake.active).toBe(1);
    controller.abort(reason);
    await expect(pending).rejects.toBe(reason);
    await expect.poll(() => fake.active).toBe(0);
  });

  it('maps an abort with a TimeoutError reason to ClamdTimeoutError', async () => {
    const { port } = await start({ mode: 'silent' });
    await expect(
      client(port).scan(Buffer.from('x'), AbortSignal.timeout(100)),
    ).rejects.toMatchObject({ kind: 'timeout', timeoutMs: null });
  });

  it('rejects at once when the signal is already aborted', async () => {
    const { fake, port } = await start();
    const reason = new Error('already');
    await expect(client(port).scan(Buffer.from('x'), AbortSignal.abort(reason))).rejects.toBe(
      reason,
    );
    expect(fake.connections).toBe(0);
  });

  it('caps concurrent connections at maxConnections', async () => {
    let maxClientActive = 0;
    let c: ClamdClient | null = null;
    const { fake, port } = await start({
      delayMs: 60,
      onScan: () => {
        maxClientActive = Math.max(maxClientActive, c?.connections.active ?? 0);
        return 'stream: OK';
      },
    });
    c = client(port, { maxConnections: 3, timeoutMs: 5_000 });
    const results = await Promise.all(
      Array.from({ length: 10 }, (_, i) => c.scan(Buffer.from(`file ${i}`))),
    );
    expect(results.every((r) => r.status === 'clean')).toBe(true);
    expect(fake.connections).toBe(10);
    expect(fake.maxActive).toBe(3);
    expect(maxClientActive).toBe(3);
    expect(c.connections).toEqual({ active: 0, waiting: 0 });
  });

  it('counts the wait for a slot against the timeout', async () => {
    const { port } = await start({ mode: 'silent' });
    const c = client(port, { maxConnections: 1, timeoutMs: 200 });
    const first = c.scan(Buffer.from('a')).catch((e: unknown) => e);
    const second = c.scan(Buffer.from('b')).catch((e: unknown) => e);
    expect(await first).toBeInstanceOf(ClamdTimeoutError);
    expect(await second).toBeInstanceOf(ClamdTimeoutError);
    expect(c.connections).toEqual({ active: 0, waiting: 0 });
  });
});
