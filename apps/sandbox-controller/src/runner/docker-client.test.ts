import { mkdtempSync, rmSync } from 'node:fs';
import http from 'node:http';
import type { Socket } from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import {
  compareApiVersions,
  DockerApiError,
  DockerClient,
  DockerStreamDemuxer,
  DockerUnreachableError,
  negotiateApiVersion,
} from './docker-client';

const muxFrame = (stream: number, payload: Buffer) => {
  const head = Buffer.alloc(8);
  head.writeUInt8(stream, 0);
  head.writeUInt32BE(payload.length, 4);
  return Buffer.concat([head, payload]);
};

describe('negotiateApiVersion', () => {
  it('pins min(server, 1.47) and refuses old or incompatible daemons', () => {
    expect(negotiateApiVersion({ ApiVersion: '1.56', MinAPIVersion: '1.44' })).toBe('1.47');
    expect(negotiateApiVersion({ ApiVersion: '1.45' })).toBe('1.45');
    expect(negotiateApiVersion({ ApiVersion: '1.43' })).toBe('1.43');
    expect(() => negotiateApiVersion({ ApiVersion: '1.41' })).toThrow(DockerApiError);
    expect(() => negotiateApiVersion({ ApiVersion: '1.60', MinAPIVersion: '1.50' })).toThrow(
      /minimum/,
    );
    expect(() => negotiateApiVersion({ ApiVersion: 'x' })).toThrow(/unparseable/);
    expect(compareApiVersions('1.9', '1.10')).toBe(-1);
  });
});

describe('DockerStreamDemuxer', () => {
  it('splits stdout/stderr frames across arbitrary chunk boundaries', () => {
    const data = Buffer.concat([
      muxFrame(1, Buffer.from('hello ')),
      muxFrame(2, Buffer.from('err')),
      muxFrame(1, Buffer.from('world')),
    ]);
    const demux = new DockerStreamDemuxer(1024);
    for (let i = 0; i < data.length; i += 3) demux.push(data.subarray(i, i + 3));
    expect(demux.result()).toEqual({
      stdout: Buffer.from('hello world'),
      stdoutBytes: 11,
      stdoutTruncated: false,
      stderrBytes: 3,
      framingError: false,
    });
  });

  it('caps stdout and counts the rest', () => {
    const demux = new DockerStreamDemuxer(4);
    demux.push(muxFrame(1, Buffer.from('abcdefgh')));
    expect(demux.result()).toMatchObject({
      stdout: Buffer.from('abcd'),
      stdoutBytes: 8,
      stdoutTruncated: true,
    });
  });

  it('flags malformed framing and incomplete frames', () => {
    const bad = new DockerStreamDemuxer(10);
    bad.push(Buffer.from([7, 0, 0, 0, 0, 0, 0, 1, 0]));
    expect(bad.result().framingError).toBe(true);
    const cut = new DockerStreamDemuxer(10);
    cut.push(muxFrame(1, Buffer.from('abcdef')).subarray(0, 10));
    expect(cut.result().framingError).toBe(true);
  });
});

describe('DockerClient over a unix socket (fake daemon)', () => {
  let dir: string;
  let socketPath: string;
  let server: http.Server;
  const requests: Array<{ method: string; url: string; body: string }> = [];
  let stdinSeen = '';

  beforeAll(async () => {
    dir = mkdtempSync(join(tmpdir(), 'eg-docker-'));
    socketPath = join(dir, 'docker.sock');
    server = http.createServer((req, res) => {
      let body = '';
      req.on('data', (c: Buffer) => (body += c.toString()));
      req.on('end', () => {
        requests.push({ method: req.method ?? '', url: req.url ?? '', body });
        const url = req.url ?? '';
        const json = (status: number, value: unknown) => {
          res.writeHead(status, { 'content-type': 'application/json' });
          res.end(JSON.stringify(value));
        };
        if (url === '/_ping') return void res.end('OK');
        if (url === '/version')
          return json(200, { Version: '29.0.0', ApiVersion: '1.56', MinAPIVersion: '1.44' });
        if (url === '/v1.47/info')
          return json(200, { SecurityOptions: ['name=seccomp,profile=builtin'] });
        if (url.startsWith('/v1.47/images/missing')) return json(404, { message: 'No such image' });
        if (url.startsWith('/v1.47/images/')) return json(200, { Id: 'sha256:' + 'b'.repeat(64) });
        if (url === '/v1.47/networks/net-1')
          return json(200, { Id: 'n', Name: 'net-1', Internal: true });
        if (url.startsWith('/v1.47/containers/create?name=ok'))
          return json(201, { Id: 'c'.repeat(64), Warnings: [] });
        if (url.startsWith('/v1.47/containers/create?name=conflict'))
          return json(409, { message: 'Conflict.\nname in use' });
        if (url.startsWith('/v1.47/containers/create?name=noid'))
          return json(201, { Warnings: [] });
        if (url === `/v1.47/containers/${'c'.repeat(64)}/json`)
          return json(200, { Id: 'c'.repeat(64), State: { Status: 'created' } });
        if (url === '/v1.47/containers/gone/json')
          return json(404, { message: 'No such container' });
        if (url.endsWith('/start')) return void res.writeHead(204).end();
        if (url.includes('/kill'))
          return void res.writeHead(url.includes('stopped') ? 409 : 204).end();
        if (req.method === 'DELETE') {
          if (url.startsWith('/v1.47/containers/gone')) return json(404, { message: 'gone' });
          if (url.startsWith('/v1.47/containers/broken'))
            return json(500, { message: 'driver failed' });
          return void res.writeHead(204).end();
        }
        if (url.includes('/wait')) {
          // Longer than Node's global-agent idle socket timeout (5 s): must not be cut.
          setTimeout(() => json(200, { StatusCode: 137 }), 5_500);
          return;
        }
        if (url.startsWith('/v1.47/containers/json'))
          return json(200, [{ Id: 'x', Labels: { a: 'b' } }]);
        if (url === '/v1.47/huge') return json(200, { big: 'x'.repeat(10_000) });
        json(404, { message: 'not found' });
      });
    });
    server.on('upgrade', (req, socket: Socket) => {
      socket.write(
        'HTTP/1.1 101 UPGRADED\r\nContent-Type: application/vnd.docker.raw-stream\r\nConnection: Upgrade\r\nUpgrade: tcp\r\n\r\n',
      );
      socket.write(muxFrame(1, Buffer.from('EGSB')));
      socket.on('data', (chunk: Buffer) => (stdinSeen += chunk.toString()));
      socket.on('end', () => {
        socket.write(muxFrame(2, Buffer.from('warning')));
        socket.end(muxFrame(1, Buffer.from(`:${stdinSeen}`)));
      });
    });
    await new Promise<void>((resolve) => server.listen(socketPath, resolve));
  });

  afterAll(async () => {
    await new Promise<void>((resolve) => server.close(() => resolve()));
    rmSync(dir, { recursive: true, force: true });
  });

  const client = () => new DockerClient({ socketPath, maxResponseBytes: 4_096 });

  it('negotiates the version once and prefixes versioned paths', async () => {
    const c = client();
    await c.ping();
    expect(c.negotiatedVersion).toBeNull();
    const info = await c.info();
    expect(info.SecurityOptions).toEqual(['name=seccomp,profile=builtin']);
    expect(c.negotiatedVersion).toBe('1.47');
    await c.info();
    expect(requests.filter((r) => r.url === '/version')).toHaveLength(1);
  });

  it('images, networks, create, inspect, start, kill, remove, list', async () => {
    const c = client();
    expect((await c.inspectImage('email-gateway/sandbox-runner:local'))?.Id).toMatch(/^sha256:/);
    expect(await c.inspectImage('missing:tag')).toBeNull();
    expect((await c.inspectNetwork('net-1'))?.Internal).toBe(true);
    const created = await c.createContainer({ Image: 'x' }, 'ok-1');
    expect(created.Id).toBe('c'.repeat(64));
    expect(JSON.parse(requests.at(-1)!.body)).toEqual({ Image: 'x' });
    await expect(c.createContainer({}, 'conflict-1')).rejects.toMatchObject({
      statusCode: 409,
      operation: 'create',
    });
    await expect(c.createContainer({}, 'noid-1')).rejects.toThrow(/no container id/);
    expect((await c.inspectContainer(created.Id))?.State?.Status).toBe('created');
    expect(await c.inspectContainer('gone')).toBeNull();
    await c.startContainer(created.Id);
    await c.killContainer(created.Id);
    await c.killContainer('stopped-1');
    expect(await c.removeContainer(created.Id)).toBe(true);
    expect(requests.at(-1)!.url).toBe(`/v1.47/containers/${'c'.repeat(64)}?force=true&v=true`);
    expect(await c.removeContainer('gone')).toBe(false);
    await expect(c.removeContainer('broken')).rejects.toThrow(/driver failed/);
    const list = await c.listContainers(['eg.sandbox.runner=1', 'eg.sandbox.controller=c-1']);
    expect(list).toEqual([{ Id: 'x', Labels: { a: 'b' } }]);
    expect(decodeURIComponent(requests.at(-1)!.url)).toContain(
      '{"label":["eg.sandbox.runner=1","eg.sandbox.controller=c-1"]}',
    );
  });

  it('refuses unsafe names and label filters before sending anything', async () => {
    const c = client();
    await expect(c.inspectContainer('../../etc')).rejects.toThrow(/invalid/);
    await expect(c.listContainers(['a"b'])).rejects.toThrow(/invalid label/);
    await expect(c.inspectImage('bad image')).rejects.toThrow(/invalid image/);
  });

  it('bounds response bodies', async () => {
    const c = client();
    await c.info();
    await expect(
      (
        c as unknown as { raw: (o: string, m: string, p: string, x: object) => Promise<unknown> }
      ).raw('huge', 'GET', '/huge', {}),
    ).rejects.toThrow(/too large/);
  });

  it('wait outlives the 5 s agent idle timeout', async () => {
    const result = await client().waitContainer('c'.repeat(64));
    expect(result.StatusCode).toBe(137);
  }, 10_000);

  it('wait is abortable', async () => {
    const abort = new AbortController();
    const pending = client().waitContainer('c'.repeat(64), abort.signal);
    setTimeout(() => abort.abort(), 50);
    await expect(pending).rejects.toThrow();
  });

  it('attach: stdin is delivered, EOF half-closes, stdout and stderr are demultiplexed', async () => {
    const c = client();
    const stream = await c.attachContainer('c'.repeat(64), { maxStdoutBytes: 1024 });
    await stream.write(Buffer.from('sample-bytes'));
    stream.endStdin();
    const out = await stream.collect();
    expect(out.stdout.toString()).toBe('EGSB:sample-bytes');
    expect(out.stderrBytes).toBe(7);
    expect(out.framingError).toBe(false);
  });

  it('an absent socket is DockerUnreachableError', async () => {
    const c = new DockerClient({ socketPath: join(dir, 'missing.sock') });
    await expect(c.ping()).rejects.toBeInstanceOf(DockerUnreachableError);
    await expect(c.attachContainer('c'.repeat(64), { maxStdoutBytes: 1 })).rejects.toBeInstanceOf(
      DockerUnreachableError,
    );
  });
});
