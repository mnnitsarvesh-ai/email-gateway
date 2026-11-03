import { createConnection } from 'node:net';
import { afterEach, describe, expect, it } from 'vitest';
import { metricValue, newMetrics, silentLogger } from '../../integration/in-session-support/fakes';
import { parseNetworkList } from '../shared/internal-networks';
import type { SocketmapLookupService } from './socketmap-lookup.service';
import { encodeNetstring } from './netstring';
import { SocketmapServerService } from './socketmap-server.service';

const ns = (...payloads: string[]) => payloads.map((p) => encodeNetstring(p).toString()).join('');

/** Sends raw bytes and collects everything until `bytes` arrived or the server closed. */
function exchange(
  port: number,
  payload: string,
  until: (data: string) => boolean,
): Promise<string> {
  return new Promise((resolve, reject) => {
    const socket = createConnection({ port, host: '127.0.0.1' });
    let data = '';
    socket.setEncoding('utf8');
    socket.on('data', (chunk: string) => {
      data += chunk;
      if (until(data)) socket.end();
    });
    socket.on('close', () => resolve(data));
    socket.on('error', (err: NodeJS.ErrnoException) =>
      err.code === 'ECONNRESET' ? resolve(data) : reject(err),
    );
    socket.write(payload);
  });
}

describe('SocketmapServerService', () => {
  let server: SocketmapServerService | undefined;
  const metrics = newMetrics();

  afterEach(async () => {
    await server?.onModuleDestroy();
    server = undefined;
  });

  async function start(
    lookup: SocketmapLookupService['lookup'],
    networks = '127.0.0.0/8',
  ): Promise<number> {
    server = new SocketmapServerService(
      { host: '127.0.0.1', port: 0, internalNetworks: parseNetworkList(networks) },
      { lookup } as unknown as SocketmapLookupService,
      metrics,
      silentLogger(),
    );
    await server.onModuleInit();
    return server.address();
  }

  it('answers pipelined requests in order and counts lookups', async () => {
    const port = await start(async (map, key) => {
      await new Promise((r) => setTimeout(r, key === 'slow.test' ? 20 : 0));
      return map === 'relay_domain' && key.endsWith('.test') ? 'OK active' : 'NOTFOUND ';
    });
    const reply = await exchange(
      port,
      ns('relay_domain slow.test', 'relay_domain other.example'),
      (d) => d.length >= ns('OK active', 'NOTFOUND ').length,
    );
    expect(reply).toBe('9:OK active,9:NOTFOUND ,');
    expect(
      await metricValue(metrics, 'smtp_socketmap_lookups_total', {
        map: 'relay_domain',
        result: 'ok',
      }),
    ).toBeGreaterThanOrEqual(1);
    await expect(server?.checkHealth()).resolves.toBeUndefined();
  });

  it('answers TEMP Lookup failed when the lookup throws (fail closed)', async () => {
    const port = await start(() => Promise.reject(new Error('db down')));
    expect(await exchange(port, ns('transport tenant.test'), (d) => d.endsWith(','))).toBe(
      '18:TEMP Lookup failed,',
    );
  });

  it('answers PERM for a request without a key separator', async () => {
    const port = await start(() => Promise.resolve('NOTFOUND '));
    expect(await exchange(port, ns('nospace'), (d) => d.endsWith(','))).toBe(
      '16:PERM Unknown map,',
    );
  });

  it('closes the connection on malformed or oversized input', async () => {
    const port = await start(() => Promise.resolve('NOTFOUND '));
    expect(await exchange(port, 'abc:def,', () => false)).toBe('');
    expect(await exchange(port, '99999:', () => false)).toBe('');
  });

  it('refuses peers outside SMTP_INTERNAL_CLIENT_NETWORKS', async () => {
    const port = await start(() => Promise.resolve('OK active'), '10.0.0.0/8');
    expect(await exchange(port, ns('relay_domain tenant.test'), () => false)).toBe('');
  });
});
