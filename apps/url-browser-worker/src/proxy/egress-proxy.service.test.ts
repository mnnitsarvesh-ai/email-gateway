import http from 'node:http';
import { MetricsService } from '@email-gateway/common';
import { createLogger } from '@email-gateway/logger';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { loadProxyConfig } from '../config';
import { EgressProxyService } from './egress-proxy.service';

const TOKEN = 't'.repeat(32);
const metrics = new MetricsService({ service: 'url-egress-proxy' });
let service: EgressProxyService;
let upstream: http.Server;
let upstreamPort = 0;

function viaProxy(
  target: string,
  auth = true,
): Promise<{ status: number; reason: string | undefined }> {
  return new Promise((resolve, reject) => {
    const req = http.request({
      host: '127.0.0.1',
      port: service.listeningPort,
      method: 'GET',
      path: target,
      headers: auth
        ? { 'proxy-authorization': `Basic ${Buffer.from(`eg:${TOKEN}`).toString('base64')}` }
        : {},
    });
    req.on('response', (res) => {
      res.resume();
      resolve({
        status: res.statusCode ?? 0,
        reason: res.headers['x-egress-blocked-reason'] as string | undefined,
      });
    });
    req.on('error', reject);
    req.end();
  });
}

beforeAll(async () => {
  upstream = http.createServer((_req, res) => res.end('ok'));
  await new Promise<void>((r) => upstream.listen(0, '127.0.0.1', r));
  upstreamPort = (upstream.address() as { port: number }).port;
  const config = {
    ...loadProxyConfig({
      NODE_ENV: 'test',
      APP_ENV: 'ci',
      URL_EGRESS_PROXY_TOKEN: TOKEN,
      URL_DNS_SERVERS: '127.0.0.1:9',
      URL_FETCH_TEST_ALLOW_CIDRS: '203.0.113.0/24',
      // The validated documentation address is dialled at the local upstream (test seam).
      URL_FETCH_TEST_DIAL_MAP: `203.0.113.10:80=127.0.0.1:${upstreamPort}`,
      HTTP_HOST: '127.0.0.1',
    }),
    URL_EGRESS_PORT: 0,
  };
  service = new EgressProxyService(
    config,
    createLogger({ service: 'test', level: 'fatal' }),
    metrics,
  );
  await service.onModuleInit();
});

afterAll(async () => {
  await service.onApplicationShutdown();
  await new Promise<void>((r) => upstream.close(() => r()));
});

describe('EgressProxyService (U15)', () => {
  it('forwards an allowed target after the guard and counts it', async () => {
    expect(await viaProxy('http://203.0.113.10/landing')).toEqual({
      status: 200,
      reason: undefined,
    });
    expect(await service.checkHealth()).toMatchObject({ activeConnections: expect.any(Number) });
  });

  it('refuses metadata, loopback, private and non-allowed ports with 403 + reason', async () => {
    expect(await viaProxy('http://169.254.169.254/latest/meta-data/')).toEqual({
      status: 403,
      reason: 'metadata',
    });
    expect(await viaProxy('http://127.0.0.1/')).toEqual({ status: 403, reason: 'loopback' });
    expect(await viaProxy('http://10.0.0.5/')).toEqual({ status: 403, reason: 'private' });
    expect(await viaProxy('http://203.0.113.10:3080/')).toEqual({ status: 403, reason: 'port' });
    const text = await metrics.metrics();
    expect(text).toContain(
      'url_egress_blocked_total{reason="metadata",service="url-egress-proxy"} 1',
    );
    expect(text).toContain(
      'url_fetch_blocked_total{reason="loopback",component="proxy",service="url-egress-proxy"} 1',
    );
  });

  it('is not an open proxy (407 without credentials)', async () => {
    expect((await viaProxy('http://203.0.113.10/landing', false)).status).toBe(407);
  });
});
