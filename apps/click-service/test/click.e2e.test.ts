import type { INestApplication } from '@nestjs/common';
import type { NestExpressApplication } from '@nestjs/platform-express';
import { Test } from '@nestjs/testing';
import { HealthService, MetricsService, PrismaService, RedisService } from '@email-gateway/common';
import { continueNonce } from '@email-gateway/url-security';
import request from 'supertest';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { createAdminServer } from '../src/admin/admin-server';
import { AppModule } from '../src/app.module';
import { ClickMetrics } from '../src/click/click-metrics';
import { ClickRepository } from '../src/click/click-repository';
import { URL_RUNTIME } from '../src/click/click.module';
import {
  completedChain,
  MemoryClickRepository,
  MemoryRedis,
  ORG,
  silentLogger,
  testConfig,
  tokenFor,
  urlRow,
} from '../src/click/click.test-support';
import { buildUrlRuntime } from '../src/click/url-runtime';
import { configurePublicApp } from '../src/http/configure';
import { CONTENT_SECURITY_POLICY } from '../src/http/security-headers';

const STORED = 'https://clean-site.test/landing?a=1#top';
const SUSPICIOUS = 'http://203.0.113.10/x';
const MALICIOUS = 'https://evil-site.test/login';

const config = testConfig({
  CLICK_RATE_LIMIT_INVALID_PER_MINUTE: '1000',
  CLICK_RATE_LIMIT_IP_PER_MINUTE: '1000',
});
const repository = new MemoryClickRepository();
const redis = new MemoryRedis();
let app: INestApplication;

function expectSecurityHeaders(res: request.Response): void {
  expect(res.headers['content-security-policy']).toBe(CONTENT_SECURITY_POLICY);
  expect(res.headers['referrer-policy']).toBe('no-referrer');
  expect(res.headers['x-content-type-options']).toBe('nosniff');
  expect(res.headers['x-frame-options']).toBe('DENY');
  expect(res.headers['cross-origin-opener-policy']).toBe('same-origin');
  expect(res.headers['cross-origin-resource-policy']).toBe('same-origin');
  expect(res.headers['permissions-policy']).toContain('camera=()');
  expect(res.headers['cache-control']).toBe('no-store');
  expect(res.headers['x-powered-by']).toBeUndefined();
  expect(res.headers['strict-transport-security']).toBeUndefined();
}

beforeAll(async () => {
  for (const [seq, url, verdict] of [
    [0, STORED, 'clean'],
    [1, SUSPICIOUS, 'suspicious'],
    [2, MALICIOUS, 'clean'],
  ] as const) {
    const row = urlRow(url, { urlSeq: seq });
    repository.addUrl(row);
    repository.addScan(row, { verdict });
  }
  repository.addFeed('domain', 'evil-site.test', 'high', 'phishing');
  const runtime = buildUrlRuntime(config, {
    redis: redis,
    feedQuery: (kind, hashes) => repository.feedRows(kind, hashes),
    metrics: new ClickMetrics(new MetricsService({ service: 'e2e-runtime' })),
  });
  (runtime as { fetcher: unknown }).fetcher = {
    fetchChain: (url: string) => Promise.resolve(completedChain(url)),
  };
  const moduleRef = await Test.createTestingModule({
    imports: [AppModule.forRoot(config, silentLogger())],
  })
    .overrideProvider(PrismaService)
    .useValue({ healthName: 'mysql', checkHealth: () => Promise.resolve() })
    .overrideProvider(RedisService)
    .useValue({ healthName: 'redis', client: redis, checkHealth: () => Promise.resolve() })
    .overrideProvider(ClickRepository)
    .useValue(repository)
    .overrideProvider(URL_RUNTIME)
    .useValue(runtime)
    .compile();
  const nest = moduleRef.createNestApplication<NestExpressApplication>();
  configurePublicApp(nest, { trustProxyHops: 0, hsts: false, logger: silentLogger() });
  await nest.init();
  app = nest;
});

afterAll(async () => {
  await app.close();
});

const token = (seq: number, extra: Parameters<typeof tokenFor>[1] = {}) =>
  tokenFor(config, { urlSeq: seq, ...extra });

describe('GET /c/:token', () => {
  it('allow → 302 to the stored URL, with every security header', async () => {
    const res = await request(app.getHttpServer())
      .get(`/c/${token(0)}`)
      .expect(302);
    expect(res.headers.location).toBe(STORED);
    expect(res.text).toBe('');
    expectSecurityHeaders(res);
  });

  it('open-redirect attempts never change the target', async () => {
    const t = token(0);
    for (const path of [
      `/c/${t}?url=https://attacker.test/`,
      `/c/${t}?next=//attacker.test&redirect=https%3A%2F%2Fattacker.test`,
      `/c/${t}?a=1&a=https://attacker.test`,
    ]) {
      const res = await request(app.getHttpServer()).get(path).expect(302);
      expect(res.headers.location).toBe(STORED);
    }
    for (const path of [
      `/c/${t}/https://attacker.test`,
      `/c/${t}/..%2f..%2fattacker.test`,
      `/c/${t}/extra`,
      `//attacker.test/c/${t}`,
      `/c/${encodeURIComponent('https://attacker.test')}`,
    ]) {
      const res = await request(app.getHttpServer()).get(path);
      expect(res.status).toBe(404);
      expect(res.headers.location).toBeUndefined();
      expectSecurityHeaders(res);
    }
  });

  it('every tampered byte → 404 generic page', async () => {
    const raw = Buffer.from(token(0), 'base64url');
    for (let i = 0; i < raw.length; i += 1) {
      const copy = Buffer.from(raw);
      copy[i] = (copy[i] ?? 0) ^ 0x80;
      const res = await request(app.getHttpServer())
        .get(`/c/${copy.toString('base64url')}`)
        .set('x-forwarded-for', `10.${i}.0.1`);
      expect(res.status).toBe(404);
      expect(res.text).toContain('This link is not valid');
      expect(res.headers.location).toBeUndefined();
    }
  });

  it('expired → 410 page', async () => {
    const res = await request(app.getHttpServer())
      .get(`/c/${token(0, { expiresAt: Math.floor(Date.now() / 1000) - 10 })}`)
      .expect(410);
    expect(res.text).toContain('expired');
    expectSecurityHeaders(res);
  });

  it('not found → 404 page', async () => {
    const res = await request(app.getHttpServer())
      .get(`/c/${token(9)}`)
      .expect(404);
    expect(res.text).toContain('not available');
  });

  it('block → 403 with the reference id of the click event', async () => {
    const res = await request(app.getHttpServer())
      .get(`/c/${token(2)}`)
      .expect(403);
    expectSecurityHeaders(res);
    const blocked = repository.events.filter((e) => e.decision === 'blocked').at(-1);
    expect(res.text).toContain(blocked?.publicId);
    expect(res.text).not.toContain('evil-site');
    expect(res.text).not.toMatch(/<script/i);
  });

  it('warn → interstitial with a continue link; continue windows', async () => {
    const t = token(1);
    const res = await request(app.getHttpServer()).get(`/c/${t}`).expect(200);
    expectSecurityHeaders(res);
    expect(res.text).toContain('203.0.113.10');
    const match = /href="(\/c\/[A-Za-z0-9_-]+\/continue\?n=[A-Za-z0-9_-]+)"/.exec(res.text);
    expect(match).not.toBeNull();
    const cont = await request(app.getHttpServer())
      .get(match?.[1] ?? '')
      .expect(302);
    expect(cont.headers.location).toBe(SUSPICIOUS);

    const now = Math.floor(Date.now() / 1000);
    const previousWindow = continueNonce(t, config.tokenKeys.current, now - 600, 600);
    await request(app.getHttpServer()).get(`/c/${t}/continue?n=${previousWindow}`).expect(302);
    const stale = continueNonce(t, config.tokenKeys.current, now - 1800, 600);
    const again = await request(app.getHttpServer()).get(`/c/${t}/continue?n=${stale}`).expect(200);
    expect(again.text).toContain('Be careful');
    // A nonce of another token is refused.
    const other = continueNonce(token(0), config.tokenKeys.current, now, 600);
    await request(app.getHttpServer()).get(`/c/${t}/continue?n=${other}`).expect(200);
    await request(app.getHttpServer()).get(`/c/${t}/continue?n=${other}&n=x`).expect(200);
  });

  it('tenant policy is read live (allowContinue=false hides the link)', async () => {
    repository.settings.set(ORG, { click: { allowContinue: false } });
    const res = await request(app.getHttpServer())
      .get(`/c/${token(1)}`)
      .expect(200);
    expect(res.text).not.toContain('/continue');
    repository.settings.delete(ORG);
  });

  it('database down → 503 page with the headers, never a redirect', async () => {
    repository.fail.findUrl = 'error';
    const res = await request(app.getHttpServer())
      .get(`/c/${token(0)}`)
      .expect(503);
    delete repository.fail.findUrl;
    expect(res.headers.location).toBeUndefined();
    expectSecurityHeaders(res);
  });

  it('rate limited → 429 page with the headers', async () => {
    const t = token(0, { expiresAt: Math.floor(Date.now() / 1000) + 12_345 });
    let last: request.Response | undefined;
    for (let i = 0; i < 31; i += 1) last = await request(app.getHttpServer()).get(`/c/${t}`);
    expect(last?.status).toBe(429);
    if (last) expectSecurityHeaders(last);
  });
});

describe('public listener surface', () => {
  it('serves the stylesheet with the headers', async () => {
    const res = await request(app.getHttpServer()).get('/static/click.css').expect(200);
    expect(res.headers['content-type']).toContain('text/css');
    expectSecurityHeaders(res);
  });

  it('has no health, metrics or other routes; other methods are 404', async () => {
    for (const path of ['/health/live', '/health/ready', '/metrics', '/', '/v1/c/x']) {
      const res = await request(app.getHttpServer()).get(path).expect(404);
      expectSecurityHeaders(res);
      expect(res.headers['content-type']).toContain('text/html');
    }
    await request(app.getHttpServer())
      .post(`/c/${token(0)}`)
      .expect(404);
  });
});

describe('admin listener', () => {
  it('serves live, ready and metrics; nothing else', async () => {
    const metrics = new MetricsService({ service: 'click-service' });
    metrics.counter('click_requests_total', 'x', ['decision']).inc({ decision: 'allowed' });
    const health = new HealthService(
      [
        { healthName: 'mysql', checkHealth: () => Promise.resolve() },
        { healthName: 'redis', checkHealth: () => Promise.reject(new Error('down')) },
      ],
      { name: 'click-service', version: 'test' },
    );
    const server = createAdminServer({ health, metrics, logger: silentLogger() });
    await request(server).get('/health/live').expect(200);
    const ready = await request(server).get('/health/ready').expect(503);
    expect(ready.body.checks.map((c: { name: string }) => c.name)).toEqual(['mysql', 'redis']);
    const scrape = await request(server).get('/metrics').expect(200);
    expect(scrape.text).toContain(
      'click_requests_total{decision="allowed",service="click-service"} 1',
    );
    await request(server).get('/c/x').expect(404);
    await request(server).post('/metrics').expect(405);
  });
});
