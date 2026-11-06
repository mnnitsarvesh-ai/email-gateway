import { spawn } from 'node:child_process';
import { resolve } from 'node:path';
import type { INestApplication } from '@nestjs/common';
import type { NestExpressApplication } from '@nestjs/platform-express';
import { NestFactory } from '@nestjs/core';
import { PrismaService, RedisService } from '@email-gateway/common';
import { PrismaClient } from '@email-gateway/database';
import { urlClickedV1 } from '@email-gateway/event-contracts';
import { normalizeUrl, sha256Hex, signToken } from '@email-gateway/url-security';
import request from 'supertest';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { AppModule } from '../src/app.module';
import { silentLogger } from '../src/click/click.test-support';
import { loadClickConfig, type ClickConfig } from '../src/config';
import { configurePublicApp } from '../src/http/configure';

/**
 * click-service against the live stack (step 4.3 §9): the real MySQL writer through the
 * `gateway_click` account (CLICK_DATABASE_URL), Redis, dns-sink (127.0.0.1:DNS_SINK_HOST_PORT)
 * and url-test (smtp-test profile, through URL_FETCH_TEST_DIAL_MAP). Fixtures are written with
 * the app account (DATABASE_URL); the click account only reads and logs. Values from .env are
 * never printed.
 */

const REPO = resolve(__dirname, '../../..');
const ORG = 910_000_000n + BigInt(Math.floor(Math.random() * 1_000_000));
const MESSAGE = 9_100_000_000_000n + BigInt(Math.floor(Math.random() * 1_000_000_000));
const RECEIVED_AT = new Date(Date.now() - 3_600_000);
const FEED_SOURCE = 'analyst';
const FEED_HOST = `wp4-${MESSAGE}.clean-site.test`;
const fixtures = new PrismaClient({ datasourceUrl: process.env.DATABASE_URL });
const clickClient = new PrismaClient({ datasourceUrl: process.env.CLICK_DATABASE_URL });
const feedIds: bigint[] = [];
const apps: INestApplication[] = [];

let config: ClickConfig;
let app: INestApplication;

async function startApp(overrides: Record<string, string> = {}): Promise<INestApplication> {
  const cfg = loadClickConfig({ ...process.env, ...overrides });
  const nest = await NestFactory.create<NestExpressApplication>(
    AppModule.forRoot(cfg, silentLogger()),
    { logger: false },
  );
  configurePublicApp(nest, { trustProxyHops: 0, hsts: false, logger: silentLogger() });
  await nest.init();
  apps.push(nest);
  return nest;
}

async function addUrl(
  seq: number,
  url: string,
  scan: { verdict: 'clean' | 'suspicious' | 'malicious' | 'unknown' } | null,
): Promise<string> {
  const result = normalizeUrl(url);
  if (!result.ok) throw new Error('fixture URL does not normalize');
  const n = result.url;
  await fixtures.messageUrl.create({
    data: {
      receivedAt: RECEIVED_AT,
      messageId: MESSAGE,
      organizationId: ORG,
      urlSeq: seq,
      url: n.stored,
      urlSha256: n.sha256,
      scheme: n.scheme,
      host: n.host,
      unicodeHost: n.unicodeHost,
      registrableDomain: n.registrableDomain,
      hostKind: n.hostKind,
      port: n.port,
      truncated: n.truncated,
      flags: n.flags,
      sources: { html_href: 1 },
      occurrences: 1,
      firstLifecycleRound: 0,
      extractorVersion: 'url-extract/1',
    },
  });
  if (scan) {
    await fixtures.urlScanResult.create({
      data: {
        receivedAt: RECEIVED_AT,
        messageId: MESSAGE,
        organizationId: ORG,
        scanId: 1n,
        urlSeq: seq,
        urlSha256: n.sha256,
        verdict: scan.verdict,
        reasonCodes: scan.verdict === 'clean' ? ['clean.no_findings'] : ['url.fetch_not_performed'],
        reputation: [],
        lookalike: [],
        fetchStatus: 'not_attempted',
        rewritten: true,
        dynamicRequested: false,
        fetchCache: 'none',
        durationMs: 1,
      },
    });
  }
  return signToken(
    {
      organizationId: ORG,
      messageId: MESSAGE,
      receivedAtMs: RECEIVED_AT.getTime(),
      urlSeq: seq,
      expiresAt: Math.floor(Date.now() / 1000) + 86_400,
    },
    config.tokenKeys.current,
  );
}

async function events(): Promise<
  Array<{
    decision: string;
    verdict: string | null;
    reasonCodes: unknown;
    publicId: string;
    clientNetwork: string | null;
    recheck: unknown;
  }>
> {
  return fixtures.urlClickEvent.findMany({
    where: { messageId: MESSAGE, messageReceivedAt: RECEIVED_AT },
    orderBy: { id: 'asc' },
    select: {
      decision: true,
      verdict: true,
      reasonCodes: true,
      publicId: true,
      clientNetwork: true,
      recheck: true,
    },
  });
}

async function waitForEvents(
  count: number,
  timeoutMs = 10_000,
): Promise<Awaited<ReturnType<typeof events>>> {
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    const rows = await events();
    if (rows.length >= count || Date.now() > deadline) return rows;
    await new Promise((r) => setTimeout(r, 100));
  }
}

/** Holds a WRITE lock on url_click_events for `seconds` (root inside the mysql container). */
function lockClickEvents(seconds: number): Promise<void> {
  return new Promise((resolveLock, reject) => {
    const database = process.env.MYSQL_DATABASE ?? 'email_gateway';
    const child = spawn(
      'docker',
      [
        'compose',
        'exec',
        '-T',
        'mysql',
        'sh',
        '-c',
        `MYSQL_PWD="$MYSQL_ROOT_PASSWORD" mysql -uroot -e "LOCK TABLES \\\`${database}\\\`.url_click_events WRITE; SELECT SLEEP(${seconds}); UNLOCK TABLES;"`,
      ],
      { cwd: REPO, stdio: ['ignore', 'ignore', 'ignore'] },
    );
    child.once('error', reject);
    child.once('exit', () => resolveLock());
  });
}

beforeAll(async () => {
  config = loadClickConfig(process.env);
  app = await startApp();
});

afterAll(async () => {
  for (const nest of apps) await nest.close();
  await fixtures.urlClickEvent.deleteMany({ where: { messageId: MESSAGE } });
  await fixtures.urlScanResult.deleteMany({ where: { messageId: MESSAGE } });
  await fixtures.urlDynamicInspection.deleteMany({ where: { messageId: MESSAGE } });
  await fixtures.messageUrl.deleteMany({ where: { messageId: MESSAGE } });
  // The test organization does not exist: its click events must not stay in the outbox (an
  // event-relay without the step 4.3 registry would retry them as unknown_event_type).
  await fixtures.messageOutbox.deleteMany({
    where: {
      eventType: 'mail.url.clicked.v1',
      aggregateId: MESSAGE.toString(),
      organizationId: ORG,
    },
  });
  if (feedIds.length > 0)
    await fixtures.threatIndicator.deleteMany({ where: { id: { in: feedIds } } });
  await fixtures.$disconnect();
  await clickClient.$disconnect();
});

describe('gateway_click account (U14 grants)', () => {
  it('reads its tables and nothing else', async () => {
    await expect(
      clickClient.$queryRawUnsafe('SELECT COUNT(*) FROM message_urls'),
    ).resolves.toBeDefined();
    await expect(
      clickClient.$queryRawUnsafe('SELECT id FROM email_messages LIMIT 1'),
    ).rejects.toThrow(/1142|denied/i);
    await expect(
      clickClient.$queryRawUnsafe('SELECT id FROM organizations LIMIT 1'),
    ).rejects.toThrow(/1142|denied/i);
    await expect(
      clickClient.$queryRawUnsafe('SELECT id FROM url_click_events LIMIT 1'),
    ).rejects.toThrow(/1142|denied/i);
  });

  it('inserts only into url_click_events and message_outbox', async () => {
    await expect(
      clickClient.$executeRawUnsafe(
        "INSERT INTO message_urls (received_at, message_id, organization_id, url_seq, url, url_sha256, scheme, host, host_kind, sources, occurrences, first_lifecycle_round, extractor_version) VALUES (NOW(3), 1, 1, 1, 'http://a.test/', REPEAT('a',64), 'http', 'a.test', 'domain', '{}', 1, 0, 'x')",
      ),
    ).rejects.toThrow(/1142|denied/i);
    await expect(
      clickClient.$executeRawUnsafe('DELETE FROM url_click_events WHERE id = 0'),
    ).rejects.toThrow(/1142|denied/i);
    await expect(
      clickClient.$executeRawUnsafe('UPDATE threat_indicators SET reason = NULL WHERE id = 0'),
    ).rejects.toThrow(/1142|denied/i);
    await expect(
      clickClient.$executeRawUnsafe('DELETE FROM message_outbox WHERE id = 0'),
    ).rejects.toThrow(/1142|denied/i);
  });
});

describe('time of click (live stack)', () => {
  it('clean → 302; after a feed row is added → block page + event + outbox (time-of-click)', async () => {
    const url = `http://${FEED_HOST}/landing?a=1`;
    const token = await addUrl(0, url, { verdict: 'clean' });
    const allowed = await request(app.getHttpServer()).get(`/c/${token}`).expect(302);
    expect(allowed.headers.location).toBe(url);

    const value = FEED_HOST.split('.').slice(-3).join('.');
    const feed = await fixtures.threatIndicator.create({
      data: {
        indicatorType: 'domain',
        value,
        valueSha256: sha256Hex(value),
        source: FEED_SOURCE,
        severity: 'high',
        category: 'phishing',
        confidence: 90,
        firstSeenAt: new Date(),
        lastSeenAt: new Date(),
        reason: 'step 4.3 WP4 click-service integration test',
      },
      select: { id: true },
    });
    feedIds.push(feed.id);
    const blocked = await request(app.getHttpServer()).get(`/c/${token}`).expect(403);
    const rows = await waitForEvents(2);
    expect(rows.map((r) => r.decision)).toEqual(['allowed', 'blocked']);
    expect(rows[1]?.verdict).toBe('malicious');
    expect(rows[1]?.reasonCodes).toContain('url.feed_malicious');
    expect(blocked.text).toContain(rows[1]?.publicId);
    expect(rows[0]?.clientNetwork).toMatch(/\/(24|48)$/);

    const outbox = await fixtures.messageOutbox.findMany({
      where: { eventType: 'mail.url.clicked.v1', aggregateId: MESSAGE.toString() },
      select: { organizationId: true, aggregateType: true, payload: true },
    });
    expect(outbox).toHaveLength(2);
    for (const row of outbox) {
      expect(row.organizationId).toBe(ORG);
      expect(row.aggregateType).toBe('message');
      const payload = urlClickedV1.parse(row.payload);
      expect(JSON.stringify(payload)).not.toContain(FEED_HOST);
    }
  });

  it('shortener → chain re-resolved through the guard → 302 to the stored short URL', async () => {
    const token = await addUrl(1, 'http://short-link.test/s/clean', { verdict: 'unknown' });
    const res = await request(app.getHttpServer()).get(`/c/${token}`);
    expect(res.status).toBe(302);
    expect(res.headers.location).toBe('http://short-link.test/s/clean');
    const rows = await waitForEvents(3);
    expect(rows[2]?.recheck).toMatchObject({ chain: expect.stringMatching(/fresh|cached/) });
    expect(rows[2]?.reasonCodes).toEqual(
      expect.arrayContaining(['url.shortened', 'url.redirected']),
    );
  });

  it('SSRF redirect at click time → redirect_blocked_internal → warn page', async () => {
    const token = await addUrl(2, 'http://short-link.test/s/metadata', null);
    const res = await request(app.getHttpServer()).get(`/c/${token}`).expect(200);
    expect(res.text).toContain('short-link.test');
    const rows = await waitForEvents(4);
    expect(rows[3]?.decision).toBe('warned');
    expect(rows[3]?.reasonCodes).toContain('url.redirect_blocked_internal');
  });

  it('recheck budget exceeded → unknown → policy (warn), response bounded', async () => {
    const budgetApp = await startApp({ CLICK_RECHECK_BUDGET_MS: '1200' });
    const token = await addUrl(3, 'http://slow-site.test/x', { verdict: 'unknown' });
    const started = Date.now();
    await request(budgetApp.getHttpServer()).get(`/c/${token}`).expect(200);
    expect(Date.now() - started).toBeLessThan(4000);
    const rows = await waitForEvents(5);
    expect(rows[4]).toMatchObject({ decision: 'warned', verdict: 'unknown' });
    expect(rows[4]?.reasonCodes).toContain('url.fetch_timeout');
  });

  it('a slow database write keeps the response bounded; the event lands afterwards', async () => {
    const token = await addUrl(4, `http://${FEED_HOST}/other`, { verdict: 'clean' });
    const lock = lockClickEvents(4);
    await new Promise((r) => setTimeout(r, 800)); // the lock is held
    const started = Date.now();
    const res = await request(app.getHttpServer()).get(`/c/${token}`);
    const elapsed = Date.now() - started;
    expect(res.status).toBe(403); // the feed row of the first test covers the whole domain
    expect(elapsed).toBeLessThan(2500);
    await lock;
    const rows = await waitForEvents(6, 15_000);
    expect(rows).toHaveLength(6);
  });

  it('IP reputation at click time: bad-ip-host.test resolves to an RBL-listed address → warn', async () => {
    // dns-sink answers 203.0.113.66 (listed on the test RBL, nothing listens there); the
    // address is looked up in parallel with the chain, so the listing is found even though the
    // fetch cannot complete within the budget.
    const token = await addUrl(6, 'http://bad-ip-host.test/x', { verdict: 'clean' });
    const res = await request(app.getHttpServer()).get(`/c/${token}`);
    expect(res.status).toBe(200);
    const rows = await waitForEvents(7, 15_000);
    expect(rows[6]?.decision).toBe('warned');
    expect(rows[6]?.verdict).not.toBe('clean');
    expect(rows[6]?.reasonCodes).toContain('url.dnsbl_spam');
  });

  it('rate limits in the real Redis (Lua window with expiry)', async () => {
    const limited = await startApp({ CLICK_RATE_LIMIT_TOKEN_PER_MINUTE: '2' });
    const token = await addUrl(5, 'http://clean-site.test/rate-limit', { verdict: 'clean' });
    await request(limited.getHttpServer()).get(`/c/${token}`);
    await request(limited.getHttpServer()).get(`/c/${token}`);
    await request(limited.getHttpServer()).get(`/c/${token}`).expect(429);
    const redis = limited.get(RedisService).client;
    const keys = await redis.keys('eg:click:rl:v1:tok:*');
    expect(keys.length).toBeGreaterThan(0);
    const ttl = await redis.pttl(keys[0] as string);
    expect(ttl).toBeGreaterThan(0);
    expect(ttl).toBeLessThanOrEqual(60_000);
  });

  it('readiness checks MySQL (click account) and Redis', async () => {
    await expect(app.get(PrismaService).checkHealth()).resolves.toBeUndefined();
    await expect(app.get(RedisService).checkHealth()).resolves.toBeUndefined();
  });
});
