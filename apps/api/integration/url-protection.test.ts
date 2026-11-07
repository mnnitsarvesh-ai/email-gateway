/**
 * Step 4.3 api routes against the real MySQL writer and replica (docs/plan/steps/
 * 11-url-protection.md U13, U16): the per-URL results and the rewrite of the scans read (replica,
 * every query filtered by the scope organization: URL, result, rewrite, inspection and click rows
 * of another organization with the same message id are never shown; another organization's
 * message is 404; no cache outcome or per-URL duration), the `url` settings through the existing
 * settings routes (normalization, public suffixes refused, audit) and the platform
 * threat-indicator catalog (permission, MFA, API keys and tenants refused, normalization,
 * public suffix refused, 409, audit rows with the before-image, replica list). URL rows are
 * inserted as the email-worker / click-service write them (fixtures).
 */
import { createHash, randomBytes, randomUUID } from 'node:crypto';
import { PrismaReadService } from '@email-gateway/common';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { createIntegrationApp, type IntegrationApp } from './support/app';
import {
  createFixtures,
  type FixtureOrganization,
  type Fixtures,
  type FixtureUser,
} from './support/fixtures';
import { apiKeyHeader, bearer, loginWithMfa, uniqueIp } from './support/http';
import {
  deleteLifecycleFixtures,
  insertLifecycleMessage,
  type LifecycleMessage,
} from './support/lifecycle';

const POLL = { timeout: 15_000, interval: 200 };
const run = randomBytes(5).toString('hex');
const sha = (value: string) => createHash('sha256').update(value).digest('hex');

let ctx: IntegrationApp;
let fx: Fixtures;
let orgA: FixtureOrganization;
let orgB: FixtureOrganization;
let readerA: Record<string, string>;
let readerB: Record<string, string>;
let platformAdmin: Record<string, string>;
let platformAdminUser: FixtureUser;
const indicatorIds = new Set<bigint>();

const headers = (auth: Record<string, string>) => ({ ...auth, 'X-Forwarded-For': uniqueIp() });
const tokenOf = async (user: FixtureUser) =>
  bearer((await loginWithMfa(ctx, fx, user)).accessToken);

async function deleteUrlFixtures(organizationIds: bigint[]): Promise<void> {
  const where = { organizationId: { in: organizationIds } };
  await ctx.prisma.urlClickEvent.deleteMany({ where });
  await ctx.prisma.urlDynamicInspection.deleteMany({ where });
  await ctx.prisma.urlRewrite.deleteMany({ where });
  await ctx.prisma.urlScanResult.deleteMany({ where });
  await ctx.prisma.messageUrl.deleteMany({ where });
  await ctx.prisma.scanEngineResult.deleteMany({ where });
  await ctx.prisma.emailScan.deleteMany({ where });
  await ctx.prisma.scanEngineSetting.deleteMany({ where });
}

/** A completed round with a url engine final and its child rows (as the email-worker writes). */
async function insertUrlRound(
  message: LifecycleMessage,
  organizationId: bigint = message.organizationId,
): Promise<bigint> {
  const startedAt = new Date(message.receivedAt.getTime() + 1_000);
  const base = { receivedAt: message.receivedAt, messageId: message.id, organizationId };
  const scan = await ctx.prisma.emailScan.create({
    data: {
      ...base,
      scanKind: 'initial',
      status: 'completed',
      lifecycleRound: 0,
      scanVerdict: 'suspicious',
      requiredEngines: ['rspamd', 'attachment', 'url'],
      reasonCodes: ['url.redirect_blocked_internal'],
      startedAt,
      completedAt: new Date(startedAt.getTime() + 2_345),
      deadlineAt: new Date(startedAt.getTime() + 1_800_000),
    },
    select: { id: true },
  });
  await ctx.prisma.scanEngineResult.create({
    data: {
      ...base,
      scanId: scan.id,
      engine: 'url',
      engineVersion: 'url/1;url-fetch/1;aaaaaaaa;bbbbbbbb',
      outcome: 'suspicious',
      durationMs: 1_234,
      attempt: 1,
      isFinal: true,
      reasonCodes: ['url.redirect_blocked_internal'],
      settingsVersion: 'url-map/1;p=0123456789ab;t=none',
      evidence: { signals: [] },
      completedAt: new Date(startedAt.getTime() + 2_345),
    },
  });
  const urls = [
    { seq: 0, url: 'https://clean-site.test/landing', host: 'clean-site.test' },
    { seq: 1, url: 'http://short-link.test/s/internal', host: 'short-link.test' },
  ];
  for (const u of urls) {
    await ctx.prisma.messageUrl.create({
      data: {
        ...base,
        urlSeq: u.seq,
        url: u.url,
        urlSha256: sha(u.url),
        scheme: u.url.startsWith('https') ? 'https' : 'http',
        host: u.host,
        registrableDomain: u.host,
        hostKind: 'domain',
        flags: [],
        sources: { html_href: 1 },
        occurrences: 1,
        firstLifecycleRound: 0,
        extractorVersion: 'url-extract/1',
      },
    });
  }
  await ctx.prisma.urlScanResult.create({
    data: {
      ...base,
      scanId: scan.id,
      urlSeq: 0,
      urlSha256: sha(urls[0]!.url),
      verdict: 'clean',
      reasonCodes: ['clean.no_findings'],
      reputation: [
        {
          provider: 'local_feed',
          version: 'local_feed/1',
          kind: 'url',
          status: 'clear',
          category: null,
          severity: null,
          cache: 'none',
        },
        {
          provider: 'dnsbl',
          version: 'dnsbl/1;12345678',
          kind: 'domain',
          status: 'clear',
          category: null,
          severity: null,
          cache: 'hit',
        },
      ],
      fetchStatus: 'not_attempted',
      rewritten: true,
      dynamicRequested: false,
      fetchCache: 'none',
      durationMs: 0,
    },
  });
  await ctx.prisma.urlScanResult.create({
    data: {
      ...base,
      scanId: scan.id,
      urlSeq: 1,
      urlSha256: sha(urls[1]!.url),
      verdict: 'suspicious',
      reasonCodes: ['url.redirect_blocked_internal', 'url.shortened'],
      reputation: [],
      fetchStatus: 'blocked',
      fetchError: 'loopback',
      hopCount: 1,
      redirectChain: [
        { host: 'short-link.test', port: 80, status: 302, kind: 'initial', blocked: null },
        { host: '127.0.0.1', port: 80, status: null, kind: 'http', blocked: 'loopback' },
      ],
      rewritten: true,
      dynamicRequested: true,
      fetchCache: 'miss',
      durationMs: 77,
    },
  });
  await ctx.prisma.urlRewrite.create({
    data: {
      ...base,
      scanId: scan.id,
      lifecycleRound: 0,
      status: 'rewritten',
      objectKey: `org/${organizationId.toString()}/rewrite/2026/11/06/${message.id.toString()}/r0-x.eml`,
      objectSha256: sha('eml'),
      objectSizeBytes: 1234,
      linksRewritten: 2,
      partsRewritten: 1,
      tokenKid: 1,
      expiresAt: new Date(Date.now() + 30 * 86_400_000),
      settingsVersion: 'url-map/1;p=0123456789ab;t=none',
    },
  });
  await ctx.prisma.urlDynamicInspection.create({
    data: {
      ...base,
      scanId: scan.id,
      urlSeq: 1,
      urlSha256: sha(urls[1]!.url),
      status: 'pending',
      requestedEventId: randomUUID(),
    },
  });
  for (const decision of ['allowed', 'blocked'] as const) {
    await ctx.prisma.urlClickEvent.create({
      data: {
        clickedAt: new Date(Date.now() - (decision === 'allowed' ? 5_000 : 1_000)),
        publicId: randomUUID(),
        organizationId,
        messageId: message.id,
        messageReceivedAt: message.receivedAt,
        urlSeq: 0,
        decision,
        verdict: decision === 'allowed' ? 'clean' : 'malicious',
        reasonCodes: [],
        tokenKid: 1,
        durationMs: 12,
      },
    });
  }
  return scan.id;
}

beforeAll(async () => {
  ctx = await createIntegrationApp();
  fx = createFixtures(ctx);
  orgA = await fx.createOrganization();
  orgB = await fx.createOrganization();
  fx.registerCleanup(() => deleteLifecycleFixtures(ctx, [orgA.id, orgB.id]));
  fx.registerCleanup(() => deleteUrlFixtures([orgA.id, orgB.id]));
  readerA = apiKeyHeader(await fx.createApiKey(orgA, ['message:read', 'policy:read']));
  readerB = apiKeyHeader(await fx.createApiKey(orgB, ['message:read', 'policy:read']));
  platformAdminUser = await fx.createPlatformUser(['platform_admin']);
  platformAdmin = await tokenOf(platformAdminUser);
  // Registered last, so it runs first (cleanups run in reverse).
  fx.registerCleanup(async () => {
    const ids = [...indicatorIds];
    await ctx.prisma.threatIndicator.deleteMany({ where: { id: { in: ids } } });
    await ctx.prisma.auditLog.deleteMany({
      where: {
        resourceType: 'threat_indicator',
        resourceId: { in: ids.map((id) => id.toString()) },
      },
    });
  });
}, 180_000);

afterAll(async () => {
  await fx?.cleanup();
  await ctx?.close();
}, 180_000);

describe('GET /messages/{messageId}/scans: per-URL results and rewrite (U16)', () => {
  it('reads them through the replica, tenant-scoped, without cache flags or durations', async () => {
    expect(ctx.get(PrismaReadService).status().mode).toBe('reader');
    const message = await insertLifecycleMessage(ctx, orgA, { state: 'scanned' });
    const scanId = await insertUrlRound(message);
    // Rows of organization B with the same message id and receivedAt: never shown.
    await ctx.prisma.messageUrl.create({
      data: {
        receivedAt: message.receivedAt,
        messageId: message.id,
        organizationId: orgB.id,
        urlSeq: 7,
        url: 'https://foreign.test/',
        urlSha256: sha('https://foreign.test/'),
        scheme: 'https',
        host: 'foreign.test',
        registrableDomain: 'foreign.test',
        hostKind: 'domain',
        sources: { text: 1 },
        occurrences: 1,
        firstLifecycleRound: 0,
        extractorVersion: 'url-extract/1',
      },
    });
    await ctx.prisma.urlScanResult.create({
      data: {
        receivedAt: message.receivedAt,
        messageId: message.id,
        organizationId: orgB.id,
        scanId,
        urlSeq: 7,
        urlSha256: sha('https://foreign.test/'),
        verdict: 'malicious',
        reasonCodes: ['url.feed_malicious'],
        reputation: [],
        fetchStatus: 'not_attempted',
        rewritten: false,
        dynamicRequested: false,
        fetchCache: 'none',
        durationMs: 0,
      },
    });
    await ctx.prisma.urlClickEvent.create({
      data: {
        clickedAt: new Date(),
        publicId: randomUUID(),
        organizationId: orgB.id,
        messageId: message.id,
        messageReceivedAt: message.receivedAt,
        urlSeq: 0,
        decision: 'warned',
        tokenKid: 1,
        durationMs: 1,
      },
    });
    const path = `/api/v1/messages/${message.publicId}/scans`;
    await expect
      .poll(async () => {
        const body = (await ctx.http.get(path).set(headers(readerA))).body as {
          data?: { engines: { urls?: unknown[]; rewrite?: unknown }[] }[];
        };
        const engine = body.data?.[0]?.engines.find(
          (e) => (e as { engine?: string }).engine === 'url',
        );
        return engine?.urls?.length === 2 && engine.rewrite !== null;
      }, POLL)
      .toBe(true);
    const res = await ctx.http.get(path).set(headers(readerA)).expect(200);
    const engine = res.body.data[0].engines.find((e: { engine: string }) => e.engine === 'url');
    expect(engine).toMatchObject({
      engine: 'url',
      final: true,
      outcome: 'suspicious',
      durationMs: null,
      rewrite: { status: 'rewritten', skipReason: null, linksRewritten: 2, partsRewritten: 1 },
    });
    expect(engine.completedAt).toMatch(/\.000Z$/);
    expect(engine.attempts[0]).toMatchObject({ durationMs: null });
    expect(engine.attempts[0].at).toMatch(/\.000Z$/);
    expect(engine.rewrite.expiresAt).toMatch(/\.000Z$/);
    expect(engine.urls.map((u: { urlSeq: number }) => u.urlSeq)).toEqual([0, 1]);
    expect(engine.urls[0]).toMatchObject({
      url: 'https://clean-site.test/landing',
      verdict: 'clean',
      reasonCodes: ['clean.no_findings'],
      reputation: [
        { provider: 'local_feed', kind: 'url', status: 'clear', category: null },
        { provider: 'dnsbl', kind: 'domain', status: 'clear', category: null },
      ],
      fetch: null,
      rewritten: true,
      // Only organization A's two clicks; the newest decides lastDecision.
      clicks: { total: 2, lastDecision: 'blocked' },
    });
    expect(engine.urls[0].clicks.lastAt).toMatch(/\.000Z$/);
    expect(engine.urls[1]).toMatchObject({
      verdict: 'suspicious',
      fetch: {
        status: 'blocked',
        hops: 1,
        chain: [
          { host: 'short-link.test', status: 302, kind: 'initial', blocked: null },
          { host: '127.0.0.1', status: null, kind: 'http', blocked: 'loopback' },
        ],
      },
      dynamic: { status: 'pending', verdict: null, reasonCodes: [], signals: null },
      clicks: { total: 0, lastDecision: null, lastAt: null },
    });
    const text = JSON.stringify(engine);
    expect(text).not.toMatch(/"cache"|fetchCache|foreign\.test|"urlSeq":7/);
    expect(text).not.toMatch(/"durationMs":\d/);

    const foreign = await ctx.http.get(path).set(headers(readerB)).expect(404);
    expect(foreign.body).toMatchObject({ code: 'message_not_found' });
  });
});

describe('url settings through /scan-settings/url (U13)', () => {
  it('lists the url engine, normalizes domains, refuses public suffixes and audits a change', async () => {
    const admin = await tokenOf(await fx.createUser(orgA, { roles: ['organization_admin'] }));
    const listed = await ctx.http.get('/api/v1/scan-settings').set(headers(admin)).expect(200);
    expect(listed.body.data.map((v: { engine: string }) => v.engine)).toEqual([
      'rspamd',
      'attachment',
      'url',
      'bec',
      'dlp',
    ]);
    const path = '/api/v1/scan-settings/url';
    const invalid = await ctx.http
      .put(path)
      .set(headers(admin))
      .send({ expectedVersion: 0, settings: { blockedDomains: ['github.io'] } })
      .expect(422);
    expect(invalid.body.violations).toEqual([
      expect.objectContaining({ path: 'blockedDomains.0', code: 'invalid' }),
    ]);
    const saved = await ctx.http
      .put(path)
      .set(headers(admin))
      .send({
        expectedVersion: 0,
        settings: {
          allowedDomains: ['Partner.Example.'],
          rewrite: { excludedDomains: ['bücher.example'], expiryDays: 14 },
          click: { suspicious: 'block' },
        },
      })
      .expect(200);
    expect(saved.body).toMatchObject({
      engine: 'url',
      version: 1,
      overrideApplied: true,
      effective: {
        allowedDomains: ['partner.example'],
        rewrite: { excludedDomains: ['xn--bcher-kva.example'], expiryDays: 14 },
        click: { suspicious: 'block' },
      },
    });
    const row = await ctx.prisma.scanEngineSetting.findFirst({
      where: { organizationId: orgA.id, engine: 'url' },
    });
    expect(row?.settings).toEqual({
      allowedDomains: ['partner.example'],
      rewrite: { excludedDomains: ['xn--bcher-kva.example'], expiryDays: 14 },
      click: { suspicious: 'block' },
    });
    const audits = await ctx.prisma.auditLog.findMany({
      where: { organizationId: orgA.id, action: 'scan_settings.updated', resourceId: 'url' },
    });
    expect(audits).toHaveLength(1);
    // Organization B never sees A's override.
    const readerSettings = await ctx.http
      .get('/api/v1/scan-settings')
      .set(headers(readerB))
      .expect(200);
    expect(
      readerSettings.body.data.find((v: { engine: string }) => v.engine === 'url').override,
    ).toBeNull();
  });
});

describe('platform threat indicators (U16)', () => {
  const path = '/api/v1/platform/threat-indicators';

  it('adds normalized as source analyst with its audit row; 409 for the same value', async () => {
    const res = await ctx.http
      .post(path)
      .set(headers(platformAdmin))
      .send({
        type: 'domain',
        value: `Login.IT-${run}.Example.`,
        severity: 'high',
        category: 'phishing',
        reason: 'integration run',
      })
      .expect(201);
    indicatorIds.add(BigInt(res.body.id));
    const value = `login.it-${run}.example`;
    expect(res.body).toMatchObject({
      type: 'domain',
      value,
      valueSha256: sha(value),
      severity: 'high',
      category: 'phishing',
      source: 'analyst',
      addedByUserId: platformAdminUser.publicId,
    });
    const row = await ctx.prisma.threatIndicator.findUnique({ where: { id: BigInt(res.body.id) } });
    expect(row).toMatchObject({
      organizationId: null,
      orgScope: 0n,
      indicatorType: 'domain',
      value,
      valueSha256: sha(value),
      source: 'analyst',
      addedByUserId: platformAdminUser.id,
      reason: 'integration run',
      category: 'phishing',
    });
    const audit = await ctx.prisma.auditLog.findMany({
      where: { action: 'threat_indicator.added', resourceId: res.body.id },
    });
    expect(audit).toHaveLength(1);
    expect(audit[0]).toMatchObject({ organizationId: null, actorId: platformAdminUser.publicId });
    expect(audit[0]!.metadata).toMatchObject({ value, type: 'domain', severity: 'high' });

    const again = await ctx.http
      .post(path)
      .set(headers(platformAdmin))
      .send({
        type: 'domain',
        value: `login.it-${run}.example`,
        severity: 'low',
        category: 'spam',
        reason: 'twice',
      })
      .expect(409);
    expect(again.body).toMatchObject({ code: 'indicator_exists', id: res.body.id });
  });

  it('normalizes URLs (identity form) and IPs; refuses public suffixes and bad values', async () => {
    const url = await ctx.http
      .post(path)
      .set(headers(platformAdmin))
      .send({
        type: 'url',
        value: `HTTPS://user:pw@IT-${run}.example:443/a/../login?x=1#frag`,
        severity: 'critical',
        category: 'malware',
        reason: 'integration run',
      })
      .expect(201);
    indicatorIds.add(BigInt(url.body.id));
    expect(url.body.value).toBe(`https://it-${run}.example/login?x=1`);
    const ip = await ctx.http
      .post(path)
      .set(headers(platformAdmin))
      .send({
        type: 'ip',
        value: '2001:DB8:0:0::7',
        severity: 'medium',
        category: 'c2',
        reason: 'integration run',
      })
      .expect(201);
    indicatorIds.add(BigInt(ip.body.id));
    expect(ip.body.value).toBe('2001:db8::7');
    for (const [type, value] of [
      ['domain', 'co.uk'],
      ['domain', 'github.io'],
      ['ip', 'not-an-ip'],
      ['url', 'ftp://x.example/'],
    ]) {
      const refused = await ctx.http
        .post(path)
        .set(headers(platformAdmin))
        .send({ type, value, severity: 'high', category: 'other', reason: 'x' })
        .expect(400);
      expect(JSON.stringify(refused.body.message)).toContain('value');
    }
  });

  it('lists through the replica and removes with the before-image (204, then 404)', async () => {
    const created = await ctx.http
      .post(path)
      .set(headers(platformAdmin))
      .send({
        type: 'domain',
        value: `rm-${run}.example`,
        severity: 'medium',
        category: 'scam',
        reason: 'to be removed',
      })
      .expect(201);
    const id = created.body.id as string;
    indicatorIds.add(BigInt(id));
    await expect
      .poll(
        async () =>
          (
            (
              await ctx.http
                .get(`${path}?type=domain&value=RM-${run}.example`)
                .set(headers(platformAdmin))
            ).body as { data?: unknown[] }
          ).data?.length,
        POLL,
      )
      .toBe(1);
    await ctx.http
      .delete(`${path}/${id}?reason=false%20positive`)
      .set(headers(platformAdmin))
      .expect(204);
    expect(await ctx.prisma.threatIndicator.findUnique({ where: { id: BigInt(id) } })).toBeNull();
    const removed = await ctx.prisma.auditLog.findFirst({
      where: { action: 'threat_indicator.removed', resourceId: id },
    });
    expect(removed?.metadata).toMatchObject({
      reason: 'false positive',
      before: {
        id,
        type: 'domain',
        value: `rm-${run}.example`,
        severity: 'medium',
        category: 'scam',
        source: 'analyst',
        reason: 'to be removed',
      },
    });
    const missing = await ctx.http
      .delete(`${path}/${id}?reason=again`)
      .set(headers(platformAdmin))
      .expect(404);
    expect(missing.body.code).toBe('threat_indicator_not_found');
  });

  it('refuses tenant administrators, API keys and sessions without MFA', async () => {
    const value = `rbac-${run}.example`;
    const body = { type: 'domain', value, severity: 'high', category: 'phishing', reason: 'x' };
    const tenantAdmin = await tokenOf(await fx.createUser(orgA, { roles: ['organization_admin'] }));
    await ctx.http.post(path).set(headers(tenantAdmin)).send(body).expect(403);
    const key = apiKeyHeader(await fx.createApiKey(orgA, ['message:read', 'policy:read']));
    await ctx.http.get(path).set(headers(key)).expect(403);
    const noMfa = await tokenOf(await fx.createPlatformUser(['platform_admin'], { mfa: false }));
    await ctx.http.post(path).set(headers(noMfa)).send(body).expect(403);
    expect(
      await ctx.prisma.threatIndicator.findFirst({ where: { valueSha256: sha(value) } }),
    ).toBeNull();
  });
});
