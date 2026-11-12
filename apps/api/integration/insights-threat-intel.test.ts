/**
 * Step 6.1 WP3 integration (real MySQL writer + replica): `GET /threat-intelligence/lookup`
 * (docs/plan/steps/18-rest-api.md §3.3, §8) against platform `threat_indicators` stored the way
 * the platform catalogue stores them (`normalizeIndicator`) and `malware_signatures`: matches by
 * type, parent-domain expansion, expiry, tenant-owned rows ignored, no analyst data in the answer,
 * and the audit row of every lookup.
 */
// @covers get /api/v1/threat-intelligence/lookup
import { createHash, randomBytes } from 'node:crypto';
import { normalizeIndicator } from '@email-gateway/url-security';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { createIntegrationApp, type IntegrationApp } from './support/app';
import { createFixtures, type FixtureOrganization, type Fixtures } from './support/fixtures';
import { apiKeyHeader, bearer, login } from './support/http';
import {
  deleteThreatFixtures,
  fixtureSource,
  insertPlatformIndicator,
  insertSignature,
  POLL,
  reader,
  waitFor,
} from './support/insights';

let ctx: IntegrationApp;
let fx: Fixtures;
let org: FixtureOrganization;
let token: string;
let key: string;
const source = fixtureSource();
const tag = randomBytes(4).toString('hex');
const domain = `phish-${tag}.example.com`;
const url = `https://login.${domain}/verify?id=${tag}`;
const ip = `198.51.100.${(parseInt(tag.slice(0, 2), 16) % 200) + 1}`;
const knownHash = randomBytes(32).toString('hex');
const expiredHash = randomBytes(32).toString('hex');
const sha = (v: string) => createHash('sha256').update(v).digest('hex');

function stored(type: 'url' | 'domain' | 'ip', raw: string) {
  const n = normalizeIndicator(type, raw);
  if (!n.ok) throw new Error(`fixture ${type} does not normalize`);
  return n;
}

beforeAll(async () => {
  ctx = await createIntegrationApp();
  fx = createFixtures(ctx);
  org = await fx.createOrganization();
  fx.registerCleanup(() => deleteThreatFixtures(ctx, source));
  const admin = await fx.createUser(org, { roles: ['security_analyst'] });
  token = (
    await login(ctx, { email: admin.email, password: admin.password, organization: org.slug })
  ).body.accessToken as string;
  key = await fx.createApiKey(org, ['threat_intel:read']);

  const d = stored('domain', domain);
  await insertPlatformIndicator(ctx, source, {
    type: 'domain',
    value: d.value,
    valueSha256: d.valueSha256,
    severity: 'high',
    category: 'phishing',
  });
  const u = stored('url', url);
  await insertPlatformIndicator(ctx, source, {
    type: 'url',
    value: u.value,
    valueSha256: u.valueSha256,
    severity: 'critical',
    category: 'phishing',
  });
  const i = stored('ip', ip);
  await insertPlatformIndicator(ctx, source, {
    type: 'ip',
    value: i.value,
    valueSha256: i.valueSha256,
    severity: 'medium',
    category: 'c2',
    expiresAt: new Date(Date.now() - 60_000),
  });
  // A tenant-owned row of the same domain: no engine reads it, the lookup ignores it.
  await insertPlatformIndicator(ctx, source, {
    type: 'domain',
    value: `tenant-${d.value}`,
    valueSha256: sha(`tenant-${d.value}`),
    severity: 'low',
    category: 'spam',
    organizationId: org.id,
  });
  await insertPlatformIndicator(ctx, source, {
    type: 'file_sha256',
    value: knownHash,
    valueSha256: sha(knownHash),
    severity: 'high',
    category: 'malware',
  });
  await insertSignature(ctx, source, knownHash, 'critical');
  await insertSignature(ctx, source, expiredHash, 'high', new Date(Date.now() - 60_000));
  await waitFor(
    async () =>
      (await reader(ctx).threatIndicator.count({ where: { source } })) +
      (await reader(ctx).malwareSignature.count({ where: { source } })),
    7,
  );
});

afterAll(async () => {
  await fx?.cleanup();
  await ctx?.close();
});

const lookup = (type: string, value: string, headers: Record<string, string> = bearer(token)) =>
  ctx.http
    .get(`/api/v1/threat-intelligence/lookup?${new URLSearchParams({ type, value }).toString()}`)
    .set(headers);

describe('GET /threat-intelligence/lookup', () => {
  it('matches a subdomain against the platform indicator of its parent domain', async () => {
    const res = await lookup('domain', `Mail.${domain.toUpperCase()}.`).expect(200);
    expect(res.body).toEqual({
      type: 'domain',
      valueSha256: sha(`mail.${domain}`),
      known: true,
      matches: [
        {
          source: 'platform_indicator',
          severity: 'high',
          category: 'phishing',
          firstSeenAt: expect.any(String),
          lastSeenAt: expect.any(String),
          expiresAt: null,
        },
      ],
    });
    expect(JSON.stringify(res.body)).not.toContain('analyst');
  });

  it('matches a URL in another spelling (engine normalization) and accepts API keys', async () => {
    const res = await lookup(
      'url',
      `HTTPS://LOGIN.${domain.toUpperCase()}:443/verify?id=${tag}#x`,
      apiKeyHeader(key),
    ).expect(200);
    expect(res.body).toMatchObject({
      known: true,
      matches: [{ severity: 'critical', category: 'phishing' }],
    });
    expect(res.body.valueSha256).toBe(stored('url', url).valueSha256);
  });

  it('ignores expired indicators and tenant-owned rows', async () => {
    expect((await lookup('ip', ip).expect(200)).body).toMatchObject({ known: false, matches: [] });
    expect((await lookup('domain', `tenant-${domain}`).expect(200)).body.known).toBe(false);
  });

  it('matches sha256 values in the indicators and the hash catalogue, not expired signatures', async () => {
    const res = await lookup('sha256', knownHash.toUpperCase()).expect(200);
    expect(
      res.body.matches.map((m: { source: string; severity: string }) => [m.source, m.severity]),
    ).toEqual([
      ['hash_catalog', 'critical'],
      ['platform_indicator', 'high'],
    ]);
    expect((await lookup('sha256', expiredHash).expect(200)).body).toMatchObject({
      known: false,
      matches: [],
    });
  });

  it('audits every lookup with the value’s SHA-256 and the result, never the value', async () => {
    const before = new Date();
    await lookup('domain', domain).expect(200);
    await expect
      .poll(
        () =>
          ctx.prisma.auditLog.findMany({
            where: {
              organizationId: org.id,
              action: 'threat_intel.looked_up',
              createdAt: { gte: before },
            },
            select: { resourceType: true, metadata: true },
          }),
        POLL,
      )
      .toEqual([
        {
          resourceType: 'threat_intelligence',
          metadata: expect.objectContaining({
            type: 'domain',
            valueSha256: sha(domain),
            known: true,
            matchCount: 1,
            requestId: expect.any(String),
          }),
        },
      ]);
    const rows = await ctx.prisma.auditLog.findMany({
      where: { organizationId: org.id, action: 'threat_intel.looked_up' },
      select: { metadata: true, resourceId: true },
    });
    expect(JSON.stringify(rows)).not.toContain(domain);
    expect(JSON.stringify(rows)).not.toContain(knownHash);
  });

  it('refuses invalid values with 400 validation_failed', async () => {
    for (const [type, value] of [
      ['domain', 'com'],
      ['sha256', 'zz'],
      ['ip', 'example.com'],
      ['url', 'javascript:alert(1)'],
    ] as const) {
      const res = await lookup(type, value).expect(400);
      expect(res.body.code).toBe('validation_failed');
    }
  });
});
